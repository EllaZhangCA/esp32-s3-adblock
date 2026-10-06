// S3 AdBlock — DNS sinkhole + web dashboard for the ESP32-S3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://s3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "protocol.h"
#include "blocklist_store.h"
#include <time.h>
#include <algorithm>
#if __has_include("secrets.h")
#include "secrets.h"
#else
#include "secrets.example.h"
#endif
// Optional compile-time WiFi credentials are only a provisioning fallback.

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // larger buckets use bounded binary search

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
String webPassword, otaPassword, setupPassword, portalToken;
bool fsReady = false;

static String randomSecret() {
  char value[33];
  for (int i = 0; i < 4; ++i) snprintf(value + i * 8, 9, "%08lx", (unsigned long)esp_random());
  return String(value);
}
static String deviceSecret(const char* key, const char* configured) {
  if (configured && strlen(configured) >= 16 && strncmp(configured, "CHANGE_ME", 9) != 0) return String(configured);
  String value = prefs.getString(key, "");
  if (value.length() < 16) { value = randomSecret(); prefs.putString(key, value); }
  return value;
}
static void initSecurity() {
  // WiFi has been started before esp_random(), providing RF entropy.
  prefs.begin("adblock-sec", false);
  webPassword = deviceSecret("web", WEB_PASS);
  otaPassword = deviceSecret("ota", OTA_PASS);
  setupPassword = deviceSecret("setup", nullptr);
  prefs.end();
  portalToken = randomSecret();
}
static void printCredentials() {
  Serial.printf("[admin] user: %s  password: %s\n[setup] WPA2 password: %s\n", WEB_USER, webPassword.c_str(), setupPassword.c_str());
#if ENABLE_ARDUINO_OTA
  Serial.printf("[ota] password: %s\n", otaPassword.c_str());
#endif
}
static void serviceSerial() {
  static bool wasOpen = false;
  bool open = bool(Serial);
  if (open && !wasOpen) printCredentials();
  // UART bridges may not expose host presence; entering '?' prints credentials.
  if (Serial.available() && Serial.read() == '?') printCredentials();
  wasOpen = open;
}
static String htmlEscape(const String& value) {
  String out;
  for (char c : value) {
    switch(c) {
      case '&': out += "&amp;"; break; case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break; case '\"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break; default: out += c;
    }
  }
  return out;
}
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) {
    return adblock::findHash(h, startPos, endPos + 1, [](uint32_t pos, uint64_t& value) {
      uint8_t bytes[HASH_BYTES];
      if (!blocklist.seek(pos * HASH_BYTES) || blocklist.read(bytes, HASH_BYTES) != HASH_BYTES) return false;
      value = unpackHash(bytes); return true;
    });
  }

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  if (blocklist.read(rangeBuf, rangeCount * HASH_BYTES) != rangeCount * HASH_BYTES) return false;

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (adblock::validDomain(l.c_str())) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase();
  if (!adblock::validDomain(d.c_str()) || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  LOCK_TCPIP_CORE();
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); break; }
  UNLOCK_TCPIP_CORE();
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x80 | (buf[2] & 1); buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int forwardUpstream(int qlen, int qend) {
  upstreamCli.flush();                                   // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
  // Rotate the source port as well as the transaction ID for each request.
  upstreamCli.stop();
  if (!upstreamCli.begin(0)) return 0;
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < 1000) {                         // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf) || !(buf[2] & 0x80) || (buf[2] & 0x78) || buf[4] || buf[5] != 1) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 1; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    if (((uint32_t)cip & (uint32_t)WiFi.subnetMask()) != ((uint32_t)WiFi.localIP() & (uint32_t)WiFi.subnetMask()) || !cport) {
      dnsServer.flush(); continue;
    }
    int qlen = dnsServer.read(buf, sizeof(buf)); dnsServer.flush();
    if (sz > (int)sizeof(buf) || qlen != sz || qlen < 17) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = adblock::parseQuery(buf, qlen, domain, &qtype, &qend);
    if (!dl) continue;
    Dev* c = getClient((uint32_t)cip);
    bool ban = isBannedIP((uint32_t)cip);
    bool blocked = ban || (blockingOn && isBlocked(domain));
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen, qend);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) {
  String out;
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
    else if (c < 0x20) { char esc[7]; snprintf(esc, sizeof(esc), "\\u%04x", c); out += esc; }
    else out += char(c);
  }
  return out;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + "false" +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// POST and authentication alone do not prevent cross-origin form submissions,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// s3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "s3-adblock";
static bool requireLogin() {
  web.sendHeader("Cache-Control", "no-store");
  web.sendHeader("X-Content-Type-Options", "nosniff");
  web.sendHeader("X-Frame-Options", "DENY");
  if (web.authenticate(WEB_USER, webPassword.c_str())) return true;
  web.requestAuthentication(); return false;
}
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, webPassword.c_str())) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip;
  if (!ip.fromString(web.arg("ip"))) { web.send(400, "text/plain", "invalid IP"); return; }
  uint32_t address = (uint32_t)ip;
  int found = -1;
  for (int i = 0; i < numBanned; ++i) if (bannedIP[i] == address) found = i;
  if (found >= 0) { bannedIP[found] = bannedIP[--numBanned]; }
  else {
    if (numBanned >= MAX_BAN) { web.send(400, "text/plain", "ban list full"); return; }
    bannedIP[numBanned++] = address;
  }
  Dev* c = getClient(address); if (c) c->banned = isBannedIP(address);
  saveBanned();
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// Stage beside the live list. A failed upload never removes the current list.
static bool validBlocklist(const char* path) {
  File f = LittleFS.open(path, "r");
  if (!f || !f.size() || f.size() % HASH_BYTES) return false;
  const size_t bytes = f.size();
  adblock::HashValidator validator;
  uint8_t entry[HASH_BYTES];
  uint32_t count = 0;
  while (f.available()) {
    if (f.read(entry, HASH_BYTES) != HASH_BYTES || !validator.add(entry)) return false;
    if ((++count & 1023) == 0) delay(0);
  }
  return validator.complete(bytes);
}
static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  numHashes = 0; memset(cacheValid, 0, sizeof(cacheValid));
  // A reset between the two rename operations restores the previous good list.
  adblock::recoverList(LittleFS, BLOCKLIST_PATH);
  if (!validBlocklist(BLOCKLIST_PATH)) return;
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static bool beginBlocklistSwap() {
  if (!fsReady) return false;
  LittleFS.remove("/blocklist.new");
  LittleFS.remove("/blocklist.bak");
  return true;
}
static bool commitNewBlocklist() {
  if (!validBlocklist("/blocklist.new")) { LittleFS.remove("/blocklist.new"); return false; }
  if (blocklist) blocklist.close();
  if (!adblock::replaceList(LittleFS, BLOCKLIST_PATH)) { reopenBlocklist(); return false; }
  reopenBlocklist();
  if (numHashes) LittleFS.remove("/blocklist.bak");
  return numHashes > 0;
}
static size_t availableForUpdate() {
  size_t free = LittleFS.totalBytes() - LittleFS.usedBytes();
  return free > 32768 ? free - 32768 : 0;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false, upWriteOk = false;
static size_t upLimit = 0, upBytes = 0;
static File upFile;
static void handleUploadDone() {
  if (!requireAuth()) return;
  bool ok = upAuthOk && upOk;
  upAuthOk = false; upOk = false;
  web.send(ok ? 200 : 500, "text/plain",
           ok ? "ok" : "rejected: incomplete, unsorted, empty or insufficient space; previous list retained");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, webPassword.c_str());
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; upBytes = 0;
      upWriteOk = beginBlocklistSwap(); upLimit = availableForUpdate();
      if (upWriteOk) upFile = LittleFS.open("/blocklist.new", "w");
      upWriteOk = upWriteOk && bool(upFile);
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upWriteOk) {
        if (upBytes + u.currentSize > upLimit || upFile.write(u.buf, u.currentSize) != u.currentSize) upWriteOk = false;
        upBytes += u.currentSize;
      }
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = upWriteOk && upBytes == u.totalSize && commitNewBlocklist();
      if (!upOk) LittleFS.remove("/blocklist.new");
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1 || updateIntervalH > 168) updateIntervalH = 24;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool validUpdateUrl(const String& url) {
  if (!url.startsWith("https://") || url.length() > 512 || url.length() <= 8) return false;
  for (char c : url) if ((uint8_t)c <= 32 || (uint8_t)c >= 127 || c == '@' || c == '\\') return false;
  return true;
}
extern const uint8_t caBundleStart[] asm("_binary_certs_x509_crt_bundle_start");
static bool fetchBlocklist(String url) {
  url.trim();
  if (!validUpdateUrl(url)) { updateStatus = "requires a valid HTTPS URL"; return false; }
  if (time(nullptr) < 1704067200) { updateStatus = "waiting for NTP time to verify TLS"; return false; }
  WiFiClientSecure cs; cs.setCACertBundle(caBundleStart); cs.setHandshakeTimeout(10);
  HTTPClient http; http.setTimeout(5000); http.setConnectTimeout(5000);
  // Redirect manually: validate every hop and never downgrade to HTTP.
  const char* headers[] = {"Location", "Transfer-Encoding"};
  int code = 0;
  for (int hop = 0; hop <= 4; ++hop) {
    if (!validUpdateUrl(url) || !http.begin(cs, url)) break;
    http.collectHeaders(headers, 2); code = http.GET();
    if (code == HTTP_CODE_OK) break;
    if (code != 301 && code != 302 && code != 303 && code != 307 && code != 308) break;
    String next = http.header("Location"); http.end(); url = next;
  }
  int len = http.getSize();
  if (code != HTTP_CODE_OK || len <= 0 || len % HASH_BYTES || http.header("Transfer-Encoding").length()) {
    http.end(); updateStatus = "download rejected: HTTPS error, redirect or unknown length"; return false;
  }
  if (!beginBlocklistSwap() || size_t(len) > availableForUpdate()) {
    http.end(); updateStatus = "insufficient staging space; old list retained"; return false;
  }
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; return false; }
  WiFiClient* stream = http.getStreamPtr();
  uint8_t b[1024]; size_t total = 0; uint32_t idle = millis(), started = millis();
  bool written = true;
  while (total < size_t(len) && millis() - started < 60000 && millis() - idle < 5000) {
    size_t avail = stream->available();
    if (avail) {
      size_t want = std::min(sizeof(b), std::min(avail, size_t(len) - total));
      int n = stream->read(b, want);
      if (n > 0) {
        if (f.write(b, n) != size_t(n)) { written = false; break; }
        total += n; idle = millis();
      }
    } else if (!http.connected()) break;
    handleDns(); delay(1); // keep DNS alive while downloading; no recursive web handling
  }
  f.close(); http.end();
  bool ok = written && total == size_t(len) && commitNewBlocklist();
  if (!ok) LittleFS.remove("/blocklist.new");
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : "incomplete/invalid data; old list retained";
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false, fwOk = false;
static void handleFwUpdateDone() {
  if (!requireAuth()) return;
  bool ok = fwAuthOk && fwOk && !Update.hasError();
  fwAuthOk = false; fwOk = false;
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwOk = false;
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, webPassword.c_str());
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if ((fwOk = Update.end(true))) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    fwOk = false; Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true);
  bool forced = prefs.getBool("portal", false);
  bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  if (forced) return false;
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  bool forced = prefs.getBool("portal", false);
  prefs.end();
  if (forced) return false;
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.setAutoReconnect(true); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>S3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; S3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave><input type=hidden name=token value=\"" + portalToken + "\">"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  if (web.arg("token") != portalToken) { web.send(403, "text/plain", "invalid setup token"); return; }
  String ss = web.arg("s"), pw = web.arg("p");
  if (ss.length() > 32 || pw.length() > 63) { web.send(400, "text/plain", "invalid WiFi credentials"); return; }
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.putBool("portal", false); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>s3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "S3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.scanDelete();
  WiFi.mode(WIFI_AP); WiFi.softAP(ap, setupPassword.c_str(), 1, 0, 1);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join WPA2 network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  printCredentials();
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    serviceSerial();
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[s3-adblock] booting");
  uint32_t serialWait = millis();
  while (!Serial && millis() - serialWait < 3000) delay(10);
  WiFi.setHostname("s3adblock"); WiFi.mode(WIFI_STA);
  initSecurity(); printCredentials();
  fsReady = LittleFS.begin(false); // never silently format data after a mount failure
  if (!fsReady) Serial.println("[fs] Mount failed: flash LittleFS using uploadfs (USB)");
  if (fsReady) reopenBlocklist();
  loadCustom(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // BOOT is sampled in loop(), after normal boot. Holding it during reset
  // enters the ROM downloader on the S3 and cannot execute application code.
  pinMode(0, INPUT_PULLUP);

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("s3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://s3adblock.local"); }

  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", HTTP_GET, []() { if (!requireLogin()) return; web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", HTTP_GET, []() { if (requireLogin()) handleStats(); });
  web.on("/ban", HTTP_POST, handleBan);
  web.on("/addblock", HTTP_POST, []() { if (!requireAuth()) return; bool ok = addCustom(web.arg("d")); web.send(ok ? 200 : 400, "text/plain", ok ? "ok" : "invalid, duplicate or full domain list"); });
  web.on("/unblock", HTTP_POST, []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", HTTP_POST, []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    if (s < 0 || s > 86400) { web.send(400, "text/plain", "pause must be 0..86400 seconds"); return; }
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", HTTP_POST, []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", HTTP_POST, []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.putBool("portal", true); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", HTTP_POST, []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", HTTP_POST, []() {
    if (!requireAuth()) return;
    String nextUrl = web.hasArg("u") ? web.arg("u") : updateUrl; nextUrl.trim();
    long hours = web.hasArg("h") ? web.arg("h").toInt() : updateIntervalH;
    if ((nextUrl.length() && !validUpdateUrl(nextUrl)) || hours < 1 || hours > 168) {
      web.send(400, "text/plain", "HTTPS URL and interval 1..168 hours required"); return;
    }
    updateUrl = nextUrl; updateIntervalH = hours; lastCheckMs = millis();
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  #if ENABLE_ARDUINO_OTA
  ArduinoOTA.setHostname("s3adblock");   // pio run -t upload --upload-port s3adblock.local
  ArduinoOTA.setPassword(otaPassword.c_str());      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  #endif
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  #if ENABLE_ARDUINO_OTA
  ArduinoOTA.handle();
  #endif
  static uint32_t pressedAt = 0;
  if (digitalRead(0) == LOW) {
    if (!pressedAt) pressedAt = millis();
    if (millis() - pressedAt >= 5000) {
      prefs.begin("wifi", false); prefs.clear(); prefs.putBool("portal", true); prefs.end(); ESP.restart();
    }
  } else pressedAt = 0;
  serviceSerial();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
