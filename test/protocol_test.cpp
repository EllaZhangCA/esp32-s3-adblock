#include "../src/protocol.h"
#include "../src/blocklist_store.h"
#include <cassert>
#include <cstdio>
#include <random>
#include <string>
#include <vector>
#include <map>

struct MemoryStorage {
  std::map<std::string,std::string> files;
  int renames=0, failAt=0;
  bool exists(const char* path) { return files.count(path) != 0; }
  bool rename(const char* from, const char* to) {
    if (++renames == failAt || !exists(from) || exists(to)) return false;
    files[to]=files[from]; files.erase(from); return true;
  }
};
static void storageTests() {
  for (int failure : {0,1,2}) {
    MemoryStorage fs;
    fs.files={{"/blocklist.bin","old"},{"/blocklist.new","new"}}; fs.failAt=failure;
    bool ok=adblock::replaceList(fs,"/blocklist.bin");
    assert(ok == (failure == 0));
    assert(fs.files["/blocklist.bin"] == (ok ? "new" : "old"));
  }
  MemoryStorage afterPowerLoss;
  afterPowerLoss.files={{"/blocklist.bak","old"},{"/blocklist.new","new"}};
  assert(adblock::recoverList(afterPowerLoss,"/blocklist.bin"));
  assert(afterPowerLoss.files["/blocklist.bin"] == "old");
  MemoryStorage installed;
  installed.files={{"/blocklist.bak","old"},{"/blocklist.bin","new"}};
  assert(adblock::recoverList(installed,"/blocklist.bin"));
  assert(installed.files["/blocklist.bin"] == "new");
}

static std::vector<uint8_t> query(const std::string& domain, uint16_t type = 1) {
  std::vector<uint8_t> q = {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
  size_t begin = 0;
  while (begin < domain.size()) {
    size_t end = domain.find('.', begin);
    if (end == std::string::npos) end = domain.size();
    q.push_back(uint8_t(end - begin));
    q.insert(q.end(), domain.begin() + begin, domain.begin() + end);
    begin = end + 1;
  }
  q.insert(q.end(), {0, uint8_t(type >> 8), uint8_t(type), 0, 1});
  return q;
}
static size_t parse(const std::vector<uint8_t>& q, std::string* result = nullptr) {
  struct { uint8_t a = 0xa5; char domain[256] = {}; uint8_t b = 0x5a; } guarded;
  uint16_t type = 0; int end = -1;
  auto length = adblock::parseQuery(q.data(), q.size(), guarded.domain, &type, &end);
  assert(guarded.a == 0xa5 && guarded.b == 0x5a);
  if (length) { assert(end >= 17 && size_t(end) <= q.size()); assert(length < 256); }
  if (result && length) *result = guarded.domain;
  return length;
}
int main() {
  storageTests();
  auto good = query("WWW.Example.COM"); std::string name;
  assert(parse(good, &name) && name == "www.example.com");
  for (size_t i = 0; i < good.size(); ++i)
    assert(!parse(std::vector<uint8_t>(good.begin(), good.begin() + i)));
  for (unsigned flag : {0x80, 0x08, 0x04, 0x02}) { auto q=good; q[2] |= flag; assert(!parse(q)); }
  for (unsigned count : {0, 2, 255}) { auto q=good; q[5]=uint8_t(count); assert(!parse(q)); }
  { auto q=good; q[12]=0xc0; assert(!parse(q)); }
  { auto q=good; q[13]=0; assert(!parse(q)); }
  { auto q=good; q.back()=3; assert(!parse(q)); }
  { auto q=good; q[3]=0x30; assert(parse(q)); } // AD/CD query flags
  { auto q=good; q[11]=1; q.insert(q.end(), {0,0,41,4,208,0,0,0,0,0,0}); assert(parse(q)); }
  assert(parse(query(std::string(63, 'a') + ".example")));
  assert(!parse(query(std::string(64, 'a') + ".example")));
  assert(!parse(query(std::string(63,'a') + "." + std::string(63,'b') + "." + std::string(63,'c') + "." + std::string(63,'d'))));
  assert(parse(query("_https._tcp.example.com", 65)));
  for (const char* d : {"ads.example.com", "xn--bcher-kva.example", "_srv.example"}) assert(adblock::validDomain(d));
  for (const char* d : {"", ".", "a..b", "-bad.com", "bad-.com", "a.<script>", "a.\ncom", "a/b.com"}) assert(!adblock::validDomain(d));
  adblock::HashValidator v; uint8_t zero[5]={}, one[5]={1};
  assert(!v.complete(0)); assert(v.add(zero)); assert(v.add(one));
  assert(v.complete(10)); assert(!v.complete(9)); assert(!v.add(one)); assert(!v.add(zero));
  // S3's larger flash exposes the old >256-entry bucket truncation bug.
  auto reader=[](uint32_t index, uint64_t& value) { value=uint64_t(index)*7; return true; };
  for (uint32_t n : {0u, 1u, 256u, 4096u, 2400000u}) {
    if (n) { assert(adblock::findHash(0,0,n,reader)); assert(adblock::findHash(uint64_t(n-1)*7,0,n,reader)); }
    assert(!adblock::findHash(uint64_t(n)*7,0,n,reader));
    assert(!adblock::findHash(3,0,n,reader));
  }
  assert(!adblock::findHash(7,0,2,[](uint32_t,uint64_t&) { return false; }));
  // Deterministic malformed-packet exercise; sanitizers run this in CI.
  std::mt19937 rng(0x5333);
  for (int i=0; i<100000; ++i) {
    auto q = i%2 ? good : std::vector<uint8_t>(rng()%1537);
    if (i%2) { for (unsigned j=0; j<1+rng()%8; ++j) q[rng()%q.size()]=uint8_t(rng()); }
    else for (auto& byte:q) byte=uint8_t(rng());
    parse(q);
  }
  puts("Protocol tests passed, including 100000 malformed packets and large hash tables.");
}
