#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace adblock {
inline bool validDomain(const char* s) {
  size_t n = strlen(s), label = 0;
  if (n == 0 || n > 253) return false;
  for (size_t i = 0; i < n; ++i) {
    unsigned char c = s[i];
    if (c == '.') { if (!label || s[i-1] == '-') return false; label = 0; }
    else {
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
      if ((!label && c == '-') || ++label > 63) return false;
    }
  }
  return label && s[n-1] != '-';
}

// Only one standard IN question. Never manufacture a response from malformed
// or compressed attacker-controlled questions. EDNS records may follow qend.
inline size_t parseQuery(const uint8_t* p, size_t n, char* out, uint16_t* type, int* end) {
  if (n < 17 || (p[2] & 0xfe) || (p[3] & 0xcf) || p[4] || p[5] != 1 || p[6] || p[7] || p[8] || p[9]) return 0;
  size_t i = 12, o = 0;
  bool terminated = false;
  while (i < n) {
    uint8_t l = p[i++];
    if (l == 0) { terminated = true; break; }
    if (l > 63 || i + l > n || o + l + (o ? 1 : 0) > 253) return 0;
    if (o) out[o++] = '.';
    for (size_t k = 0; k < l; ++k) {
      uint8_t c = p[i++];
      if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
      out[o++] = c;
    }
  }
  if (!terminated || !o || i + 4 > n || p[i+2] || p[i+3] != 1) return 0;
  out[o] = 0;
  *type = (uint16_t(p[i]) << 8) | p[i+1]; *end = int(i + 4);
  return o;
}

inline uint64_t unpack(const uint8_t* b) {
  uint64_t h = 0;
  for (unsigned i = 0; i < 5; ++i) h |= uint64_t(b[i]) << (i * 8);
  return h;
}

// Shared by firmware and host tests: complete, strictly sorted 40-bit entries.
class HashValidator {
  uint64_t previous = 0;
  size_t entries = 0;
public:
  bool add(const uint8_t* b) {
    uint64_t h = unpack(b);
    if (entries && h <= previous) return false;
    previous = h; ++entries; return true;
  }
  bool complete(size_t bytes) const { return entries && bytes == entries * 5; }
};

// Reader returns false on I/O failure. End is exclusive; no fixed bucket cap.
template<class Reader>
bool findHash(uint64_t wanted, uint32_t begin, uint32_t end, Reader read) {
  while (begin < end) {
    uint32_t mid = begin + (end - begin) / 2;
    uint64_t value;
    if (!read(mid, value)) return false;
    if (value == wanted) return true;
    if (value < wanted) begin = mid + 1; else end = mid;
  }
  return false;
}
}  // namespace adblock
