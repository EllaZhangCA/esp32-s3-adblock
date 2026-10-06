#pragma once

namespace adblock {
// LittleFS metadata renames are atomic. Keep a backup across the two renames
// and recover it on boot if power failed before the new file became live.
template<class Storage>
bool recoverList(Storage& fs, const char* live) {
  return fs.exists(live) || (fs.exists("/blocklist.bak") && fs.rename("/blocklist.bak", live));
}
template<class Storage>
bool replaceList(Storage& fs, const char* live) {
  if (fs.exists(live) && !fs.rename(live, "/blocklist.bak")) return false;
  if (!fs.rename("/blocklist.new", live)) {
    recoverList(fs, live);
    return false;
  }
  return true;
}
}
