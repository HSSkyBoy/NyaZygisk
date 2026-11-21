#pragma once

namespace zn {

// Scan /data/adb/modules/*/zn_modules.txt and load matching Zygisk Next modules
// `connect_retry` is the number of daemon connection attempts (1s apart).
void loadAllModules(unsigned char connect_retry = 1);

// Returns true when any ZN module or ByteHook trampoline state requires libzygisk.so
// to remain mapped across app specialization.
bool hasResidentState();

}  // namespace zn
