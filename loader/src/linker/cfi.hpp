#pragma once

#include <cstddef>
#include <cstdint>

// Android cross-DSO CFI keeps a global "[anon:cfi shadow]" that bionic's linker
// fills for every library it loads: each 256 KiB granule of address space maps
// to a uint16_t pointing at the covering library's __cfi_check (or to a special
// value). A module we map ourselves is never registered there, so its granules
// stay kInvalidShadow (0) and any cross-DSO CFI-checked indirect call that lands
// in our module — e.g. a hook a module installs into a CFI-instrumented library,
// redirecting that library's own indirect call to the module's handler — aborts.
//
// We mark our module's granules kUncheckedShadow (1, "every address here is a
// valid target"), which is exactly how bionic marks a non-CFI library, so such
// calls are allowed. The pure slot-writing logic lives here so it can be unit
// tested without a live CFI runtime; the find-shadow/mprotect I/O wrapper is in
// injector/clean.cpp.
namespace linker {

// bionic CFIShadow constants (libc/private/CFIShadow.h).
constexpr uintptr_t kCfiShadowGranularity = 18;  // 256 KiB per shadow element
constexpr uint16_t kCfiInvalidShadow = 0;
constexpr uint16_t kCfiUncheckedShadow = 1;

inline uintptr_t CfiShadowByteOffset(uintptr_t addr) {
    return (addr >> kCfiShadowGranularity) << 1;  // MemToShadowOffset
}

// Set every shadow slot covering [base, base+size) to kUncheckedShadow, but only
// where it is still kInvalidShadow — a slot already claimed by a real library
// (>= 2, encoding a __cfi_check) or already unchecked is left alone, so a 256 KiB
// granule shared with another library keeps that library's CFI intact. The
// shadow at [shadow_start, shadow_end) must already be writable. Returns the
// number of slots changed. No-op (returns 0) if the range falls outside the
// shadow.
int CfiMarkUncheckedRange(uintptr_t shadow_start, uintptr_t shadow_end, uintptr_t base,
                          size_t size);

}  // namespace linker
