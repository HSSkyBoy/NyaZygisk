#pragma once

#include <link.h>

#include <cstdint>
#include <functional>

// Decoders for the two compact relocation encodings NDK modules use:
//   * APS2 packed relocations (DT_ANDROID_REL / DT_ANDROID_RELA)
//   * RELR relative relocations (DT_RELR)
// Both are translated into plain callbacks so the arch-specific applier in
// linker.cpp stays in one place.

namespace linker {

// Emit one decoded relocation: r_offset, the full r_info (decode type/sym with
// RELOC_R_TYPE / RELOC_R_SYM), and the addend (0 for REL-form entries). info is
// carried as a fixed-width integer so the signature is identical on LP64/ILP32.
bool ForEachPackedReloc(const uint8_t *stream, size_t size,
                        const std::function<void(ElfW(Addr), uint64_t, int64_t)> &emit);

// Emit the address of each word that needs load_bias added to it.
void ForEachRelr(const ElfW(Relr) * table, size_t count, uintptr_t load_bias,
                 const std::function<void(ElfW(Addr) *)> &emit);

}  // namespace linker
