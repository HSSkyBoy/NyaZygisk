#pragma once

#include <elf.h>

// Per-architecture relocation type constants, normalized to a small common set
// the relocator understands. Only the forms NDK-built shared objects actually
// emit are listed; anything else is treated as unsupported.
//
// arm64 and x86_64 are the first-class targets (exercised in the chroot test
// harness). arm (32-bit) and riscv64 are compiled but not runtime-verified here,
// so their tables are best-effort and should be validated on-device.

namespace linker {

#if defined(__aarch64__)

#ifndef R_AARCH64_NONE
#define R_AARCH64_NONE 0
#endif
#define RELOC_RELATIVE R_AARCH64_RELATIVE
#define RELOC_GLOB_DAT R_AARCH64_GLOB_DAT
#define RELOC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define RELOC_ABS R_AARCH64_ABS64
#define RELOC_IRELATIVE R_AARCH64_IRELATIVE
// TLS relocations we explicitly refuse (module would need a system load).
#define RELOC_TLS_DTPMOD R_AARCH64_TLS_DTPMOD
#define RELOC_TLS_DTPREL R_AARCH64_TLS_DTPREL
#define RELOC_TLS_TPREL R_AARCH64_TLS_TPREL
#define RELOC_TLSDESC R_AARCH64_TLSDESC
#define LINKER_USES_RELA 1

#elif defined(__x86_64__)

#define RELOC_RELATIVE R_X86_64_RELATIVE
#define RELOC_GLOB_DAT R_X86_64_GLOB_DAT
#define RELOC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define RELOC_ABS R_X86_64_64
#define RELOC_IRELATIVE R_X86_64_IRELATIVE
#define RELOC_TLS_DTPMOD R_X86_64_DTPMOD64
#define RELOC_TLS_DTPREL R_X86_64_DTPOFF64
#define RELOC_TLS_TPREL R_X86_64_TPOFF64
#define RELOC_TLSDESC R_X86_64_TLSDESC
#define LINKER_USES_RELA 1

#elif defined(__riscv) && __riscv_xlen == 64

#define RELOC_RELATIVE R_RISCV_RELATIVE
#define RELOC_GLOB_DAT R_RISCV_64
#define RELOC_JUMP_SLOT R_RISCV_JUMP_SLOT
#define RELOC_ABS R_RISCV_64
#define RELOC_IRELATIVE R_RISCV_IRELATIVE
#define RELOC_TLS_DTPMOD R_RISCV_TLS_DTPMOD64
#define RELOC_TLS_DTPREL R_RISCV_TLS_DTPREL64
#define RELOC_TLS_TPREL R_RISCV_TLS_TPREL64
#define RELOC_TLSDESC R_RISCV_TLSDESC
#define LINKER_USES_RELA 1

#elif defined(__arm__)

#define RELOC_RELATIVE R_ARM_RELATIVE
#define RELOC_GLOB_DAT R_ARM_GLOB_DAT
#define RELOC_JUMP_SLOT R_ARM_JUMP_SLOT
#define RELOC_ABS R_ARM_ABS32
#define RELOC_IRELATIVE R_ARM_IRELATIVE
#define RELOC_TLS_DTPMOD R_ARM_TLS_DTPMOD32
#define RELOC_TLS_DTPREL R_ARM_TLS_DTPOFF32
#define RELOC_TLS_TPREL R_ARM_TLS_TPOFF32
// arm has no TLSDESC constant in all headers; alias to an unused value.
#ifdef R_ARM_TLS_DESC
#define RELOC_TLSDESC R_ARM_TLS_DESC
#else
#define RELOC_TLSDESC 0xffffffffu
#endif
#define LINKER_USES_RELA 0

#else
#error "linker: unsupported architecture"
#endif

// True for the TLS relocation types we refuse. Centralized so the relocator and
// the dynamic parser agree on what counts as "needs TLS".
inline bool IsTlsReloc(uint32_t type) {
    return type == RELOC_TLS_DTPMOD || type == RELOC_TLS_DTPREL || type == RELOC_TLS_TPREL ||
           type == RELOC_TLSDESC;
}

}  // namespace linker
