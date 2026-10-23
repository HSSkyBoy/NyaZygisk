#pragma once

#include <elf.h>
#include <link.h>

// Small portability shims so the loader code reads the same on LP64 and ILP32
// without sprinkling #ifdefs. link.h gives us ElfW(); these cover the few
// pieces it does not, plus a couple of dynamic-tag constants that are missing
// from older NDK headers.

#if defined(__LP64__)
#define ELFCLASS_NATIVE ELFCLASS64
#define RELOC_R_TYPE(info) ELF64_R_TYPE(info)
#define RELOC_R_SYM(info) ELF64_R_SYM(info)
#else
#define ELFCLASS_NATIVE ELFCLASS32
#define RELOC_R_TYPE(info) ELF32_R_TYPE(info)
#define RELOC_R_SYM(info) ELF32_R_SYM(info)
#endif

// DT_RELR is the standard tag; some headers still only ship the Android
// pre-standard aliases. Define whichever is absent so the switch can list both.
#ifndef DT_RELR
#define DT_RELR 0x24
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 0x23
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 0x25
#endif
#ifndef DT_ANDROID_RELR
#define DT_ANDROID_RELR 0x6fffe000
#endif
#ifndef DT_ANDROID_RELRSZ
#define DT_ANDROID_RELRSZ 0x6fffe001
#endif
#ifndef DT_ANDROID_RELRENT
#define DT_ANDROID_RELRENT 0x6fffe003
#endif

// GNU indirect function symbol type (resolver chosen at load time).
#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif

// APS2 packed relocations.
#ifndef DT_ANDROID_REL
#define DT_ANDROID_REL 0x6000000f
#endif
#ifndef DT_ANDROID_RELSZ
#define DT_ANDROID_RELSZ 0x60000010
#endif
#ifndef DT_ANDROID_RELA
#define DT_ANDROID_RELA 0x60000011
#endif
#ifndef DT_ANDROID_RELASZ
#define DT_ANDROID_RELASZ 0x60000012
#endif
