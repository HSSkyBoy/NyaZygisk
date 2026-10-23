#pragma once

#include <link.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// A minimal from-scratch loader for Zygisk / ZN module shared objects.
//
// Rationale: android_dlopen_ext records every loaded library in the dynamic
// linker's solist, which NyaZygisk then has to walk and scrub (see
// injector/solist.cpp). Mapping the module ourselves keeps it out of solist
// entirely, so none of that post-hoc cleanup is needed for modules loaded this
// way. Dependencies (DT_NEEDED) are still resolved through the system linker,
// since they are almost always already resident in Zygote.
//
// This is an experimental component: it handles the relocation and symbol forms
// that NDK-built modules actually emit (RELATIVE / JUMP_SLOT / GLOB_DAT / ABS,
// plus APS2-packed and RELR relocations). TLS and text relocations are refused
// rather than mishandled; callers decide what to do on refusal.
namespace linker {

// Why a module could not be mapped by us. kUnsupported means the ELF uses a
// feature we deliberately do not handle (TLS, TEXTREL); the caller may fall
// back to the system linker. kError means the image is malformed or a mapping
// syscall failed.
enum class LoadError {
    kNone,
    kUnsupported,
    kError,
};

class Image {
public:
    // Map and fully relocate the module backed by `fd` (e.g. a memfd). `name`
    // is only used for logging and for the synthetic dladdr/dl_iterate_phdr
    // identity. Returns nullptr on failure, with `err` set.
    static Image *Load(int fd, const char *name, LoadError *err);

    ~Image();

    Image(const Image &) = delete;
    Image &operator=(const Image &) = delete;

    // Resolve an exported symbol, mirroring dlsym(handle, name) semantics.
    void *Symbol(const char *name) const;

    uintptr_t base() const { return load_bias_; }
    size_t size() const { return map_size_; }
    uintptr_t map_start() const { return map_start_; }
    const std::string &name() const { return name_; }
    const ElfW(Phdr) * phdr() const { return phdr_; }
    size_t phnum() const { return phnum_; }

    // True if `addr` falls inside this image's mapped range.
    bool Contains(const void *addr) const {
        auto a = reinterpret_cast<uintptr_t>(addr);
        return a >= map_start_ && a < map_start_ + map_size_;
    }

private:
    Image() = default;

    bool MapSegments(int fd, const ElfW(Ehdr) & ehdr, const std::vector<ElfW(Phdr)> &phdrs,
                     LoadError *err);
    bool ParseDynamic(LoadError *err);
    bool Relocate(LoadError *err);
    void Protect();
    void CallConstructors();
    void CallDestructors();

    // Resolve a named symbol for a relocation: our interpose table, then this
    // image (Bsymbolic-style), then DT_NEEDED libraries, then RTLD_DEFAULT.
    void *ResolveSymbol(const char *name, bool *is_weak_undef) const;

    std::string name_;

    // The whole reservation (every PT_LOAD, aligned up). munmap target.
    uintptr_t map_start_ = 0;
    size_t map_size_ = 0;
    // load_bias_ = map_start_ - first PT_LOAD p_vaddr. All runtime addresses are
    // p_vaddr + load_bias_.
    uintptr_t load_bias_ = 0;

    const ElfW(Phdr) *phdr_ = nullptr;
    size_t phnum_ = 0;

    // Parsed from PT_DYNAMIC.
    const char *strtab_ = nullptr;
    const ElfW(Sym) *symtab_ = nullptr;

    const uint32_t *gnu_bucket_ = nullptr;
    const uint32_t *gnu_chain_ = nullptr;
    size_t gnu_nbucket_ = 0;
    uint32_t gnu_symndx_ = 0;
    uint32_t gnu_maskwords_ = 0;
    uint32_t gnu_shift2_ = 0;
    const ElfW(Addr) *gnu_bloom_ = nullptr;
    bool has_gnu_hash_ = false;

    const uint32_t *sysv_bucket_ = nullptr;
    const uint32_t *sysv_chain_ = nullptr;
    size_t sysv_nbucket_ = 0;
    size_t sysv_nchain_ = 0;

    // Relocation tables.
    const ElfW(Rela) *rela_ = nullptr;
    size_t rela_count_ = 0;
    const ElfW(Rel) *rel_ = nullptr;
    size_t rel_count_ = 0;
    const uint8_t *plt_rel_ = nullptr;  // JMPREL; type decided by DT_PLTREL.
    size_t plt_rel_size_ = 0;
    bool plt_is_rela_ = true;

    const uint8_t *android_rel_ = nullptr;  // APS2 packed (DT_ANDROID_REL[A]).
    size_t android_rel_size_ = 0;
    bool android_is_rela_ = true;

    const ElfW(Relr) *relr_ = nullptr;
    size_t relr_count_ = 0;

    // Constructors / destructors.
    void (*init_func_)() = nullptr;
    void (*fini_func_)() = nullptr;
    ElfW(Addr) *init_array_ = nullptr;
    size_t init_array_count_ = 0;
    ElfW(Addr) *fini_array_ = nullptr;
    size_t fini_array_count_ = 0;
    bool constructors_called_ = false;

    // DT_NEEDED: resolved lazily through the system linker, kept for dlclose.
    std::vector<std::string> needed_names_;
    std::vector<void *> needed_handles_;

    const ElfW(Dyn) *dynamic_ = nullptr;
    bool bind_now_ = false;
};

// Public entry points used by the module loaders (module.cpp / zn_loader.cpp).
// Load a module from an fd; on success returns an opaque handle usable with the
// functions below. On kUnsupported the caller may retry with android_dlopen_ext.
void *Dlopen(int fd, const char *name, LoadError *err);
void *Dlsym(void *handle, const char *name);
bool Dlclose(void *handle);
bool IsOurHandle(void *handle);

// Internal helpers shared with interpose.cpp. Not part of the module-facing API.
Image *FindImageByAddress(const void *addr);
void ForEachImage(void (*fn)(Image *, void *), void *arg);

}  // namespace linker
