#include "linker.hpp"

#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <vector>

#include "elf_compat.hpp"
#include "interpose.hpp"
#include "logging.hpp"
#include "reloc_arch.hpp"
#include "relocate.hpp"

namespace linker {

namespace {

size_t PageSize() {
    static size_t pg = []() {
        long v = sysconf(_SC_PAGESIZE);
        return v > 0 ? static_cast<size_t>(v) : 4096;
    }();
    return pg;
}

uintptr_t PageStart(uintptr_t addr, size_t pg) { return addr & ~(static_cast<uintptr_t>(pg) - 1); }
uintptr_t PageEnd(uintptr_t addr, size_t pg) { return PageStart(addr + pg - 1, pg); }

int ToProt(ElfW(Word) p_flags) {
    int prot = 0;
    if (p_flags & PF_R) prot |= PROT_READ;
    if (p_flags & PF_W) prot |= PROT_WRITE;
    if (p_flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

// Call a GNU ifunc resolver and return the address it selects. bionic uses the
// same no-argument cast; resolvers that read hwcap args tolerate the extra
// registers being whatever they are.
ElfW(Addr) CallIfuncResolver(uintptr_t resolver_addr) {
    return reinterpret_cast<ElfW(Addr) (*)()>(resolver_addr)();
}

uintptr_t AlignUp(uintptr_t v, uintptr_t a) { return (v + a - 1) & ~(a - 1); }

uint32_t ReadU32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

// pread the whole [off, off+len) range into `dst`, tolerating short reads.
bool PreadFull(int fd, void *dst, size_t len, off_t off) {
    auto *p = static_cast<uint8_t *>(dst);
    while (len > 0) {
        ssize_t n = pread(fd, p, len, off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;  // unexpected EOF
        p += n;
        off += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

// Registry of images we loaded, so Dlsym/Dlclose/IsOurHandle and the dladdr
// interpose can map an address or handle back to an Image.
std::mutex g_images_lock;
std::vector<Image *> g_images;

}  // namespace

// --------------------------------------------------------------------------
// Mapping
// --------------------------------------------------------------------------

bool Image::MapSegments(int fd, const ElfW(Ehdr) & ehdr, const std::vector<ElfW(Phdr)> &phdrs,
                        bool anonymous, LoadError *err) {
    const size_t pg = PageSize();

    // The reservation must honour the maximum p_align across loadable segments
    // (riscv64 ships 64 KiB-aligned segments), not just the system page size.
    size_t max_align = pg;
    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    for (const auto &ph : phdrs) {
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_align > max_align) max_align = ph.p_align;
        if (ph.p_vaddr < min_vaddr) min_vaddr = ph.p_vaddr;
        if (ph.p_vaddr + ph.p_memsz > max_vaddr) max_vaddr = ph.p_vaddr + ph.p_memsz;
    }
    if (min_vaddr == UINTPTR_MAX) {
        LOGE("linker: no PT_LOAD segments in %s", name_.c_str());
        *err = LoadError::kError;
        return false;
    }

    min_vaddr = PageStart(min_vaddr, pg);
    max_vaddr = PageEnd(max_vaddr, pg);
    size_t span = max_vaddr - min_vaddr;

    // Over-reserve by one alignment unit so we can align the base up inside the
    // reservation, then trim the slack on both sides.
    size_t reserve = span + max_align;
    void *raw = mmap(nullptr, reserve, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) {
        LOGE("linker: reservation mmap failed for %s: %s", name_.c_str(), strerror(errno));
        *err = LoadError::kError;
        return false;
    }

    uintptr_t raw_addr = reinterpret_cast<uintptr_t>(raw);
    uintptr_t aligned = (raw_addr + max_align - 1) & ~(static_cast<uintptr_t>(max_align) - 1);
    // Trim front slack.
    if (aligned != raw_addr) munmap(raw, aligned - raw_addr);
    // Trim back slack.
    uintptr_t tail = aligned + span;
    uintptr_t raw_end = raw_addr + reserve;
    if (raw_end > tail) munmap(reinterpret_cast<void *>(tail), raw_end - tail);

    map_start_ = aligned;
    map_size_ = span;
    load_bias_ = aligned - min_vaddr;

    // Fill each PT_LOAD. Two strategies (see Load's `anonymous` doc):
    //   anonymous: the reservation is already private-anonymous; just make each
    //     segment writable and pread the file bytes in. .bss stays zero because
    //     anonymous pages are zero-filled, and the fd never shows in maps.
    //   file-backed: mmap each segment from `fd` (memfd), then hand-zero the
    //     .bss tail that shares the last file page.
    for (const auto &ph : phdrs) {
        if (ph.p_type != PT_LOAD) continue;

        uintptr_t seg_start = load_bias_ + PageStart(ph.p_vaddr, pg);
        uintptr_t seg_file_end = load_bias_ + ph.p_vaddr + ph.p_filesz;
        uintptr_t seg_mem_end = load_bias_ + PageEnd(ph.p_vaddr + ph.p_memsz, pg);

        if (anonymous) {
            // The reservation covers this range as PROT_NONE; open it for writing.
            if (mprotect(reinterpret_cast<void *>(seg_start), seg_mem_end - seg_start,
                         PROT_READ | PROT_WRITE) != 0) {
                LOGE("linker: segment mprotect failed for %s: %s", name_.c_str(), strerror(errno));
                *err = LoadError::kError;
                return false;
            }
            if (ph.p_filesz > 0 &&
                !PreadFull(fd, reinterpret_cast<void *>(load_bias_ + ph.p_vaddr), ph.p_filesz,
                           static_cast<off_t>(ph.p_offset))) {
                LOGE("linker: segment pread failed for %s: %s", name_.c_str(), strerror(errno));
                *err = LoadError::kError;
                return false;
            }
            continue;
        }

        // Map the file portion writable (we relocate before Protect()).
        uintptr_t file_page_end = PageEnd(seg_file_end, pg);
        if (ph.p_filesz > 0) {
            off_t file_off = static_cast<off_t>(PageStart(ph.p_offset, pg));
            size_t len = file_page_end - seg_start;
            void *m = mmap(reinterpret_cast<void *>(seg_start), len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_FIXED, fd, file_off);
            if (m == MAP_FAILED) {
                LOGE("linker: segment mmap failed for %s: %s", name_.c_str(), strerror(errno));
                *err = LoadError::kError;
                return false;
            }
            // Zero the .bss bytes that share the last file-backed page with
            // initialized data: everything from filesz to the end of that page.
            // This must run whenever the segment has memsz beyond filesz — even
            // when the whole .bss fits inside this page (seg_mem_end ==
            // file_page_end). The old `seg_mem_end > file_page_end` guard
            // skipped that case, leaving file bytes in .bss (e.g. a zero-init
            // global reading back as the lld version string).
            if (ph.p_memsz > ph.p_filesz && file_page_end > seg_file_end) {
                memset(reinterpret_cast<void *>(seg_file_end), 0, file_page_end - seg_file_end);
            }
        }

        // Remaining whole .bss pages: anonymous zero fill.
        if (seg_mem_end > file_page_end) {
            size_t bss_len = seg_mem_end - file_page_end;
            void *m = mmap(reinterpret_cast<void *>(file_page_end), bss_len,
                           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (m == MAP_FAILED) {
                LOGE("linker: bss mmap failed for %s: %s", name_.c_str(), strerror(errno));
                *err = LoadError::kError;
                return false;
            }
        }
    }

    // Locate the program headers in the mapped image (for dl_iterate_phdr).
    phnum_ = ehdr.e_phnum;
    for (const auto &ph : phdrs) {
        if (ph.p_type == PT_PHDR) {
            phdr_ = reinterpret_cast<const ElfW(Phdr) *>(load_bias_ + ph.p_vaddr);
            break;
        }
    }
    if (phdr_ == nullptr) {
        // Fall back to finding phdrs inside a PT_LOAD by file offset.
        for (const auto &ph : phdrs) {
            if (ph.p_type == PT_LOAD && ph.p_offset <= ehdr.e_phoff &&
                ehdr.e_phoff < ph.p_offset + ph.p_filesz) {
                phdr_ = reinterpret_cast<const ElfW(Phdr) *>(load_bias_ + ph.p_vaddr +
                                                             (ehdr.e_phoff - ph.p_offset));
                break;
            }
        }
    }

    // Does the module opt into AArch64 BTI? Only then may we add PROT_BTI to its
    // executable segments; doing so on a module without landing pads would fault.
    for (const auto &ph : phdrs) {
        if (ph.p_type == PT_GNU_PROPERTY) {
            wants_bti_ = GnuPropertyNoteHasBti(
                reinterpret_cast<const uint8_t *>(load_bias_ + ph.p_vaddr), ph.p_memsz);
            break;
        }
    }
    return true;
}

// --------------------------------------------------------------------------
// Dynamic section
// --------------------------------------------------------------------------

bool Image::ParseDynamic(LoadError *err) {
    // Find PT_DYNAMIC from the mapped phdrs.
    for (size_t i = 0; i < phnum_; i++) {
        if (phdr_[i].p_type == PT_DYNAMIC) {
            dynamic_ = reinterpret_cast<const ElfW(Dyn) *>(load_bias_ + phdr_[i].p_vaddr);
        }
        if (phdr_[i].p_type == PT_GNU_RELRO) {
            // Recorded for Protect(); nothing to do here.
        }
    }
    if (dynamic_ == nullptr) {
        LOGE("linker: no PT_DYNAMIC in %s", name_.c_str());
        *err = LoadError::kError;
        return false;
    }

    const ElfW(Addr) bias = load_bias_;
    size_t plt_rel_type = 0;

    for (const ElfW(Dyn) *d = dynamic_; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_STRTAB:
                strtab_ = reinterpret_cast<const char *>(bias + d->d_un.d_ptr);
                break;
            case DT_SYMTAB:
                symtab_ = reinterpret_cast<const ElfW(Sym) *>(bias + d->d_un.d_ptr);
                break;
            case DT_GNU_HASH: {
                auto *h = reinterpret_cast<const uint32_t *>(bias + d->d_un.d_ptr);
                gnu_nbucket_ = h[0];
                gnu_symndx_ = h[1];
                gnu_maskwords_ = h[2];
                gnu_shift2_ = h[3];
                gnu_bloom_ = reinterpret_cast<const ElfW(Addr) *>(h + 4);
                gnu_bucket_ = reinterpret_cast<const uint32_t *>(gnu_bloom_ + gnu_maskwords_);
                gnu_chain_ = gnu_bucket_ + gnu_nbucket_ - gnu_symndx_;
                has_gnu_hash_ = true;
                break;
            }
            case DT_HASH: {
                auto *h = reinterpret_cast<const uint32_t *>(bias + d->d_un.d_ptr);
                sysv_nbucket_ = h[0];
                sysv_nchain_ = h[1];
                sysv_bucket_ = h + 2;
                sysv_chain_ = sysv_bucket_ + sysv_nbucket_;
                break;
            }
            case DT_RELA:
                rela_ = reinterpret_cast<const ElfW(Rela) *>(bias + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
                break;
            case DT_REL:
                rel_ = reinterpret_cast<const ElfW(Rel) *>(bias + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
                break;
            case DT_JMPREL:
                plt_rel_ = reinterpret_cast<const uint8_t *>(bias + d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                plt_rel_size_ = d->d_un.d_val;
                break;
            case DT_PLTREL:
                plt_rel_type = d->d_un.d_val;
                break;
            case DT_ANDROID_RELA:
            case DT_ANDROID_REL:
                android_rel_ = reinterpret_cast<const uint8_t *>(bias + d->d_un.d_ptr);
                android_is_rela_ = (d->d_tag == DT_ANDROID_RELA);
                break;
            case DT_ANDROID_RELASZ:
            case DT_ANDROID_RELSZ:
                android_rel_size_ = d->d_un.d_val;
                break;
            case DT_RELR:
            case DT_ANDROID_RELR:
                relr_ = reinterpret_cast<const ElfW(Relr) *>(bias + d->d_un.d_ptr);
                break;
            case DT_RELRSZ:
            case DT_ANDROID_RELRSZ:
                relr_count_ = d->d_un.d_val / sizeof(ElfW(Relr));
                break;
            case DT_INIT:
                init_func_ = reinterpret_cast<void (*)()>(bias + d->d_un.d_ptr);
                break;
            case DT_FINI:
                fini_func_ = reinterpret_cast<void (*)()>(bias + d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                init_array_ = reinterpret_cast<ElfW(Addr) *>(bias + d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                init_array_count_ = d->d_un.d_val / sizeof(ElfW(Addr));
                break;
            case DT_FINI_ARRAY:
                fini_array_ = reinterpret_cast<ElfW(Addr) *>(bias + d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                fini_array_count_ = d->d_un.d_val / sizeof(ElfW(Addr));
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_BIND_NOW) bind_now_ = true;
                if (d->d_un.d_val & DF_TEXTREL) {
                    LOGW("linker: %s has DF_TEXTREL, refusing", name_.c_str());
                    *err = LoadError::kUnsupported;
                    return false;
                }
                break;
            case DT_FLAGS_1:
                if (d->d_un.d_val & DF_1_NOW) bind_now_ = true;
                break;
            case DT_TEXTREL:
                LOGW("linker: %s has DT_TEXTREL, refusing", name_.c_str());
                *err = LoadError::kUnsupported;
                return false;
            case DT_NEEDED:
                // Resolved after strtab is known; record the offset for now by
                // stashing the string pointer below.
                break;
            default:
                break;
        }
    }

    if (strtab_ == nullptr || symtab_ == nullptr) {
        LOGE("linker: %s missing strtab/symtab", name_.c_str());
        *err = LoadError::kError;
        return false;
    }

    plt_is_rela_ = (plt_rel_type == DT_RELA);

    // Second pass for DT_NEEDED now that strtab_ is valid.
    for (const ElfW(Dyn) *d = dynamic_; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_NEEDED) {
            needed_names_.emplace_back(strtab_ + d->d_un.d_val);
        }
    }

    return true;
}

// --------------------------------------------------------------------------
// Symbol lookup within this image
// --------------------------------------------------------------------------

static uint32_t GnuHash(const char *name) {
    uint32_t h = 5381;
    for (const uint8_t *p = reinterpret_cast<const uint8_t *>(name); *p != 0; p++) {
        h += (h << 5) + *p;
    }
    return h;
}

static uint32_t SysvHash(const char *name) {
    uint32_t h = 0, g;
    for (const uint8_t *p = reinterpret_cast<const uint8_t *>(name); *p != 0; p++) {
        h = (h << 4) + *p;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

// Find an exported, defined symbol by name. Returns the Sym or nullptr.
static const ElfW(Sym) *
    LookupInImage(const ElfW(Sym) * symtab, const char *strtab, const char *name,
                  bool has_gnu, const uint32_t *gnu_bucket, const uint32_t *gnu_chain,
                  size_t gnu_nbucket, uint32_t gnu_symndx, uint32_t gnu_maskwords,
                  uint32_t gnu_shift2, const ElfW(Addr) *gnu_bloom, const uint32_t *sysv_bucket,
                  const uint32_t *sysv_chain, size_t sysv_nbucket) {
    if (has_gnu) {
        uint32_t hash = GnuHash(name);
        constexpr uint32_t kBits = sizeof(ElfW(Addr)) * 8;
        ElfW(Addr) word = gnu_bloom[(hash / kBits) % gnu_maskwords];
        ElfW(Addr) mask = (static_cast<ElfW(Addr)>(1) << (hash % kBits)) |
                          (static_cast<ElfW(Addr)>(1) << ((hash >> gnu_shift2) % kBits));
        if ((word & mask) != mask) return nullptr;

        uint32_t n = gnu_bucket[hash % gnu_nbucket];
        if (n < gnu_symndx) return nullptr;
        do {
            if ((gnu_chain[n] | 1) == (hash | 1)) {
                const ElfW(Sym) *s = &symtab[n];
                if (s->st_shndx != SHN_UNDEF && strcmp(strtab + s->st_name, name) == 0) {
                    return s;
                }
            }
        } while ((gnu_chain[n++] & 1) == 0);
        return nullptr;
    }

    if (sysv_bucket != nullptr) {
        uint32_t hash = SysvHash(name);
        for (uint32_t n = sysv_bucket[hash % sysv_nbucket]; n != 0; n = sysv_chain[n]) {
            const ElfW(Sym) *s = &symtab[n];
            if (s->st_shndx != SHN_UNDEF && strcmp(strtab + s->st_name, name) == 0) {
                return s;
            }
        }
    }
    return nullptr;
}

void *Image::Symbol(const char *name) const {
    const ElfW(Sym) *s = LookupInImage(
        symtab_, strtab_, name, has_gnu_hash_, gnu_bucket_, gnu_chain_, gnu_nbucket_, gnu_symndx_,
        gnu_maskwords_, gnu_shift2_, gnu_bloom_, sysv_bucket_, sysv_chain_, sysv_nbucket_);
    if (s == nullptr) return nullptr;
    ElfW(Addr) addr = load_bias_ + s->st_value;
    // Mirror dlsym: an exported ifunc resolves to the address its resolver picks.
    if (ELF_ST_TYPE(s->st_info) == STT_GNU_IFUNC) addr = CallIfuncResolver(addr);
    return reinterpret_cast<void *>(addr);
}

// --------------------------------------------------------------------------
// Symbol resolution for relocations
// --------------------------------------------------------------------------

void *Image::ResolveSymbol(const char *name, bool *is_weak_undef) const {
    *is_weak_undef = false;

    // 1. Interpose table (dl_iterate_phdr, dladdr, dlsym, dlclose, ...).
    if (void *ov = InterposeLookup(name)) return ov;

    // 2. This image itself (Bsymbolic-style: a module's own static libc++ must
    //    bind to itself, not to a same-named symbol elsewhere).
    if (void *self = Symbol(name)) return self;

    // 3. DT_NEEDED libraries, in order, through the system linker.
    for (void *h : needed_handles_) {
        if (h == nullptr) continue;
        if (void *sym = dlsym(h, name)) return sym;
    }

    // 4. Global default scope.
    if (void *sym = dlsym(RTLD_DEFAULT, name)) return sym;

    *is_weak_undef = true;
    return nullptr;
}

// --------------------------------------------------------------------------
// Relocation
// --------------------------------------------------------------------------

bool Image::Relocate(LoadError *err) {
    // Resolve DT_NEEDED up front (eager); they are nearly always already
    // resident in Zygote, so RTLD_NOLOAD succeeds without touching solist.
    for (const auto &n : needed_names_) {
        void *h = dlopen(n.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (h == nullptr) h = dlopen(n.c_str(), RTLD_NOW);
        if (h == nullptr) {
            LOGW("linker: %s needs %s which is not loadable: %s", name_.c_str(), n.c_str(),
                 dlerror());
        }
        needed_handles_.push_back(h);
    }

    bool ok = true;

    auto apply = [&](ElfW(Addr) offset, uint64_t info, int64_t addend) {
        uint32_t type = RELOC_R_TYPE(info);
        uint32_t sym = RELOC_R_SYM(info);
        auto *where = reinterpret_cast<ElfW(Addr) *>(load_bias_ + offset);

        auto where_addr = reinterpret_cast<uintptr_t>(where);
        if (where_addr < map_start_ || where_addr >= map_start_ + map_size_) {
            LOGE("linker: %s relocation target %p out of mapped range [%p,%p), type=%u",
                 name_.c_str(), where, reinterpret_cast<void *>(map_start_),
                 reinterpret_cast<void *>(map_start_ + map_size_), type);
            *err = LoadError::kError;
            ok = false;
            return;
        }

        if (type == 0) return;

        if (IsTlsReloc(type)) {
            LOGW("linker: %s uses TLS relocation (type %u), refusing", name_.c_str(), type);
            *err = LoadError::kUnsupported;
            ok = false;
            return;
        }

        if (type == RELOC_RELATIVE) {
            *where = load_bias_ + addend;
            return;
        }
        if (type == RELOC_IRELATIVE) {
            *where = CallIfuncResolver(load_bias_ + addend);
            return;
        }

        // Symbol-based relocation.
        const ElfW(Sym) *s = &symtab_[sym];
        const char *sym_name = strtab_ + s->st_name;
        ElfW(Addr) value = 0;

        if (s->st_shndx != SHN_UNDEF) {
            // Defined in this module (local or global): resolve module-first to
            // our own definition. For an ifunc, st_value is the resolver — call
            // it, as bionic does for the relocating object.
            value = load_bias_ + s->st_value;
            if (ELF_ST_TYPE(s->st_info) == STT_GNU_IFUNC) value = CallIfuncResolver(value);
        } else {
            // Undefined here: resolve externally. dlsym already runs an ifunc
            // resolver, so nothing extra to do for those.
            bool weak_undef = false;
            void *resolved = ResolveSymbol(sym_name, &weak_undef);
            if (resolved == nullptr) {
                if (ELF_ST_BIND(s->st_info) == STB_WEAK) {
                    value = 0;  // Permitted: weak undefined resolves to 0.
                } else {
                    LOGE("linker: %s cannot resolve symbol '%s'", name_.c_str(), sym_name);
                    *err = LoadError::kError;
                    ok = false;
                    return;
                }
            } else {
                value = reinterpret_cast<ElfW(Addr)>(resolved);
            }
        }

        switch (type) {
            case RELOC_JUMP_SLOT:
                // S only: on REL targets the in-place value is a PLT stub, not
                // an addend; on RELA targets the addend is 0.
                *where = value;
                break;
            case RELOC_GLOB_DAT:
#if (RELOC_ABS) == (RELOC_GLOB_DAT)
                // riscv64 folds GLOB_DAT and ABS into one type (R_RISCV_64),
                // which carries an addend.
                *where = value + addend;
#else
                *where = value;
#endif
                break;
#if (RELOC_ABS) != (RELOC_GLOB_DAT)
            case RELOC_ABS:
                *where = value + addend;
                break;
#endif
            default:
                LOGE("linker: %s unsupported relocation type %u", name_.c_str(), type);
                *err = LoadError::kUnsupported;
                ok = false;
                return;
        }
    };

    // RELR first (relative-only, cheapest).
    if (relr_ != nullptr && relr_count_ > 0) {
        ForEachRelr(relr_, relr_count_, load_bias_,
                    [&](ElfW(Addr) *w) { *w += load_bias_; });
    }

    // APS2 packed.
    if (android_rel_ != nullptr && android_rel_size_ > 0) {
        if (!ForEachPackedReloc(android_rel_, android_rel_size_, apply)) {
            *err = LoadError::kError;
            return false;
        }
        if (!ok) return false;
    }

    // Plain RELA.
    for (size_t i = 0; i < rela_count_ && ok; i++) {
        apply(rela_[i].r_offset, rela_[i].r_info, rela_[i].r_addend);
    }
    // Plain REL (implicit addend read from the slot).
    for (size_t i = 0; i < rel_count_ && ok; i++) {
        auto *where = reinterpret_cast<ElfW(Addr) *>(load_bias_ + rel_[i].r_offset);
        apply(rel_[i].r_offset, rel_[i].r_info, static_cast<int64_t>(static_cast<intptr_t>(*where)));
    }

    // PLT relocations (JMPREL). With BIND_NOW these resolve eagerly; we always
    // resolve them eagerly regardless, since we do not install a lazy resolver.
    if (plt_rel_ != nullptr && plt_rel_size_ > 0 && ok) {
        if (plt_is_rela_) {
            auto *r = reinterpret_cast<const ElfW(Rela) *>(plt_rel_);
            size_t n = plt_rel_size_ / sizeof(ElfW(Rela));
            for (size_t i = 0; i < n && ok; i++) apply(r[i].r_offset, r[i].r_info, r[i].r_addend);
        } else {
            auto *r = reinterpret_cast<const ElfW(Rel) *>(plt_rel_);
            size_t n = plt_rel_size_ / sizeof(ElfW(Rel));
            for (size_t i = 0; i < n && ok; i++) {
                auto *where = reinterpret_cast<ElfW(Addr) *>(load_bias_ + r[i].r_offset);
                apply(r[i].r_offset, r[i].r_info,
                      static_cast<int64_t>(static_cast<intptr_t>(*where)));
            }
        }
    }

    return ok;
}

// --------------------------------------------------------------------------
// Protection + constructors
// --------------------------------------------------------------------------

void Image::SetSegmentProtections() {
    const size_t pg = PageSize();
    for (size_t i = 0; i < phnum_; i++) {
        if (phdr_[i].p_type != PT_LOAD) continue;
        uintptr_t start = load_bias_ + PageStart(phdr_[i].p_vaddr, pg);
        uintptr_t end = load_bias_ + PageEnd(phdr_[i].p_vaddr + phdr_[i].p_memsz, pg);
        int prot = ToProt(phdr_[i].p_flags);
#if defined(__aarch64__)
        // Enforce BTI on executable segments only when the module advertised it
        // (GNU_PROPERTY_AARCH64_FEATURE_1_BTI); adding PROT_BTI to code without
        // landing pads would fault indirect branches into it.
        if (wants_bti_ && (prot & PROT_EXEC)) prot |= PROT_BTI;
#endif
        // Writable segments keep PROT_WRITE here so relocations (and the RELRO
        // region, which lives inside a PF_W segment) can still be written; the
        // RELRO range is sealed read-only later in ApplyRelro.
        mprotect(reinterpret_cast<void *>(start), end - start, prot);
    }
}

void Image::ApplyRelro() {
    const size_t pg = PageSize();
    for (size_t i = 0; i < phnum_; i++) {
        if (phdr_[i].p_type != PT_GNU_RELRO) continue;
        uintptr_t start = load_bias_ + PageStart(phdr_[i].p_vaddr, pg);
        uintptr_t end = load_bias_ + PageEnd(phdr_[i].p_vaddr + phdr_[i].p_memsz, pg);
        mprotect(reinterpret_cast<void *>(start), end - start, PROT_READ);
    }

    __builtin___clear_cache(reinterpret_cast<char *>(map_start_),
                            reinterpret_cast<char *>(map_start_ + map_size_));
}

void Image::CallConstructors() {
    if (constructors_called_) return;
    constructors_called_ = true;
    if (init_func_ != nullptr) init_func_();
    for (size_t i = 0; i < init_array_count_; i++) {
        auto fn = reinterpret_cast<void (*)()>(init_array_[i]);
        if (fn != nullptr && fn != reinterpret_cast<void (*)()>(-1)) fn();
    }
}

void Image::CallDestructors() {
    if (!constructors_called_) return;
    for (size_t i = fini_array_count_; i > 0; i--) {
        auto fn = reinterpret_cast<void (*)()>(fini_array_[i - 1]);
        if (fn != nullptr && fn != reinterpret_cast<void (*)()>(-1)) fn();
    }
    if (fini_func_ != nullptr) fini_func_();
}

// --------------------------------------------------------------------------
// Load / destroy
// --------------------------------------------------------------------------

Image *Image::Load(int fd, const char *name, bool anonymous, LoadError *err) {
    *err = LoadError::kNone;

    ElfW(Ehdr) ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr))) {
        LOGE("linker: cannot read ELF header of %s", name);
        *err = LoadError::kError;
        return nullptr;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS_NATIVE || ehdr.e_type != ET_DYN) {
        LOGE("linker: %s is not a native ET_DYN shared object", name);
        *err = LoadError::kError;
        return nullptr;
    }

    std::vector<ElfW(Phdr)> phdrs(ehdr.e_phnum);
    if (pread(fd, phdrs.data(), ehdr.e_phnum * sizeof(ElfW(Phdr)), ehdr.e_phoff) !=
        static_cast<ssize_t>(ehdr.e_phnum * sizeof(ElfW(Phdr)))) {
        LOGE("linker: cannot read program headers of %s", name);
        *err = LoadError::kError;
        return nullptr;
    }

    // Refuse TLS up front, before committing any mapping.
    for (const auto &ph : phdrs) {
        if (ph.p_type == PT_TLS && ph.p_memsz > 0) {
            LOGW("linker: %s has PT_TLS, refusing (needs system linker)", name);
            *err = LoadError::kUnsupported;
            return nullptr;
        }
    }

    auto *img = new Image();
    img->name_ = name ? name : "(anonymous)";

    if (!img->MapSegments(fd, ehdr, phdrs, anonymous, err) || !img->ParseDynamic(err)) {
        delete img;  // ~Image unmaps whatever was mapped.
        return nullptr;
    }

    // Final protections (text R-X) BEFORE relocation, so ifunc resolvers the
    // relocation pass may call are executable; then relocate, then seal RELRO.
    img->SetSegmentProtections();
    if (!img->Relocate(err)) {
        delete img;
        return nullptr;
    }
    img->ApplyRelro();
    img->CallConstructors();

    {
        std::lock_guard<std::mutex> lk(g_images_lock);
        g_images.push_back(img);
    }
    return img;
}

Image::~Image() {
    CallDestructors();
    for (void *h : needed_handles_) {
        if (h != nullptr) dlclose(h);
    }
    if (map_start_ != 0 && map_size_ != 0) {
        munmap(reinterpret_cast<void *>(map_start_), map_size_);
    }
}

// --------------------------------------------------------------------------
// Public C-ish API + interpose support
// --------------------------------------------------------------------------

void *Dlopen(int fd, const char *name, bool anonymous, LoadError *err) {
    LoadError local = LoadError::kNone;
    Image *img = Image::Load(fd, name, anonymous, err ? err : &local);
    return img;
}

void *Dlsym(void *handle, const char *name) {
    if (handle == nullptr) return nullptr;
    auto *img = static_cast<Image *>(handle);
    {
        std::lock_guard<std::mutex> lk(g_images_lock);
        bool known = false;
        for (auto *i : g_images) {
            if (i == img) {
                known = true;
                break;
            }
        }
        if (!known) return nullptr;
    }
    return img->Symbol(name);
}

bool Dlclose(void *handle) {
    auto *img = static_cast<Image *>(handle);
    {
        std::lock_guard<std::mutex> lk(g_images_lock);
        auto it = g_images.end();
        for (auto i = g_images.begin(); i != g_images.end(); ++i) {
            if (*i == img) {
                it = i;
                break;
            }
        }
        if (it == g_images.end()) return false;
        g_images.erase(it);
    }
    delete img;
    return true;
}

bool IsOurHandle(void *handle) {
    std::lock_guard<std::mutex> lk(g_images_lock);
    for (auto *i : g_images) {
        if (i == handle) return true;
    }
    return false;
}

// Used by interpose.cpp's dladdr override.
Image *FindImageByAddress(const void *addr) {
    std::lock_guard<std::mutex> lk(g_images_lock);
    for (auto *i : g_images) {
        if (i->Contains(addr)) return i;
    }
    return nullptr;
}

void ForEachImage(void (*fn)(Image *, void *), void *arg) {
    std::lock_guard<std::mutex> lk(g_images_lock);
    for (auto *i : g_images) fn(i, arg);
}

bool GnuPropertyNoteHasBti(const uint8_t *note, size_t size) {
    const uint8_t *p = note;
    const uint8_t *end = note + size;
    while (p + 12 <= end) {
        uint32_t namesz = ReadU32(p);
        uint32_t descsz = ReadU32(p + 4);
        uint32_t ntype = ReadU32(p + 8);
        const uint8_t *name = p + 12;
        const uint8_t *desc = name + AlignUp(namesz, 4);
        if (desc > end) break;

        if (ntype == NT_GNU_PROPERTY_TYPE_0 && namesz == 4 && memcmp(name, "GNU", 4) == 0) {
            const uint8_t *pp = desc;
            const uint8_t *pend = desc + descsz;
            if (pend > end) pend = end;
            // Each property: pr_type (u32), pr_datasz (u32), data, padded to a
            // pointer-size boundary (8 on LP64).
            while (pp + 8 <= pend) {
                uint32_t pr_type = ReadU32(pp);
                uint32_t pr_datasz = ReadU32(pp + 4);
                const uint8_t *pr_data = pp + 8;
                if (pr_data + pr_datasz > pend) break;
                if (pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND && pr_datasz >= 4) {
                    if (ReadU32(pr_data) & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) return true;
                }
                pp = pr_data + AlignUp(pr_datasz, sizeof(ElfW(Addr)));
            }
        }
        p = desc + AlignUp(descsz, 4);
    }
    return false;
}

}  // namespace linker
