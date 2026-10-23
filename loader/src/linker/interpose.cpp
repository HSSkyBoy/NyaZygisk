#include "interpose.hpp"

#include <dlfcn.h>
#include <link.h>

#include <cstring>

#include "linker.hpp"
#include "logging.hpp"

namespace linker {

namespace {

// ---- dl_iterate_phdr -------------------------------------------------------
// Report each of our images, then defer to the real implementation for the
// system-visible ones. Exception unwinding relies on this to find a module's
// .eh_frame (and PT_GNU_EH_FRAME) via its program headers.

struct IterateCtx {
    int (*cb)(dl_phdr_info *, size_t, void *);
    void *data;
    int result;
    bool stop;
};

void EmitImage(Image *img, void *arg) {
    auto *ctx = static_cast<IterateCtx *>(arg);
    if (ctx->stop) return;

    dl_phdr_info info{};
    info.dlpi_addr = img->base();
    info.dlpi_name = img->name().c_str();
    info.dlpi_phdr = img->phdr();
    info.dlpi_phnum = static_cast<ElfW(Half)>(img->phnum());
    // Remaining fields (TLS, adds/subs) are left zero: we refuse TLS modules,
    // and the unwinder does not consult the counters.

    int r = ctx->cb(&info, sizeof(info), ctx->data);
    if (r != 0) {
        ctx->result = r;
        ctx->stop = true;
    }
}

int MyIteratePhdr(int (*cb)(dl_phdr_info *, size_t, void *), void *data) {
    IterateCtx ctx{cb, data, 0, false};
    ForEachImage(EmitImage, &ctx);
    if (ctx.stop) return ctx.result;
    return dl_iterate_phdr(cb, data);
}

// ---- dladdr ----------------------------------------------------------------

int MyDladdr(const void *addr, Dl_info *info) {
    Image *img = FindImageByAddress(addr);
    if (img == nullptr) return dladdr(addr, info);

    // Synthesize a minimal Dl_info. We do not expose per-symbol names (the
    // module is meant to be opaque); fname/fbase are enough for unwinding and
    // for the common "which library am I in" query.
    memset(info, 0, sizeof(*info));
    info->dli_fname = img->name().c_str();
    info->dli_fbase = reinterpret_cast<void *>(img->base());
    return 1;
}

// ---- dlsym / dlclose -------------------------------------------------------

void *MyDlsym(void *handle, const char *symbol) {
    if (IsOurHandle(handle)) return Dlsym(handle, symbol);
    return dlsym(handle, symbol);
}

int MyDlclose(void *handle) {
    if (IsOurHandle(handle)) return Dlclose(handle) ? 0 : -1;
    return dlclose(handle);
}

#if defined(__arm__)
// ---- dl_unwind_find_exidx (arm32 only) -------------------------------------
// The arm EABI unwinder calls this to find a module's .ARM.exidx table.
extern "C" _Unwind_Ptr __real_dl_unwind_find_exidx(_Unwind_Ptr pc, int *pcount);

_Unwind_Ptr MyUnwindFindExidx(_Unwind_Ptr pc, int *pcount) {
    Image *img = FindImageByAddress(reinterpret_cast<const void *>(pc));
    if (img != nullptr) {
        const ElfW(Phdr) *ph = img->phdr();
        for (size_t i = 0; i < img->phnum(); i++) {
            if (ph[i].p_type == PT_ARM_EXIDX) {
                *pcount = ph[i].p_memsz / 8;
                return static_cast<_Unwind_Ptr>(img->base() + ph[i].p_vaddr);
            }
        }
        *pcount = 0;
        return 0;
    }
    return dl_unwind_find_exidx(pc, pcount);
}
#endif

struct Entry {
    const char *name;
    void *fn;
};

const Entry kTable[] = {
    {"dl_iterate_phdr", reinterpret_cast<void *>(&MyIteratePhdr)},
    {"dladdr", reinterpret_cast<void *>(&MyDladdr)},
    {"dlsym", reinterpret_cast<void *>(&MyDlsym)},
    {"dlclose", reinterpret_cast<void *>(&MyDlclose)},
#if defined(__arm__)
    {"dl_unwind_find_exidx", reinterpret_cast<void *>(&MyUnwindFindExidx)},
#endif
};

}  // namespace

void *InterposeLookup(const char *name) {
    for (const auto &e : kTable) {
        if (strcmp(e.name, name) == 0) return e.fn;
    }
    return nullptr;
}

}  // namespace linker
