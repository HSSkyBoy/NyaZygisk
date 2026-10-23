#include "module_loader.hpp"

#include <dlfcn.h>

#include "dl.hpp"
#include "linker.hpp"
#include "logging.hpp"
#include "zygisk.hpp"

namespace modloader {

void *Dlopen(int memfd, const char *name, bool *via_system) {
    // Map into anonymous memory (no memfd trace in /proc/self/maps) when the
    // device/config allows anonymous executable memory; otherwise map
    // file-backed from the memfd, matching the regular loader's behaviour where
    // execmem is denied.
    const bool anonymous = is_anonymous_memory_enabled();
    linker::LoadError err = linker::LoadError::kNone;
    if (void *h = linker::Dlopen(memfd, name, anonymous, &err)) {
        *via_system = false;
        LOGI("modloader: %s loaded by custom linker", name ? name : "(module)");
        return h;
    }

    if (err == linker::LoadError::kUnsupported) {
        LOGW("modloader: %s unsupported by custom linker, using system loader",
             name ? name : "(module)");
    } else {
        LOGW("modloader: %s failed in custom linker, using system loader",
             name ? name : "(module)");
    }

    *via_system = true;
    return DlopenMem(memfd, RTLD_NOW, name);
}

void *Dlsym(void *handle, const char *name) {
    if (linker::IsOurHandle(handle)) return linker::Dlsym(handle, name);
    return dlsym(handle, name);
}

bool Dlclose(void *handle) {
    if (linker::IsOurHandle(handle)) return linker::Dlclose(handle);
    return dlclose(handle) == 0;
}

bool IsCustom(void *handle) { return linker::IsOurHandle(handle); }

}  // namespace modloader
