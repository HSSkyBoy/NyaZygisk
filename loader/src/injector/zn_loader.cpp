#include "zn_loader.hpp"
#include "zn_api.hpp"
#include "logging.hpp"
#include "daemon.hpp"
#include "dl.hpp"
#include "zygisk.hpp"
#include "zygisk_next_api.h"

#include <dlfcn.h>
#include <limits.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace zn {

namespace {

std::string getProcessPath() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    std::string p(buf, static_cast<size_t>(n));
    // Strip the " (deleted)" suffix that the kernel appends when the
    // on-disk binary has been replaced (e.g. during system updates).
    constexpr std::string_view kDeleted = " (deleted)";
    if (p.size() > kDeleted.size() &&
        p.compare(p.size() - kDeleted.size(), kDeleted.size(), kDeleted) == 0) {
        p.resize(p.size() - kDeleted.size());
    }
    return p;
}

std::string getProcessName() {
    const std::string p = getProcessPath();
    const auto pos = p.rfind('/');
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

constexpr char kZnMemfdName[] = "zn-module";

bool loadEntry(const zygiskd::ZnPlanEntry& entry) {
    void* lib = DlopenMem(entry.lib_fd.get(), RTLD_NOW, kZnMemfdName);
    if (!lib) {
        LOGE("ZN: dlopen %s (fd %d) failed: %s", entry.lib_path.c_str(), entry.lib_fd.get(), dlerror());
        zygiskd::ReportZnModule(entry.lib_path, false);
        return false;
    }

    auto* m = reinterpret_cast<ZygiskNextModule*>(dlsym(lib, "zn_module"));
    if (!m || !m->onModuleLoaded) {
        LOGE("ZN: %s does not export zn_module", entry.lib_path.c_str());
        zygiskd::ReportZnModule(entry.lib_path, false);
        return false;
    }

    if (m->target_api_version > ZYGISK_NEXT_API_VERSION) {
        LOGW("ZN: %s requires API version %d, only up to %d supported", entry.lib_path.c_str(),
             m->target_api_version, ZYGISK_NEXT_API_VERSION);
        zygiskd::ReportZnModule(entry.lib_path, false);
        return false;
    }

    auto* handle = new ZnModuleHandle();
    handle->lib_path = entry.lib_path;
    handle->companion = entry.companion;
    handle->target_api_version = m->target_api_version;

    if (entry.companion && m->target_api_version < 3) {
        LOGW("ZN: module %s declares companion but targets API %d (< 3), skipping companion process",
             entry.lib_path.c_str(), m->target_api_version);
    }

    const ZygiskNextAPI* api = getApiForVersion(m->target_api_version);

    LOGI("ZN: loading module %s (companion=%s, api=%d)", entry.lib_path.c_str(),
         entry.companion ? "yes" : "no", m->target_api_version);
    m->onModuleLoaded(handle, api);
    zygiskd::ReportZnModule(entry.lib_path, true);
    return true;
}

}  // namespace

void loadAllModules(unsigned char connect_retry) {
    const std::string proc_name = getProcessName();
    const std::string proc_path = getProcessPath();
    LOGI("ZN: requesting boot plan for pid %d (name=%s, path=%s)", getpid(),
         proc_name.c_str(), proc_path.c_str());

    auto plan = zygiskd::GetZnPlan(proc_name, proc_path, connect_retry);
    LOGI("ZN: received %zu module(s) from daemon", plan.size());

    size_t loaded_count = 0;
    for (const auto& entry : plan) {
        if (entry.lib_fd.get() < 0) continue;
        if (loadEntry(entry)) loaded_count++;
    }

    // Batch the cleanup after the whole plan is processed, same as the regular Zygisk
    // module path does once for every module instead of per-module.
    if (loaded_count > 0 && is_anonymous_memory_enabled()) {
        spoof_virtual_maps(kZnMemfdName, /*private_only=*/true);
        clean_linker_trace(kZnMemfdName, loaded_count, loaded_count, /*unload_soinfo=*/true);
    }
}

}  // namespace zn
