#include "zn_loader.hpp"
#include "zn_api.hpp"
#include "logging.hpp"
#include "zygisk_next_api.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace zn {

// Helper: resolve dlopenViaFd from zn_api
extern void* dlopenViaFd(const char* path, int flags);

namespace {

std::string getProcessPath() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return buf;
}

std::string getProcessName() {
    const std::string p = getProcessPath();
    const auto pos = p.rfind('/');
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

struct ModuleEntry {
    bool is_name = false;   // name=... (true) or path=... (false)
    std::string target;     // target process name or path
    bool companion = false;
    std::string lib;        // relative or absolute path to library
    std::string module_dir;
};

std::vector<ModuleEntry> parseZnModulesFile(const std::string& moddir, const std::string& file) {
    std::vector<ModuleEntry> out;
    FILE* f = fopen(file.c_str(), "re");
    if (!f) return out;

    char* line = nullptr;
    size_t cap = 0;
    while (getline(&line, &cap, f) > 0) {
        std::string l = line;

        std::vector<std::string> toks;
        size_t i = 0;
        while (i < l.size()) {
            while (i < l.size() && isspace(static_cast<unsigned char>(l[i]))) ++i;
            size_t j = i;
            while (j < l.size() && !isspace(static_cast<unsigned char>(l[j]))) ++j;
            if (j > i) toks.push_back(l.substr(i, j - i));
            i = j;
        }
        if (toks.size() < 2) continue;

        ModuleEntry e;
        e.module_dir = moddir;

        if (toks[0].rfind("path=", 0) == 0) {
            e.is_name = false;
            e.target = toks[0].substr(5);
        } else if (toks[0].rfind("name=", 0) == 0) {
            e.is_name = true;
            e.target = toks[0].substr(5);
        } else {
            continue;
        }

        for (size_t k = 1; k + 1 < toks.size(); ++k) {
            if (toks[k] == "companion") e.companion = true;
        }
        e.lib = toks.back();
        out.push_back(std::move(e));
    }
    free(line);
    fclose(f);
    return out;
}

bool matchEntry(const ModuleEntry& e) {
    const std::string proc_name = getProcessName();
    const std::string proc_path = getProcessPath();
    if (e.is_name) {
        // Special case: "zygote" matches zygote, zygote64, app_process, app_process64, app_process32
        if (e.target == "zygote" || e.target == "zygote64" || e.target == "zygote32") {
            if (proc_name.find("zygote") != std::string::npos || proc_name.find("app_process") != std::string::npos) {
                return true;
            }
        }
        return proc_name == e.target;
    }
    return proc_path == e.target;
}

bool resolveLibPath(const ModuleEntry& e, std::string& out) {
    std::string candidate = e.lib;
    if (candidate.empty() || candidate[0] != '/') candidate = e.module_dir + "/" + candidate;

    char real_mod[PATH_MAX];
    char real_lib[PATH_MAX];
    if (!realpath(e.module_dir.c_str(), real_mod)) return false;
    if (!realpath(candidate.c_str(), real_lib)) return false;

    const std::string mod = real_mod;
    const std::string lib = real_lib;
    if (lib.size() <= mod.size() || lib.compare(0, mod.size(), mod) != 0 || lib[mod.size()] != '/') {
        return false;
    }
    out = lib;
    return true;
}

void loadEntry(const ModuleEntry& e) {
    std::string lib_path;
    if (!resolveLibPath(e, lib_path)) {
        LOGE("ZN: module lib path %s is not inside module dir, skipping", e.lib.c_str());
        return;
    }

    void* lib = dlopenViaFd(lib_path.c_str(), RTLD_NOW);
    if (!lib) {
        LOGE("ZN: dlopen %s failed: %s", lib_path.c_str(), dlerror());
        return;
    }

    auto* m = reinterpret_cast<ZygiskNextModule*>(dlsym(lib, "zn_module"));
    if (!m || !m->onModuleLoaded) {
        LOGE("ZN: %s does not export zn_module", lib_path.c_str());
        return;
    }

    if (m->target_api_version > ZYGISK_NEXT_API_VERSION) {
        LOGW("ZN: %s requires API version %d, only up to %d supported", lib_path.c_str(),
             m->target_api_version, ZYGISK_NEXT_API_VERSION);
        return;
    }

    auto* handle = new ZnModuleHandle();
    handle->lib_path = lib_path;

    if (e.companion && m->target_api_version >= 3) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(sv[0]);
                companionMain(lib_path.c_str(), sv[1]);
                _exit(0);
            } else if (pid > 0) {
                close(sv[1]);
                handle->companion_fd = sv[0];
                handle->companion_pid = pid;
            } else {
                close(sv[0]);
                close(sv[1]);
            }
        }
    } else if (e.companion) {
        LOGW("ZN: module %s declares companion but targets API %d (< 3), skipping companion process",
             lib_path.c_str(), m->target_api_version);
    }

    const ZygiskNextAPI* api = getApiForVersion(m->target_api_version);

    LOGI("ZN: loading module %s (companion=%s, api=%d)", lib_path.c_str(),
         e.companion ? "yes" : "no", m->target_api_version);
    m->onModuleLoaded(handle, api);
}

}  // namespace

void loadAllModules() {
    DIR* d = opendir("/data/adb/modules");
    if (!d) {
        LOGW("ZN: cannot open /data/adb/modules: %s", strerror(errno));
        return;
    }

    std::vector<std::string> moddirs;
    struct dirent* de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        std::string dir = std::string("/data/adb/modules/") + de->d_name;
        if (access((dir + "/disable").c_str(), F_OK) == 0) continue;
        if (access((dir + "/remove").c_str(), F_OK) == 0) continue;
        if (access((dir + "/zn_modules.txt").c_str(), R_OK) != 0) continue;
        moddirs.push_back(std::move(dir));
    }
    closedir(d);

    for (const auto& moddir : moddirs) {
        for (auto& e : parseZnModulesFile(moddir, moddir + "/zn_modules.txt")) {
            if (matchEntry(e)) loadEntry(e);
        }
    }
}

}  // namespace zn
