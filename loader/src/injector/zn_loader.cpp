#include "zn_loader.hpp"
#include "zn_api.hpp"
#include "logging.hpp"
#include "zygisk_next_api.h"

#include <android/dlext.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "daemon.hpp"
#include "socket_utils.hpp"

namespace zn {

// Helper: resolve dlopenViaFd from zn_api
extern void* dlopenViaFd(const char* path, int flags);

namespace {

// Load a library straight from an already-open file descriptor (a memfd
// provided by the root daemon), bypassing path and namespace restrictions.
void* dlopenFromFd(int fd, const char* name, int flags) {
    android_dlextinfo ext = {};
    ext.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    ext.library_fd = fd;
    return android_dlopen_ext(name, flags, &ext);
}

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

// A ZN module record served by the root daemon (zygiskd).
struct DaemonModule {
    std::string lib_path;
    bool companion = false;
    int fd = -1;
};

// Ask the root daemon (zygiskd) for the ZN modules matching this process.
// The daemon resolves and memfds the libraries, so we never need to read
// /data/adb/modules ourselves (which non-root targets cannot do).
// Returns false when the daemon is unreachable or the exchange fails.
bool requestModulesFromDaemon(const std::string& process_name,
                              const std::string& process_path,
                              std::vector<DaemonModule>& out) {
    int fd = zygiskd::Connect(1);
    if (fd < 0) {
        LOGW("ZN: cannot connect to zygiskd: %s", strerror(errno));
        return false;
    }
    struct timeval tv {};
    tv.tv_sec = 5;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (!socket_utils::write_u8(fd, static_cast<uint8_t>(zygiskd::SocketAction::ReadZnModules)) ||
        !socket_utils::write_string(fd, process_name) ||
        !socket_utils::write_string(fd, process_path)) {
        close(fd);
        return false;
    }

    size_t count = socket_utils::read_usize(fd);
    for (size_t i = 0; i < count; ++i) {
        std::string lib = socket_utils::read_string(fd);
        bool companion = socket_utils::read_u8(fd) != 0;
        int mfd = socket_utils::recv_fd(fd);
        if (mfd < 0) {
            LOGE("ZN: failed to receive module fd from zygiskd");
            close(fd);
            return false;
        }
        out.push_back({std::move(lib), companion, mfd});
    }
    close(fd);
    return true;
}

// Ask the root daemon to spawn a companion process for `lib_path`. The
// companion then runs in the daemon's privileged SELinux domain instead of
// this process's (possibly restricted) domain. Returns the control socket fd,
// or -1 when the daemon is unavailable or refused.
int requestDaemonCompanion(const std::string& lib_path) {
    int fd = zygiskd::Connect(1);
    if (fd < 0) return -1;
    struct timeval tv {};
    tv.tv_sec = 5;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (!socket_utils::write_u8(fd,
                                static_cast<uint8_t>(zygiskd::SocketAction::SpawnZnCompanion)) ||
        !socket_utils::write_string(fd, lib_path)) {
        close(fd);
        return -1;
    }
    if (socket_utils::read_u8(fd) != 1) {
        close(fd);
        return -1;
    }
    int cfd = socket_utils::recv_fd(fd);
    close(fd);
    return cfd;
}

void loadEntry(const ModuleEntry& e, int module_fd = -1) {
    std::string lib_path;
    if (module_fd >= 0) {
        // Provided by the root daemon: lib_path is already the resolved path.
        lib_path = e.lib;
    } else if (!resolveLibPath(e, lib_path)) {
        LOGE("ZN: module lib path %s is not inside module dir, skipping", e.lib.c_str());
        return;
    }

    void* lib = module_fd >= 0 ? dlopenFromFd(module_fd, lib_path.c_str(), RTLD_NOW)
                               : dlopenViaFd(lib_path.c_str(), RTLD_NOW);
    if (!lib) {
        const char* err = dlerror();
        LOGE("ZN: dlopen %s failed: %s", lib_path.c_str(), err ? err : "unknown error");
        if (err && std::string(err).find("Permission denied") != std::string::npos) {
            LOGE("ZN: hint: dlopen needs the `execute` permission on the memfd's "
                 "SELinux label (\"tmpfs\", \"unlabeled\", or <domain>_memfd, e.g. "
                 "zygiskd's domain). NyaZygisk ships `allow * * file execute` in "
                 "sepolicy.rule to cover every label.");
        }
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
        // Prefer a companion spawned by the root daemon: it keeps the daemon's
        // privileged SELinux domain. Fall back to forking here (which inherits
        // this process's domain) only when the daemon is unreachable.
        int cfd = requestDaemonCompanion(lib_path);
        if (cfd >= 0) {
            LOGI("ZN: companion for %s spawned by zygiskd (fd %d)", lib_path.c_str(), cfd);
            handle->companion_fd = cfd;
            handle->companion_pid = -1;
        } else {
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
    // Preferred path: let the root daemon resolve and memfd the matching
    // module libraries. This works for targets that cannot read
    // /data/adb/modules (non-root processes, restricted SELinux domains).
    std::vector<DaemonModule> mods;
    if (requestModulesFromDaemon(getProcessName(), getProcessPath(), mods)) {
        LOGI("ZN: got %zu module(s) from zygiskd", mods.size());
        for (auto& m : mods) {
            ModuleEntry e;
            e.is_name = true;
            e.target = getProcessName();
            e.companion = m.companion;
            e.lib = m.lib_path;
            e.module_dir.clear();
            loadEntry(e, m.fd);
            if (m.fd >= 0) close(m.fd);
        }
        return;
    }
    LOGW("ZN: zygiskd unavailable, falling back to direct /data/adb/modules read");

    // Fallback for privileged targets (e.g. zygote): read /data/adb/modules
    // directly.
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
