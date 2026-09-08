#include "zn_api.hpp"

#include "elf_util.h"
#include "logging.hpp"

#include <dobby.h>
#include <lsplt.hpp>

#include <android/dlext.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <set>
#include <string_view>
#include <vector>

using namespace znn;

// Opaque symbol resolver in global scope matching zygisk_next_api.h
struct ZnSymbolResolver {
    znn::ElfImage* image = nullptr;
};

namespace zn {

// Helper: load library from memfd to bypass namespace restrictions
void* dlopenViaFd(const char* path, int flags) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOGE("dlopen %s: cannot open: %s", path, strerror(errno));
        return nullptr;
    }

    int memfd = static_cast<int>(syscall(SYS_memfd_create, "znn-module", MFD_CLOEXEC));
    if (memfd < 0) {
        LOGE("dlopen %s: memfd_create failed: %s", path, strerror(errno));
        close(fd);
        return nullptr;
    }

    char buf[16384];
    ssize_t n;
    bool ok = true;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t left = n;
        const char* p = buf;
        while (left > 0) {
            ssize_t w = write(memfd, p, static_cast<size_t>(left));
            if (w <= 0) {
                ok = false;
                break;
            }
            p += w;
            left -= w;
        }
        if (!ok) break;
    }
    close(fd);
    if (!ok || n < 0) {
        LOGE("dlopen %s: copy to memfd failed: %s", path, strerror(errno));
        close(memfd);
        return nullptr;
    }

    android_dlextinfo extinfo = {};
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    extinfo.library_fd = memfd;

    void* lib = android_dlopen_ext(path, flags, &extinfo);
    if (!lib) {
        LOGE("dlopen %s via memfd failed: %s", path, dlerror());
    }
    return lib;
}

namespace {

constexpr char kCmdConnect = 1;

std::mutex g_hook_mutex;
std::set<uintptr_t> g_hooked;

int api_pltHook(void* base, const char* symbol, void* hook, void** original) {
    if (!base || !symbol || !hook) return ZN_FAILED;

    LOGI("ZN pltHook base=%p symbol=%s", base, symbol);
    const uintptr_t b = reinterpret_cast<uintptr_t>(base);
    auto maps = parseMaps("self");
    const MapEntry* target_entry = nullptr;
    for (const auto& m : maps) {
        uintptr_t load_base = m.start - m.offset;
        if ((b >= m.start && b < m.end) || b == m.start || b == load_base) {
            if (m.inode == 0) continue;
            for (const auto& h : maps) {
                if (h.inode == m.inode && h.dev == m.dev && h.offset == 0) {
                    target_entry = &h;
                    break;
                }
            }
            if (!target_entry) target_entry = &m;
            break;
        }
    }

    if (!target_entry) {
        LOGE("ZN pltHook %s: base %p not found in maps", symbol, base);
        return ZN_FAILED;
    }

    void* backup = nullptr;
    if (!lsplt::RegisterHook(target_entry->dev, target_entry->inode, symbol, hook, &backup)) {
        LOGE("ZN pltHook %s: RegisterHook failed", symbol);
        return ZN_FAILED;
    }
    if (!lsplt::CommitHook()) {
        LOGE("ZN pltHook %s: CommitHook failed", symbol);
        return ZN_FAILED;
    }
    if (!backup) {
        LOGE("ZN pltHook %s: symbol not found in PLT (backup is null)", symbol);
        return ZN_FAILED;
    }
    if (original) *original = backup;
    return ZN_SUCCESS;
}

int api_inlineHook(void* target, void* addr, void** original) {
    if (!target || !addr) return ZN_FAILED;

    const uintptr_t t = reinterpret_cast<uintptr_t>(target);
    {
        std::lock_guard<std::mutex> lk(g_hook_mutex);
        if (g_hooked.count(t)) {
            LOGW("ZN inlineHook %p already hooked", target);
            return ZN_FAILED;
        }
    }

    if (DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(addr),
                  reinterpret_cast<dobby_dummy_func_t*>(original)) != RS_SUCCESS) {
        LOGE("ZN inlineHook %p: DobbyHook failed", target);
        return ZN_FAILED;
    }

    std::lock_guard<std::mutex> lk(g_hook_mutex);
    g_hooked.insert(t);
    return ZN_SUCCESS;
}

int api_inlineUnhook(void* target) {
    if (!target) return ZN_FAILED;

    const uintptr_t t = reinterpret_cast<uintptr_t>(target);
    if (DobbyDestroy(target) != RS_SUCCESS) return ZN_FAILED;

    std::lock_guard<std::mutex> lk(g_hook_mutex);
    g_hooked.erase(t);
    return ZN_SUCCESS;
}

ZnSymbolResolver* api_newSymbolResolver(const char* path, void* base) {
    if (!path) return nullptr;

    auto* resolver = new ZnSymbolResolver();
    resolver->image = new ElfImage(path, reinterpret_cast<uintptr_t>(base));
    if (!resolver->image->valid()) {
        LOGW("ZN newSymbolResolver %s: invalid", path);
        delete resolver->image;
        delete resolver;
        return nullptr;
    }
    return resolver;
}

void api_freeSymbolResolver(ZnSymbolResolver* resolver) {
    if (!resolver) return;
    delete resolver->image;
    delete resolver;
}

void* api_getBaseAddress(ZnSymbolResolver* resolver) {
    if (!resolver || !resolver->image) return nullptr;
    return reinterpret_cast<void*>(resolver->image->base());
}

void* api_symbolLookup(ZnSymbolResolver* resolver, const char* name, bool prefix, size_t* size) {
    if (!resolver || !resolver->image || !name) return nullptr;

    const SymbolInfo* s = resolver->image->lookup(name, prefix);
    if (s) {
        if (size) *size = s->size;
        return reinterpret_cast<void*>(s->addr);
    }

    if (!prefix) {
        uintptr_t a = resolver->image->runtimeLookup(name, size);
        if (a) {
            return reinterpret_cast<void*>(a);
        }
    }
    return nullptr;
}

void api_forEachSymbols(ZnSymbolResolver* resolver,
                        bool (*callback)(const char* name, void* addr, size_t size, void* data),
                        void* data) {
    if (!resolver || !resolver->image || !callback) return;
    resolver->image->forEach([&](const char* name, uintptr_t addr, size_t size) {
        return callback(name, reinterpret_cast<void*>(addr), size, data);
    });
}

int api_connectCompanion(void* handle) {
    auto* h = static_cast<ZnModuleHandle*>(handle);
    if (!h || h->companion_fd < 0) return -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) return -1;

    char cmd = kCmdConnect;
    struct iovec iov = {&cmd, sizeof(cmd)};
    char cmsg_buf[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &sv[1], sizeof(int));
    msg.msg_controllen = cmsg->cmsg_len;

    if (sendmsg(h->companion_fd, &msg, 0) < 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    close(sv[1]);
    return sv[0];
}

// Helper: Raw inline hook via Dobby
bool inlineHookRaw(void* target, void* addr, void** original) {
    if (!target || !addr) return false;
    return DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(addr),
                     reinterpret_cast<dobby_dummy_func_t*>(original)) == RS_SUCCESS;
}

// ZN API v4 Runtime: the HyperOS Rust Runtime (HYOS)
constexpr int kMaxHyosModules = 16;
bool g_hyos_runtime = false;
ZygiskNextHyosModule g_hyos_modules[kMaxHyosModules] = {};
int g_hyos_module_count = 0;
bool g_hyos_in_child = false;
bool g_hyos_fired = false;

typedef int (*HyosSetcontextFn)(uid_t uid, int is_system_server, const char* se_info,
                                const char* pkg_name);
typedef int (*HyosSetnameFn)(pthread_t thread, const char* name);
HyosSetcontextFn g_orig_setcontext = nullptr;
HyosSetnameFn g_orig_setname = nullptr;
bool g_hyos_warned = false;

char g_cap_process_name[256] = {};
bool g_cap_has_process_name = false;

bool readProcCmdline(char* out, size_t max_len) {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, max_len - 1);
    close(fd);
    if (n <= 0) return false;
    out[n] = '\0';
    return out[0] != '\0';
}

void hyosDeliverAppSpecialized(const char* pkg_name, const char* se_info) {
    if (!g_hyos_in_child || g_hyos_fired || g_hyos_module_count == 0) return;
    g_hyos_fired = true;

    char process_name[256] = {};
    char package_name[256] = {};
    char se_info_buf[64] = {};

    if (g_cap_has_process_name && g_cap_process_name[0] != '\0') {
        strlcpy(process_name, g_cap_process_name, sizeof(process_name));
    } else if (!readProcCmdline(process_name, sizeof(process_name)) || process_name[0] == '\0') {
        if (prctl(PR_GET_NAME, process_name, 0, 0, 0) != 0 || process_name[0] == '\0') {
            strlcpy(process_name, "hyos_app", sizeof(process_name));
        }
    }

    strlcpy(package_name, pkg_name ? pkg_name : "", sizeof(package_name));
    strlcpy(se_info_buf, se_info ? se_info : "", sizeof(se_info_buf));

    ZnHyosAppSpecializeArgs args = {process_name, package_name, se_info_buf};
    LOGI("HYOS app specialized: process=%s package=%s se_info=%s", process_name,
         package_name, se_info_buf);

    for (int i = 0; i < g_hyos_module_count; ++i) {
        if (g_hyos_modules[i].onAppSpecialized) {
            g_hyos_modules[i].onAppSpecialized(&args);
        }
    }
}

int hyosSetcontextHook(uid_t uid, int is_system_server, const char* se_info,
                       const char* pkg_name) {
    int ret = g_orig_setcontext ? g_orig_setcontext(uid, is_system_server, se_info, pkg_name)
                                : -1;
    if (ret == 0) {
        hyosDeliverAppSpecialized(pkg_name, se_info);
    } else if (!g_hyos_fired && g_hyos_in_child) {
        LOGW("HYOS: selinux_android_setcontext failed (%d)", ret);
    }
    return ret;
}

int hyosSetnameHook(pthread_t thread, const char* name) {
    int ret = g_orig_setname ? g_orig_setname(thread, name) : -1;
    if (ret == 0 && !g_cap_has_process_name && g_hyos_in_child && !g_hyos_fired &&
        thread == pthread_self() && name && name[0] != '\0') {
        strlcpy(g_cap_process_name, name, sizeof(g_cap_process_name));
        g_cap_has_process_name = true;
        LOGI("HYOS: captured process name %s", g_cap_process_name);
    }
    return ret;
}

void hyosAtForkChild() {
    g_hyos_in_child = true;
    g_hyos_fired = false;
    g_cap_has_process_name = false;
    g_cap_process_name[0] = '\0';
}

void hyosInstallHooks();

void hyosAtForkPrepare() {
    if (g_hyos_module_count > 0 && (!g_orig_setcontext || !g_orig_setname)) {
        hyosInstallHooks();
    }
}

void hyosInstallHooks() {
    if (!g_orig_setcontext) {
        void* fn = dlsym(RTLD_DEFAULT, "selinux_android_setcontext");
        if (!fn) {
            void* h = dlopen("libselinux.so", RTLD_NOW);
            if (h) fn = dlsym(h, "selinux_android_setcontext");
        }
        if (fn && inlineHookRaw(fn, reinterpret_cast<void*>(hyosSetcontextHook),
                                reinterpret_cast<void**>(&g_orig_setcontext))) {
            LOGI("HYOS: hooked selinux_android_setcontext at %p", fn);
        }
    }
    if (!g_orig_setname) {
        void* fn = dlsym(RTLD_DEFAULT, "pthread_setname_np");
        if (!fn) {
            void* h = dlopen("libc.so", RTLD_NOW);
            if (h) fn = dlsym(h, "pthread_setname_np");
        }
        if (fn && inlineHookRaw(fn, reinterpret_cast<void*>(hyosSetnameHook),
                                reinterpret_cast<void**>(&g_orig_setname))) {
            LOGI("HYOS: hooked pthread_setname_np at %p", fn);
        }
    }
    if (!g_orig_setcontext && !g_hyos_warned) {
        g_hyos_warned = true;
        LOGW("HYOS: selinux_android_setcontext not available, onAppSpecialized will not fire");
    }
}

int api_hyos_registerModule(const void* module) {
    if (!module) return ZN_FAILED;
    const auto* m = static_cast<const ZygiskNextHyosModule*>(module);
    if (!m->onAppSpecialized) return ZN_FAILED;
    if (m->target_api_version > ZYGISK_NEXT_HYOS_API_VERSION) {
        LOGE("HYOS: module targets API version %d, only up to %d supported",
             m->target_api_version, ZYGISK_NEXT_HYOS_API_VERSION);
        return ZN_FAILED;
    }
    if (g_hyos_module_count >= kMaxHyosModules) {
        LOGE("HYOS: too many modules registered (max %d)", kMaxHyosModules);
        return ZN_FAILED;
    }
    g_hyos_modules[g_hyos_module_count++] = *m;

    if (!g_hyos_in_child) {
        pthread_atfork(hyosAtForkPrepare, nullptr, hyosAtForkChild);
        hyosInstallHooks();
    }
    LOGI("HYOS: module registered (%d)", g_hyos_module_count);
    return ZN_SUCCESS;
}

const ZygiskNextRuntime kHyosRuntime = {
    .type = ZN_RUNTIME_HYOS,
    .api_version = ZYGISK_NEXT_HYOS_API_VERSION,
    .registerModule = api_hyos_registerModule,
};

const ZygiskNextRuntime* api_getRuntime() {
    return g_hyos_runtime ? &kHyosRuntime : nullptr;
}

const ZygiskNextRuntime* api_getRuntimeUnavailable() {
    LOGW("ZN: Runtime API (HyperOS) not enabled");
    return nullptr;
}

// Stubs for API < 2
struct ZnSymbolResolver* api_symbolResolverUnavailable(const char*, void*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
    return nullptr;
}
void api_freeSymbolResolverUnavailable(struct ZnSymbolResolver*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
}
void* api_getBaseAddressUnavailable(struct ZnSymbolResolver*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
    return nullptr;
}
void* api_symbolLookupUnavailable(struct ZnSymbolResolver*, const char*, bool, size_t*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
    return nullptr;
}
void api_forEachSymbolsUnavailable(struct ZnSymbolResolver*, bool (*)(const char*, void*, size_t, void*), void*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
}

const ZygiskNextAPI kApiV4 = {
    api_pltHook,           api_inlineHook,   api_inlineUnhook,
    api_newSymbolResolver, api_freeSymbolResolver, api_getBaseAddress,
    api_symbolLookup,      api_forEachSymbols,
    api_connectCompanion,
    api_getRuntime,
};

const ZygiskNextAPI kApiFull = {
    api_pltHook,           api_inlineHook,   api_inlineUnhook,
    api_newSymbolResolver, api_freeSymbolResolver, api_getBaseAddress,
    api_symbolLookup,      api_forEachSymbols,
    api_connectCompanion,
    api_getRuntimeUnavailable,
};

const ZygiskNextAPI kApiNoSymbolResolver = {
    api_pltHook,                   api_inlineHook,             api_inlineUnhook,
    api_symbolResolverUnavailable, api_freeSymbolResolverUnavailable,
    api_getBaseAddressUnavailable, api_symbolLookupUnavailable,
    api_forEachSymbolsUnavailable,
    api_connectCompanion,
    api_getRuntimeUnavailable,
};

}  // namespace

const ZygiskNextAPI* getApiForVersion(int target_api_version) {
    if (target_api_version >= 4) return &kApiV4;
    if (target_api_version >= 2) return &kApiFull;
    return &kApiNoSymbolResolver;
}

[[noreturn]] void companionMain(const char* lib_path, int ctl_fd) {
    void* lib = dlopenViaFd(lib_path, RTLD_NOW);
    if (!lib) {
        LOGE("companion: dlopen %s failed: %s", lib_path, dlerror());
        _exit(1);
    }

    auto* m = reinterpret_cast<ZygiskNextCompanionModule*>(dlsym(lib, "zn_companion_module"));
    if (!m || !m->onCompanionLoaded || !m->onModuleConnected) {
        LOGE("companion: %s does not export zn_companion_module", lib_path);
        _exit(1);
    }

    m->onCompanionLoaded();

    for (;;) {
        char cmd = 0;
        int fd = -1;
        struct iovec iov = {&cmd, sizeof(cmd)};
        char cmsg_buf[CMSG_SPACE(sizeof(int))] = {0};
        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        ssize_t n = recvmsg(ctl_fd, &msg, 0);
        if (n <= 0) break;

        if (cmd != kCmdConnect) continue;

        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
                break;
            }
        }
        if (fd >= 0) {
            m->onModuleConnected(fd);
            fd = -1;
        }
    }
    _exit(0);
}

bool isHyosSpawner() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return false;
    buf[n] = '\0';
    std::string_view p(buf);
    if (p.ends_with(" (deleted)")) {
        p.remove_suffix(10);
    }
    return p == "/system_ext/bin/hyos_spawner" || p.ends_with("/hyos_spawner");
}

void initHyosRuntime() {
    g_hyos_runtime = true;
    LOGI("ZN: HyperOS Runtime enabled in pid %d", getpid());
}

bool isHyosRuntime() {
    return g_hyos_runtime;
}

}  // namespace zn
