#include "daemon.hpp"

#include <linux/un.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <climits>

#include "logging.hpp"
#include "socket_utils.hpp"

// Forward declaration of the shared memory layout since we cannot include the
// Rust-side constants header directly here.
namespace constants {
constexpr size_t SHM_HASH_MAP_SIZE = 8192;

struct ShmEntry {
    std::atomic<uint32_t> uid;
    std::atomic<uint32_t> flags;
};

struct ShmLayout {
    std::atomic<uint32_t> version;
    ShmEntry entries[SHM_HASH_MAP_SIZE];
};
}  // namespace constants

namespace zygiskd {
static std::string TMP_PATH;
static constants::ShmLayout *g_shm_base = nullptr;
static bool g_shm_init_attempted = false;

void Init(const char *path) {
    TMP_PATH = path;
}

void UnmapSharedMemory() {
    if (g_shm_base) {
        munmap(g_shm_base, sizeof(constants::ShmLayout));
        g_shm_base = nullptr;
    }
}

std::string GetTmpPath() { return TMP_PATH; }

int Connect(uint8_t retry) {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr{
        .sun_family = AF_UNIX,
        .sun_path = {0},
    };
    auto socket_path = GetTmpPath() + kCPSocketName;
    strcpy(addr.sun_path, socket_path.c_str());
    socklen_t socklen = sizeof(addr);

    while (retry--) {
        int r = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), socklen);
        if (r == 0) return fd;
        if (retry) {
            LOGW("retrying to connect to zygiskd, sleep 1s");
            sleep(1);
        }
    }

    close(fd);
    return -1;
}

bool PingHeartbeat() {
    UniqueFd fd = Connect(5);
    if (fd == -1) {
        PLOGE("connecting to zygiskd");
        return false;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::PingHeartbeat);
    return true;
}

uint32_t GetProcessFlags(uid_t uid) {
    if (!g_shm_init_attempted) {
        g_shm_init_attempted = true;
        UniqueFd shm_fd = UniqueFd(GetSharedMemoryFd());
        if (shm_fd >= 0) {
            void *mapped = mmap(nullptr, sizeof(constants::ShmLayout), PROT_READ, MAP_SHARED,
                                shm_fd, 0);
            if (mapped != MAP_FAILED) {
                g_shm_base = static_cast<constants::ShmLayout *>(mapped);
                LOGV("zygiskd: mapped shared memory cache for ProcessFlags");
            } else {
                PLOGE("mmap shared memory cache");
            }
        }
    }

    if (g_shm_base) {
        uint32_t version_before = g_shm_base->version.load(std::memory_order_acquire);
        if ((version_before & 1U) == 0) {
            const size_t mask = constants::SHM_HASH_MAP_SIZE - 1;
            size_t index = static_cast<size_t>(uid) & mask;
            const size_t start = index;
            bool found = false;
            uint32_t cached_flags = 0;

            do {
                const uint32_t current_uid =
                    g_shm_base->entries[index].uid.load(std::memory_order_relaxed);
                if (current_uid == static_cast<uint32_t>(uid)) {
                    cached_flags =
                        g_shm_base->entries[index].flags.load(std::memory_order_relaxed);
                    found = true;
                    break;
                }
                if (current_uid == UINT32_MAX) {
                    break;
                }
                index = (index + 1) & mask;
            } while (index != start);

            if (found) {
                uint32_t version_after = g_shm_base->version.load(std::memory_order_acquire);
                if (version_before == version_after) {
                    return cached_flags;
                }
            }
        }
    }

    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetProcessFlags");
        return 0;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetProcessFlags);
    socket_utils::write_u32(fd, uid);
    return socket_utils::read_u32(fd);
}

void CacheMountNamespace(pid_t pid) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("CacheMountNamespace");
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::CacheMountNamespace);
    socket_utils::write_u32(fd, (uint32_t) pid);
}

// Returns the file descriptor >= 0 on success, or -1 on failure.
int UpdateMountNamespace(MountNamespace type) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("UpdateMountNamespace");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::UpdateMountNamespace);
    socket_utils::write_u8(fd, (uint8_t) type);

    // Read Status Byte
    uint8_t status = socket_utils::read_u8(fd);
    // Handle Failure Case (Not Cached)
    if (status == 0) {
        // Daemon explicitly told us it doesn't have it.
        return -1;
    }
    // Handle Success Case
    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) {
        PLOGE("UpdateMountNamespace: failed to receive fd");
        return -1;
    }

    return namespace_fd;
}

std::vector<Module> ReadModules() {
    std::vector<Module> modules;
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("ReadModules");
        return modules;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::ReadModules);
    size_t len = socket_utils::read_usize(fd);
    for (size_t i = 0; i < len; i++) {
        std::string name = socket_utils::read_string(fd);
        int module_fd = socket_utils::recv_fd(fd);
        modules.emplace_back(name, module_fd);
    }
    return modules;
}

int ConnectCompanion(size_t index) {
    int fd = Connect(1);
    if (fd == -1) {
        PLOGE("ConnectCompanion");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::RequestCompanionSocket);
    socket_utils::write_usize(fd, index);
    if (socket_utils::read_u8(fd) == 1) {
        return fd;
    } else {
        close(fd);
        return -1;
    }
}

int GetModuleDir(size_t index) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetModuleDir");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetModuleDir);
    socket_utils::write_usize(fd, index);
    return socket_utils::recv_fd(fd);
}

void ZygoteRestart() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        if (errno == ENOENT) {
            LOGD("could not notify ZygoteRestart (maybe it hasn't been created)");
        } else {
            PLOGE("notify ZygoteRestart");
        }
        return;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::ZygoteRestart)) {
        PLOGE("request ZygoteRestart");
    }
}

void SystemServerStarted() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("report system server started");
    } else {
        if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::SystemServerStarted)) {
            PLOGE("report system server started");
        }
    }
}

int GetSharedMemoryFd() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetSharedMemoryFd");
        return -1;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::GetSharedMemoryFd);

    const uint8_t status = socket_utils::read_u8(fd);
    if (status == 0) {
        return -1;
    }

    const int shm_fd = socket_utils::recv_fd(fd);
    if (shm_fd < 0) {
        PLOGE("GetSharedMemoryFd: recv_fd");
        return -1;
    }
    return shm_fd;
}
}  // namespace zygiskd
