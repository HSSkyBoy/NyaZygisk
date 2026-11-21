#include "socket_utils.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>

#include "logging.hpp"

namespace socket_utils {

ssize_t xread(int fd, void* buf, size_t count) {
    size_t read_sz = 0;
    ssize_t ret;
    do {
        ret = read(fd, (std::byte*) buf + read_sz, count - read_sz);
        if (ret < 0) {
            if (errno == EINTR) continue;
            PLOGE("read");
            return ret;
        }
        read_sz += ret;
    } while (read_sz != count && ret != 0);
    if (read_sz != count) {
        PLOGE("read (%zu != %zu)", count, read_sz);
    }
    return read_sz;
}

size_t xwrite(int fd, const void* buf, size_t count) {
    size_t write_sz = 0;
    ssize_t ret;
    bool use_write = false;
    do {
        if (!use_write) {
            ret = send(fd, (const std::byte*) buf + write_sz, count - write_sz, MSG_NOSIGNAL);
            if (ret < 0 && errno == ENOTSOCK) {
                use_write = true;
                continue;
            }
        } else {
            ret = write(fd, (const std::byte*) buf + write_sz, count - write_sz);
        }
        if (ret < 0) {
            if (errno == EINTR) continue;
            PLOGE("write");
            return write_sz;
        }
        write_sz += ret;
    } while (write_sz != count && ret != 0);
    if (write_sz != count) {
        PLOGE("write (%zu != %zu)", count, write_sz);
    }
    return write_sz;
}

ssize_t xrecvmsg(int sockfd, struct msghdr* msg, int flags) {
    ssize_t rec;
    do {
        rec = recvmsg(sockfd, msg, flags | MSG_CMSG_CLOEXEC);
    } while (rec < 0 && errno == EINTR);
    if (rec < 0) PLOGE("recvmsg");
    return rec;
}

static void close_attached_fds(struct msghdr* msg) {
    for (cmsghdr* cmsg = CMSG_FIRSTHDR(msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            const auto* raw = reinterpret_cast<const unsigned char*>(CMSG_DATA(cmsg));
            for (size_t i = 0; i < nfds; ++i) {
                int fd = -1;
                memcpy(&fd, raw + i * sizeof(int), sizeof(int));
                if (fd >= 0) close(fd);
            }
        }
    }
}

void* recv_fds(int sockfd, char* cmsgbuf, size_t bufsz, int cnt) {
    // Create a throwaway buffer.
    // It must match the size Rust sends (sizeof(int) = 4 bytes).
    int dummy_data = 0;
    memset(cmsgbuf, 0, bufsz);

    iovec iov = {
        .iov_base = &dummy_data,
        .iov_len = sizeof(dummy_data),
    };
    msghdr msg = {.msg_name = nullptr,
                  .msg_namelen = 0,
                  .msg_iov = &iov,
                  .msg_iovlen = 1,
                  .msg_control = cmsgbuf,
                  .msg_controllen = bufsz,
                  .msg_flags = 0};

    ssize_t rec = xrecvmsg(sockfd, &msg, MSG_WAITALL);

    // --- IO Failed or Stream Desync ---
    if (rec != static_cast<ssize_t>(sizeof(dummy_data))) {
        PLOGE("recv_fds: IO failure. Read %zd bytes, expected %zu", rec, sizeof(dummy_data));
        if (rec > 0) close_attached_fds(&msg);
        return nullptr;
    }

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);

    // --- No headers received ---
    if (cmsg == nullptr) {
        // MSG_CTRUNC tells the two cases apart: the peer attached descriptors and the
        // kernel refused to install them, typically an SELinux denial on the file being
        // passed, versus the peer having attached none at all.
        LOGE("recv_fds: No control headers received. msg_controllen=%zu, %s",
             (size_t) msg.msg_controllen,
             (msg.msg_flags & MSG_CTRUNC) ? "the kernel dropped the descriptors"
                                          : "the peer attached none");
        return nullptr;
    }

    if (msg.msg_flags & MSG_CTRUNC) {
        LOGE("recv_fds: control message truncated (MSG_CTRUNC)");
        close_attached_fds(&msg);
        return nullptr;
    }

    size_t expected_cmsg_len = CMSG_LEN(sizeof(int) * cnt);
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len != expected_cmsg_len) {
        LOGE("recv_fds: Invalid CMSG header (level=%d, type=%d, len=%zu, exp_len=%zu)",
             cmsg->cmsg_level, cmsg->cmsg_type, (size_t) cmsg->cmsg_len, expected_cmsg_len);
        close_attached_fds(&msg);
        return nullptr;
    }

    return CMSG_DATA(cmsg);
}

template <typename T>
inline T read_exact_or(int fd, T fail) {
    T res;
    return sizeof(T) == xread(fd, &res, sizeof(T)) ? res : fail;
}

template <typename T>
inline bool write_exact(int fd, T val) {
    return sizeof(T) == xwrite(fd, &val, sizeof(T));
}

uint8_t read_u8(int fd) { return read_exact_or<uint8_t>(fd, 0); }

uint32_t read_u32(int fd) { return read_exact_or<uint32_t>(fd, 0); }

size_t read_usize(int fd) { return read_exact_or<size_t>(fd, 0); }

bool write_usize(int fd, size_t val) { return write_exact<size_t>(fd, val); }

constexpr size_t kMaxIpcStringLen = 1024 * 1024;

std::string read_string(int fd) {
    auto len = read_usize(fd);
    if (len == 0) return {};
    if (len > kMaxIpcStringLen) {
        LOGE("read_string: length %zu exceeds max %zu", len, kMaxIpcStringLen);
        return {};
    }
    std::string str(len, '\0');
    if (xread(fd, str.data(), len) != static_cast<ssize_t>(len)) {
        return {};
    }
    return str;
}

bool write_u8(int fd, uint8_t val) { return write_exact<uint8_t>(fd, val); }

bool write_u32(int fd, uint32_t val) { return write_exact<uint32_t>(fd, val); }

bool write_string(int fd, std::string_view str) {
    return write_usize(fd, str.size()) && str.size() == xwrite(fd, str.data(), str.size());
}

int recv_fd(int sockfd) {
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = {};

    void* data = recv_fds(sockfd, cmsgbuf, sizeof(cmsgbuf), 1);
    if (data == nullptr) return -1;

    int result = -1;
    memcpy(&result, data, sizeof(int));
    return result;
}

bool send_fd(int sockfd, int fd) {
    if (fd < 0) {
        errno = EBADF;
        return false;
    }

    uint8_t dummy = 1;
    struct iovec iov = {
        .iov_base = &dummy,
        .iov_len = sizeof(dummy),
    };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control = {};
    struct msghdr msg = {
        .msg_name = nullptr,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.buf,
        .msg_controllen = sizeof(control.buf),
        .msg_flags = 0,
    };
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    msg.msg_controllen = cmsg->cmsg_len;

    ssize_t ret;
    do {
        ret = sendmsg(sockfd, &msg, MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    if (ret != static_cast<ssize_t>(sizeof(dummy))) {
        if (ret >= 0) errno = EIO;
        return false;
    }
    return true;
}
}  // namespace socket_utils
