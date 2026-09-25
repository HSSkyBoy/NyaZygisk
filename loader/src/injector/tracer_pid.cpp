#include "tracer_pid.hpp"

#include <unistd.h>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "logging.hpp"

namespace tracer_pid {

namespace {

// Lock-free, fixed-capacity FD tracking pool.
// Avoids mutexes to ensure 100% fork-safety (preventing fork-with-lock-held deadlocks).
constexpr size_t kMaxTrackedFds = 16;
std::atomic<int> g_tracked_fds[kMaxTrackedFds] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1
};

}  // namespace

bool is_status_path(const char *path) {
    if (path == nullptr) return false;

    // Fast prefix check
    constexpr std::string_view kProcPrefix = "/proc/";
    if (std::strncmp(path, kProcPrefix.data(), kProcPrefix.size()) != 0) {
        return false;
    }

    const char *sub = path + kProcPrefix.size();

    // Check /proc/self/status and /proc/thread-self/status
    if (std::strcmp(sub, "self/status") == 0 || std::strcmp(sub, "thread-self/status") == 0) {
        return true;
    }

    // Check /proc/<id>/status where <id> is getpid() or gettid()
    if (isdigit(static_cast<unsigned char>(*sub))) {
        char *endptr = nullptr;
        errno = 0;
        long target_id = std::strtol(sub, &endptr, 10);
        if (errno == 0 && endptr != sub && std::strcmp(endptr, "/status") == 0) {
            pid_t pid = getpid();
            pid_t tid = gettid();
            if (target_id == pid || target_id == tid) {
                return true;
            }
        }
    }

    return false;
}

void track_fd(int fd) {
    if (fd < 0) return;
    for (auto &slot : g_tracked_fds) {
        int expected = -1;
        if (slot.compare_exchange_strong(expected, fd, std::memory_order_relaxed)) {
            LOGV("Tracking status FD %d", fd);
            return;
        }
    }
}

void untrack_fd(int fd) {
    if (fd < 0) return;
    for (auto &slot : g_tracked_fds) {
        int expected = fd;
        if (slot.compare_exchange_strong(expected, -1, std::memory_order_relaxed)) {
            LOGV("Untracking status FD %d", fd);
            return;
        }
    }
}

bool is_tracked_fd(int fd) {
    if (fd < 0) return false;
    for (const auto &slot : g_tracked_fds) {
        if (slot.load(std::memory_order_relaxed) == fd) {
            return true;
        }
    }
    return false;
}

void sanitize_tracer_pid(char *buf, size_t nbytes) {
    static constexpr std::string_view kKey = "TracerPid:";
    if (buf == nullptr || nbytes < kKey.size()) return;

    for (size_t i = 0; i + kKey.size() <= nbytes; ++i) {
        // Must be at line start (start of buffer or after '\n')
        if (i > 0 && buf[i - 1] != '\n') continue;

        if (std::memcmp(buf + i, kKey.data(), kKey.size()) != 0) continue;

        size_t pos = i + kKey.size();
        // Standard kernel procfs output uses tab "\t"
        if (pos >= nbytes || (buf[pos] != '\t' && buf[pos] != ' ')) continue;

        // Skip whitespace delimiter
        while (pos < nbytes && (buf[pos] == '\t' || buf[pos] == ' ')) {
            pos++;
        }

        if (pos >= nbytes || !isdigit(static_cast<unsigned char>(buf[pos]))) continue;

        size_t num_start = pos;
        while (pos < nbytes && isdigit(static_cast<unsigned char>(buf[pos]))) {
            pos++;
        }
        size_t num_len = pos - num_start;

        // Verify the character immediately after the number is valid line end or whitespace
        if (pos < nbytes && buf[pos] != '\n' && buf[pos] != '\r' && buf[pos] != ' ' && buf[pos] != '\t') {
            continue;  // Malformed field, do not alter
        }

        // If already single '0', no modification needed
        if (num_len == 1 && buf[num_start] == '0') {
            return;
        }

        // Format: '0' followed by (num_len - 1) suffix spaces.
        // e.g. "12345" (len 5) -> "0    "
        // This ensures downstream parsers seeking the first non-whitespace char see '0',
        // while perfectly maintaining total line length and subsequent line offsets.
        buf[num_start] = '0';
        for (size_t k = 1; k < num_len; ++k) {
            buf[num_start + k] = ' ';
        }

        LOGV("Sanitized TracerPid: replaced %zu digits with '0' + %zu suffix spaces",
             num_len, num_len - 1);
        return;
    }
}

}  // namespace tracer_pid
