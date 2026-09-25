#pragma once

#include <sys/types.h>
#include <cstddef>

namespace tracer_pid {

/// Returns true if the path points to the status file of the current process or thread.
/// Specifically matches:
///   - "/proc/self/status"
///   - "/proc/thread-self/status"
///   - "/proc/<id>/status" where <id> is getpid() or gettid()
bool is_status_path(const char *path);

/// Tracks an open file descriptor pointing to a status file.
/// Thread-safe, lock-free, fork-safe.
///
/// Known limitations:
/// - dup/dup2: If a tracked FD is duplicated via dup/dup2, the alias descriptor
///   is not tracked.
/// - openat2: Currently openat2(2) syscall is not intercepted.
void track_fd(int fd);

/// Untracks a closed file descriptor.
void untrack_fd(int fd);

/// Returns true if the file descriptor is currently tracked as a status file.
bool is_tracked_fd(int fd);

/// Rewrites any "TracerPid:\t<non-zero>" line in the read buffer to "TracerPid:\t0<spaces>\n".
/// Uses suffix spaces to strictly maintain buffer line length and offset consistency.
///
/// Known limitation:
/// - Assumes the "TracerPid:" line is fully contained within the read buffer (standard
///   in Android where buffers are >= 1KB and TracerPid is in the first ~200 bytes).
void sanitize_tracer_pid(char *buf, size_t nbytes);

}  // namespace tracer_pid
