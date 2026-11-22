#pragma once

#include <cstdint>

#include "trace.hpp"

void init_monitor();
bool trace_target(int pid, TraceMode mode);

enum Command {
    START = 1,
    STOP = 2,
    EXIT = 3,
    // sent from daemon
    ZYGOTE_INJECTED = 4,
    DAEMON_SET_INFO = 5,
    DAEMON_SET_ERROR_INFO = 6,
    SYSTEM_SERVER_STARTED = 7,
    // Arm against an already-running system: refresh the daemon's module snapshot and
    // live-attach to whichever of zygote and system_server are up but not yet injected.
    // This is the single late-start entry point, whether it arrives from a KernelSU
    // late-load stage script or from a root shell on a build with no root solution.
    REARM = 8
};

enum class RearmResult : uint8_t {
    Injecting = 0,
    AlreadyHooked = 1,
    NoZygote = 2,
    Failed = 3,
};

const char *rearm_result_name(RearmResult result);
bool monitor_is_running();
bool wait_for_monitor();
bool send_control_command(Command cmd, bool quiet = false);
bool send_rearm_command(RearmResult &result, bool quiet = false);
