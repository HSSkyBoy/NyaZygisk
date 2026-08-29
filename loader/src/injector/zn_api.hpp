#pragma once

#include "zygisk_next_api.h"
#include <string>

namespace zn {

struct ZnModuleHandle {
    std::string lib_path;
    int companion_fd = -1;
    pid_t companion_pid = -1;
};

const ZygiskNextAPI* getApiForVersion(int target_api_version);
[[noreturn]] void companionMain(const char* lib_path, int ctl_fd);

}  // namespace zn
