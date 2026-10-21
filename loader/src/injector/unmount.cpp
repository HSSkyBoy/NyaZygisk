#include <sys/sysmacros.h>  // For makedev
#include <sys/types.h>

#include <algorithm>  // For std::sort
#include <cerrno>     // For errno
#include <cstring>    // For strerror
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "logging.hpp"
#include "module.hpp"
#include "zygisk.hpp"

// Extremely fast inline string-to-int parser (avoids sscanf overhead)
static inline int fast_atoi(const char* str) {
    int val = 0;
    while (*str >= '0' && *str <= '9') {
        val = val * 10 + (*str++ - '0');
    }
    return val;
}

// Fast parser for major:minor device format
static inline bool parse_device(const char* str, unsigned int& maj, unsigned int& min) {
    maj = 0;
    min = 0;
    
    // Parse major
    while (*str >= '0' && *str <= '9') {
        maj = maj * 10 + (*str++ - '0');
    }
    if (*str != ':') return false;
    str++;
    
    // Parse minor
    while (*str >= '0' && *str <= '9') {
        min = min * 10 + (*str++ - '0');
    }
    return true;
}

// Use string_view for more efficient prefix checking
static bool starts_with(std::string_view str, std::string_view prefix) {
    return str.length() >= prefix.length() && str.compare(0, prefix.length(), prefix) == 0;
}

// Helper to extract the next token separated by a space
static std::string_view get_next_token(std::string_view& str) {
    size_t pos = str.find(' ');
    std::string_view token = str.substr(0, pos);
    if (pos != std::string_view::npos) {
        // Skip consecutive spaces
        size_t next_start = str.find_first_not_of(' ', pos);
        str = (next_start != std::string_view::npos) ? str.substr(next_start) : "";
    } else {
        str = "";
    }
    return token;
}

std::vector<mount_info> parse_mount_info(const char* pid) {
    std::string path = "/proc/";
    path += pid;
    path += "/mountinfo";

    // fopen/getline instead of std::ifstream: iostreams pull libc++'s locale into the binary.
    FILE* file = fopen(path.c_str(), "re");
    if (file == nullptr) {
        PLOGE("open %s", path.c_str());
        return {};
    }

    std::vector<mount_info> result;
    std::string line;
    
    // Pre-allocate some memory to avoid frequent reallocations
    // 150 is a reasonable estimate for the number of mounts on an Android system
    result.reserve(150); 

    char* raw_line = nullptr;
    size_t raw_cap = 0;
    ssize_t raw_len;
    while ((raw_len = getline(&raw_line, &raw_cap, file)) != -1) {
        if (raw_len > 0 && raw_line[raw_len - 1] == '\n') raw_len--;
        line.assign(raw_line, raw_len);
        size_t separator_pos = line.find(" - ");
        if (separator_pos == std::string::npos) {
            LOGE("malformed line (no ' - ' separator): %s", line.c_str());
            continue;
        }

        mount_info info = {};
        info.raw_info = line;

        std::string_view part1(line.c_str(), separator_pos);
        std::string_view part2(line.c_str() + separator_pos + 3);

        // 1. Parse the first part
        std::string_view id_sv = get_next_token(part1);
        std::string_view parent_sv = get_next_token(part1);
        std::string_view device_sv = get_next_token(part1);
        info.root = get_next_token(part1);
        info.target = get_next_token(part1);
        info.vfs_options = part1; // Remaining string is vfs_options

        // Parse integers using fast_atoi (avoids sscanf overhead)
        info.id = fast_atoi(id_sv.data());
        info.parent = fast_atoi(parent_sv.data());

        // Parse the "major:minor" string using fast parser
        unsigned int maj = 0, min = 0;
        if (!parse_device(device_sv.data(), maj, min)) {
            LOGE("malformed line (invalid device format): %s", line.c_str());
            continue;
        }
        info.device = makedev(maj, min);

        // 4. Parse the second part of the line.
        info.type = get_next_token(part2);
        info.source = get_next_token(part2);
        info.fs_options = part2; // Remaining string is fs_options

        result.push_back(std::move(info));
    }
    free(raw_line);
    fclose(file);
    return result;
}

std::vector<mount_info> check_zygote_traces(uint32_t info_flags, size_t round) {
    std::vector<mount_info> traces;

    auto mount_infos = parse_mount_info("self");
    if (mount_infos.empty()) {
        LOGV("mount info is empty or could not be parsed.");
        return traces;
    }

    std::string_view mount_source_name;
    bool is_kernelsu = false;

    if (info_flags & PROCESS_ROOT_IS_APATCH) {
        mount_source_name = "APatch";
    } else if (info_flags & PROCESS_ROOT_IS_KSU) {
        mount_source_name = "KSU";
        is_kernelsu = true;
    } else if (info_flags & PROCESS_ROOT_IS_MAGISK) {
        mount_source_name = "magisk";
    } else {
        LOGE("could not determine root implementation, aborting unmount.");
        return traces;
    }

    std::string_view kernel_su_module_source;
    if (is_kernelsu) {
        for (const auto& info : mount_infos) {
            if (info.target == "/data/adb/modules" && starts_with(info.source, "/dev/block/loop")) {
                kernel_su_module_source = info.source;
                LOGV("detected KernelSU loop device module source: %s", info.source.c_str());
                break;
            }
        }
    }

    for (const auto& info : mount_infos) {
        const bool should_unmount =
            starts_with(info.root, "/adb/modules") ||
            starts_with(info.target, "/data/adb/modules") || 
            (info.source == mount_source_name) ||
            (!kernel_su_module_source.empty() && info.source == kernel_su_module_source);

        if (should_unmount) {
            traces.push_back(info);
        }
    }

    if (traces.empty()) {
        LOGV("no relevant mount points found to unmount.");
        return traces;
    }

    // Sort the collected traces by mount ID in descending order for safe unmounting
    std::sort(traces.begin(), traces.end(),
              [](const mount_info& a, const mount_info& b) { return a.id > b.id; });

    LOGV("found %zu mounting traces in zygote [round: %zu].", traces.size(), round);

    return traces;
}
