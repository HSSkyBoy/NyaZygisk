#include "fossil.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "logging.hpp"

namespace Fossil {

MountArgv::MountArgv(const char* start, const char* search_limit) {
    parseFromMemory(start, search_limit);
}

MountArgv::MountArgv(const MountInfoEntry& clean_entry, const char* target_address,
                     uint32_t base_flags) {
    m_start_address = target_address;

    m_source = clean_entry.source;
    m_target = clean_entry.target;
    m_filesystem_type = clean_entry.filesystem_type;
    m_mount_options = clean_entry.mount_options;
    m_base_flags = base_flags;

    m_fossil_size = (m_source.length() + 1) + (m_target.length() + 1) +
                    (m_filesystem_type.length() + 1) + (m_mount_options.length() + 1) +
                    sizeof(uint32_t);

    m_remnant_size = 0;
    m_valid = true;
}

MountArgv MountArgv::find(char* search_from, char* search_to) {
    for (char* p = search_from; p < search_to; ++p) {
        MountArgv mount_argv(p, search_to);
        if (mount_argv.isValid() && mount_argv.passesHeuristics()) {
            LOGV("found a high-confidence fossil at address %p", static_cast<void*>(p));
            return mount_argv;
        }
    }
    return MountArgv(nullptr, nullptr);
}

void MountArgv::writeToMemory() const {
    if (!isValid()) {
        LOGV("cannot write an invalid fossil to memory.");
        return;
    }

    LOGV("writing fossil data to %p...", static_cast<const void*>(m_start_address));
    char* ptr = const_cast<char*>(m_start_address);

    memcpy(ptr, m_source.c_str(), m_source.length() + 1);
    ptr += m_source.length() + 1;
    memcpy(ptr, m_target.c_str(), m_target.length() + 1);
    ptr += m_target.length() + 1;
    memcpy(ptr, m_filesystem_type.c_str(), m_filesystem_type.length() + 1);
    ptr += m_filesystem_type.length() + 1;
    memcpy(ptr, m_mount_options.c_str(), m_mount_options.length() + 1);
    ptr += m_mount_options.length() + 1;
    uint32_t flags = getBaseFlags();
    memcpy(ptr, &flags, sizeof(uint32_t));
}

void MountArgv::cleanMemory() const {
    if (!isValid()) {
        LOGV("cannot clean remnants of an invalid fossil.");
        return;
    }
    auto total_size = m_fossil_size + m_remnant_size;
    if (total_size > 0) {
        char* start_ptr = const_cast<char*>(m_start_address);
        LOGV("cleaning %zu bytes at address %p...", total_size,
             static_cast<const void*>(start_ptr));
        memset(start_ptr, 0, total_size);
        LOGV("memory cleaning complete.");
    }
}

// --- Accessors ---
bool MountArgv::isValid() const { return m_valid; }
const std::string& MountArgv::getSource() const { return m_source; }
const std::string& MountArgv::getTarget() const { return m_target; }
const std::string& MountArgv::getFilesystemType() const { return m_filesystem_type; }
const std::string& MountArgv::getMountOptions() const { return m_mount_options; }
uint32_t MountArgv::getBaseFlags() const { return m_base_flags; }
size_t MountArgv::getRemnantSize() const { return m_remnant_size; }
size_t MountArgv::getFossilSize() const { return m_fossil_size; }
const char* MountArgv::getStartAddress() const { return m_start_address; }

void MountArgv::dump(const char* summary) const {
    if (!m_valid) {
        LOGD("MountArgvFossil is not valid.");
        return;
    }

    std::string text(m_source.size() + m_target.size() + m_filesystem_type.size() +
                         m_mount_options.size() + 512,
                     '\0');
    int len = snprintf(text.data(), text.size(),
                       "--- Parsed Mount Argument Vector Fossil ---\n"
                       "\tStart Address:\t%p\n"
                       "\tFossil Size:\t%zu bytes\n"
                       "\tSource:\t\t\t'%s'\n"
                       "\tTarget:\t\t\t'%s'\n"
                       "\tFS Type:\t\t'%s'\n"
                       "\tOptions:\t\t'%s'\n"
                       "\tBase Flags:\t\t%#x\n"
                       "\tRemnant Size:\t%zu bytes (until '\\0\\0')\n"
                       "-------------------------------------------",
                       static_cast<const void*>(m_start_address), m_fossil_size, m_source.c_str(),
                       m_target.c_str(), m_filesystem_type.c_str(), m_mount_options.c_str(),
                       m_base_flags, m_remnant_size);
    text.resize(len > 0 ? std::min<size_t>(len, text.size() - 1) : 0);

    // Issue a single, atomic log call with the fully formatted string.
    LOGV("%s\n%s", summary, text.c_str());
}

// --- Private Implementation ---

void MountArgv::parseFromMemory(const char* start, const char* search_limit) {
    if (!start || !search_limit || start >= search_limit) return;

    m_start_address = start;
    const char* ptr = start;

    if (!parse_and_copy_string_field(m_source, ptr, search_limit)) return;
    if (!parse_and_copy_string_field(m_target, ptr, search_limit)) return;
    if (!parse_and_copy_string_field(m_filesystem_type, ptr, search_limit)) return;
    if (!parse_and_copy_string_field(m_mount_options, ptr, search_limit)) return;

    if (ptr + sizeof(uint32_t) > search_limit) return;
    memcpy(&m_base_flags, ptr, sizeof(uint32_t));
    const char* end_of_fossil = ptr + sizeof(uint32_t);

    const char* remnants_start = end_of_fossil;
    const char* remnants_end = find_double_null(remnants_start, search_limit);

    m_remnant_size = remnants_end ? (remnants_end - remnants_start) : 0;
    m_fossil_size = end_of_fossil - start;
    m_valid = true;
}

bool MountArgv::parse_and_copy_string_field(std::string& out_str, const char*& ptr,
                                            const char* limit) {
    size_t len = strnlen(ptr, limit - ptr);
    if (len == (size_t) (limit - ptr)) return false;

    out_str = std::string(ptr, len);

    ptr += len + 1;
    return (ptr <= limit);
}

const char* MountArgv::find_double_null(const char* start, const char* limit) const {
    const char* p = start;
    while (p + 1 < limit) {
        if (*p == '\0' && *(p + 1) == '\0') return p;
        p++;
    }
    return nullptr;
}

bool MountArgv::passesHeuristics() const {
    if (!m_valid) return false;
    if (getTarget().empty() || getSource().empty() || getFilesystemType().empty()) return false;
    if (getTarget()[0] != '/') return false;
    size_t type_len = getFilesystemType().length();
    if (type_len > 10 || type_len < 2) return false;
    if (getMountOptions().find("seclabel") == std::string::npos) return false;
    return true;
}

// --- Standalone Function Implementations ---

static void trim_leading(std::string& s) {
    s.erase(s.begin(),
            std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
}

// Pops the next whitespace-delimited token off the front of `s`.
static std::string_view next_token(std::string_view& s) {
    size_t begin = 0;
    while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin]))) begin++;
    size_t end = begin;
    while (end < s.size() && !std::isspace(static_cast<unsigned char>(s[end]))) end++;
    std::string_view token = s.substr(begin, end - begin);
    s.remove_prefix(end);
    return token;
}

static MountInfoEntry parseMountInfoLine(const std::string& line) {
    MountInfoEntry entry;

    // The separator " - " divides the line into two main parts.
    size_t separator_pos = line.find(" - ");
    if (separator_pos == std::string::npos) {
        return entry;  // Malformed line
    }

    // Part 1: Before the separator. Contains the target mount point.
    std::string_view before(line.data(), separator_pos);

    // The mountinfo format has fixed fields before the target.
    // We must read and discard the first four fields to isolate the fifth.
    next_token(before);  // Field 1: mount-id
    next_token(before);  // Field 2: parent-id
    next_token(before);  // Field 3: major:minor
    next_token(before);  // Field 4: root

    // The fifth field is the target mount point.
    entry.target = std::string(next_token(before));

    // Part 2: After the separator. Contains fs-type, source, and superblock options.
    std::string_view after(line.data() + separator_pos + 3, line.size() - separator_pos - 3);

    // The first token is the filesystem type, the second is the source device.
    entry.filesystem_type = std::string(next_token(after));
    entry.source = std::string(next_token(after));

    // Everything that remains on the line is the superblock options.
    entry.mount_options = std::string(after);
    trim_leading(entry.mount_options);  // Remove any leading space left after the source.

    return entry;
}

std::vector<MountInfoEntry> parseMountInfo() {
    std::vector<MountInfoEntry> entries;
    FILE* mountinfo_file = fopen("/proc/self/mountinfo", "re");
    if (mountinfo_file == nullptr) {
        LOGE("failed to open /proc/self/mountinfo");
        return entries;
    }

    const std::vector<std::string> keywords = {"KSU",       "/debug_ramdisk", "APATCH",
                                               "/data/adb", "/adb/modules",   "/dev/block/loop"};

    std::string line;
    char* raw_line = nullptr;
    size_t raw_cap = 0;
    ssize_t raw_len;
    while ((raw_len = getline(&raw_line, &raw_cap, mountinfo_file)) != -1) {
        if (raw_len > 0 && raw_line[raw_len - 1] == '\n') raw_len--;
        line.assign(raw_line, raw_len);
        MountInfoEntry entry = parseMountInfoLine(line);

        for (const auto& keyword : keywords) {
            if (line.find(keyword) != std::string::npos) {
                entry.is_suspicious = true;
                break;
            }
        }

        entries.push_back(entry);
    }
    free(raw_line);
    fclose(mountinfo_file);
    return entries;
}
}  // namespace Fossil
