#include <linux/mman.h>
#include <sys/mman.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>

#include <lsplt.hpp>

#include "atexit.hpp"
#include "fossil.hpp"
#include "logging.hpp"
#include "solist.hpp"
#include "zygisk.hpp"

constexpr const char *kConfigPath = "/data/adb/modules/zygisksu/config.prop";

void clean_libc_trace() {
    auto g_array = Atexit::findAtexitArray();
    if (g_array != nullptr) {
        g_array->recompact();
        LOGV("g_array after recompact: %s", g_array->format_state_string().c_str());
    }
}

void clean_linker_trace(const char *path, size_t loaded_modules, size_t unloaded_modules,
                        bool unload_soinfo) {
    LOGV("cleaning linker trace for path %s", path);
    Linker::dropSoPath(path, unload_soinfo);

    if (unload_soinfo) {
        Linker::resetCounters(loaded_modules, loaded_modules);
    } else {
        Linker::resetCounters(loaded_modules, unloaded_modules);
    }
}

bool is_anonymous_memory_enabled() {
    FILE *fp = fopen(kConfigPath, "r");
    if (fp == nullptr) return false;

    char line[128];
    bool enabled = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        char *end = line + strlen(line);
        while (end > line && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' ||
                              end[-1] == '\t')) {
            *--end = '\0';
        }
        if (strcmp(line, "anonymous_memory=1") == 0) {
            enabled = true;
            break;
        }
    }
    fclose(fp);
    return enabled;
}

static void spoof_virtual_maps(std::span<const char *const> paths, bool clear_write_permission) {
    // spoofing map path names is futile in Android, we do it simply
    // to avoid trivial Zygisk detections based on string comparison.
    for (auto &map : lsplt::MapInfo::Scan()) {
        void *addr = (void *) map.start;
        size_t size = map.end - map.start;

        bool should_spoof = false;
        for (const char *path : paths) {
            if (strstr(map.path.c_str(), path)) {
                should_spoof = true;
                break;
            }
        }

        if (should_spoof) {
            LOGV("spoofing entry path contaning string %s", map.path.c_str());
            void *copy = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (copy == MAP_FAILED) {
                LOGE("failed to backup block %s [%p, %p]", map.path.c_str(), addr,
                     (void *) map.end);
                continue;
            }

            if ((map.perms & PROT_READ) == 0) {
                if (mprotect(addr, size, map.perms | PROT_READ) == -1) {
                    PLOGE("make entry readable before spoofing %s [%p, %p]", map.path.c_str(), addr,
                          (void *) map.end);
                    munmap(copy, size);
                    continue;
                }
            }

            memcpy(copy, addr, size);

            // Move the replacement with its final permissions already applied. This avoids a
            // window where executable mappings would temporarily become write-only.
            if (mprotect(copy, size, map.perms) == -1) {
                PLOGE("set replacement permissions before spoofing %s [%p, %p]",
                      map.path.c_str(), addr, (void *) map.end);
                munmap(copy, size);
                if ((map.perms & PROT_READ) == 0 && mprotect(addr, size, map.perms) == -1) {
                    PLOGE("restore permissions after failed spoof preparation %s [%p, %p]",
                          map.path.c_str(), addr, (void *) map.end);
                }
                continue;
            }

            if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr) != MAP_FAILED) {
                LOGV("spoofed entry with anonymous memory %s [%p, %p]", map.path.c_str(), addr,
                     (void *) map.end);
            } else {
                LOGE("mremap failed for %s [%p, %p]", map.path.c_str(), addr, (void *) map.end);
                munmap(copy, size);
                if ((map.perms & PROT_READ) == 0 && mprotect(addr, size, map.perms) == -1) {
                    PLOGE("restore permissions after failed spoofing %s [%p, %p]",
                          map.path.c_str(), addr, (void *) map.end);
                }
            }
        }

        if (clear_write_permission && map.path.size() > 0 &&
            (map.perms & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
                (PROT_READ | PROT_WRITE | PROT_EXEC)) {
            LOGV("clearing write permission for entry %s", map.path.c_str());
            int new_perms = map.perms & ~PROT_WRITE;  // Remove the write permission
            if (mprotect(addr, size, new_perms) == -1) {
                PLOGE("remove write permission from %s [%p, %p]", map.path.c_str(), addr,
                      (void *) map.end);
            } else {
                LOGV("write permission removed from %s [%p, %p]", map.path.c_str(), addr,
                     (void *) map.end);
            }
        }
    }
}

void spoof_virtual_maps(const char *path, bool clear_write_permission) {
    std::array paths{path};
    spoof_virtual_maps(std::span<const char *const>(paths.data(), paths.size()),
                       clear_write_permission);
}

void spoof_module_maps(bool clear_write_permission) {
    constexpr std::array paths{"jit-cache-zygisk", "zygisk-module"};
    spoof_virtual_maps(std::span<const char *const>(paths.data(), paths.size()),
                       clear_write_permission);
}

void spoof_zygote_fossil(char *search_from, char *search_to, const char *anchor) {
    Fossil::MountArgv suspicious_fossil = Fossil::MountArgv::find(search_from, search_to);
    if (!suspicious_fossil.isValid()) {
        LOGV("no valid fossil found on the stack");
        return;
    }
    suspicious_fossil.dump("current fossil");

    if (suspicious_fossil.getTarget().find(anchor) != std::string::npos) {
        LOGV("stack fossil appears to be the legitimate 'ref_profiles' entry");
        return;
    }

    auto mount_entries = Fossil::parseMountInfo();
    std::optional<Fossil::MountInfoEntry> clean_template_opt;
    for (size_t i = 1; i < mount_entries.size(); ++i) {
        if (mount_entries[i - 1].target.find(anchor) != std::string::npos &&
            mount_entries[i].is_suspicious) {
            clean_template_opt = mount_entries[i - 1];
            break;
        }
    }
    if (!clean_template_opt) {
        LOGV("no suspicious mount was found in mountinfo to identify a template");
        return;
    }
    const Fossil::MountInfoEntry &clean_entry = *clean_template_opt;
    LOGV("using preceding entry as the clean spoof template: '%s'", clean_entry.target.c_str());

    Fossil::MountArgv clean_fossil_to_write(clean_entry, suspicious_fossil.getStartAddress(),
                                            suspicious_fossil.getBaseFlags());
    clean_fossil_to_write.dump("spoofed fossil");

    suspicious_fossil.cleanMemory();
    clean_fossil_to_write.writeToMemory();
}
