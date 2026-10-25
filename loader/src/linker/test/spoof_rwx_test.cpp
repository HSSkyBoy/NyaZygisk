// Regression test for the spoof_module_maps() write-permission overreach: the old code,
// after anonymizing the module's own memfd-backed mappings, rescanned the WHOLE
// /proc/self/maps for any "rwxp" line (no path filter) and stripped its write bit —
// which would also clobber an unrelated subsystem's legitimate RWX mapping (ART's JIT
// cache, a GPU shader compiler cache, ...) that happens to exist in the same process.
// The fix scopes the write-bit clear to exactly the ranges already matched by path
// substring. This links the real clean.cpp (plus its two small real dependencies) and
// exercises it directly, rather than re-implementing the logic for the test.
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <cstdio>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#include "zygisk.hpp"

namespace {
int g_failures = 0;
void Check(const char* what, bool ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) g_failures++;
}

int CurrentProt(uintptr_t addr) {
    FILE* fp = fopen("/proc/self/maps", "re");
    if (!fp) return -1;
    char line[512];
    int prot = -1;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long lo = 0, hi = 0;
        char perms[5] = {};
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) != 3) continue;
        if (addr < lo || addr >= hi) continue;
        prot = (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0) |
               (perms[2] == 'x' ? PROT_EXEC : 0);
        break;
    }
    fclose(fp);
    return prot;
}
}  // namespace

int main() {
    const size_t pg = 4096;

    // "Our module": a memfd-backed RWX mapping whose VMA name matches what
    // spoof_module_maps() looks for.
    int memfd = memfd_create("zygisk-module", 0);
    if (memfd < 0 || ftruncate(memfd, pg) != 0) {
        printf("memfd setup failed\n");
        return 2;
    }
    // MAP_PRIVATE, matching how the real loader (android_dlopen_ext, and our own
    // file-backed path) maps a module's segments — spoof_virtual_maps only matches
    // private mappings (private_only=true), same as a MAP_SHARED memfd never would be.
    void* module_map = mmap(nullptr, pg, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, memfd, 0);
    close(memfd);
    if (module_map == MAP_FAILED) {
        printf("module mmap failed\n");
        return 2;
    }

    // "Someone else's subsystem": an unrelated anonymous RWX mapping with a
    // completely different name (stands in for an ART JIT cache, a GPU shader
    // compiler cache, etc.) that must be left alone.
    void* other_map = mmap(nullptr, pg, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (other_map == MAP_FAILED) {
        printf("other mmap failed\n");
        return 2;
    }
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, other_map, pg, "art-jit-fake");

    printf("module_map=%p other_map=%p (before: prot=0x%x / 0x%x)\n", module_map, other_map,
           CurrentProt(reinterpret_cast<uintptr_t>(module_map)),
           CurrentProt(reinterpret_cast<uintptr_t>(other_map)));

    spoof_module_maps(/*clear_write_permission=*/true);

    int module_prot = CurrentProt(reinterpret_cast<uintptr_t>(module_map));
    int other_prot = CurrentProt(reinterpret_cast<uintptr_t>(other_map));
    printf("after: module_prot=0x%x other_prot=0x%x\n", module_prot, other_prot);

    Check("our module's RWX mapping had its write bit cleared",
          module_prot == (PROT_READ | PROT_EXEC));
    Check("the unrelated subsystem's RWX mapping was left untouched",
          other_prot == (PROT_READ | PROT_WRITE | PROT_EXEC));

    printf("\n%s (%d failure(s))\n", g_failures == 0 ? "ALL PASS" : "FAILURES", g_failures);
    return g_failures == 0 ? 0 : 1;
}
