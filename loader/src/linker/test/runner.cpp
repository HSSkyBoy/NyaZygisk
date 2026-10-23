// Host-side (chroot) harness that loads test_lib.so with the custom linker and
// checks each exported behaviour against the expected result. Also loads it via
// the system linker as a sanity baseline. Exits non-zero on any mismatch.
//
// Build + run via run.sh; not part of the shipped module.
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "cfi.hpp"
#include "linker.hpp"

#ifdef SEGV_DIAG
static void SegvHandler(int, siginfo_t* si, void* uc) {
    auto* ctx = static_cast<ucontext_t*>(uc);
#if defined(__x86_64__)
    void* pc = reinterpret_cast<void*>(ctx->uc_mcontext.gregs[REG_RIP]);
#elif defined(__aarch64__)
    void* pc = reinterpret_cast<void*>(ctx->uc_mcontext.pc);
#else
    void* pc = nullptr;
#endif
    Dl_info info;
    memset(&info, 0, sizeof(info));
    const char* fn = dladdr(pc, &info) ? info.dli_fname : "?";
    fprintf(stderr, "SEGV pc=%p fault=%p sys_in=%s sys_base=%p\n", pc, si->si_addr, fn,
            info.dli_fbase);
    if (linker::Image* img = linker::FindImageByAddress(pc)) {
        fprintf(stderr, "  pc in custom %s base=%p off=%#lx\n", img->name().c_str(),
                reinterpret_cast<void*>(img->base()),
                (unsigned long) ((uintptr_t) pc - img->base()));
    }
    if (linker::Image* img = linker::FindImageByAddress(si->si_addr)) {
        fprintf(stderr, "  fault in custom %s base=%p off=%#lx\n", img->name().c_str(),
                reinterpret_cast<void*>(img->base()),
                (unsigned long) ((uintptr_t) si->si_addr - img->base()));
    }
    // Which mapping holds the faulting address?
    FILE* m = fopen("/proc/self/maps", "r");
    if (m) {
        char line[512];
        auto want = reinterpret_cast<uintptr_t>(si->si_addr);
        while (fgets(line, sizeof(line), m)) {
            uintptr_t lo, hi;
            if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && want >= lo && want < hi) {
                fprintf(stderr, "  maps: %s", line);
                break;
            }
        }
        fclose(m);
    }
    _exit(139);
}
static void InstallSegvHandler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = SegvHandler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
}
#endif

namespace {

int g_failures = 0;

// Records the ids reported by the module's static-object destructors, so the
// runner can confirm they actually ran (and in reverse order) on Dlclose.
int g_dtor_seq[8];
int g_dtor_n = 0;
void DtorSink(int id) {
    if (g_dtor_n < 8) g_dtor_seq[g_dtor_n++] = id;
}

void Check(const char* what, bool ok, const char* detail = "") {
    printf("  [%s] %s %s\n", ok ? "PASS" : "FAIL", what, detail);
    if (!ok) g_failures++;
}

template <typename T>
T Sym(void* h, const char* name, bool custom) {
    return reinterpret_cast<T>(custom ? linker::Dlsym(h, name) : dlsym(h, name));
}

// Return the pathname column of the /proc/self/maps line covering `addr`,
// or "" if that VMA is anonymous (nameless). Used to prove the hiding path.
static std::string MapsPathAt(uintptr_t addr) {
    FILE* m = fopen("/proc/self/maps", "re");
    if (!m) return "";
    char line[512];
    std::string path;
    while (fgets(line, sizeof(line), m)) {
        unsigned long lo = 0, hi = 0;
        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2) continue;
        if (addr < lo || addr >= hi) continue;
        // pathname is the 6th field; a '/' or '[' marks a named mapping.
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        const char* p = line;
        int fields = 0;
        while (*p && fields < 5) {
            while (*p == ' ') p++;
            while (*p && *p != ' ') p++;
            fields++;
        }
        while (*p == ' ') p++;
        path = p;
        break;
    }
    fclose(m);
    return path;
}

int ExerciseCustom(const char* path, bool anonymous) {
    printf("== custom linker (%s): %s\n", anonymous ? "anonymous" : "file-backed", path);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("  cannot open %s\n", path);
        return 1;
    }
    linker::LoadError err = linker::LoadError::kNone;
    void* h = linker::Dlopen(fd, "test_lib.so", anonymous, &err);
    close(fd);
    if (h == nullptr) {
        printf("  Dlopen failed (err=%d)\n", static_cast<int>(err));
        return 1;
    }

    auto get42 = Sym<int (*)()>(h, "tl_get42", true);
    Check("tl_get42==42", get42 && get42() == 42);

    auto sum = Sym<int (*)()>(h, "tl_table_sum", true);
    Check("tl_table_sum==36 (relative relocs)", sum && sum() == 36);

    auto slen = Sym<int (*)(const char*)>(h, "tl_strlen_of", true);
    Check("tl_strlen_of (NEEDED libc)", slen && slen("hello") == 5);

    auto order = Sym<const char* (*)()>(h, "tl_ctor_order", true);
    Check("constructors ran in order", order && strcmp(order(), "12") == 0,
          order ? order() : "");

    auto thr = Sym<int (*)()>(h, "tl_throw_catch", true);
    Check("C++ exception unwinds via interpose", thr && thr() == 7);

    auto weak = Sym<void* (*)()>(h, "tl_weak_addr", true);
    Check("weak undefined resolves to 0", weak && weak() == nullptr);

    auto callif = Sym<int (*)()>(h, "tl_call_ifunc", true);
    Check("internal ifunc call resolves to impl", callif && callif() == 111);
    auto ifsym = Sym<int (*)()>(h, "tl_ifunc", true);
    Check("dlsym of ifunc resolves to impl", ifsym && ifsym() == 111);

    auto who = Sym<const char* (*)()>(h, "tl_who_am_i", true);
    Check("dladdr self reports our name", who && strstr(who(), "test_lib.so") != nullptr,
          who ? who() : "");

    // Maps footprint: anonymous mode must leave no file/memfd name on the
    // module's mapping; file-backed mode shows the fd path.
    uintptr_t base = static_cast<linker::Image*>(h)->map_start();
    std::string mpath = MapsPathAt(base);
    if (anonymous) {
        Check("anonymous: no path in maps", mpath.empty(), mpath.c_str());
    } else {
        Check("file-backed: path present in maps", !mpath.empty(), mpath.c_str());
    }

    // Arm the destructor probe, then close: the static dtors must run (via
    // __on_dlclose -> __cxa_finalize) in reverse construction order.
    auto set_cb = Sym<void (*)(void (*)(int))>(h, "tl_set_dtor_cb", true);
    if (set_cb) set_cb(DtorSink);
    g_dtor_n = 0;

    bool closed = linker::Dlclose(h);
    Check("Dlclose succeeds", closed);
    Check("static destructors ran in reverse order",
          g_dtor_n == 2 && g_dtor_seq[0] == 2 && g_dtor_seq[1] == 1);
    return 0;
}

int ExerciseSystem(const char* path) {
    printf("== system linker (baseline): %s\n", path);
    void* h = dlopen(path, RTLD_NOW);
    if (h == nullptr) {
        printf("  dlopen failed: %s\n", dlerror());
        return 1;
    }
    auto get42 = Sym<int (*)()>(h, "tl_get42", false);
    auto sum = Sym<int (*)()>(h, "tl_table_sum", false);
    auto thr = Sym<int (*)()>(h, "tl_throw_catch", false);
    Check("baseline get42/sum/throw",
          get42 && get42() == 42 && sum && sum() == 36 && thr && thr() == 7);
    dlclose(h);
    return 0;
}

// Unit test for the pure CFI-shadow slot logic (no live CFI runtime needed).
// A fake shadow buffer stands in for "[anon:cfi shadow]" covering address 0 up,
// so small synthetic module addresses index into the first few slots.
void TestCfiShadow() {
    printf("== cfi shadow slot logic\n");
    uint16_t shadow[8] = {0};
    auto start = reinterpret_cast<uintptr_t>(shadow);
    auto end = start + sizeof(shadow);

    // A real library already owns granule 2 (shadow value >= 2 encodes __cfi_check).
    shadow[2] = 7;

    // Module spanning granules 1..2 (base 256 KiB, size 512 KiB).
    uintptr_t base = 1u << linker::kCfiShadowGranularity;
    size_t size = 2u << linker::kCfiShadowGranularity;
    int changed = linker::CfiMarkUncheckedRange(start, end, base, size);

    Check("granule 1 (was invalid) -> unchecked", shadow[1] == linker::kCfiUncheckedShadow);
    Check("granule 2 (real library) left intact", shadow[2] == 7);
    Check("granule 0 untouched", shadow[0] == linker::kCfiInvalidShadow);
    Check("only the one invalid granule changed", changed == 1);

    // Out-of-shadow range is a no-op.
    int oob = linker::CfiMarkUncheckedRange(start, end, base, 64u << linker::kCfiShadowGranularity);
    Check("range past shadow end -> no change", oob == 0);
}

}  // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);  // unbuffered: survive a crash mid-test
#ifdef SEGV_DIAG
    InstallSegvHandler();
#endif
    if (argc < 2) {
        printf("usage: %s <test_lib.so> [more.so ...]\n", argv[0]);
        return 2;
    }
    TestCfiShadow();
    for (int i = 1; i < argc; i++) {
        ExerciseSystem(argv[i]);
        ExerciseCustom(argv[i], /*anonymous=*/true);
        ExerciseCustom(argv[i], /*anonymous=*/false);
    }
    printf("\n%s (%d failure(s))\n", g_failures == 0 ? "ALL PASS" : "FAILURES", g_failures);
    return g_failures == 0 ? 0 : 1;
}
