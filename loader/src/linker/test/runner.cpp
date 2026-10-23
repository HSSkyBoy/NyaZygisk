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

void Check(const char* what, bool ok, const char* detail = "") {
    printf("  [%s] %s %s\n", ok ? "PASS" : "FAIL", what, detail);
    if (!ok) g_failures++;
}

template <typename T>
T Sym(void* h, const char* name, bool custom) {
    return reinterpret_cast<T>(custom ? linker::Dlsym(h, name) : dlsym(h, name));
}

int ExerciseCustom(const char* path) {
    printf("== custom linker: %s\n", path);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("  cannot open %s\n", path);
        return 1;
    }
    linker::LoadError err = linker::LoadError::kNone;
    void* h = linker::Dlopen(fd, "test_lib.so", &err);
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

    auto who = Sym<const char* (*)()>(h, "tl_who_am_i", true);
    Check("dladdr self reports our name", who && strstr(who(), "test_lib.so") != nullptr,
          who ? who() : "");

    bool closed = linker::Dlclose(h);
    Check("Dlclose + destructors", closed);
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
    for (int i = 1; i < argc; i++) {
        ExerciseSystem(argv[i]);
        ExerciseCustom(argv[i]);
    }
    printf("\n%s (%d failure(s))\n", g_failures == 0 ? "ALL PASS" : "FAILURES", g_failures);
    return g_failures == 0 ? 0 : 1;
}
