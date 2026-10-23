// A test module shaped like a real Zygisk module, used to exercise the custom
// linker against realistic conditions the synthetic test_lib does not cover:
//   * shared libc++ as a DT_NEEDED (libc++_shared.so) — cross-DSO new/delete,
//     typeinfo and exceptions, not the -static-libstdc++ of test_lib;
//   * a polymorphic class whose vtable lives in .data.rel.ro (RELRO) and is
//     dispatched after the loader seals RELRO read-only;
//   * an exported struct of function pointers (the shape of zygisk_module_entry)
//     rather than loose functions.
//
// It does NOT touch the JNIEnv / API table it is handed — those need a live
// Android runtime and are covered by on-device testing. onLoad only exercises
// the C++/STL/vtable machinery and records a result the harness can read back.
//
// NOTE: it deliberately does NOT throw a C++ exception. With shared libc++ the
// unwinder lives in libc++_shared.so and finds a frame's unwind info through
// the system _dl_find_object/dl_iterate_phdr, which cannot see a module we
// mapped ourselves (it is not in solist) — so an exception crossing into that
// external unwinder terminates. Modules needing exceptions must use
// -static-libstdc++ (then the unwinder is in-module and our interpose handles
// it, as test_lib verifies). This is a documented limitation of the hidden
// loader, not something this test should trip over.
#include <android/log.h>

#include <memory>
#include <string>
#include <vector>

namespace {

struct Animal {
    virtual ~Animal() = default;
    virtual int sound() const = 0;
};
struct Cat : Animal {
    int sound() const override { return 9; }
};

int g_result = -1;

}  // namespace

extern "C" {

// Mirrors the leading layout of the real module ABI closely enough to be
// fetched and called the same way (api_version first, then onLoad).
struct TestModuleAbi {
    long api_version;
    void (*onLoad)(void* api, void* env);
    int (*result)();
};

static void ModOnLoad(void* /*api*/, void* /*env*/) {
    // Virtual dispatch through a vtable in freshly-sealed RELRO, plus STL
    // containers and cross-DSO new/delete from libc++_shared.so.
    std::vector<std::unique_ptr<Animal>> zoo;
    zoo.push_back(std::make_unique<Cat>());
    int s = zoo[0]->sound();        // 9, virtual call
    std::string tag = "nya!";       // heap string via shared libc++
    s += static_cast<int>(tag.size());  // + 4

    __android_log_print(ANDROID_LOG_INFO, "mod_lib", "onLoad result=%d", s);
    g_result = s;  // 13
}

static int ModResult() { return g_result; }

// The exported entry a real loader would dlsym.
__attribute__((visibility("default"))) TestModuleAbi zygisk_module_entry = {
    /*api_version=*/5,
    /*onLoad=*/ModOnLoad,
    /*result=*/ModResult,
};

}  // extern "C"
