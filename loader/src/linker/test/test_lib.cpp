// Test module exercised by runner.cpp through both the system linker and the
// custom linker. Deliberately touches the features the loader must get right:
// relative relocations (the big pointer table), symbol-based relocations into
// libc (NEEDED resolution), constructor/destructor ordering, C++ exceptions
// (unwinder inside the module calling our interposed dl_iterate_phdr), weak
// undefined symbols, and self-identification via dladdr.
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {

// --- basic + symbol relocation into libc ---------------------------------
int tl_get42() { return 42; }

int tl_strlen_of(const char* s) { return static_cast<int>(strlen(s)); }

// --- relative relocations: a table of pointers into our own code ----------
static int a() { return 1; }
static int b() { return 2; }
static int c() { return 4; }
using Fn = int (*)();
// Each entry needs a RELATIVE (or RELR) relocation; forces the relocator to
// patch many slots with load_bias.
Fn tl_table[] = {a, b, c, a, b, c, a, b, c, a, b, c, a, b, c, a};
int tl_table_sum() {
    int s = 0;
    for (Fn f : tl_table) s += f();
    return s;  // 3*(1+2+4)+1 = 22
}

// --- constructor / destructor ordering ------------------------------------
static std::string g_order;
struct Ctor1 {
    Ctor1() { g_order += "1"; }
    ~Ctor1() { g_order += "~1"; }
};
struct Ctor2 {
    Ctor2() { g_order += "2"; }
    ~Ctor2() { g_order += "~2"; }
};
static Ctor1 g1;
static Ctor2 g2;
const char* tl_ctor_order() { return g_order.c_str(); }

// --- C++ exceptions (unwinding must find our eh_frame) --------------------
int tl_throw_catch() {
    try {
        throw 123;
    } catch (int v) {
        return v == 123 ? 7 : -1;
    }
    return -2;
}

// --- weak undefined symbol -------------------------------------------------
// Resolves to nullptr when absent; the loader must leave it 0, not fail.
__attribute__((weak)) extern void tl_missing_weak(void);
void* tl_weak_addr() { return reinterpret_cast<void*>(&tl_missing_weak); }

// --- dladdr self lookup (goes through our interpose in the custom case) ----
const char* tl_who_am_i() {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(reinterpret_cast<void*>(&tl_get42), &info) && info.dli_fname) {
        return info.dli_fname;
    }
    return "(none)";
}

}  // extern "C"
