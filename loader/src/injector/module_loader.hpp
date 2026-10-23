#pragma once

// Thin façade over the from-scratch module loader (linker/) and the system
// loader (DlopenMem / android_dlopen_ext). Zygisk and ZN module loading go
// through this so the two call sites stay identical.
//
// Policy on this experimental branch: always try the custom linker first. Only
// when it refuses (e.g. the module uses TLS, which we do not map) or errors do
// we fall back to android_dlopen_ext. A module that falls back is loaded by the
// system linker and therefore still appears in solist, so the caller must still
// scrub its trace; `via_system` reports which path was taken.
namespace modloader {

// Load a module from a (mem)fd. `name` is the memfd label used for logging and,
// on fallback, as the android_dlopen_ext soname. On success returns a handle
// and sets *via_system to whether the system linker was used.
void *Dlopen(int memfd, const char *name, bool *via_system);

// dlsym / dlclose that route to whichever loader owns the handle.
void *Dlsym(void *handle, const char *name);
bool Dlclose(void *handle);

// Whether a handle was produced by the custom linker (i.e. is hidden from
// solist). Used by the trace-cleanup accounting.
bool IsCustom(void *handle);

}  // namespace modloader
