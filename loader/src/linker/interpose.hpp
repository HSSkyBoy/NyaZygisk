#pragma once

// A tiny interposition table consulted first when resolving a module's imports
// (see Image::ResolveSymbol). Because a module we map ourselves is invisible to
// the system linker, libc functions that walk the loaded-library list on the
// module's behalf — dl_iterate_phdr (C++ exception unwinding, profilers),
// dladdr, dl_unwind_find_exidx (arm32 unwinding) — would not see it. We redirect
// those to our own implementations, which report our images and then chain to
// the real libc function for everything else.
//
// The redirection is per-module: only the relocated GOT of a module we loaded
// points at these overrides. The system's own dl_iterate_phdr is untouched, so
// our modules stay hidden from everyone else, including detection code.

namespace linker {

// Return the override for `name`, or nullptr if we do not interpose it.
void *InterposeLookup(const char *name);

}  // namespace linker
