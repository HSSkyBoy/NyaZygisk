#pragma once

namespace zn::hook {

enum class PltEngine { kByteHook, kLsplt };

void setPltEngine(PltEngine e);
void initPltEngineFromConfig();
PltEngine getPltEngine();

// True if ByteHook was initialized or any inline/PLT hook chain is active
// (so libzygisk.so and its dispatch stubs must stay mapped).
bool hasActiveHooks();

// Multi-module chain-capable PLT hook. Calling with hook == previously returned
// *original unhooks that module's entry without disrupting other modules in the chain.
bool pltHook(void* base, const char* symbol, void* hook, void** original);

// Multi-module chain-capable inline hook. Multiple modules may hook the same target
// address; each receives an *original trampoline that chains to the previous hook
// (and ultimately to the relocated original function).
bool inlineHook(void* target, void* addr, void** original);

// Unhooks a single module's inline hook on `target` (matching `caller_addr`'s DSO
// when multiple hooks are stacked, or popping the latest hook otherwise). Calls the
// underlying unhook engine only once the last hook on `target` is removed.
bool inlineUnhook(void* target, void* caller_addr = nullptr);

}  // namespace zn::hook
