# Usage

## Entry point

The DLL exports a single entry point:

```cpp
extern "C" __declspec(dllexport)
BOOL WINAPI clientdll(HMODULE hModule, void* config = nullptr);
```

## Load flow

The intended load flow (from `src/main.cpp`):

1. The loader calls `clientdll(...)`.
2. A `SetupThread` is spawned on a fresh thread.
3. The thread `freeze()`s all other threads, calls `xigncode::initialize()`,
   and `unfreeze()`s the threads.

See [`architecture.md`](architecture.md) for what `xigncode::initialize()`
does under the hood.
