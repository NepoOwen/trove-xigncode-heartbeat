# Trove Xigncode

A native Windows DLL that hooks the XIGNCODE3 anti-cheat client inside
**Trove** and answers its challenge/response handshake.

> ⚠️ **Disclaimer** - This project is provided for **research and educational
> purposes only**. It is not affiliated with Trove, gamigo, or Wellbia
> (`XIGNCODE3`). It was written to study how the XIGNCODE3 client verifies its
> integrity. Using it to bypass anti-cheat software violates the game's Terms of
> Service and may result in a permanent account ban. You are solely responsible
> for how you use this code.

---

## What it does

XIGNCODE3 issues a periodic **challenge** (the `A2` payload) and expects the game
process to return the correct **response** (`A3`). This project intercepts that
handshake inside the running game process and computes `A3` without talking to
the XIGNCODE3 server.

The pipeline is:

1. **Find and suspend** the other threads in the target process (`freeze`) so the
   solve runs atomically.
2. **Hook `ws2_32.dll`** - `send`, `recv`, and `connect` - to intercept the
   anti-cheat's socket traffic.
3. **Hook the challenge dispatcher** (the `state == 85` path) to capture `A2`.
4. **Solve `A2` offline**:
   - Decode the daily `M1` key from the challenge (RSA public-op → Z85 → LZMA1).
   - Compute the `M1` and `M2` MD5 MACs from the decoded key, timestamp, and a
     constant GUID.
   - Emit the `A3` response with the expected day counter and offsets.
5. If anything fails or a xem file update is detected, show a dialog and
   terminate the process (`pop()`).

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/architecture.md`](docs/architecture.md) | Full deep-dive: the XEM module, the A2/A3 handshake, the offline solver, hooks, failure handling, and a flow diagram. |
| [`docs/usage.md`](docs/usage.md) | Entry point and load flow. |
| [`docs/build.md`](docs/build.md) | Prerequisites and build instructions. |
| [`docs/updating.md`](docs/updating.md) | Summary of what to update when XEM/Trove changes. |
| [`docs/ida-diagnostics.md`](docs/ida-diagnostics.md) | How to recover hardcoded constants from the XEM module in IDA. |
| [`project/src/xem_update.md`](project/src/xem_update.md) | The complete procedure for recovering a rotated RSA modulus and the `.vlizer` GUID. |

---

## Repository layout

```
.
├── readme.md                          # this file (overview + index)
├── docs/                              # detailed documentation
│   ├── architecture.md                # how the XIGNCODE implementation works
│   ├── usage.md                       # entry point & load flow
│   ├── build.md                       # build instructions
│   └── updating.md                    # update summary
├── client.sln                         # Visual Studio solution
├── project/                           # the project + its sources
│   ├── client.vcxproj
│   ├── client.vcxproj.filters
│   ├── client.vcxproj.user
│   ├── minhook/                       # MinHook x86/x64 inline hooking library
│   │   ├── include/
│   │   └── src/
│   └── src/
│       ├── main.cpp                   # DLL entry / thread bootstrap
│       ├── challenge.hpp              # the A2 → A3 solver (RSA/Z85/LZMA1/MD5)
│       └── xem_update.md              # guide for updating hardcoded constants
└── build/                             # build output (auto-generated)
```

---

## Quick start

```powershell
# Build (x64 Release only)
msbuild client.sln /p:Configuration=Release /p:Platform=x64

# Output
# build\client.dll
```

See [`docs/build.md`](docs/build.md) and [`docs/usage.md`](docs/usage.md).

---

## Attribution

- Hooking is provided by the bundled
  [MinHook](https://github.com/TsudaKageyu/minhook) library.

---

## License

This project is licensed under the MIT License - see the
[`LICENSE`](LICENSE) file for details. The bundled
[MinHook](https://github.com/TsudaKageyu/minhook) library retains its own
license (see the MinHook headers); review and comply with each component's
licensing before redistributing.
