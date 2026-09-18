# IDA Diagnostics

Reverse-engineering notes for the Trove client's XIGNCODE3 (XEM) integration,
covering the functions involved in the anti-cheat handshake, the hooks we place,
and the strategy used to bypass the anti-cheat.

---

## Table of contents

- [Functions of interest](#functions-of-interest)
- [The challenge/response handshake](#the-challengeresponse-handshake)
- [Why the handshake matters](#why-the-handshake-matters)
- [The bypass strategy](#the-bypass-strategy)
- [Glossary](#glossary)

---

## Functions of interest

All signatures are 64-bit (`__fastcall`) and located via byte-pattern scans rather
than fixed addresses, since the binary shifts between game updates.

| Function | Signature | Signature bytes |
|----------|-----------|-----------------|
| `AC_NetworkSend_Guarded` | `char __fastcall AC_NetworkSend_Guarded(void *Src, size_t Size, __int64 a3)` | `48 8B C4 48 89 58 ? 4C 89 40 ? 55` |
| `AC_OnProbeResponse` | `void __fastcall AC_OnProbeResponse(__int64 a1, __int64 a2, const char *a3, unsigned __int64 a4, __int64 *a5)` | `48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 9C 24 ? ? ? ? 49 8B F1` |
| `AC_SendStateChange` | `__int64 AC_SendStateChange(unsigned int a1, ...)` | `89 4C 24 ? 48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 48 83 EC` |
| `AC_Watchdog_Startup` | `void AC_Watchdog_Startup()` | `40 55 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 80 3D ? ? ? ? 00` |

> `?` denotes a wildcard byte (a register/offset/immediate that varies between builds).

---

## The challenge/response handshake

Inside `AC_NetworkSend_Guarded`, the client issues the anti-cheat probe through
`AC_SendStateChange`:

```c
if ( !(unsigned int)AC_SendStateChange(
    85,                                          // probe state / command id
    *(QWORD *)(v15 + 16),                        // challenge (A2) - const char *
    *(QWORD *)(v15 + 24) - *(QWORD *)(v15 + 16), // challenge length
    AC_OnProbeResponse,                          // success callback
    AC_OnProbeFailed,                            // failure callback
    v18) )
{
    ...
}
```

Field-by-field:

| Argument | Meaning |
|----------|---------|
| `85` | The probe state - this is the `state == 85` branch our hook intercepts. |
| `*(QWORD *)(v15 + 16)` | Pointer to the **challenge** string (`A2`). |
| `*(QWORD *)(v15 + 24) - *(QWORD *)(v15 + 16)` | The **challenge length** (end pointer − start pointer). |
| `AC_OnProbeResponse` | Callback invoked on success; receives the **response** (`A3`) via `const void *a3`. |
| `AC_OnProbeFailed` | Callback invoked on failure. |

The flow is:

1. The client calls `AC_SendStateChange(85, challenge, len, ...)`, handing the
   challenge to `x3_x64.xem`.
2. The XEM module computes the response (`A3`) from the challenge (`A2`).
3. On success, XEM calls `AC_OnProbeResponse`, where `const char *a3` holds the
   computed response.
4. The response is then forwarded to the Trove servers.

> In our solver (`src/challenge.hpp` → `detail::xem::solve`), the `state == 85`
> hook (`hss`) calls `xem::solve(a2)` and writes the result back through the
> located response-sink function (`p0`, which corresponds to
> `AC_OnProbeResponse`'s prologue) - see [the bypass strategy](#the-bypass-strategy).

---

## Why the handshake matters

If **no response** is ever sent back to the servers, the game bricks at the
**`World: Login Finished`** loading screen. The login sequence stalls until
`AC_OnProbeResponse` is called with a legitimate response - at which point the
client signals *"yes, the anti-cheat is running"* and the server lets us in.

The practical consequence: **Trove's only hard requirement is this single
server ↔ XEM challenge**, which means the game can be run with the anti-cheat
completely absent as long as this one handshake is answered correctly.

---

## The bypass strategy

Two independent mechanisms are used together: (1) patch the anti-cheat's
*initialized* flags so its watchdog never actually starts, and (2) intercept the
probe callback and answer the challenge offline.

### 1. Strip the anti-cheat (`XignCode_Initialized` flags)

```cpp
static void strip() {
    static const int p[] = {
        0x80,0x3D,-1,-1,-1,-1,0x00, 0x74,-1,
        0x80,0x3D,-1,-1,-1,-1,0x00, 0x0F,0x85,-1,-1,-1,-1,
        0x48,0x83,0x3D,-1,-1,-1,-1,0x00
    };
    uint8_t* p1 = helper::find_pattern(p, sizeof(p) / sizeof(int));
    uint8_t* i1 = p1 ? helper::resolve_relative(p1, 2, 7) : nullptr;
    uint8_t* i2 = p1 ? helper::resolve_relative(p1 + 9, 2, 7) : nullptr;

    bool ok = true;
    if (i1 && helper::is_valid_ptr(i1, 1)) *i1 = 1; else ok = false;
    if (i2 && helper::is_valid_ptr(i2, 1)) *i2 = 1; else ok = false;
    if (!ok) pop();
}
```

This patch sets both `XignCode_Initialized` and `XignCode_Initialized2` to `1`
(boolean `true`), which short-circuits the first guard in `AC_Watchdog_Startup`:

```c
if ( (!XignCode_Initialized || !XignCode_Initialized2) && qword_1413B1D88 )
```

- `helper::find_pattern` scans the loaded image for the byte pattern (wildcards `-1`).
- `helper::resolve_relative(addr, offset, size)` resolves a RIP-relative operand
  (`addr + size + *(int32 *)(addr + offset)`).
- `helper::is_valid_ptr(addr, n)` verifies the target is valid, committed, readable/writable
  memory before writing.

Because the guard reads both flags as "already initialized", the watchdog's real
initialization path never runs - the anti-cheat is effectively **stripped**.

### 2. Answer the challenge offline

Even with the watchdog stripped, the server still expects a valid probe response,
so the client side must still answer the challenge. This is handled by hooking the
`state == 85` probe dispatch (`hss` in `detail::client`) and computing `A3` locally
via `detail::xem::solve` (RSA → Z85 → LZMA1 → MD5), then returning it through the
located response callback.

For the full algorithm, see [`architecture.md`](architecture.md) and
[`../src/xem_update.md`](../src/xem_update.md).

---

## Glossary

| Term | Meaning |
|------|---------|
| **XEM** | The XIGNCODE3 module (`x3_x64.xem`) loaded by Trove. |
| **`A2` / challenge** | The probe challenge string issued by `AC_SendStateChange`. |
| **`A3` / response** | The computed answer returned via `AC_OnProbeResponse`. |
| **probe state `85`** | The XEM dispatch case that carries the challenge/response. |
| **`XignCode_Initialized` / `XignCode_Initialized2`** | Watchdog flags checked by `AC_Watchdog_Startup`. |
| **`helper::find_pattern` / `helper::resolve_relative` / `helper::is_valid_ptr`** | Pattern-scan / RIP-relative-resolve / memory-validate helpers. |
| **`pop()`** | Fail-safe: freeze threads, show a message, and terminate the process. |