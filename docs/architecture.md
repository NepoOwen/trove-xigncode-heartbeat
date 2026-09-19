# Architecture - How Trove's XIGNCODE implementation works

A detailed walkthrough of how the XIGNCODE3 (XEM) anti-cheat is wired into Trove
and how each part of the challenge/response handshake is structured. Everything
below is reverse-engineered from the on-disk `x3_x64.xem` module and
`trove.exe`, and mirrors what `src/challenge.hpp` reimplements.

## The XEM module

XIGNCODE3 ships as a native module, `x3_x64.xem`, which the game loads from
`XIGNCODE\Client\1__live\` (relative to the process working directory /
install root). The module:

- Runs inside `trove.exe` and periodically "probes" the client to confirm it
  has not been tampered with.
- Communicates with Wellbia's servers over the `xls.cgi` side-channel using TLS.
- Bundles virtualized bytecode (a `.vlizer` VM section, RVA `0x595000`) that
  materializes constants and functions only at runtime, and a 1024-bit RSA key
  used to wrap the daily session key.

The initialize routine guards against the module silently changing on disk: it
opens `x3_x64.xem` and compares its size against a hardcoded expected size
(`6885808` bytes). If the file exists but its size differs, the code treats the
anti-cheat as updated/unknown and calls `pop()` - show a message box and
terminate the process rather than risk a wrong solve.

## The challenge (`A2`) and response (`A3`) handshake

During a probe the anti-cheat produces a **challenge string** (`A2`) and expects
the game process to compute and return a **response string** (`A3`). Both are
plain ASCII with a fixed layout.

```
A2 = hex8(ts) + Z85(body)
A3 = pp + "_" + hex8(ts) + "_" + hex32(M1) + "_" + hex32(M2)
```

| Field | Meaning | Size |
|-------|---------|------|
| `ts`  | Unix timestamp of the probe, as 8 lowercase hex chars | 4 bytes → 8 chars |
| `pp`  | Day counter, 2 digits in `1..99` | 2 chars |
| `M1`  | `MD5(hex8(ts) + key)` - the dynamic session MAC | 16 bytes → 32 hex |
| `M2`  | `MD5(hex8(ts) + kM2Suffix)` - the static GUID MAC | 16 bytes → 32 hex |

The **A2 body** is a Z85-encoded blob (`body`), prefixed by the same 8-hex-char
timestamp. The body is `1166` chars once encoded, and begins with a fixed
8-byte signature prefix `mz865r6:zF0SSi2`.

## Step-by-step solve (`challenge.hpp` → `detail::xem`)

The solver turns an `A2` into an `A3` entirely offline, in four stages.

### 1. Parse the timestamp (`solve`)

The first 8 characters of `A2` are parsed as a big-endian hex timestamp:
`ts = (ts << 4) | hexval(c)` for each of the 8 chars. `A3` re-emits the same
timestamp verbatim, so no clock drift correction is needed.

### 2. Decode the daily `M1` key (`detail::xem::key::decode_key`)

This is the cryptographic core. The flow is:

1. **Z85 decode** - the body (everything after the 8-char timestamp) is decoded
   with ZeroMQ Z85: every group of 5 characters is treated as a base-85 number
   and unpacked into 4 bytes, yielding a `932`-byte raw body.

2. **RSA public operation** - the raw body holds **7 × 128-byte ciphertext
   records** starting at offset `36`. Each is decrypted with the public verify
   operation `m = c^65537 mod N`, where `N` is a hardcoded 1024-bit RSA
   modulus stored as 32 little-endian `u32` limbs in `kRsaN`.

   - The exponentiation uses the classic **16 squarings + 1 multiply** trick
     (`x = c^65537` = `c^(2^16) * c`), implemented with schoolbook 32-limb
     multiplication and bit-level long-division reduction (`big_reduce`).
   - After the operation, each 128-byte record's first 3 bytes are a header and
     are **discarded**; the remaining 125 bytes per record are concatenated to
     produce an `875`-byte stream (`7 × 125`).

3. **LZMA1 decode** - the 875-byte stream is a single LZMA1 ("aligned"
   LZMA/LZMA) frame with a **mirrored range coder**. Parameters are `lc=3`,
   `lp=0`, `pb=2`, parsed from the `props` byte at `body[28]`. The decompressed
   size is read as a 4-byte little-endian value at `body[24..27]` (capped at
   `0x10000`). The decoder walks the standard LZMA state machine -
   `ISMATCH/ISREP/ISREPG*/ISREP0LONG`, `POSSLOT/SPECPOS/ALIGN`,
   `LEN/REPLEN/LITERAL` probability tables - and emits a **Lua chunk**.

4. **Locate the key** - inside the decompressed Lua chunk, the key is stored as
   the byte sequence `_2JP 0x04 <lenbyte> <key bytes>`, where each key byte is
   stored XOR-folded against its own index (`key[i] ^ i`). The length byte is
   decremented by one, and valid key lengths are constrained to `8..32`. The
   code scans for the `_2JP` marker, validates the length, un-XORs the bytes,
   and returns the NUL-terminated ASCII key.

> The daily key itself is **never hardcoded** - it is recovered from each
> challenge. This is what makes the handshake "unpredictable" to a naive
> observer, since the payload changes every day and per probe.

### 3. Compute the MACs (`detail::xem::challenge::mac_compute`)

Two MD5 digests are computed (a hand-rolled MD5, since the target avoids
linking crypto libraries):

- `M1 = MD5(hex8(ts) ‖ key)` - ties the response to the recovered session key.
- `M2 = MD5(hex8(ts) ‖ kM2Suffix)` - ties the response to a **constant version-4
  UUID** (`{CBEC4943-AFE5-4F24-A6FA-2DC80D1A1A18}`). This GUID lives only in the
  xem's virtualized `.vlizer` section and is not present anywhere in the
  challenge or the plaintext string table.

### 4. Emit `A3` (`detail::xem::challenge::generate_a3`)

The response is assembled from fixed offsets (`A3_TS_OFF=2`, `A3_M1_OFF=11`,
`A3_M2_OFF=44`, total length `76`):

- A **2-digit day counter** prefix, computed as
  `((day − 20592 − 1) % 99) + 1`, where `day = ts / 86400` (the `20592` anchor
  and `% 99` wrap are reverse-engineered constants).
- The timestamp, `M1`, and `M2`, each rendered as lowercase hex and separated
  by underscores.

## The hooks (`detail::client`)

To intercept the handshake in-process, the DLL installs several hooks and
locates hook targets with byte-pattern scans (`helper::find_pattern`) instead of
hardcoded addresses, because `trove.exe` shifts between game updates.

| Target | Hook | Behavior |
|--------|------|----------|
| `ws2_32.dll!send` | `hs` | Pass-through (returns `n`). |
| `ws2_32.dll!recv` | `hr` | Pass-through (returns `n`). |
| `ws2_32.dll!connect` | `hc` | Always returns `1` - simulates a connected socket, blocking the anti-cheat's real connections. |
| challenge dispatcher | `hkAC_SendStateChange` | Invoked with a state value; when `state == 85` the `A2` is at `v[0]`. It calls `xem::solve`, and writes the answer back via the located response sink. |
| game-entry signature | `strip` | Patch two flags (via the relative-address helper) that gate the anti-cheat's probe; if they can't be patched, `pop()`. |

`hkAC_SendStateChange` is the heart of the interception: on the probe state
(`85`), it reads the challenge pointer, solves it, and calls the located response
sink (`oAC_OnProbeResponse`) with the computed `A3`.

## Failure handling (`pop`)

If any byte pattern fails to resolve (meaning the anti-cheat or the game was
updated and the offsets moved), the DLL calls `pop()`: it freezes all other
threads, shows a message box ("Xigncode bypass has failed and must be
updated…"), terminates the process with exit code `0xC0000409`
(`STATUS_STACK_BUFFER_OVERRUN`), and never continues with a possibly-wrong
answer.

## Summary diagram

```
A2 (hex8(ts) + Z85(body))
  │  Z85 decode
  ▼
932-byte body ──► 7 × 128-byte RSA records (offset 36)
  │  m = c^65537 mod N  (kRsaN, 1024-bit)
  ▼
875-byte stream (125 × 7, headers stripped)
  │  LZMA1 decode (lc=3 lp=0 pb=2, mirrored range coder)
  ▼
Lua chunk ──► find "_2JP" 0x04 <len> → un-XOR → M1 key
  │
  │  M1 = MD5(hex8(ts) + key)
  │  M2 = MD5(hex8(ts) + kM2Suffix)
  ▼
A3 = pp + "_" + hex8(ts) + "_" + M1 + "_" + M2
```

The only values that must be kept in sync when the anti-cheat updates are the
**RSA modulus `N`** (rotates with key changes) and the **`kM2Suffix` GUID**
(normally constant). Everything else is derived from the challenge at runtime.
See [`updating.md`](updating.md) and `src/xem_update.md` for the full
extraction/update procedure.
