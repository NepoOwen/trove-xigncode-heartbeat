# XEM Update Guide

How to update the hardcoded values in `challenge.hpp` when
Wellbia ships a new `x3_x64.xem`.

Everything the offline solver needs is either **derived from the challenge at
runtime** or **hardcoded from a one-time reverse-engineering pass**. When the xem
updates, only the hardcoded values can break - and there are exactly two that
cannot be recomputed from the challenge alone.

---

## What's hardcoded, and where

| Value | Location | Derivable offline? | Likelihood of change |
|---|---|---|---|
| RSA modulus `N` | `detail::key::kRsaN` | **No** - needs the binary/memory | **High** (key rotation) |
| RSA exponent `e = 65537` | `detail::key::rsa_pub` (16 squarings + 1 mul) | Standard, fixed | Very low |
| `kM2Suffix` GUID | `detail::xem::challenge::kM2Suffix` | **No** - constant GUID in the `.vlizer` VM section | Very low (constant) |
| LZMA params `lc=3 lp=0 pb=2` | `detail::key::Lzma::decode` (`pos & 3`, `prev >> 5`) | Yes - in `props` byte (`body[28]`), but currently hardcoded | Low |
| Challenge structure (7×128 records, header offsets) | `detail::key::decode_key` | No | Low |
| Key encoding `"_2JP" 0x04 <key[i]^i>` | `detail::key::decode_key` | No | Low |
| Day-counter anchor (`day - 20592`, `% 99`) | `detail::xem::challenge::day_counter` / `generate_a3` | No | Very low |
| A3 response offsets/length | `detail::xem::challenge` (`A3_*`) | No | Low |
| `state == 85` + trove.exe byte patterns | `challenge.hpp` | No (trove.exe, not xem) | On **Trove** updates, not xem |

The daily M1 key itself is **not** hardcoded - it is decoded from each challenge
via RSA + LZMA.

---

## 1. Recovering a new RSA modulus (`kRsaN`)

`N` is a 1024-bit number embedded in the xem and materialized in process memory
during a probe. We recover it by finding the **`[N|E]` blob**:

- `N`: 128 bytes big-endian, odd, top bit set, no small prime factors.
- `E`: 128 bytes big-endian, mostly zeros ending in `0x010001` (65537),
  or `0x0101` (257), `0x11` (17), `0x03` (3).

`E` may precede or follow `N`.

> ⚠ **The `[N|E]` shape is NOT unique.** The xem also keeps TLS public keys (for
> its `xls.cgi` side-channel) as identical `[N|E]` blobs. A plain scan that
> returns the *first* strong hit will hand you a **TLS key** (we hit this on run
> 65504), not the challenge key. You must **verify each candidate** against a
> captured challenge record - only the real key yields `m[0] == 0x00`.

### Steps

1. Run the game, let a probe fire (state 85); capture the challenge `challenge`.
2. Dump the process (or the loaded `x3_x64.xem` module) to a file.
3. Collect **all** `[N|E]` candidates, then for each test `m = c^65537 mod N` on
   a known 128-byte ciphertext record from `challenge`. The correct `N` is the one where
   `m[0] == 0x00` (the RSA record's first byte is zero and gets stripped).
4. Convert the verified `N` to 32 little-endian `u32` limbs.

```python
# Scan a memory dump for ALL [N|E] / [E|N] blobs, then VERIFY each against a
# captured challenge record. The real challenge key is the one where
#   m = c^65537 mod N   has m[0] == 0x00  (the record's first byte is zero and
# gets stripped). A plain scan is NOT enough - the xem also holds TLS keys.
SMALL = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

def has_small_factor(n):
    return any(n % p == 0 for p in SMALL)

def match_e(e):
    t = e[127]
    if t == 0x01 and e[126] == 0x01 and all(x == 0 for x in e[:126]): return 257
    if t == 0x01 and e[126] == 0x00 and e[125] == 0x01 and all(x == 0 for x in e[:125]): return 65537
    if t in (0x03, 0x11) and all(x == 0 for x in e[:127]): return t
    return 0

def collect_n(data):
    seen, out = set(), []
    for i in range(len(data) - 256):
        for n, e in ((data[i:i+128], data[i+128:i+256]),     # N then E
                     (data[i+128:i+256], data[i:i+128])):    # E then N
            if n[0] & 0x80 and n[127] & 1 and match_e(e) \
               and not has_small_factor(int.from_bytes(n, 'big')):
                if n not in seen:
                    seen.add(n); out.append(n)
    return out

def rsa_pub(c, N):
    return pow(int.from_bytes(c, 'big'), 65537, N).to_bytes(128, 'big')

# Paste the first 128-byte ciphertext record from a real challenge (body[36:164]) as hex.
cipher = bytes.fromhex('0000...')   # <-- 128 bytes = 256 hex chars

for n in collect_n(open('dump.bin', 'rb').read()):
    N = int.from_bytes(n, 'big')
    if rsa_pub(cipher, N)[0] == 0x00:
        limbs = ', '.join(f'0x{(N >> (32*i)) & 0xFFFFFFFF:08x}u' for i in range(32))
        print('// VERIFIED - paste into detail::key::kRsaN:')
        print(limbs)
        break
else:
    print('no candidate passed m[0]==0 (check ciphertext + dump coverage)')
```

Paste the printed limbs into `kRsaN` (32 entries, least-significant first).

> Why not offline? `c = m^d mod N` - recovering `N` from a `(c, m)` pair needs a
> known `m`, and `m` is only available *after* decrypting, which needs `N`.
> Circular, so `N` must come from the binary/memory.

---

## 2. Recovering the M2 suffix (`kM2Suffix`)

`kM2Suffix` is a **version-4 UUID constant** baked into the `.vlizer` VM section.
It is *not* in the plaintext string table (a normal `strings`/GUID-regex pass over
the xem file will **not** find it) - the bytes live inside the virtualized
bytecode, materialized at runtime. It is *also* not present in the challenge (the
challenge only carries three other UUIDs at offsets 568/726/884, plus the daily
key). It cannot be computed - only extracted from memory.

Because it is a **constant** (not a rotated key), it survives xem updates unless
Wellbia deliberately changes it. Only re-extract it if `MD5(ts + kM2Suffix)`
stops matching the `M2` field in a captured response.

### Steps (if it ever changes)

1. Capture one live probe: the challenge (`challenge`) and its response (`response`).
2. From the response, read `ts` (chars 2..10) and `M2` (chars 44..76, hex).
3. Dump the process while a probe is live (the `.vlizer` bytecode + its constants
   are runtime-generated/loaded, so a raw file scan is insufficient).
4. Scan the **memory dump** (not the file) for GUID-shaped strings.
5. For each GUID, check `MD5(ts + GUID) == M2`.

```python
import re, hashlib

# Scan a PROCESS MEMORY dump, not the on-disk xem file.
data = open('mem.dump', 'rb').read()
guids = set(m.group(0) for m in re.finditer(
    rb'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}', data))

ts = '6aa8cf09'                     # chars 2..10 of the response
m2 = 'afa889af29dbae10467d5d1545fd60b5'   # chars 44..76 of the response

for g in guids:
    if hashlib.md5(ts + g).hexdigest() == m2:
        print('kM2Suffix =', g.decode())
```

If the GUID is not materialized as contiguous ASCII in memory (e.g. built
byte-by-byte inside the VM), fall back to dumping the `.vlizer` section
(RVA `0x595000`, ~4.6 MB) and scanning it for the GUID bytes - but note the VM
may XOR/obfuscate its constants, in which case it must be captured from a
running process.

Paste the result into `detail::xem::challenge::kM2Suffix`.

> `M2 = MD5(ts + kM2Suffix)`. The three GUIDs inside the challenge are *not* the
> M2 suffix - the M2 suffix is a fourth, separate GUID that only lives in the
> xem's `.vlizer` VM section.

---

## 3. Everything else (rare, but check if a solve silently breaks)

- **LZMA params** - the `props` byte at `body[28]` actually encodes
  `lc + 9*lp + 45*pb`. The current code hardcodes `3/0/2`. If a decode starts
  producing garbage, parse `props` and drive `lc/lp/pb` dynamically instead.
- **Key encoding** - if the `"_2JP"` marker, the `0x04` type byte, the
  `key[i]^i` XOR, or the `8..32` key-length window changes, key extraction breaks.
- **Day counter** - if the two-digit prefix in the response drifts, re-fit the
  anchor (`20592`) and the `% 99` wrap.
- **A3 format** - if offsets (`A3_TS_OFF`, `A3_M1_OFF`, `A3_M2_OFF`) or the total
  length change, `generate_a3` breaks.
- **Trove.exe patterns / state 85** - these are signatures of `trove.exe`, so they
  break on a *game* update, not a xem update.

---

## Quick update checklist

1. Grab a live probe + response (to have a known `ts`/`M2`).
2. Dump the xem, extract new `N` → regenerate `kRsaN` limbs.
3. `kM2Suffix` is a constant in the `.vlizer` section - skip unless `M2`
   validation fails, then scan a **memory dump** (not the file) + `MD5` check.
4. Rebuild; verify `solve()` against the captured challenge produces the same
   `response` as the live response.
