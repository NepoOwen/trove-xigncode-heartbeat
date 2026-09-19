# Updating for new XEM / Trove builds

When Wellbia ships a new `x3_x64.xem` (or Trove updates its executable), the
byte patterns and a handful of hardcoded values can break. The full procedure -
including how to recover a rotated RSA modulus and the `.vlizer` GUID - is in
[`../src/xem_update.md`](../src/xem_update.md).

## Quick checklist

1. Capture a live probe and its response (need a known `ts` / `M2`).
2. Extract the new RSA `N` from a memory dump → regenerate `kRsaN` limbs.
3. `kM2Suffix` is a constant in the `.vlizer` section - leave it unless `M2`
   validation fails.
4. Rebuild and confirm `solve()` reproduces the live `A3`.

## What can break

| Value | Location | Rotates? | See |
|-------|----------|----------|-----|
| RSA modulus `N` | `detail::key::kRsaN` | Yes (key rotation) | `src/xem_update.md` §1 |
| `kM2Suffix` GUID | `detail::xem::challenge::kM2Suffix` | Rarely (constant) | `src/xem_update.md` §2 |
| LZMA params (`lc/lp/pb`) | `detail::key::Lzma::decode` | Low | `src/xem_update.md` §3 |
| Byte patterns | `detail::client` + `xigncode::initialize` | On Trove updates | `src/xem_update.md` |
