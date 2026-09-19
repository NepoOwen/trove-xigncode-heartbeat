// File: bypass.hpp
// Author: NepoOwen
// https://github.com/NepoOwen/trove-xigncode-heartbeat
// ============================================================================
// Standalone key generator: decode the daily M1 key from the A2 challenge.
//   challenge = hex8(ts) + Z85(body)
//   body[36+i*128 .. 36+(i+1)*128] = RSA-encrypted 128-byte records
//   m = record ^ 65537 mod N   (public verify op)
//   stream = concat(m[3:128])  (875 bytes)
//   LZMA1 (mirrored range coder) -> Lua chunk
//   key = "_2JP" 0x04 <lenbyte> <key[i]^i>
// ============================================================================

#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <intrin.h>
#include <tlhelp32.h>
#include "../minhook/include/MinHook.h"

namespace detail {

    namespace xem {

        namespace key {

            // ---- 1024-bit modular arithmetic (RSA public op) ----
            static constexpr int kLimbs = 32;  // 1024 bits = 32 x 32-bit limbs

            // 125074632951789243237322579729460806160406220391025639729197221662205380033322179499117784526432319625733375175514899956986862127844987707942364637124026267693045043423764332390585667212778657880958991504482590882917719011959873148023191847900324939157010850480404581460070676697211071603034700436037777479347
            static constexpr uint32_t kRsaN[kLimbs] = {
                0x40c3d6b3u, 0xb55d9978u, 0xc19a3442u, 0x911e015cu, 0x83ff249cu, 0xfc86f025u, 0x236b2c1eu, 0x54f76c5eu,
                0xebeaa476u, 0x7be90ce0u, 0x90fc5321u, 0x63da15e3u, 0x65a31488u, 0x867d9311u, 0xf1d55222u, 0xe03ec2a6u,
                0x3c4d0c63u, 0x83543f35u, 0xaee8c44bu, 0xedbe21c6u, 0xa51988aeu, 0xa8090b6fu, 0xa95a959du, 0x72df4268u,
                0xa6eb052cu, 0xbc3a4200u, 0x227895bfu, 0xe5a5539au, 0x5219a713u, 0x44e788d5u, 0x01f53eb8u, 0xb21cb874u,
            };

            static int big_cmp(const uint32_t* a, const uint32_t* b, int n) {
                for (int i = n - 1; i >= 0; --i)
                    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
                return 0;
            }

            static void big_mul(const uint32_t* a, const uint32_t* b, uint32_t* r, int n) {
                for (int i = 0; i < 2 * n; ++i) r[i] = 0;
                for (int i = 0; i < n; ++i) {
                    uint32_t carry = 0;
                    for (int j = 0; j < n; ++j) {
                        uint64_t cur = (uint64_t)a[i] * b[j] + r[i + j] + carry;
                        r[i + j] = (uint32_t)cur;
                        carry = (uint32_t)(cur >> 32);
                    }
                    int k = i + n;
                    while (carry) {
                        uint64_t cur = (uint64_t)r[k] + carry;
                        r[k] = (uint32_t)cur;
                        carry = (uint32_t)(cur >> 32);
                        ++k;
                    }
                }
            }

            // r = t mod N  (t has 2n limbs, N has n limbs) - bit-level long division
            static void big_reduce(const uint32_t* t, uint32_t* r, int n) {
                uint32_t R[33] = { 0 };  // n+1 limbs
                int total_bits = 2 * n * 32;
                for (int bit = total_bits - 1; bit >= 0; --bit) {
                    uint32_t carry = (t[bit >> 5] >> (bit & 31)) & 1;
                    for (int i = 0; i <= n; ++i) {
                        uint32_t nc = R[i] >> 31;
                        R[i] = (R[i] << 1) | carry;
                        carry = nc;
                    }
                    if (R[n] != 0 || big_cmp(R, kRsaN, n) >= 0) {
                        uint64_t borrow = 0;
                        for (int i = 0; i < n; ++i) {
                            uint64_t cur = (uint64_t)R[i] - kRsaN[i] - borrow;
                            R[i] = (uint32_t)cur;
                            borrow = (cur >> 63) & 1;
                        }
                        R[n] = 0;
                    }
                }
                for (int i = 0; i < n; ++i) r[i] = R[i];
            }

            static void big_modmul(const uint32_t* a, const uint32_t* b, uint32_t* r) {
                uint32_t t[64];
                big_mul(a, b, t, kLimbs);
                big_reduce(t, r, kLimbs);
            }

            // out = in ^ 65537 mod N  (in/out are 128-byte big-endian)
            static void rsa_pub(const uint8_t* in, uint8_t* out) {
                uint32_t base[32], x[32], tmp[32];
                for (int i = 0; i < kLimbs; ++i) {
                    int off = 128 - 4 * (i + 1);
                    base[i] = ((uint32_t)in[off] << 24) | ((uint32_t)in[off + 1] << 16) |
                        ((uint32_t)in[off + 2] << 8) | (uint32_t)in[off + 3];
                }
                for (int i = 0; i < kLimbs; ++i) x[i] = base[i];
                for (int i = 0; i < 16; ++i) {  // 16 squarings -> base^(2^16)
                    big_modmul(x, x, tmp);
                    for (int j = 0; j < kLimbs; ++j) x[j] = tmp[j];
                }
                big_modmul(x, base, tmp);  // * base -> base^65537
                for (int i = 0; i < kLimbs; ++i) {
                    int off = 128 - 4 * (i + 1);
                    out[off] = (uint8_t)(tmp[i] >> 24);
                    out[off + 1] = (uint8_t)(tmp[i] >> 16);
                    out[off + 2] = (uint8_t)(tmp[i] >> 8);
                    out[off + 3] = (uint8_t)tmp[i];
                }
            }

            // ---- Z85 decode ----
            static int z85_index(char c) {
                static const char Z85[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
                for (int i = 0; i < 85; ++i) if (Z85[i] == c) return i;
                return -1;
            }

            static size_t z85_decode(const char* s, size_t len, uint8_t* out) {
                size_t olen = 0;
                for (size_t i = 0; i + 5 <= len; i += 5) {
                    uint64_t v = 0;
                    bool ok = true;
                    for (int j = 0; j < 5; ++j) {
                        int idx = z85_index(s[i + j]);
                        if (idx < 0) { ok = false; break; }
                        v = v * 85 + (uint64_t)idx;
                    }
                    if (!ok) break;
                    out[olen++] = (uint8_t)(v >> 24);
                    out[olen++] = (uint8_t)(v >> 16);
                    out[olen++] = (uint8_t)(v >> 8);
                    out[olen++] = (uint8_t)v;
                }
                return olen;
            }

            // ---- LZMA1 (mirrored range coder) ----
            static const int ISMATCH = 0, ISREP = 192, ISREPG0 = 204, ISREPG1 = 216, ISREPG2 = 228,
                ISREP0LONG = 240, POSSLOT = 432, SPECPOS = 687, ALIGN = 802,
                LEN = 818, REPLEN = 1332, LITERAL = 1846;

            struct RC {
                const uint8_t* data;
                int pos;
                uint32_t range, code;
                void init(const uint8_t* d) {
                    data = d; pos = 5;
                    range = ((uint32_t)d[1] << 24) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 8) | (uint32_t)d[4];
                    code = 0xFFFFFFFF;
                }
                void normalize() {
                    if (code < 0x1000000) {
                        range = ((range << 8) | data[pos]) & 0xFFFFFFFF;
                        code = (code << 8) & 0xFFFFFFFF;
                        ++pos;
                    }
                }
                int bit(uint16_t& prob) {
                    normalize();
                    uint32_t bound = (code >> 11) * prob;
                    if (range < bound) {
                        code = bound;
                        prob += (uint16_t)((0x800 - prob) >> 5);
                        return 0;
                    }
                    range = (range - bound) & 0xFFFFFFFF;
                    code = (code - bound) & 0xFFFFFFFF;
                    prob -= (uint16_t)(prob >> 5);
                    return 1;
                }
                int dbit() {
                    normalize();
                    code >>= 1;
                    range = (range - code) & 0xFFFFFFFF;
                    if (range & 0x80000000) {
                        range = (range + code) & 0xFFFFFFFF;
                        return 0;
                    }
                    return 1;
                }
            };

            struct Lzma {
                RC rc;
                uint16_t probs[8192];
                int reps[4];
                int state;
                uint8_t* out;
                int pos;

                void init(const uint8_t* stream, uint8_t* outbuf) {
                    rc.init(stream);
                    out = outbuf;
                    for (int i = 0; i < 8192; ++i) probs[i] = 0x400;
                    reps[0] = reps[1] = reps[2] = reps[3] = 1;
                    state = 0; pos = 0;
                }
                int bit(int idx) { return rc.bit(probs[idx]); }
                int dbit() { return rc.dbit(); }
                int len_decode(int base) {
                    if (bit(base) == 0) {
                        int ps = pos & 3;
                        int sym = 1;
                        for (int i = 0; i < 3; ++i) sym = (sym << 1) | bit(base + 2 + ps * 8 + sym);
                        return sym - 8;
                    }
                    else if (bit(base + 1) == 0) {
                        int ps = pos & 3;
                        int sym = 1;
                        for (int i = 0; i < 3; ++i) sym = (sym << 1) | bit(base + 130 + ps * 8 + sym);
                        return sym;
                    }
                    else {
                        int sym = 1;
                        for (int i = 0; i < 8; ++i) sym = (sym << 1) | bit(base + 258 + sym);
                        return sym - 256 + 16;
                    }
                }
                void decode(int out_size) {
                    while (pos < out_size) {
                        int ps = pos & 3;
                        if (bit(ISMATCH + state * 16 + ps) == 0) {
                            int prev = (pos > 0) ? out[pos - 1] : 0;
                            int lit_state = prev >> (8 - 3);  // lc=3, lp=0
                            int base = LITERAL + 0x300 * lit_state;
                            if (state < 7) {
                                int sym = 1;
                                while (sym < 0x100) sym = (sym << 1) | bit(base + sym);
                                out[pos++] = (uint8_t)(sym & 0xFF);
                            }
                            else {
                                int matchByte = out[pos - reps[0]];
                                int sym = 1;
                                bool matched = true;
                                for (int k = 0; k < 8; ++k) {
                                    int matchBit = (matchByte >> 7) & 1;
                                    matchByte = (matchByte << 1) & 0xFF;
                                    int idx = matched ? (0x100 + matchBit * 0x100 + sym) : sym;
                                    int b = bit(base + idx);
                                    sym = (sym << 1) | b;
                                    if (matched && matchBit != b) matched = false;
                                }
                                out[pos++] = (uint8_t)(sym & 0xFF);
                            }
                            state = (state < 4) ? 0 : ((state < 10) ? state - 3 : state - 6);
                        }
                        else {
                            int length = 0;
                            if (bit(ISREP + state) == 0) {
                                reps[3] = reps[2]; reps[2] = reps[1]; reps[1] = reps[0];
                                length = len_decode(LEN);
                                int ltp = (length < 4) ? length : 3;
                                int slot = 1;
                                for (int k = 0; k < 6; ++k) slot = (slot << 1) | bit(POSSLOT + ltp * 64 + slot);
                                slot -= 64;
                                int d;
                                if (slot < 4) {
                                    d = slot;
                                }
                                else if (slot < 14) {
                                    int num_bits = (slot >> 1) - 1;
                                    d = (2 | (slot & 1)) << num_bits;
                                    int idx = d - slot;
                                    int tree = 1;
                                    for (int j = 0; j < num_bits; ++j) {
                                        int b = bit(SPECPOS + idx + tree);
                                        tree = (tree << 1) | b;
                                        if (b) d |= (1 << j);
                                    }
                                }
                                else {
                                    int num_bits = (slot >> 1) - 1;
                                    d = 2 | (slot & 1);
                                    for (int k = 0; k < num_bits - 4; ++k) d = (d << 1) | dbit();
                                    d <<= 4;
                                    int i = 1;
                                    for (int j = 0; j < 4; ++j) {
                                        int b = bit(ALIGN + i);
                                        i = (i << 1) | b;
                                        if (b) d |= (1 << j);
                                    }
                                }
                                reps[0] = d + 1;
                                state = (state < 7) ? 7 : 10;
                                length += 2;
                            }
                            else {
                                if (bit(ISREPG0 + state) == 0) {
                                    if (bit(ISREP0LONG + state * 16 + ps) == 0) {
                                        state = (state < 7) ? 9 : 11;
                                        length = 1;
                                    }
                                    else {
                                        length = len_decode(REPLEN) + 2;
                                        state = (state < 7) ? 8 : 11;
                                    }
                                }
                                else {
                                    int d;
                                    if (bit(ISREPG1 + state)) {
                                        if (bit(ISREPG2 + state)) { d = reps[3]; reps[3] = reps[2]; }
                                        else d = reps[2];
                                        reps[2] = reps[1];
                                    }
                                    else {
                                        d = reps[1];
                                    }
                                    reps[1] = reps[0];
                                    reps[0] = d;
                                    length = len_decode(REPLEN) + 2;
                                    state = (state < 7) ? 8 : 11;
                                }
                            }
                            for (int k = 0; k < length; ++k) {
                                if (pos >= out_size || pos - reps[0] < 0) return;
                                out[pos] = out[pos - reps[0]];
                                ++pos;
                            }
                        }
                    }
                }
            };

            // decode the M1 key from the A2 challenge; returns key length (0 on failure)
            static int decode_key(const std::string& challenge, char* out_key) {
                uint8_t body[932];
                size_t blen = z85_decode(challenge.data() + 8, challenge.size() - 8, body);
                if (blen < 36 + 128 * 7) return 0;

                uint8_t stream[875];
                for (int i = 0; i < 7; ++i) {
                    uint8_t m[128];
                    rsa_pub(body + 36 + i * 128, m);
                    for (int j = 0; j < 125; ++j) stream[i * 125 + j] = m[3 + j];
                }

                int out_size = (int)body[24] | ((int)body[25] << 8) | ((int)body[26] << 16) | ((int)body[27] << 24);
                if (out_size <= 0 || out_size > 0x10000) return 0;

                uint8_t* outbuf = new uint8_t[out_size];

                Lzma lz;
                lz.init(stream, outbuf);
                lz.decode(out_size);

                int result = 0;
                // find the key: "_2JP" 0x04 <lenbyte> <key[i]^i>, short key (8..32) - UUIDs are 38
                for (int i = 0; i + 6 <= lz.pos; ++i) {
                    if (lz.out[i] == '_' && lz.out[i + 1] == '2' && lz.out[i + 2] == 'J' && lz.out[i + 3] == 'P' && lz.out[i + 4] == 0x04) {
                        int klen = (int)lz.out[i + 5] - 1;
                        if (klen >= 8 && klen <= 32) {
                            for (int j = 0; j < klen; ++j) out_key[j] = (char)(lz.out[i + 6 + j] ^ j);
                            out_key[klen] = 0;
                            result = klen;
                            break;
                        }
                    }
                }
                delete[] outbuf;
                return result;
            }

        } // namespace key

        namespace challenge {

            static constexpr const char* kM2Suffix = "{CBEC4943-AFE5-4F24-A6FA-2DC80D1A1A18}"; // hardcoded, may change in future
            static constexpr const char* A2_BODY_PREFIX = "mz865r6:zF0SSi2";
            static constexpr size_t A2_BODY_LEN = 1166;
            static constexpr size_t A3_TOTAL_LEN = 76;
            static constexpr size_t A3_TS_OFF = 2;
            static constexpr size_t A3_M1_OFF = 11;
            static constexpr size_t A3_M2_OFF = 44;

            inline char nibble_to_hex(uint8_t n) {
                return (n < 10) ? char('0' + n) : char('a' + (n - 10));
            }

            inline void bytes_to_hex(const uint8_t* in, size_t n, char* out) {
                for (size_t i = 0; i < n; ++i) {
                    out[2 * i] = nibble_to_hex(in[i] >> 4);
                    out[2 * i + 1] = nibble_to_hex(in[i] & 0x0F);
                }
            }

            inline unsigned day_counter(uint32_t unix_ts) {
                int64_t day = int64_t(unix_ts) / 86400;
                int64_t diff = day - 20592;
                return unsigned(diff);
            }

            struct Md5 {
                uint32_t h[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
                uint64_t total = 0;
                uint8_t  block[64];
                uint32_t blocklen = 0;

                static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

                static const uint32_t K[64];
                static const uint8_t  S[64];

                static void compress_block(uint32_t h[4], const uint8_t* p) {
                    uint32_t m[16];
                    for (int i = 0; i < 16; ++i)
                        m[i] = uint32_t(p[4 * i]) | (uint32_t(p[4 * i + 1]) << 8) |
                        (uint32_t(p[4 * i + 2]) << 16) | (uint32_t(p[4 * i + 3]) << 24);

                    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
                    for (int i = 0; i < 64; ++i) {
                        uint32_t f; int g;
                        if (i < 16) { f = (b & c) | (~b & d);  g = i; }
                        else if (i < 32) { f = (d & b) | (~d & c);  g = (5 * i + 1) & 15; }
                        else if (i < 48) { f = b ^ c ^ d;           g = (3 * i + 5) & 15; }
                        else { f = c ^ (b | ~d);        g = (7 * i) & 15; }
                        uint32_t t = d;
                        d = c; c = b;
                        b = b + rotl(a + f + K[i] + m[g], S[i]);
                        a = t;
                    }
                    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
                }

                void update(const void* data, size_t n) {
                    const uint8_t* p = (const uint8_t*)data;
                    total += n;
                    while (n > 0) {
                        size_t take = 64 - blocklen;
                        if (take > n) take = n;
                        std::memcpy(block + blocklen, p, take);
                        blocklen += uint32_t(take);
                        p += take; n -= take;
                        if (blocklen == 64) { compress_block(h, block); blocklen = 0; }
                    }
                }

                void finalize(uint8_t out[16]) {
                    uint64_t bits = total * 8;
                    uint8_t pad[128];
                    std::memset(pad, 0, sizeof(pad));
                    size_t padlen = (blocklen < 56) ? (56 - blocklen) : (120 - blocklen);
                    pad[0] = 0x80;
                    for (int i = 0; i < 8; ++i)
                        pad[padlen + i] = uint8_t(bits >> (8 * i));
                    update(pad, padlen + 8);
                    for (int i = 0; i < 4; ++i) {
                        out[4 * i] = uint8_t(h[i]);
                        out[4 * i + 1] = uint8_t(h[i] >> 8);
                        out[4 * i + 2] = uint8_t(h[i] >> 16);
                        out[4 * i + 3] = uint8_t(h[i] >> 24);
                    }
                }

                static void digest(const void* data, size_t n, uint8_t out[16]) {
                    Md5 m;
                    m.update(data, n);
                    m.finalize(out);
                }
            };

            inline const uint32_t Md5::K[64] = {
                0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
                0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
                0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
                0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
                0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
                0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
                0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
                0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
                0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
                0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
                0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
                0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
                0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
                0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
                0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
                0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
            };

            inline const uint8_t Md5::S[64] = {
                7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
            };

            static void mac_compute(uint32_t unix_ts, const char* key, uint8_t out_m1[16], uint8_t out_m2[16]) {
                char ts[9];
                uint8_t tsb[4] = {
                    uint8_t((unix_ts >> 24) & 0xFF),
                    uint8_t((unix_ts >> 16) & 0xFF),
                    uint8_t((unix_ts >> 8) & 0xFF),
                    uint8_t(unix_ts & 0xFF),
                };
                bytes_to_hex(tsb, 4, ts);
                ts[8] = 0;

                {
                    Md5 m;
                    m.update(ts, 8);
                    m.update(key, std::strlen(key));
                    m.finalize(out_m1);
                }
                {
                    Md5 m;
                    m.update(ts, 8);
                    m.update(kM2Suffix, std::strlen(kM2Suffix));
                    m.finalize(out_m2);
                }
            }

            static std::string generate_a3(uint32_t unix_ts, const uint8_t m1[16], const uint8_t m2[16]) {
                char buf[A3_TOTAL_LEN + 1];

                unsigned p = ((day_counter(unix_ts) - 1) % 99) + 1;
                buf[0] = char('0' + (p / 10) % 10);
                buf[1] = char('0' + (p % 10));

                char ts[9];
                uint8_t tsb[4] = {
                    uint8_t((unix_ts >> 24) & 0xFF),
                    uint8_t((unix_ts >> 16) & 0xFF),
                    uint8_t((unix_ts >> 8) & 0xFF),
                    uint8_t(unix_ts & 0xFF),
                };
                bytes_to_hex(tsb, 4, ts);
                ts[8] = 0;
                std::memcpy(buf + A3_TS_OFF, ts, 8);

                buf[2 + 8] = '_';

                char m1h[32];
                bytes_to_hex(m1, 16, m1h);
                std::memcpy(buf + A3_M1_OFF, m1h, 32);
                buf[A3_M1_OFF + 32] = '_';

                char m2h[32];
                bytes_to_hex(m2, 16, m2h);
                std::memcpy(buf + A3_M2_OFF, m2h, 32);

                buf[A3_TOTAL_LEN] = 0;
                return std::string(buf, A3_TOTAL_LEN);
            }

        } // namespace solve

        inline std::string solve(const std::string& challenge) {
            if (challenge.size() < 8) return std::string();
            uint32_t ts = 0;
            for (int i = 0; i < 8; ++i) {
                char c = challenge[i];
                uint8_t v = (c >= '0' && c <= '9') ? uint8_t(c - '0')
                    : (c >= 'a' && c <= 'f') ? uint8_t(c - 'a' + 10)
                    : (c >= 'A' && c <= 'F') ? uint8_t(c - 'A' + 10)
                    : 0;
                ts = (ts << 4) | v;
            }
            char key[48] = { 0 };
            if (key::decode_key(challenge, key) == 0) return std::string();
            uint8_t m1[16], m2[16];
            challenge::mac_compute(ts, key, m1, m2);
            std::string response = challenge::generate_a3(ts, m1, m2);
            return response;
        }

    } // namespace xem

    namespace client {

        namespace helper {

            inline uint8_t* find_pattern(const int* p, size_t n) noexcept {
                if (!p || n == 0) return nullptr;
                HMODULE m = GetModuleHandleA(nullptr);
                if (!m) return nullptr;
                auto* im = reinterpret_cast<uint8_t*>(m);
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(im);
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(im + dos->e_lfanew);
                DWORD is = nt->OptionalHeader.SizeOfImage;
                if ((size_t)is < n) return nullptr;
                size_t lim = (size_t)is - n + 1;
                for (size_t i = 0; i < lim; ++i) {
                    bool f = true;
                    for (size_t j = 0; j < n; ++j) { if (im[i + j] != (uint8_t)p[j] && p[j] != -1) { f = false; break; } }
                    if (f) return &im[i];
                }
                return nullptr;
            }

            inline uint8_t* resolve_relative(uint8_t* i, size_t o, size_t s) { auto d = *reinterpret_cast<const int32_t*>(reinterpret_cast<uintptr_t>(i) + o); return i + s + d; }

            inline bool is_valid_ptr(const void* p, size_t n = 1) {
                if (!p) return false;
                MEMORY_BASIC_INFORMATION m{};
                if (VirtualQuery(p, &m, sizeof(m)) == 0) return false;
                if (m.State != MEM_COMMIT) return false;
                if (m.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
                auto re = reinterpret_cast<const uint8_t*>(m.BaseAddress) + m.RegionSize;
                auto pe = reinterpret_cast<const uint8_t*>(p) + n;
                return pe <= re;
            }

            inline std::vector<HANDLE> freeze() {
                DWORD ct = GetCurrentThreadId(); DWORD pd = GetCurrentProcessId();
                HANDLE sn = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (sn == INVALID_HANDLE_VALUE) return {};
                THREADENTRY32 te{ sizeof(THREADENTRY32) };
                std::vector<HANDLE> v;
                if (Thread32First(sn, &te)) {
                    do {
                        if (te.th32OwnerProcessID != pd) continue;
                        if (te.th32ThreadID == ct) continue;
                        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (h) { SuspendThread(h); v.push_back(h); }
                    } while (Thread32Next(sn, &te));
                }
                CloseHandle(sn);
                return v;
            }

            inline void unfreeze(const std::vector<HANDLE>& v) { for (HANDLE h : v) { ResumeThread(h); CloseHandle(h); } }

        } // namespace helper

        void pop() {
            auto m = [](LPVOID) -> DWORD {
                MessageBoxA(NULL, "Xigncode bypass has failed and must be updated.\nTo protect you and your computer the program has been closed.", "Failure", MB_OK | MB_ICONINFORMATION);
                return 0;
                };
            helper::freeze();
            HANDLE h = CreateThread(NULL, 0, m, NULL, 0, NULL);
            if (h) { WaitForSingleObject(h, INFINITE); CloseHandle(h); }
            TerminateProcess(GetCurrentProcess(), 0xC0000409u);
            ExitProcess(0xC0000409u);
            int* dd = nullptr; *dd = 42;
        }

        template <typename T>
        static bool hk(const char* dd, const char* n, void* h, T* o) {
            HMODULE m = GetModuleHandleA(dd);
            if (!m) return false;
            FARPROC f = GetProcAddress(m, n);
            if (!f) return false;
            if (MH_CreateHook(f, h, (void**)o) != MH_OK) return false;
            if (MH_EnableHook(f) != MH_OK) return false;
            return true;
        }

        typedef int(__stdcall* sd_t)(UINT_PTR, const char*, int, int);
        typedef int(__stdcall* rc_t)(UINT_PTR, char*, int, int);
        typedef int(__stdcall* cn_t)(UINT_PTR, const struct sockaddr*, int);
        static sd_t os = nullptr;
        static rc_t orr = nullptr;
        static cn_t oc = nullptr;

        int __stdcall hs(UINT_PTR, const char*, int n, int) { return n; }
        int __stdcall hr(UINT_PTR, char*, int n, int) { return n; }
        int __stdcall hc(UINT_PTR, const struct sockaddr*, int) { return 1; }

        typedef int(__fastcall* tAC_OnProbeResponse)(uint64_t, const char*, const char*, size_t, uint64_t);
        typedef __int64(__fastcall* tAC_SendStateChange)(unsigned, uint64_t*);
        static tAC_OnProbeResponse oAC_OnProbeResponse = nullptr;
        static tAC_SendStateChange oAC_SendStateChange = nullptr;

        static __int64 __fastcall hkAC_SendStateChange(unsigned a, uint64_t* v) {
            if (a == 85) {
                const char* challenge = (const char*)v[0];
                std::string response = xem::solve(std::string(challenge));
                if (response.empty()) { pop(); return 1; }
                oAC_OnProbeResponse((uint64_t)challenge, challenge, response.c_str(), (size_t)v[1], v[4]);
            }
            return 1;
        }

        static void strip() {
            static const int p[] = { // 80 3D ? ? ? ? 00 74 ? 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 48 83 3D ? ? ? ? 00
                0x80,0x3D,-1,-1,-1,-1,0x00,0x74,-1,
                0x80,0x3D,-1,-1,-1,-1,0x00,0x0F,0x85,-1,-1,-1,-1,
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

	} // namespace client

} // namespace detail





// ----- PUBLIC API -----

namespace xigncode {

    inline void initialize() {
        // Updated 2026-09-16
		constexpr LONGLONG file_size = 6885808; // Expected size of the x3_x64.xem file
        HANDLE h = CreateFileW(L"XIGNCODE\\Client\\1__live\\x3_x64.xem", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { LARGE_INTEGER size; if (GetFileSizeEx(h, &size)) if (size.QuadPart != file_size) detail::client::pop(); CloseHandle(h); }

        MH_Initialize();
        detail::client::strip();
        detail::client::hk("ws2_32.dll", "send", detail::client::hs, &detail::client::os);
        detail::client::hk("ws2_32.dll", "recv", detail::client::hr, &detail::client::orr);
        detail::client::hk("ws2_32.dll", "connect", detail::client::hc, &detail::client::oc);
        {   // AC_SendStateChange: 89 4C 24 ? 48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 48 83 EC
            const int p[] = {
                0x48,0x89,0x5C,0x24,-1,0x57,0x48,0x83,0xEC,-1,
                0x48,0x8B,0x05,-1,-1,-1,-1,0x48,0x8B,0xDA,0x8B,0xF9,0x48,0x85,0xC0
            };
            uint8_t* a = detail::client::helper::find_pattern(p, sizeof(p) / sizeof(int));
            if (!a || MH_CreateHook(a, detail::client::hkAC_SendStateChange, (void**)&detail::client::oAC_SendStateChange) != MH_OK || MH_EnableHook(a) != MH_OK)
                detail::client::pop();
        }
        {   // AC_OnProbeResponse: 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 9C 24 ? ? ? ? 49 8B F1
            const int p[] = {
                0x48,0x8B,0xC4,0x48,0x83,0xEC,-1,0x48,0x89,0x58,-1,0x48,0x8B,0x9C,0x24
            };
            uint8_t* a = detail::client::helper::find_pattern(p, sizeof(p) / sizeof(int));
            if (a) detail::client::oAC_OnProbeResponse = reinterpret_cast<detail::client::tAC_OnProbeResponse>(a);
        }
    }

}  // namespace xigncode