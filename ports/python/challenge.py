# File: challenge.py
# Port of the `detail::xem` namespace from challenge.hpp.
# Solve the daily M1 key from a challenge and build the response.
#
#   challenge = hex8(ts) + Z85(body)
#   body[36+i*128 .. 36+(i+1)*128] = RSA-encrypted 128-byte records
#   m = record ^ 65537 mod N          (public verify op)
#   stream = concat(m[3:128])         (875 bytes)
#   LZMA1 (mirrored range coder) -> Lua chunk
#   key = "_2JP" 0x04 <lenbyte> <key[i]^i>
#   M1 = MD5(hex8(ts) + key)
#   M2 = MD5(hex8(ts) + kM2Suffix)
#   response = pp + "_" + hex8(ts) + "_" + hex32(M1) + "_" + hex32(M2)
#
# Usage:
#   from challenge import solve
#   print(solve(challenge))
#
# If run directly:
#   python challenge.py <challenge>
#
# Only the standard library is required.

import sys


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 1024-bit RSA modulus (public verify op). 32 little-endian u32 limbs.
kRsaN = [
    0x40c3d6b3, 0xb55d9978, 0xc19a3442, 0x911e015c, 0x83ff249c, 0xfc86f025,
    0x236b2c1e, 0x54f76c5e, 0xebeaa476, 0x7be90ce0, 0x90fc5321, 0x63da15e3,
    0x65a31488, 0x867d9311, 0xf1d55222, 0xe03ec2a6, 0x3c4d0c63, 0x83543f35,
    0xaee8c44b, 0xedbe21c6, 0xa51988ae, 0xa8090b6f, 0xa95a959d, 0x72df4268,
    0xa6eb052c, 0xbc3a4200, 0x227895bf, 0xe5a5539a, 0x5219a713, 0x44e788d5,
    0x01f53eb8, 0xb21cb874,
]

# Response layout.
kM2Suffix = "{CBEC4943-AFE5-4F24-A6FA-2DC80D1A1A18}"          # hardcoded, may change
CHALLENGE_BODY_PREFIX = "mz865r6:zF0SSi2"
CHALLENGE_BODY_LEN = 1166
RESPONSE_TOTAL_LEN = 76
RESPONSE_TS_OFF = 2
RESPONSE_M1_OFF = 11
RESPONSE_M2_OFF = 44

# Z85 alphabet.
Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_Z85_INDEX = {c: i for i, c in enumerate(Z85)}


# ---------------------------------------------------------------------------
# 1024-bit modular arithmetic (RSA public op)
# ---------------------------------------------------------------------------

def rsa_pub(in_bytes: bytes) -> bytes:
    """out = in ^ 65537 mod N  (in/out are 128-byte big-endian)."""
    nlimbs = len(kRsaN)

    def big_cmp(a, b, n):
        for i in range(n - 1, -1, -1):
            if a[i] != b[i]:
                return -1 if a[i] < b[i] else 1
        return 0

    def big_reduce(t, n):
        """r = t mod N (t has 2n limbs, N has n limbs) - bit-level long division."""
        R = [0] * (n + 1)
        total_bits = 2 * n * 32
        for bit in range(total_bits - 1, -1, -1):
            carry = (t[bit >> 5] >> (bit & 31)) & 1
            for i in range(n + 1):
                nc = R[i] >> 31
                R[i] = ((R[i] << 1) | carry) & 0xFFFFFFFF
                carry = nc
            if R[n] != 0 or big_cmp(R, kRsaN, n) >= 0:
                borrow = 0
                for i in range(n):
                    cur = R[i] - kRsaN[i] - borrow
                    R[i] = cur & 0xFFFFFFFF
                    borrow = (cur >> 63) & 1
                R[n] = 0
        return R[:n]

    def big_modmul(a, b):
        # a, b are n limbs; return (a*b) mod N as n limbs.
        n = len(a)
        t = [0] * (2 * n)
        for i in range(n):
            carry = 0
            for j in range(n):
                cur = a[i] * b[j] + t[i + j] + carry
                t[i + j] = cur & 0xFFFFFFFF
                carry = cur >> 32
            k = i + n
            while carry:
                cur = t[k] + carry
                t[k] = cur & 0xFFFFFFFF
                carry = cur >> 32
                k += 1
        return big_reduce(t, n)

    # Unpack 128-byte big-endian input into little-endian u32 limbs.
    base = [0] * nlimbs
    for i in range(nlimbs):
        off = 128 - 4 * (i + 1)
        base[i] = (in_bytes[off] << 24) | (in_bytes[off + 1] << 16) \
            | (in_bytes[off + 2] << 8) | in_bytes[off + 3]

    x = base[:]
    for _ in range(16):  # 16 squarings -> base^(2^16)
        x = big_modmul(x, x)
    result = big_modmul(x, base)  # * base -> base^65537

    out = bytearray(128)
    for i in range(nlimbs):
        off = 128 - 4 * (i + 1)
        out[off] = (result[i] >> 24) & 0xFF
        out[off + 1] = (result[i] >> 16) & 0xFF
        out[off + 2] = (result[i] >> 8) & 0xFF
        out[off + 3] = result[i] & 0xFF
    return bytes(out)


# ---------------------------------------------------------------------------
# Z85 decode
# ---------------------------------------------------------------------------

def z85_decode(s: str) -> bytes:
    olen = 0
    out = bytearray()
    i = 0
    n = len(s)
    while i + 5 <= n:
        v = 0
        ok = True
        for j in range(5):
            ch = s[i + j]
            if ch not in _Z85_INDEX:
                ok = False
                break
            v = v * 85 + _Z85_INDEX[ch]
        if not ok:
            break
        out.append((v >> 24) & 0xFF)
        out.append((v >> 16) & 0xFF)
        out.append((v >> 8) & 0xFF)
        out.append(v & 0xFF)
        olen += 4
        i += 5
    return bytes(out)


# ---------------------------------------------------------------------------
# LZMA1 (mirrored range coder)
# ---------------------------------------------------------------------------

class Lzma:
    ISMATCH = 0
    ISREP = 192
    ISREPG0 = 204
    ISREPG1 = 216
    ISREPG2 = 228
    ISREP0LONG = 240
    POSSLOT = 432
    SPECPOS = 687
    ALIGN = 802
    LEN = 818
    REPLEN = 1332
    LITERAL = 1846

    def __init__(self, stream: bytes, out_size: int):
        self.data = stream
        self.pos = 5
        self.range = (stream[1] << 24) | (stream[2] << 16) | (stream[3] << 8) | stream[4]
        self.code = 0xFFFFFFFF
        self.probs = [0x400] * 8192
        self.reps = [1, 1, 1, 1]
        self.state = 0
        self.out = bytearray(out_size)
        self.opos = 0
        self.out_size = out_size

    def normalize(self):
        if self.code < 0x1000000:
            self.range = ((self.range << 8) | self.data[self.pos]) & 0xFFFFFFFF
            self.code = (self.code << 8) & 0xFFFFFFFF
            self.pos += 1

    def bit(self, prob_idx):
        self.normalize()
        prob = self.probs[prob_idx]
        bound = (self.code >> 11) * prob
        if self.range < bound:
            self.code = bound
            self.probs[prob_idx] = (prob + ((0x800 - prob) >> 5)) & 0xFFFF
            return 0
        self.range = (self.range - bound) & 0xFFFFFFFF
        self.code = (self.code - bound) & 0xFFFFFFFF
        self.probs[prob_idx] = (prob - (prob >> 5)) & 0xFFFF
        return 1

    def dbit(self):
        self.normalize()
        self.code >>= 1
        self.range = (self.range - self.code) & 0xFFFFFFFF
        if self.range & 0x80000000:
            self.range = (self.range + self.code) & 0xFFFFFFFF
            return 0
        return 1

    def len_decode(self, base):
        if self.bit(base) == 0:
            ps = self.opos & 3
            sym = 1
            for _ in range(3):
                sym = (sym << 1) | self.bit(base + 2 + ps * 8 + sym)
            return sym - 8
        elif self.bit(base + 1) == 0:
            ps = self.opos & 3
            sym = 1
            for _ in range(3):
                sym = (sym << 1) | self.bit(base + 130 + ps * 8 + sym)
            return sym
        else:
            sym = 1
            for _ in range(8):
                sym = (sym << 1) | self.bit(base + 258 + sym)
            return sym - 256 + 16

    def decode(self):
        while self.opos < self.out_size:
            ps = self.opos & 3
            if self.bit(self.ISMATCH + self.state * 16 + ps) == 0:
                prev = self.out[self.opos - 1] if self.opos > 0 else 0
                lit_state = prev >> (8 - 3)  # lc=3, lp=0
                base = self.LITERAL + 0x300 * lit_state
                if self.state < 7:
                    sym = 1
                    while sym < 0x100:
                        sym = (sym << 1) | self.bit(base + sym)
                    self.out[self.opos] = sym & 0xFF
                    self.opos += 1
                else:
                    match_byte = self.out[self.opos - self.reps[0]]
                    sym = 1
                    matched = True
                    for _ in range(8):
                        match_bit = (match_byte >> 7) & 1
                        match_byte = (match_byte << 1) & 0xFF
                        idx = (0x100 + match_bit * 0x100 + sym) if matched else sym
                        b = self.bit(base + idx)
                        sym = (sym << 1) | b
                        if matched and match_bit != b:
                            matched = False
                    self.out[self.opos] = sym & 0xFF
                    self.opos += 1
                self.state = 0 if self.state < 4 else (self.state - 3 if self.state < 10 else self.state - 6)
            else:
                length = 0
                if self.bit(self.ISREP + self.state) == 0:
                    self.reps[3] = self.reps[2]
                    self.reps[2] = self.reps[1]
                    self.reps[1] = self.reps[0]
                    length = self.len_decode(self.LEN)
                    ltp = length if length < 4 else 3
                    slot = 1
                    for _ in range(6):
                        slot = (slot << 1) | self.bit(self.POSSLOT + ltp * 64 + slot)
                    slot -= 64
                    if slot < 4:
                        d = slot
                    elif slot < 14:
                        num_bits = (slot >> 1) - 1
                        d = (2 | (slot & 1)) << num_bits
                        idx = d - slot
                        tree = 1
                        for j in range(num_bits):
                            b = self.bit(self.SPECPOS + idx + tree)
                            tree = (tree << 1) | b
                            if b:
                                d |= (1 << j)
                    else:
                        num_bits = (slot >> 1) - 1
                        d = 2 | (slot & 1)
                        for _ in range(num_bits - 4):
                            d = (d << 1) | self.dbit()
                        d <<= 4
                        i = 1
                        for j in range(4):
                            b = self.bit(self.ALIGN + i)
                            i = (i << 1) | b
                            if b:
                                d |= (1 << j)
                    self.reps[0] = d + 1
                    self.state = 7 if self.state < 7 else 10
                    length += 2
                else:
                    if self.bit(self.ISREPG0 + self.state) == 0:
                        if self.bit(self.ISREP0LONG + self.state * 16 + ps) == 0:
                            self.state = 9 if self.state < 7 else 11
                            length = 1
                        else:
                            length = self.len_decode(self.REPLEN) + 2
                            self.state = 8 if self.state < 7 else 11
                    else:
                        if self.bit(self.ISREPG1 + self.state):
                            if self.bit(self.ISREPG2 + self.state):
                                d = self.reps[3]
                                self.reps[3] = self.reps[2]
                            else:
                                d = self.reps[2]
                            self.reps[2] = self.reps[1]
                        else:
                            d = self.reps[1]
                        self.reps[1] = self.reps[0]
                        self.reps[0] = d
                        length = self.len_decode(self.REPLEN) + 2
                        self.state = 8 if self.state < 7 else 11
                for _ in range(length):
                    if self.opos >= self.out_size or self.opos - self.reps[0] < 0:
                        return
                    self.out[self.opos] = self.out[self.opos - self.reps[0]]
                    self.opos += 1


# ---------------------------------------------------------------------------
# MD5 (hand-rolled, matches challenge.hpp)
# ---------------------------------------------------------------------------

class Md5:
    def __init__(self):
        self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self.total = 0
        self.block = bytearray(64)
        self.blocklen = 0

    K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]

    S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]

    @staticmethod
    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def compress_block(self, p):
        m = [0] * 16
        for i in range(16):
            m[i] = p[4 * i] | (p[4 * i + 1] << 8) | (p[4 * i + 2] << 16) | (p[4 * i + 3] << 24)
        a, b, c, d = self.h
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) & 15
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) & 15
            else:
                f = c ^ (b | ~d)
                g = (7 * i) & 15
            f &= 0xFFFFFFFF
            t = d
            d = c
            c = b
            b = (b + self.rotl((a + f + self.K[i] + m[g]) & 0xFFFFFFFF, self.S[i])) & 0xFFFFFFFF
            a = t
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF

    def update(self, data):
        p = data
        self.total += len(data)
        i = 0
        n = len(data)
        while n > 0:
            take = 64 - self.blocklen
            if take > n:
                take = n
            self.block[self.blocklen:self.blocklen + take] = p[i:i + take]
            self.blocklen += take
            i += take
            n -= take
            if self.blocklen == 64:
                self.compress_block(self.block)
                self.blocklen = 0

    def finalize(self):
        bits = self.total * 8
        pad = bytearray(128)
        padlen = (56 - self.blocklen) if self.blocklen < 56 else (120 - self.blocklen)
        pad[0] = 0x80
        for i in range(8):
            pad[padlen + i] = (bits >> (8 * i)) & 0xFF
        self.update(bytes(pad[:padlen + 8]))
        out = bytearray(16)
        for i in range(4):
            out[4 * i] = self.h[i] & 0xFF
            out[4 * i + 1] = (self.h[i] >> 8) & 0xFF
            out[4 * i + 2] = (self.h[i] >> 16) & 0xFF
            out[4 * i + 3] = (self.h[i] >> 24) & 0xFF
        return bytes(out)

    @staticmethod
    def digest(data):
        m = Md5()
        m.update(data)
        return m.finalize()


# ---------------------------------------------------------------------------
# Key decoding and MAC computation
# ---------------------------------------------------------------------------

def _bytes_to_hex(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)


def _hex8_ts(ts: int) -> bytes:
    """Encode a 4-byte timestamp as an ASCII 8-hex-char string."""
    tsb = bytes([
        (ts >> 24) & 0xFF,
        (ts >> 16) & 0xFF,
        (ts >> 8) & 0xFF,
        ts & 0xFF,
    ])
    return _bytes_to_hex(tsb).encode('ascii')


def decode_key(challenge: str) -> str:
    """Decode the daily M1 key from the challenge; returns '' on failure."""
    body = z85_decode(challenge[8:])
    if len(body) < 36 + 128 * 7:
        return ''

    stream = bytearray(875)
    for i in range(7):
        record = body[36 + i * 128: 36 + (i + 1) * 128]
        m = rsa_pub(record)
        for j in range(125):
            stream[i * 125 + j] = m[3 + j]

    out_size = body[24] | (body[25] << 8) | (body[26] << 16) | (body[27] << 24)
    if out_size <= 0 or out_size > 0x10000:
        return ''

    lz = Lzma(bytes(stream), out_size)
    lz.decode()
    out = lz.out[:lz.opos]

    # find the key: "_2JP" 0x04 <lenbyte> <key[i]^i>, short key (8..32)
    for i in range(len(out) - 6 + 1):
        if (out[i] == ord('_') and out[i + 1] == ord('2') and out[i + 2] == ord('J')
                and out[i + 3] == ord('P') and out[i + 4] == 0x04):
            klen = out[i + 5] - 1
            if 8 <= klen <= 32:
                return ''.join(chr(out[i + 6 + j] ^ j) for j in range(klen))
    return ''


def day_counter(unix_ts: int) -> int:
    day = unix_ts // 86400
    diff = day - 20592
    return diff


def mac_compute(unix_ts: int, key: str):
    ts = _hex8_ts(unix_ts)
    m1 = Md5.digest(ts + key.encode('ascii'))
    m2 = Md5.digest(ts + kM2Suffix.encode('ascii'))
    return m1, m2


def generate_response(unix_ts: int, m1: bytes, m2: bytes) -> str:
    buf = bytearray(RESPONSE_TOTAL_LEN)

    p = ((day_counter(unix_ts) - 1) % 99) + 1
    buf[0] = ord('0') + (p // 10) % 10
    buf[1] = ord('0') + (p % 10)

    ts = _hex8_ts(unix_ts)
    buf[RESPONSE_TS_OFF:RESPONSE_TS_OFF + 8] = ts

    buf[2 + 8] = ord('_')

    m1h = _bytes_to_hex(m1).encode('ascii')
    buf[RESPONSE_M1_OFF:RESPONSE_M1_OFF + 32] = m1h
    buf[RESPONSE_M1_OFF + 32] = ord('_')

    m2h = _bytes_to_hex(m2).encode('ascii')
    buf[RESPONSE_M2_OFF:RESPONSE_M2_OFF + 32] = m2h

    return buf.decode('ascii')


def solve(challenge: str) -> str:
    """Turn a challenge into a response. Returns '' on failure."""
    if len(challenge) < 8:
        return ''
    ts = 0
    for i in range(8):
        c = challenge[i]
        if '0' <= c <= '9':
            v = ord(c) - ord('0')
        elif 'a' <= c <= 'f':
            v = ord(c) - ord('a') + 10
        elif 'A' <= c <= 'F':
            v = ord(c) - ord('A') + 10
        else:
            v = 0
        ts = (ts << 4) | v

    key = decode_key(challenge)
    if key == '':
        return ''
    m1, m2 = mac_compute(ts, key)
    return generate_response(ts, m1, m2)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python challenge.py <challenge>')
        sys.exit(1)
    response = solve(sys.argv[1].strip())
    if response:
        print(response)
    else:
        print('solve() failed (empty response)', file=sys.stderr)
        sys.exit(2)
