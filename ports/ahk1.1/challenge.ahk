; ============================================================================
; File: challenge.ahk
; Port of the `detail::xem` namespace from challenge.hpp (AutoHotkey v1.1).
; Solve the daily M1 key from a challenge and build the response.
;
;   challenge = hex8(ts) + Z85(body)
;   body[36+i*128 .. 36+(i+1)*128] = RSA-encrypted 128-byte records
;   m = record ^ 65537 mod N          (public verify op)
;   stream = concat(m[3:128])         (875 bytes)
;   LZMA1 (mirrored range coder) -> Lua chunk
;   key = "_2JP" 0x04 <lenbyte> <key[i]^i>
;   M1 = MD5(hex8(ts) + key)
;   M2 = MD5(hex8(ts) + kM2Suffix)
;   response = pp + hex8(ts) + "_" + hex32(M1) + "_" + hex32(M2)
;
; Usage (as a library):
;   #Include challenge.ahk
;   response := Solve(challenge)
; ============================================================================

; ---------------------------------------------------------------------------
; Constants
; ---------------------------------------------------------------------------

; 1024-bit RSA modulus (public verify op). 32 little-endian u32 limbs.
kRsaN := [0x40c3d6b3, 0xb55d9978, 0xc19a3442, 0x911e015c
        , 0x83ff249c, 0xfc86f025, 0x236b2c1e, 0x54f76c5e
        , 0xebeaa476, 0x7be90ce0, 0x90fc5321, 0x63da15e3
        , 0x65a31488, 0x867d9311, 0xf1d55222, 0xe03ec2a6
        , 0x3c4d0c63, 0x83543f35, 0xaee8c44b, 0xedbe21c6
        , 0xa51988ae, 0xa8090b6f, 0xa95a959d, 0x72df4268
        , 0xa6eb052c, 0xbc3a4200, 0x227895bf, 0xe5a5539a
        , 0x5219a713, 0x44e788d5, 0x01f53eb8, 0xb21cb874]

kM2Suffix := "{CBEC4943-AFE5-4F24-A6FA-2DC80D1A1A18}"
RESPONSE_TOTAL_LEN := 76
RESPONSE_TS_OFF := 2
RESPONSE_M1_OFF := 11
RESPONSE_M2_OFF := 44

Z85 := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
; Reverse index keyed by the character's ASCII code (integer key), to avoid
; AHK v1.1's ambiguous single-character string-key coercion for object keys.
_Z85Index := {}
Loop, % StrLen(Z85)
    _Z85Index[Asc(SubStr(Z85, A_Index, 1))] := A_Index - 1

; ---------------------------------------------------------------------------
; Small numeric helpers
; ---------------------------------------------------------------------------

; Full-width logical right shift: floor(a / 2^n). Exact for a < 2^63.
shr64(a, n) {
    return a // (1 << n)
}

; Rotate-left for a 32-bit value.
rotl(x, n) {
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
}

; 32-bit bitwise NOT (returns value in [0, 2^32)).
bnot32(x) {
    return (~x) & 0xFFFFFFFF
}

; ---------------------------------------------------------------------------
; 1024-bit modular arithmetic (RSA public op)
; ---------------------------------------------------------------------------

; Compare two n-limb (1-based) little-endian arrays. Returns -1 / 0 / 1.
big_cmp(a, b, n) {
    Loop, % n
    {
        i := n - A_Index + 1
        if (a[i] != b[i])
            return (a[i] < b[i]) ? -1 : 1
    }
    return 0
}

; r = t mod N.  t: 1-based 2n-limb array; N (kRsaN): 1-based n-limb array.
big_reduce(t, n) {
    global kRsaN
    R := []
    Loop, % n + 1
        R[A_Index] := 0
    totalBits := 2 * n * 32
    Loop, % totalBits
    {
        bit := totalBits - A_Index
        woff := (bit >> 5) + 1                     ; 1-based limb index into t
        carry := (t[woff] >> (bit & 31)) & 1
        Loop, % n + 1
        {
            i := A_Index
            nc := R[i] >> 31
            R[i] := ((R[i] << 1) | carry) & 0xFFFFFFFF
            carry := nc
        }
        if (R[n + 1] != 0 || big_cmp(R, kRsaN, n) >= 0)
        {
            borrow := 0
            Loop, % n
            {
                i := A_Index
                cur := R[i] - kRsaN[i] - borrow
                R[i] := cur & 0xFFFFFFFF
                borrow := (cur >> 63) & 1
            }
            R[n + 1] := 0
        }
    }
    out := []
    Loop, % n
        out[A_Index] := R[A_Index]
    return out
}

; Multiply two 32-bit unsigned values. Returns array [hi, lo] in [0, 2^32).
umul32(a, b) {
    a0 := a & 0xFFFF
    a1 := a >> 16
    b0 := b & 0xFFFF
    b1 := b >> 16
    p := a0 * b0
    w0 := p & 0xFFFF
    carry := p >> 16
    p := a0 * b1 + a1 * b0 + carry
    w1 := p & 0xFFFF
    carry := p >> 16
    p := a1 * b1 + carry
    w2 := p & 0xFFFF
    carry := p >> 16
    lo := (w1 << 16) | w0
    hi := (carry << 16) | w2
    return [hi, lo]
}

; a, b are n-limb (1-based) arrays; return (a*b) mod N as an n-limb array.
big_modmul(a, b) {
    n := a.Length()
    t := []
    Loop, % 2 * n
        t[A_Index] := 0
    Loop, % n
    {
        i := A_Index - 1                            ; 0-based row
        carry := 0
        Loop, % n
        {
            j := A_Index - 1                        ; 0-based col
            r := umul32(a[i + 1], b[j + 1])
            hi := r[1]
            lo := r[2]
            acc := lo + t[i + j + 1] + carry
            t[i + j + 1] := acc & 0xFFFFFFFF
            carry := shr64(acc, 32) + hi
        }
        k := i + n
        while (carry != 0)
        {
            acc := t[k + 1] + carry
            t[k + 1] := acc & 0xFFFFFFFF
            carry := shr64(acc, 32)
            k += 1
        }
    }
    return big_reduce(t, n)
}

; out = in ^ 65537 mod N.  in: 1-based byte array of length 128.
rsa_pub(inBytes) {
    global kRsaN
    KLIMBS := kRsaN.Length()
    base := []
    Loop, % KLIMBS
    {
        i := A_Index - 1                            ; 0-based limb index
        off := 128 - 4 * (i + 1)                    ; 0-based byte offset
        o := off + 1                                ; 1-based
        base[A_Index] := (inBytes[o] << 24) | (inBytes[o + 1] << 16)
                       | (inBytes[o + 2] << 8) | inBytes[o + 3]
    }
    x := base.Clone()
    Loop, 16                                        ; 16 squarings -> base^(2^16)
        x := big_modmul(x, x)
    result := big_modmul(x, base)                   ; * base -> base^65537

    out := []
    Loop, 128
        out[A_Index] := 0
    Loop, % KLIMBS
    {
        i := A_Index - 1
        off := 128 - 4 * (i + 1)
        o := off + 1
        out[o]     := (result[A_Index] >> 24) & 0xFF
        out[o + 1] := (result[A_Index] >> 16) & 0xFF
        out[o + 2] := (result[A_Index] >> 8) & 0xFF
        out[o + 3] := result[A_Index] & 0xFF
    }
    return out
}

; ---------------------------------------------------------------------------
; Z85 decode
; ---------------------------------------------------------------------------

; Decode a Z85 string into a 1-based byte array.
z85_decode(s) {
    global _Z85Index
    out := []
    i := 1
    n := StrLen(s)
    while (i + 4 <= n)
    {
        v := 0
        ok := true
        Loop, 5
        {
            j := A_Index - 1
            c := SubStr(s, i + j, 1)
            idx := _Z85Index[Asc(c)]
            if (idx = "")
            {
                ok := false
                break
            }
            v := v * 85 + idx
        }
        if (!ok)
            break
        out.Push((v >> 24) & 0xFF)
        out.Push((v >> 16) & 0xFF)
        out.Push((v >> 8) & 0xFF)
        out.Push(v & 0xFF)
        i += 5
    }
    return out
}

; ---------------------------------------------------------------------------
; LZMA1 (mirrored range coder)
; ---------------------------------------------------------------------------

ISMATCH   := 0
ISREP     := 192
ISREPG0   := 204
ISREPG1   := 216
ISREPG2   := 228
ISREP0LONG := 240
POSSLOT   := 432
SPECPOS   := 687
ALIGN     := 802
LEN       := 818
REPLEN    := 1332
LITERAL   := 1846

Lzma_new(stream, outSize) {
    self := {}
    self.data := stream            ; 1-based
    self.pos := 6                  ; 0-based pos 5 -> 1-based index 6
    self.range := (stream[2] << 24) | (stream[3] << 16) | (stream[4] << 8) | stream[5]
    self.code := 0xFFFFFFFF
    self.probs := []
    Loop, 8192
        self.probs[A_Index] := 0x400
    self.reps := [1, 1, 1, 1]
    self.state := 0
    self.out := []
    self.opos := 0
    self.outSize := outSize
    return self
}

Lzma_normalize(self) {
    if (self.code < 0x1000000)
    {
        self.range := ((self.range << 8) | self.data[self.pos]) & 0xFFFFFFFF
        self.code := (self.code << 8) & 0xFFFFFFFF
        self.pos += 1
    }
}

Lzma_bit(self, probIdx) {
    Lzma_normalize(self)
    prob := self.probs[probIdx + 1]
    bound := shr64(self.code, 11) * prob
    if (self.range < bound)
    {
        self.code := bound
        self.probs[probIdx + 1] := (prob + ((0x800 - prob) >> 5)) & 0xFFFF
        return 0
    }
    self.range := (self.range - bound) & 0xFFFFFFFF
    self.code := (self.code - bound) & 0xFFFFFFFF
    self.probs[probIdx + 1] := (prob - (prob >> 5)) & 0xFFFF
    return 1
}

Lzma_dbit(self) {
    Lzma_normalize(self)
    self.code := shr64(self.code, 1)
    self.range := (self.range - self.code) & 0xFFFFFFFF
    if (self.range & 0x80000000)
    {
        self.range := (self.range + self.code) & 0xFFFFFFFF
        return 0
    }
    return 1
}

Lzma_len_decode(self, base) {
    global
    if (Lzma_bit(self, base) == 0)
    {
        ps := self.opos & 3
        sym := 1
        Loop, 3
            sym := (sym << 1) | Lzma_bit(self, base + 2 + ps * 8 + sym)
        return sym - 8
    }
    else if (Lzma_bit(self, base + 1) == 0)
    {
        ps := self.opos & 3
        sym := 1
        Loop, 3
            sym := (sym << 1) | Lzma_bit(self, base + 130 + ps * 8 + sym)
        return sym
    }
    else
    {
        sym := 1
        Loop, 8
            sym := (sym << 1) | Lzma_bit(self, base + 258 + sym)
        return sym - 256 + 16
    }
}

Lzma_decode(self) {
    global ISMATCH, ISREP, ISREPG0, ISREPG1, ISREPG2, ISREP0LONG
        , POSSLOT, SPECPOS, ALIGN, LEN, REPLEN, LITERAL
    while (self.opos < self.outSize)
    {
        ps := self.opos & 3
        if (Lzma_bit(self, ISMATCH + self.state * 16 + ps) == 0)
        {
            prev := 0
            if (self.opos > 0)
                prev := self.out[self.opos]
            litState := prev >> (8 - 3)          ; lc=3, lp=0
            base := LITERAL + 0x300 * litState
            if (self.state < 7)
            {
                sym := 1
                while (sym < 0x100)
                    sym := (sym << 1) | Lzma_bit(self, base + sym)
                self.opos += 1
                self.out[self.opos] := sym & 0xFF
            }
            else
            {
                matchByte := self.out[self.opos - self.reps[1] + 1]
                sym := 1
                matched := true
                Loop, 8
                {
                    matchBit := (matchByte >> 7) & 1
                    matchByte := (matchByte << 1) & 0xFF
                    if (matched)
                        idx := 0x100 + matchBit * 0x100 + sym
                    else
                        idx := sym
                    b := Lzma_bit(self, base + idx)
                    sym := (sym << 1) | b
                    if (matched && matchBit != b)
                        matched := false
                }
                self.opos += 1
                self.out[self.opos] := sym & 0xFF
            }
            if (self.state < 4)
                self.state := 0
            else if (self.state < 10)
                self.state := self.state - 3
            else
                self.state := self.state - 6
        }
        else
        {
            length := 0
            if (Lzma_bit(self, ISREP + self.state) == 0)
            {
                self.reps[4] := self.reps[3]
                self.reps[3] := self.reps[2]
                self.reps[2] := self.reps[1]
                length := Lzma_len_decode(self, LEN)
                if (length < 4)
                    ltp := length
                else
                    ltp := 3
                slot := 1
                Loop, 6
                    slot := (slot << 1) | Lzma_bit(self, POSSLOT + ltp * 64 + slot)
                slot -= 64
                if (slot < 4)
                {
                    d := slot
                }
                else if (slot < 14)
                {
                    numBits := (slot >> 1) - 1
                    d := (2 | (slot & 1)) << numBits
                    idx := d - slot
                    tree := 1
                    Loop, % numBits
                    {
                        j := A_Index - 1
                        b := Lzma_bit(self, SPECPOS + idx + tree)
                        tree := (tree << 1) | b
                        if (b)
                            d |= (1 << j)
                    }
                }
                else
                {
                    numBits := (slot >> 1) - 1
                    d := 2 | (slot & 1)
                    Loop, % numBits - 4
                        d := (d << 1) | Lzma_dbit(self)
                    d := d << 4
                    i2 := 1
                    Loop, 4
                    {
                        j := A_Index - 1
                        b := Lzma_bit(self, ALIGN + i2)
                        i2 := (i2 << 1) | b
                        if (b)
                            d |= (1 << j)
                    }
                }
                self.reps[1] := d + 1
                if (self.state < 7)
                    self.state := 7
                else
                    self.state := 10
                length += 2
            }
            else
            {
                if (Lzma_bit(self, ISREPG0 + self.state) == 0)
                {
                    if (Lzma_bit(self, ISREP0LONG + self.state * 16 + ps) == 0)
                    {
                        if (self.state < 7)
                            self.state := 9
                        else
                            self.state := 11
                        length := 1
                    }
                    else
                    {
                        length := Lzma_len_decode(self, REPLEN) + 2
                        if (self.state < 7)
                            self.state := 8
                        else
                            self.state := 11
                    }
                }
                else
                {
                    if (Lzma_bit(self, ISREPG1 + self.state) != 0)
                    {
                        if (Lzma_bit(self, ISREPG2 + self.state) != 0)
                        {
                            d := self.reps[4]
                            self.reps[4] := self.reps[3]
                        }
                        else
                            d := self.reps[3]
                        self.reps[3] := self.reps[2]
                    }
                    else
                        d := self.reps[2]
                    self.reps[2] := self.reps[1]
                    self.reps[1] := d
                    length := Lzma_len_decode(self, REPLEN) + 2
                    if (self.state < 7)
                        self.state := 8
                    else
                        self.state := 11
                }
            }
            Loop, % length
            {
                if (self.opos >= self.outSize || self.opos - self.reps[1] < 0)
                    return
                self.out[self.opos + 1] := self.out[self.opos - self.reps[1] + 1]
                self.opos += 1
            }
        }
    }
}

; ---------------------------------------------------------------------------
; MD5 (hand-rolled, matches challenge.hpp)
; ---------------------------------------------------------------------------

MD5_K := [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a
        , 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be
        , 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340
        , 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8
        , 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8
        , 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c
        , 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa
        , 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
        , 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92
        , 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1
        , 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

MD5_S := [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22
        , 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20
        , 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23
        , 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

; Compress one 64-byte block p (1-based); h is a 1-based 4-elem array mutated
; in place and returned.
md5_compress(h, p) {
    global MD5_K, MD5_S, rotl, bnot32
    m := []
    Loop, 16
    {
        i := A_Index - 1
        o := i * 4 + 1
        m[A_Index] := p[o] | (p[o + 1] << 8) | (p[o + 2] << 16) | (p[o + 3] << 24)
    }
    a := h[1], b := h[2], c := h[3], d := h[4]
    Loop, 64
    {
        i := A_Index - 1
        if (i < 16)
        {
            f := (b & c) | (bnot32(b) & d)
            g := i
        }
        else if (i < 32)
        {
            f := (d & b) | (bnot32(d) & c)
            g := (5 * i + 1) & 15
        }
        else if (i < 48)
        {
            f := b ^ c ^ d
            g := (3 * i + 5) & 15
        }
        else
        {
            f := c ^ (b | bnot32(d))
            g := (7 * i) & 15
        }
        f := f & 0xFFFFFFFF
        t := d
        d := c
        c := b
        b := (b + rotl((a + f + MD5_K[i + 1] + m[g + 1]) & 0xFFFFFFFF, MD5_S[i + 1])) & 0xFFFFFFFF
        a := t
    }
    h[1] := (h[1] + a) & 0xFFFFFFFF
    h[2] := (h[2] + b) & 0xFFFFFFFF
    h[3] := (h[3] + c) & 0xFFFFFFFF
    h[4] := (h[4] + d) & 0xFFFFFFFF
    return h
}

md5(data) {
    h := [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    block := []
    blocklen := 0

    total := data.Length()
    i := 1
    n := total
    while (n > 0)
    {
        take := 64 - blocklen
        if (take > n)
            take := n
        Loop, % take
        {
            j := A_Index - 1
            block[blocklen + j + 1] := data[i + j]
        }
        blocklen += take
        i += take
        n -= take
        if (blocklen == 64)
        {
            md5_compress(h, block)
            blocklen := 0
        }
    }

    ; finalize
    bits := total * 8
    if (blocklen < 56)
        padlen := 56 - blocklen
    else
        padlen := 120 - blocklen
    pad := []
    pad[1] := 0x80
    Loop, 8
    {
        j := A_Index - 1
        pad[padlen + j + 1] := (bits >> (8 * j)) & 0xFF
    }
    padbytes := []
    Loop, % padlen + 8
    {
        if (pad[A_Index] = "")
            padbytes[A_Index] := 0
        else
            padbytes[A_Index] := pad[A_Index]
    }

    pi := 1
    pn := padbytes.Length()
    while (pn > 0)
    {
        take := 64 - blocklen
        if (take > pn)
            take := pn
        Loop, % take
        {
            j := A_Index - 1
            block[blocklen + j + 1] := padbytes[pi + j]
        }
        blocklen += take
        pi += take
        pn -= take
        if (blocklen == 64)
        {
            md5_compress(h, block)
            blocklen := 0
        }
    }

    out := []
    Loop, 4
    {
        i := A_Index - 1
        out[i * 4 + 1] := h[A_Index] & 0xFF
        out[i * 4 + 2] := (h[A_Index] >> 8) & 0xFF
        out[i * 4 + 3] := (h[A_Index] >> 16) & 0xFF
        out[i * 4 + 4] := (h[A_Index] >> 24) & 0xFF
    }
    return out
}

; ---------------------------------------------------------------------------
; Key decoding and MAC computation
; ---------------------------------------------------------------------------

bytes_to_hex(bytes) {
    hex := "0123456789abcdef"
    out := ""
    Loop, % bytes.Length()
    {
        b := bytes[A_Index]
        out .= SubStr(hex, (b >> 4) + 1, 1)
        out .= SubStr(hex, (b & 0x0F) + 1, 1)
    }
    return out
}

hex8_ts(ts) {
    tsb := [(ts >> 24) & 0xFF, (ts >> 16) & 0xFF, (ts >> 8) & 0xFF, ts & 0xFF]
    return bytes_to_hex(tsb)
}

str_bytes(s) {
    out := []
    Loop, % StrLen(s)
        out[A_Index] := Asc(SubStr(s, A_Index, 1))
    return out
}

decode_key(challenge) {
    global
    body := z85_decode(SubStr(challenge, 9))
    if (body.Length() < 36 + 128 * 7)
        return ""

    stream := []
    Loop, 7
    {
        i := A_Index - 1
        record := []
        Loop, 128
        {
            j := A_Index - 1
            record[A_Index] := body[36 + i * 128 + j + 1]
        }
        m := rsa_pub(record)
        Loop, 125
        {
            j := A_Index - 1
            stream[i * 125 + j + 1] := m[3 + j + 1]
        }
    }

    outSize := body[25] | (body[26] << 8) | (body[27] << 16) | (body[28] << 24)
    if (outSize <= 0 || outSize > 0x10000)
        return ""

    lz := Lzma_new(stream, outSize)
    Lzma_decode(lz)
    out := lz.out

    Loop, % lz.opos - 6 + 1
    {
        i := A_Index
        if (out[i] == 0x5F && out[i + 1] == 0x32 && out[i + 2] == 0x4A
            && out[i + 3] == 0x50 && out[i + 4] == 0x04)
        {
            klen := out[i + 5] - 1
            if (klen >= 8 && klen <= 32)
            {
                key := ""
                Loop, % klen
                {
                    j := A_Index - 1
                    key .= Chr(out[i + 6 + j] ^ j)
                }
                return key
            }
        }
    }
    return ""
}

day_counter(unix_ts) {
    day := unix_ts // 86400
    return day - 20592
}

mac_compute(unix_ts, key) {
    global kM2Suffix
    ts := hex8_ts(unix_ts)
    m1 := md5(str_bytes(ts . key))
    m2 := md5(str_bytes(ts . kM2Suffix))
    return [m1, m2]
}

generate_response(unix_ts, m1, m2) {
    global RESPONSE_TOTAL_LEN, RESPONSE_TS_OFF, RESPONSE_M1_OFF, RESPONSE_M2_OFF
    p := Mod(day_counter(unix_ts) - 1, 99) + 1

    arr := []
    Loop, % RESPONSE_TOTAL_LEN
        arr[A_Index] := 0

    arr[1] := 48 + Mod(p // 10, 10)
    arr[2] := 48 + Mod(p, 10)

    ts := hex8_ts(unix_ts)
    Loop, 8
        arr[RESPONSE_TS_OFF + A_Index] := Asc(SubStr(ts, A_Index, 1))

    arr[RESPONSE_TS_OFF + 8 + 1] := 95          ; '_'

    m1h := bytes_to_hex(m1)
    Loop, 32
        arr[RESPONSE_M1_OFF + A_Index] := Asc(SubStr(m1h, A_Index, 1))
    arr[RESPONSE_M1_OFF + 32 + 1] := 95

    m2h := bytes_to_hex(m2)
    Loop, 32
        arr[RESPONSE_M2_OFF + A_Index] := Asc(SubStr(m2h, A_Index, 1))

    res := ""
    Loop, % RESPONSE_TOTAL_LEN
        res .= Chr(arr[A_Index])
    return res
}

Solve(challenge) {
    if (StrLen(challenge) < 8)
        return ""
    ts := 0
    Loop, 8
    {
        c := SubStr(challenge, A_Index, 1)
        if (c >= "0" && c <= "9")
            v := Asc(c) - 48
        else if (c >= "a" && c <= "f")
            v := Asc(c) - 97 + 10
        else if (c >= "A" && c <= "F")
            v := Asc(c) - 65 + 10
        else
            v := 0
        ts := (ts << 4) | v
    }
    key := decode_key(challenge)
    if (key = "")
        return ""
    r := mac_compute(ts, key)
    return generate_response(ts, r[1], r[2])
}
