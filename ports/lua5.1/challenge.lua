-- File: challenge.lua
-- Port of the `detail::xem` namespace from challenge.hpp.
-- Solve the daily M1 key from a challenge and build the response.
--
--   challenge = hex8(ts) + Z85(body)
--   body[36+i*128 .. 36+(i+1)*128] = RSA-encrypted 128-byte records
--   m = record ^ 65537 mod N          (public verify op)
--   stream = concat(m[3:128])         (875 bytes)
--   LZMA1 (mirrored range coder) -> Lua chunk
--   key = "_2JP" 0x04 <lenbyte> <key[i]^i>
--   M1 = MD5(hex8(ts) + key)
--   M2 = MD5(hex8(ts) + kM2Suffix)
--   response = pp + "_" + hex8(ts) + "_" + hex32(M1) + "_" + hex32(M2)
--
-- Usage:
--   local challenge = require("challenge")
--   print(challenge.solve(challenge_str))
--
-- If run directly:
--   lua challenge.lua <challenge>
--
-- Requires only the standard library (Lua 5.1 / 5.2 / 5.3 / 5.4, plus LuaJIT).

local challenge = {}

-- 1024-bit RSA modulus (public verify op). 32 little-endian u32 limbs.
local kRsaN = {
    0x40c3d6b3, 0xb55d9978, 0xc19a3442, 0x911e015c, 0x83ff249c, 0xfc86f025,
    0x236b2c1e, 0x54f76c5e, 0xebeaa476, 0x7be90ce0, 0x90fc5321, 0x63da15e3,
    0x65a31488, 0x867d9311, 0xf1d55222, 0xe03ec2a6, 0x3c4d0c63, 0x83543f35,
    0xaee8c44b, 0xedbe21c6, 0xa51988ae, 0xa8090b6f, 0xa95a959d, 0x72df4268,
    0xa6eb052c, 0xbc3a4200, 0x227895bf, 0xe5a5539a, 0x5219a713, 0x44e788d5,
    0x01f53eb8, 0xb21cb874,
}
local KLIMBS = #kRsaN  -- 32

-- Response layout.
local kM2Suffix = "{CBEC4943-AFE5-4F24-A6FA-2DC80D1A1A18}"  -- hardcoded, may change
local RESPONSE_TOTAL_LEN = 76
local RESPONSE_TS_OFF = 2
local RESPONSE_M1_OFF = 11
local RESPONSE_M2_OFF = 44

-- Z85 alphabet.
local Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
local Z85_INDEX = {}
for i = 1, #Z85 do
    Z85_INDEX[Z85:sub(i, i)] = i - 1
end

-- ---------------------------------------------------------------------------
-- bit stuff
-- ---------------------------------------------------------------------------
--
-- All bitwise arithmetic is emulated with pure integer math so the code runs
-- identically on every interpreter (Lua 5.1 / 5.2 / 5.3 / 5.4, plus LuaJIT).
--
-- When the `bit` library is available (LuaJIT), we use it for the 32-bit
-- logical ops: they are JIT-compiled and dramatically faster than the
-- arithmetic fallback. This is safe because every operand passed to these
-- helpers is already reduced to a 32-bit unsigned value (they are always fed a
-- masked limb/byte or an intermediate `% 2^32`). `shr`/`shl` keep their plain
-- arithmetic forms, since their inputs are not always 32-bit.

local U32 = 4294967296  -- 2^32

local bit = rawget(_G, 'bit')
-- LuaJIT's bit library is JIT-compiled and exact for 32-bit unsigned inputs.

local function band(a, b)
    if bit then return bit.band(a, b) % U32 end
    a, b = a % U32, b % U32
    local r, p = 0, 1
    for _ = 1, 32 do
        if a % 2 == 1 and b % 2 == 1 then r = r + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end
    return r
end

local function bor(a, b)
    if bit then return bit.bor(a, b) % U32 end
    a, b = a % U32, b % U32
    local r, p = 0, 1
    for _ = 1, 32 do
        if a % 2 == 1 or b % 2 == 1 then r = r + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end
    return r
end

local function bxor(a, b)
    if bit then return bit.bxor(a, b) % U32 end
    a, b = a % U32, b % U32
    local r, p = 0, 1
    for _ = 1, 32 do
        if a % 2 ~= b % 2 then r = r + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end
    return r
end

local function bnot(a)
    if bit then return bit.bnot(a) % U32 end
    a = a % U32
    local r, p = 0, 1
    for _ = 1, 32 do
        if a % 2 == 0 then r = r + p end
        a = math.floor(a / 2)
        p = p * 2
    end
    return r
end

local function bnot32(a)
    return band(bnot(a), 0xFFFFFFFF)
end

local function shl(a, n)
    a = a % U32
    for _ = 1, n do a = (a * 2) % U32 end
    return a
end

local function shr(a, n)
    return math.floor((a % U32) / 2^n)
end

local function rotl(x, n)
    return bor(shl(x, n), shr(x, 32 - n))
end

local function ashr64(a, n)
    return math.floor(a / 2^n)
end

local function shr64(a, n)
    return math.floor(a / 2^n)
end

local function bytes_to_hex(bytes)
    local hex = "0123456789abcdef"
    local out = {}
    for i = 1, #bytes do
        local b = bytes[i]
        out[#out + 1] = hex:sub(shr(b, 4) + 1, shr(b, 4) + 1)
        out[#out + 1] = hex:sub(band(b, 0x0F) + 1, band(b, 0x0F) + 1)
    end
    return table.concat(out)
end

local function hex_to_bytes(hexstr)
    local bytes = {}
    for i = 1, #hexstr, 2 do
        bytes[#bytes + 1] = tonumber(hexstr:sub(i, i + 1), 16)
    end
    return bytes
end

local function hex8_ts(ts)
    local tsb = {
        band(shr(ts, 24), 0xFF),
        band(shr(ts, 16), 0xFF),
        band(shr(ts, 8), 0xFF),
        band(ts, 0xFF),
    }
    return bytes_to_hex(tsb)
end

-- ---------------------------------------------------------------------------
-- 1024-bit modular arithmetic (RSA public op)
-- ---------------------------------------------------------------------------

local function big_cmp(a, b, n)
    for i = n, 1, -1 do
        if a[i] ~= b[i] then
            if a[i] < b[i] then return -1 else return 1 end
        end
    end
    return 0
end

local function big_reduce(t, n)
    -- r = t mod N. t is a 1-based array of 2n u32 limbs; N has n u32 limbs (1-based).
    local R = {}
    for i = 1, n + 1 do R[i] = 0 end
    local total_bits = 2 * n * 32
    for bit = total_bits - 1, 0, -1 do
        local carry = band(shr(t[math.floor(bit / 32) + 1], band(bit, 31)), 1)
        for i = 1, n + 1 do
            local nc = shr(R[i], 31)
            R[i] = bor(band(shl(R[i], 1), 0xFFFFFFFF), carry)
            carry = nc
        end
        if R[n + 1] ~= 0 or big_cmp(R, kRsaN, n) >= 0 then
            local borrow = 0
            for i = 1, n do
                local cur = R[i] - kRsaN[i] - borrow
                R[i] = band(cur, 0xFFFFFFFF)
                borrow = band(ashr64(cur, 63), 1)
            end
            R[n + 1] = 0
        end
    end
    local out = {}
    for i = 1, n do out[i] = R[i] end
    return out
end

-- Multiply two 32-bit unsigned values; return hi, lo (each <= 0xFFFFFFFF) of
-- the 64-bit product. Uses 16-bit decomposition so every intermediate stays
-- below 2^53 (exact for doubles), avoiding the need for 64-bit integers.
local function umul32(a, b)
    local a0 = band(a, 0xFFFF)
    local a1 = shr(a, 16)
    local b0 = band(b, 0xFFFF)
    local b1 = shr(b, 16)
    local p = a0 * b0
    local w0 = band(p, 0xFFFF)
    local carry = shr64(p, 16)
    p = a0 * b1 + a1 * b0 + carry
    local w1 = band(p, 0xFFFF)
    carry = shr64(p, 16)
    p = a1 * b1 + carry
    local w2 = band(p, 0xFFFF)
    carry = shr64(p, 16)
    local w3 = carry
    local lo = bor(shl(w1, 16), w0)
    local hi = bor(shl(w3, 16), w2)
    return hi, lo
end

local function big_modmul(a, b)
    -- a, b are n u32 limbs; return (a*b) mod N as n limbs.
    local n = #a
    local t = {}
    for i = 0, 2 * n do t[i + 1] = 0 end
    for i = 0, n - 1 do
        local carry = 0
        for j = 0, n - 1 do
            local hi, lo = umul32(a[i + 1], b[j + 1])
            -- acc = lo + t[i+j] + carry  (< 2^34, exact for doubles)
            local acc = lo + t[i + j + 1] + carry
            t[i + j + 1] = band(acc, 0xFFFFFFFF)
            carry = shr64(acc, 32) + hi
        end
        -- propagate remaining carry into higher limbs
        local k = i + n
        while carry ~= 0 do
            local acc = t[k + 1] + carry
            t[k + 1] = band(acc, 0xFFFFFFFF)
            carry = shr64(acc, 32)
            k = k + 1
        end
    end
    return big_reduce(t, n)
end

local function rsa_pub(in_bytes)
    -- out = in ^ 65537 mod N (in/out are 128-byte big-endian)
    local base = {}
    for i = 0, KLIMBS - 1 do
        local off = 128 - 4 * (i + 1)  -- 0-based index into in_bytes
        local o1 = off + 1  -- 1-based Lua index
        base[i + 1] = bor(bor(bor(shl(in_bytes[o1], 24), shl(in_bytes[o1 + 1], 16)),
            shl(in_bytes[o1 + 2], 8)), in_bytes[o1 + 3])
    end
    local x = {}
    for i = 1, KLIMBS do x[i] = base[i] end
    for _ = 1, 16 do  -- 16 squarings -> base^(2^16)
        x = big_modmul(x, x)
    end
    local result = big_modmul(x, base)  -- * base -> base^65537

    local out = {}
    for i = 0, KLIMBS - 1 do
        local off = 128 - 4 * (i + 1)
        local o1 = off + 1
        out[o1] = band(shr(result[i + 1], 24), 0xFF)
        out[o1 + 1] = band(shr(result[i + 1], 16), 0xFF)
        out[o1 + 2] = band(shr(result[i + 1], 8), 0xFF)
        out[o1 + 3] = band(result[i + 1], 0xFF)
    end
    return out
end

-- ---------------------------------------------------------------------------
-- Z85 decode
-- ---------------------------------------------------------------------------

local function z85_decode(s)
    local out = {}
    local i = 1
    local n = #s
    while i + 4 <= n do
        local v = 0
        local ok = true
        for j = 0, 4 do
            local c = s:sub(i + j, i + j)
            local idx = Z85_INDEX[c]
            if idx == nil then ok = false break end
            v = v * 85 + idx
        end
        if not ok then break end
        out[#out + 1] = band(shr(v, 24), 0xFF)
        out[#out + 1] = band(shr(v, 16), 0xFF)
        out[#out + 1] = band(shr(v, 8), 0xFF)
        out[#out + 1] = band(v, 0xFF)
        i = i + 5
    end
    return out
end

-- ---------------------------------------------------------------------------
-- LZMA1 (mirrored range coder)
-- ---------------------------------------------------------------------------

local Lzma = {}
Lzma.__index = Lzma

local ISMATCH = 0
local ISREP = 192
local ISREPG0 = 204
local ISREPG1 = 216
local ISREPG2 = 228
local ISREP0LONG = 240
local POSSLOT = 432
local SPECPOS = 687
local ALIGN = 802
local LEN = 818
local REPLEN = 1332
local LITERAL = 1846

function Lzma.new(stream, out_size)
    local self = setmetatable({}, Lzma)
    self.data = stream          -- 1-based
    self.pos = 6                -- 0-based pos 5 -> 1-based index 6
    self.range = bor(bor(bor(shl(stream[2], 24), shl(stream[3], 16)),
        shl(stream[4], 8)), stream[5])
    self.code = 0xFFFFFFFF
    self.probs = {}
    for i = 1, 8192 do self.probs[i] = 0x400 end
    self.reps = { 1, 1, 1, 1 }
    self.state = 0
    self.out = {}
    self.opos = 0
    self.out_size = out_size
    return self
end

function Lzma:normalize()
    if self.code < 0x1000000 then
        self.range = band(bor(shl(self.range, 8), self.data[self.pos]), 0xFFFFFFFF)
        self.code = band(shl(self.code, 8), 0xFFFFFFFF)
        self.pos = self.pos + 1
    end
end

function Lzma:bit(prob_idx)
    self:normalize()
    local prob = self.probs[prob_idx + 1]
    local bound = shr64(self.code, 11) * prob
    if self.range < bound then
        self.code = bound
        self.probs[prob_idx + 1] = band(prob + ashr64(0x800 - prob, 5), 0xFFFF)
        return 0
    end
    self.range = band(self.range - bound, 0xFFFFFFFF)
    self.code = band(self.code - bound, 0xFFFFFFFF)
    self.probs[prob_idx + 1] = band(prob - shr(prob, 5), 0xFFFF)
    return 1
end

function Lzma:dbit()
    self:normalize()
    self.code = shr64(self.code, 1)
    self.range = band(self.range - self.code, 0xFFFFFFFF)
    if band(self.range, 0x80000000) ~= 0 then
        self.range = band(self.range + self.code, 0xFFFFFFFF)
        return 0
    end
    return 1
end

function Lzma:len_decode(base)
    if self:bit(base) == 0 then
        local ps = band(self.opos, 3)
        local sym = 1
        for _ = 1, 3 do sym = bor(shl(sym, 1), self:bit(base + 2 + ps * 8 + sym)) end
        return sym - 8
    elseif self:bit(base + 1) == 0 then
        local ps = band(self.opos, 3)
        local sym = 1
        for _ = 1, 3 do sym = bor(shl(sym, 1), self:bit(base + 130 + ps * 8 + sym)) end
        return sym
    else
        local sym = 1
        for _ = 1, 8 do sym = bor(shl(sym, 1), self:bit(base + 258 + sym)) end
        return sym - 256 + 16
    end
end

function Lzma:decode()
    while self.opos < self.out_size do
        local ps = band(self.opos, 3)
        if self:bit(ISMATCH + self.state * 16 + ps) == 0 then
            local prev = 0
            if self.opos > 0 then prev = self.out[self.opos] end
            local lit_state = shr(prev, 8 - 3)  -- lc=3, lp=0
            local base = LITERAL + 0x300 * lit_state
            if self.state < 7 then
                local sym = 1
                while sym < 0x100 do sym = bor(shl(sym, 1), self:bit(base + sym)) end
                self.opos = self.opos + 1
                self.out[self.opos] = band(sym, 0xFF)
            else
                local match_byte = self.out[self.opos - self.reps[1] + 1]
                local sym = 1
                local matched = true
                for _ = 1, 8 do
                    local match_bit = band(shr(match_byte, 7), 1)
                    match_byte = band(shl(match_byte, 1), 0xFF)
                    local idx
                    if matched then idx = 0x100 + match_bit * 0x100 + sym else idx = sym end
                    local b = self:bit(base + idx)
                    sym = bor(shl(sym, 1), b)
                    if matched and match_bit ~= b then matched = false end
                end
                self.opos = self.opos + 1
                self.out[self.opos] = band(sym, 0xFF)
            end
            if self.state < 4 then self.state = 0
            elseif self.state < 10 then self.state = self.state - 3
            else self.state = self.state - 6 end
        else
            local length = 0
            if self:bit(ISREP + self.state) == 0 then
                self.reps[4] = self.reps[3]
                self.reps[3] = self.reps[2]
                self.reps[2] = self.reps[1]
                length = self:len_decode(LEN)
                local ltp
                if length < 4 then ltp = length else ltp = 3 end
                local slot = 1
                for _ = 1, 6 do slot = bor(shl(slot, 1), self:bit(POSSLOT + ltp * 64 + slot)) end
                slot = slot - 64
                local d
                if slot < 4 then
                    d = slot
                elseif slot < 14 then
                    local num_bits = shr(slot, 1) - 1
                    d = shl(bor(2, band(slot, 1)), num_bits)
                    local idx = d - slot
                    local tree = 1
                    for j = 0, num_bits - 1 do
                        local b = self:bit(SPECPOS + idx + tree)
                        tree = bor(shl(tree, 1), b)
                        if b ~= 0 then d = bor(d, shl(1, j)) end
                    end
                else
                    local num_bits = shr(slot, 1) - 1
                    d = bor(2, band(slot, 1))
                    for _ = 1, num_bits - 4 do d = bor(shl(d, 1), self:dbit()) end
                    d = shl(d, 4)
                    local i = 1
                    for j = 0, 3 do
                        local b = self:bit(ALIGN + i)
                        i = bor(shl(i, 1), b)
                        if b ~= 0 then d = bor(d, shl(1, j)) end
                    end
                end
                self.reps[1] = d + 1
                if self.state < 7 then self.state = 7 else self.state = 10 end
                length = length + 2
            else
                if self:bit(ISREPG0 + self.state) == 0 then
                    if self:bit(ISREP0LONG + self.state * 16 + ps) == 0 then
                        if self.state < 7 then self.state = 9 else self.state = 11 end
                        length = 1
                    else
                        length = self:len_decode(REPLEN) + 2
                        if self.state < 7 then self.state = 8 else self.state = 11 end
                    end
                else
                    local d
                    if self:bit(ISREPG1 + self.state) ~= 0 then
                        if self:bit(ISREPG2 + self.state) ~= 0 then
                            d = self.reps[4]
                            self.reps[4] = self.reps[3]
                        else
                            d = self.reps[3]
                        end
                        self.reps[3] = self.reps[2]
                    else
                        d = self.reps[2]
                    end
                    self.reps[2] = self.reps[1]
                    self.reps[1] = d
                    length = self:len_decode(REPLEN) + 2
                    if self.state < 7 then self.state = 8 else self.state = 11 end
                end
            end
            for _ = 1, length do
                if self.opos >= self.out_size or self.opos - self.reps[1] < 0 then
                    return
                end
                self.out[self.opos + 1] = self.out[self.opos - self.reps[1] + 1]
                self.opos = self.opos + 1
            end
        end
    end
end

-- ---------------------------------------------------------------------------
-- MD5 (hand-rolled, matches challenge.hpp)
-- ---------------------------------------------------------------------------

local MD5_K = {
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
}

local MD5_S = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

local function md5(data)
    local h = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 }
    local total = #data
    local block = {}
    local blocklen = 0

    local function compress(p)
        local m = {}
        for i = 0, 15 do
            local o = i * 4 + 1
            m[i + 1] = bor(bor(bor(p[o], shl(p[o + 1], 8)), shl(p[o + 2], 16)),
                shl(p[o + 3], 24))
        end
        local a, b, c, d = h[1], h[2], h[3], h[4]
        for i = 0, 63 do
            local f, g
            if i < 16 then
                f = bor(band(b, c), band(bnot32(b), d))
                g = i
            elseif i < 32 then
                f = bor(band(d, b), band(bnot32(d), c))
                g = band(5 * i + 1, 15)
            elseif i < 48 then
                f = bxor(bxor(b, c), d)
                g = band(3 * i + 5, 15)
            else
                f = bxor(c, bor(b, bnot32(d)))
                g = band(7 * i, 15)
            end
            f = band(f, 0xFFFFFFFF)
            local t = d
            d = c
            c = b
            b = band(b + rotl(band(a + f + MD5_K[i + 1] + m[g + 1], 0xFFFFFFFF), MD5_S[i + 1]), 0xFFFFFFFF)
            a = t
        end
        h[1] = band(h[1] + a, 0xFFFFFFFF)
        h[2] = band(h[2] + b, 0xFFFFFFFF)
        h[3] = band(h[3] + c, 0xFFFFFFFF)
        h[4] = band(h[4] + d, 0xFFFFFFFF)
    end

    local i = 1
    local n = #data
    while n > 0 do
        local take = 64 - blocklen
        if take > n then take = n end
        for j = 0, take - 1 do
            block[blocklen + j + 1] = data[i + j]
        end
        blocklen = blocklen + take
        i = i + take
        n = n - take
        if blocklen == 64 then
            compress(block)
            blocklen = 0
        end
    end

    -- finalize
    local bits = total * 8
    local padlen
    if blocklen < 56 then padlen = 56 - blocklen else padlen = 120 - blocklen end
    local pad = {}
    pad[1] = 0x80
    for j = 0, 7 do pad[padlen + j + 1] = band(shr(bits, 8 * j), 0xFF) end
    -- process pad
    local padbytes = {}
    for j = 1, padlen + 8 do padbytes[j] = pad[j] or 0 end
    -- manual update
    local pi = 1
    local pn = #padbytes
    while pn > 0 do
        local take = 64 - blocklen
        if take > pn then take = pn end
        for j = 0, take - 1 do
            block[blocklen + j + 1] = padbytes[pi + j]
        end
        blocklen = blocklen + take
        pi = pi + take
        pn = pn - take
        if blocklen == 64 then
            compress(block)
            blocklen = 0
        end
    end

    local out = {}
    for i = 0, 3 do
        out[i * 4 + 1] = band(h[i + 1], 0xFF)
        out[i * 4 + 2] = band(shr(h[i + 1], 8), 0xFF)
        out[i * 4 + 3] = band(shr(h[i + 1], 16), 0xFF)
        out[i * 4 + 4] = band(shr(h[i + 1], 24), 0xFF)
    end
    return out
end

-- ---------------------------------------------------------------------------
-- Key decoding and MAC computation
-- ---------------------------------------------------------------------------

local function decode_key(challenge_str)
    -- Decode the daily M1 key from the challenge; returns nil on failure.
    local body = z85_decode(challenge_str:sub(9))
    if #body < 36 + 128 * 7 then return nil end

    local stream = {}
    for i = 0, 6 do
        local record = {}
        for j = 0, 127 do record[j + 1] = body[36 + i * 128 + j + 1] end
        local m = rsa_pub(record)
        for j = 0, 124 do stream[i * 125 + j + 1] = m[3 + j + 1] end
    end

    local out_size = bor(bor(bor(body[25], shl(body[26], 8)), shl(body[27], 16)),
        shl(body[28], 24))
    if out_size <= 0 or out_size > 0x10000 then return nil end

    local lz = Lzma.new(stream, out_size)
    lz:decode()
    local out = lz.out

    -- find the key: "_2JP" 0x04 <lenbyte> <key[i]^i>, short key (8..32)
    for i = 1, lz.opos - 6 + 1 do
        if out[i] == 0x5F and out[i + 1] == 0x32 and out[i + 2] == 0x4A
            and out[i + 3] == 0x50 and out[i + 4] == 0x04 then
            local klen = out[i + 5] - 1
            if klen >= 8 and klen <= 32 then
                local chars = {}
                for j = 0, klen - 1 do
                    chars[j + 1] = string.char(bxor(out[i + 6 + j], j))
                end
                return table.concat(chars)
            end
        end
    end
    return nil
end

local function day_counter(unix_ts)
    local day = math.floor(unix_ts / 86400)
    local diff = day - 20592
    return diff
end

local function mac_compute(unix_ts, key)
    local ts = hex8_ts(unix_ts)
    local m1_data = {}
    local m2_data = {}

    local m1_buf = {}
    for i = 1, #ts do m1_buf[#m1_buf + 1] = ts:byte(i) end
    for i = 1, #key do m1_buf[#m1_buf + 1] = key:byte(i) end
    local m1 = md5(m1_buf)

    local m2_buf = {}
    for i = 1, #ts do m2_buf[#m2_buf + 1] = ts:byte(i) end
    for i = 1, #kM2Suffix do m2_buf[#m2_buf + 1] = kM2Suffix:byte(i) end
    local m2 = md5(m2_buf)

    return m1, m2
end

local function generate_response(unix_ts, m1, m2)
    local buf = {}
    local p = ((day_counter(unix_ts) - 1) % 99) + 1
    local pstr = string.format("%02d", p)
    for i = 1, 2 do buf[i] = pstr:byte(i) end

    local ts = hex8_ts(unix_ts)
    for i = 1, 8 do buf[RESPONSE_TS_OFF + i] = ts:byte(i) end

    buf[11] = string.byte("_")

    local m1h = bytes_to_hex(m1)
    for i = 1, 32 do buf[RESPONSE_M1_OFF + i] = m1h:byte(i) end
    buf[RESPONSE_M1_OFF + 32 + 1] = string.byte("_")

    local m2h = bytes_to_hex(m2)
    for i = 1, 32 do buf[RESPONSE_M2_OFF + i] = m2h:byte(i) end

    local out = {}
    for i = 1, RESPONSE_TOTAL_LEN do out[i] = string.char(buf[i]) end
    return table.concat(out)
end

function challenge.solve(challenge_str)
    -- Turn a challenge into a response. Returns nil on failure.
    if #challenge_str < 8 then return nil end
    local ts = 0
    for i = 1, 8 do
        local c = challenge_str:sub(i, i)
        local v = tonumber(c, 16) or 0
        ts = bor(shl(ts, 4), v)
    end

    local key = decode_key(challenge_str)
    if not key then return nil end
    local m1, m2 = mac_compute(ts, key)
    return generate_response(ts, m1, m2)
end

-- Internal helpers exposed for the test driver (run_tests.lua).
challenge._debug = {
    decode_key = decode_key,
    day_counter = day_counter,
    mac_compute = mac_compute,
    bytes_to_hex = bytes_to_hex,
}

return challenge
