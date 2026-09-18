-- File: run_tests.lua
-- Driver for test_lua.bat: reads ../challenges.txt (one challenge per line),
-- solves each challenge, and prints detailed per-challenge info to stdout.
-- The batch file redirects this output to results.txt.

package.path = 'lua_modules/?.lua;' .. package.path

local script_dir = arg[0] and arg[0]:match('^(.*)[/\\]') or '.'
local challenge_path = script_dir .. '/challenge.lua'

-- Load the challenge module via dofile so we can call its exported `solve`,
-- and expose internal helpers we need (decode_key, day_counter, mac_compute).
-- We re-require the internals by loading with a table that exposes locals is not
-- possible, so we make challenge.lua expose the extra helpers for the test driver.
-- To keep challenge.lua's public API clean, this driver depends on the extra
-- debug exports below. See note at bottom.

local challenge = dofile(challenge_path)

-- The challenge module only exports `solve`. For detailed per-challenge output
-- we re-implement parse_ts and day_counter here locally (they are trivial and
-- mirror challenge.hpp), and derive the key indirectly is NOT possible without
-- the internal decode_key. Therefore we add a small extension: challenge.lua
-- exports `_debug = { decode_key, day_counter, mac_compute, bytes_to_hex }`.

local dbg = challenge._debug
if not dbg then
    io.stderr:write('ERROR: challenge.lua does not export _debug helpers.\n')
    os.exit(1)
end

local function parse_ts(challenge_str)
    local ts = 0
    for i = 1, 8 do
        local c = challenge_str:sub(i, i)
        local v = tonumber(c, 16) or 0
        ts = ts * 16 + v
    end
    return ts
end

local challenges_file = script_dir .. '/../challenges.txt'
local f = io.open(challenges_file, 'r')
if not f then
    io.stderr:write('ERROR: cannot open ' .. challenges_file .. '\n')
    os.exit(1)
end
local lines = {}
for line in f:lines() do
    line = line:gsub('^%s+', ''):gsub('%s+$', '')
    if line ~= '' then lines[#lines + 1] = line end
end
f:close()

for idx, challenge_str in ipairs(lines) do
    local ts = parse_ts(challenge_str)
    local ts_hex = challenge_str:sub(1, 8)
    local key = dbg.decode_key(challenge_str)
    local dc = dbg.day_counter(ts)
    local pp = ((dc - 1) % 99) + 1
    local response = challenge.solve(challenge_str)

    print(string.rep('=', 72))
    print(string.format('Challenge #%d', idx))
    print(string.rep('=', 72))
    print('  challenge : ' .. challenge_str)
    print(string.format('  timestamp : 0x%s  (= %d decimal)', ts_hex, ts))
    print(string.format('  day-counter: %d', dc))
    print(string.format('  response prefix (pp): %02d', pp))
    if key then
        print(string.format('  key (M1)  : %q  (len=%d)', key, #key))
        local m1, m2 = dbg.mac_compute(ts, key)
        if m1 then
            print('  M1 (MD5)  : ' .. dbg.bytes_to_hex(m1))
            print('  M2 (MD5)  : ' .. dbg.bytes_to_hex(m2))
        end
    else
        print('  key (M1)  : <failed to decode>')
    end
    print('  response  : ' .. tostring(response))
    print()
end
