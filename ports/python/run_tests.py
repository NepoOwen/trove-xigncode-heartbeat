# run_tests.py
# Driver for test_python.bat: reads ports/challenges.txt (one challenge per line),
# solves each challenge, and prints detailed per-challenge info to stdout.
# The batch file redirects this output to results.txt.

import os
import sys

# Make sure `challenge` is importable from this directory (challenge.py lives here).
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import challenge  # noqa: E402


def parse_ts(challenge_str):
    """Parse the 8 leading hex chars of the challenge as a big-endian timestamp."""
    ts = 0
    for c in challenge_str[:8]:
        if '0' <= c <= '9':
            v = ord(c) - ord('0')
        elif 'a' <= c <= 'f':
            v = ord(c) - ord('a') + 10
        elif 'A' <= c <= 'F':
            v = ord(c) - ord('A') + 10
        else:
            v = 0
        ts = (ts << 4) | v
    return ts


def main():
    challenges_path = os.path.join(os.path.dirname(HERE), 'challenges.txt')

    with open(challenges_path, 'r', encoding='utf-8') as f:
        lines = [ln.strip() for ln in f if ln.strip()]

    for i, challenge_str in enumerate(lines, 1):
        ts = parse_ts(challenge_str)
        ts_hex = challenge_str[:8]
        key = challenge.decode_key(challenge_str)
        dc = challenge.day_counter(ts)
        pp = ((dc - 1) % 99) + 1  # the 2-digit prefix used in the response
        m1, m2 = challenge.mac_compute(ts, key) if key else (b'', b'')
        response = challenge.solve(challenge_str)

        print('=' * 72)
        print(f'Challenge #{i}')
        print('=' * 72)
        print(f'  challenge : {challenge_str}')
        print(f'  timestamp : 0x{ts_hex}  (= {ts} decimal)')
        print(f'  day-counter: {dc}')
        print(f'  response prefix (pp): {pp:02d}')
        print(f'  key (M1)  : {key!r}  (len={len(key)})')
        if m1:
            print(f'  M1 (MD5)  : {challenge._bytes_to_hex(m1)}')
            print(f'  M2 (MD5)  : {challenge._bytes_to_hex(m2)}')
        print(f'  response  : {response}')
        print()


if __name__ == '__main__':
    main()
