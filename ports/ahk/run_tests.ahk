; ============================================================================
; File: run_tests.ahk
; Driver for test_ahk.bat: reads ../challenges.txt (one challenge per line),
; solves each challenge with the challenge.ahk port, and writes detailed
; per-challenge results to stdout. The batch file redirects this to results.txt.
; ============================================================================

#Include %A_ScriptDir%\challenge.ahk

; Determine script/module dir.
scriptDir := A_ScriptDir
challengesFile := scriptDir . "\..\challenges.txt"

if (!FileExist(challengesFile))
{
    FileAppend, ERROR: challenges.txt not found`n, *
    ExitApp, 1
}

FileRead, rawText, %challengesFile%
lines := StrSplit(rawText, "`n", "`r")
n := 0
Loop, % lines.Length()
{
    s := Trim(lines[A_Index], " `r`n`t")
    if (s != "")
    {
        n += 1
        lines[n] := s
    }
}

outFile := A_ScriptDir . "\results.txt"
FileDelete, %outFile%

Loop, % n
{
    idx := A_Index
    ch := lines[A_Index]
    tsHex := SubStr(ch, 1, 8)

    ts := 0
    Loop, 8
    {
        c := SubStr(ch, A_Index, 1)
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

    key := decode_key(ch)
    dc := day_counter(ts)
    pp := Mod(dc - 1, 99) + 1

    ppStr := SubStr("0000000000" . pp, -1)
    block := "========================================================================" . "`n"
    block .= "Challenge #" . idx . "`n"
    block .= "========================================================================" . "`n"
    block .= "  challenge : " . ch . "`n"
    block .= "  timestamp : 0x" . tsHex . "  (= " . ts . " decimal)`n"
    block .= "  day-counter: " . dc . "`n"
    block .= "  response prefix (pp): " . ppStr . "`n"

    if (key = "")
    {
        block .= "  key (M1)  : <failed to decode>`n"
    }
    else
    {
        block .= "  key (M1)  : " . Chr(34) . key . Chr(34) . "  (len=" . StrLen(key) . ")`n"
        r := mac_compute(ts, key)
        m1 := r[1]
        m2 := r[2]
        block .= "  M1 (MD5)  : " . bytes_to_hex(m1) . "`n"
        block .= "  M2 (MD5)  : " . bytes_to_hex(m2) . "`n"
    }

    resp := Solve(ch)
    block .= "  response  : " . resp . "`n"
    block .= "`n"

    f := FileOpen(outFile, "a", "UTF-8")
    f.Write(block)
    f.Close()
}

ExitApp, 0
