# The LINK-1 guards for the exe that ships (from VibeLink's R-LINK-3 and VibePerf's R-PERF-2; every
# app made from this template carries the same file), and the no-build-path check (IA1); build.ps1
# runs all three, tests/pe.rs tests all three.
#   check.ps1           the build environment, the variables that reach rustc or the linker:
#                       RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS (set, even empty, they replace
#                       .cargo/config.toml's rustflags, so they must carry +crt-static),
#                       CARGO_TARGET_<triple>_RUSTFLAGS, CARGO_BUILD_RUSTFLAGS (added to or used in
#                       place of the config's), LINK and _LINK_ (link.exe reads them). None may set
#                       an entry point (/ENTRY, -entry, --entry; -e too, except in LINK and _LINK_,
#                       where link.exe has no -e), drop the static CRT (-crt-static, /NODEFAULTLIB,
#                       /DEFAULTLIB, a dynamic CRT library), set /DEPENDENTLOADFLAG (build.rs sets
#                       it), name a response file (@) or, in the rustflags ones, a linker.
#   check.ps1 -Exe <p>  the exe: DependentLoadFlags 0x800 in its load config, and every imported
#                       DLL (import and delay-load tables) in System32 or an API set, no C/C++
#                       runtime: no redistributable, no dynamic UCRT (ucrtbase, api-ms-win-crt-*).
#   check.ps1 -Paths <p> the file holds no build path or user name (installer-audit IA1): not the
#                       user's profile folder, `\<user name>\` or `/<user name>/`, `C:\Users\` or
#                       `C:\Projects`, as UTF-8 or UTF-16, in any case. build.ps1's remaps keep
#                       them out of the release exe; a debug build has them.
# Exit 0 when it holds, 1 (with the reason on stderr) when it does not. Windows PowerShell 5.1.
param([string]$Exe, [string]$Paths)
$ErrorActionPreference = "Stop"

function Fail([string]$why) {
    [Console]::Error.WriteLine("check.ps1: $why")
    exit 1
}

if ($Paths) {
    # Latin-1 maps each byte to one character, so the search reads the bytes as they are.
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString([IO.File]::ReadAllBytes($Paths))
    $needles = @("C:\Users\", "C:\Projects")
    if ($env:USERPROFILE) { $needles += $env:USERPROFILE }
    if ($env:USERNAME) { $needles += "\$env:USERNAME\", "/$env:USERNAME/" }
    $found = @()
    foreach ($n in $needles) {
        foreach ($enc in @([Text.Encoding]::UTF8, [Text.Encoding]::Unicode)) {
            $form = $latin1.GetString($enc.GetBytes($n))
            $count = 0
            $i = $text.IndexOf($form, [StringComparison]::OrdinalIgnoreCase)
            while ($i -ge 0) { $count++; $i = $text.IndexOf($form, $i + $form.Length, [StringComparison]::OrdinalIgnoreCase) }
            if ($count -gt 0) { $found += "'$n' as $($enc.WebName) $count times" }
        }
    }
    if ($found.Count -gt 0) { Fail "$Paths holds a build path or the user name: $($found -join ', ')" }
    exit 0
}

# What one word of a variable (lower case, split at spaces, the 0x1F of CARGO_ENCODED_RUSTFLAGS,
# `,`, `=`, `;`, quotes and `\`) does to the link, or $null. $linker: LINK or _LINK_, which go to
# link.exe as they are (where `-e` is no option, and -ERRORREPORT is one).
function LinkChange([string]$w, [bool]$linker) {
    if ($w.StartsWith("@")) { return "names a response file ('$w'), which this check can't read" }
    if ($w -match '^(/|-|--)entry' -or (-not $linker -and $w.StartsWith("-e"))) { return "sets an entry point ('$w'), so the C runtime's start code (which calls main) would not run first" }
    if ($w -eq "-crt-static" -or $w -match '^[/-](no)?defaultlib' -or $w -match '^(msvcrt|ucrt|vcruntime|msvcprt)d?(\.lib)?$') { return "drops the static C runtime ('$w'), so the exe would import the C runtime DLLs" }
    if ($w -match '^[/-]dependentloadflag') { return "sets /DEPENDENTLOADFLAG ('$w'), which build.rs sets to 0x800 (LOAD_LIBRARY_SEARCH_SYSTEM32)" }
    if (-not $linker -and ($w -eq "linker" -or $w -eq "-clinker")) { return "names a linker, which can change the link in any way" }
    return $null
}

if (-not $Exe) {
    # The whole block, so a variable set to nothing counts (names compare case-insensitively).
    $vars = [Environment]::GetEnvironmentVariables()
    foreach ($name in @($vars.Keys | Sort-Object)) {
        $n = ([string]$name).ToUpperInvariant()
        $linker = $n -eq "LINK" -or $n -eq "_LINK_"
        $replaces = $n -eq "RUSTFLAGS" -or $n -eq "CARGO_ENCODED_RUSTFLAGS"
        if (-not ($linker -or $replaces -or $n -eq "CARGO_BUILD_RUSTFLAGS" -or $n -match '^CARGO_TARGET_.+_RUSTFLAGS$')) { continue }
        $v = [string]$vars[$name]
        $parts = if ($n -eq "CARGO_ENCODED_RUSTFLAGS") { $v -split [char]0x1F } else { $v -split '\s+' }
        $words = @($parts | ForEach-Object { $_.ToLowerInvariant() -split '[,=;"''\\]' } | Where-Object { $_ })
        if ($replaces -and $words -notcontains "+crt-static") {
            Fail "$name is set ('$v') and replaces .cargo/config.toml's rustflags, so the exe would import vcruntime140.dll again. Unset it or add -C target-feature=+crt-static."
        }
        foreach ($w in $words) {
            $why = LinkChange $w $linker
            if ($why) { Fail "$name is set ('$v') and $why. Unset it." }
        }
    }
    exit 0
}

$d = [IO.File]::ReadAllBytes($Exe)
function U16([long]$o) { [BitConverter]::ToUInt16($d, $o) }
function U32([long]$o) { [BitConverter]::ToUInt32($d, $o) }

$pe = U32 0x3C
if ((U32 $pe) -ne 0x4550) { Fail "$Exe is not a PE file" }
$nsec = U16 ($pe + 6)
$opt = $pe + 24
if ((U16 $opt) -ne 0x20B) { Fail "$Exe is not PE32+" }
$ndirs = U32 ($opt + 108)
function PeDir([int]$i) { if ($i -lt $ndirs) { @((U32 ($opt + 112 + 8 * $i)), (U32 ($opt + 116 + 8 * $i))) } else { @(0, 0) } }
$sec0 = $opt + (U16 ($pe + 20))
$sections = for ($i = 0; $i -lt $nsec; $i++) {
    $s = $sec0 + 40 * $i
    , @((U32 ($s + 12)), [Math]::Max((U32 ($s + 8)), (U32 ($s + 16))), (U32 ($s + 20)))
}
function Off([long]$rva) {
    foreach ($s in $sections) { if ($rva -ge $s[0] -and $rva -lt $s[0] + $s[1]) { return $rva - $s[0] + $s[2] } }
    Fail "RVA $rva is outside every section"
}
function CStr([long]$rva) {
    $o = Off $rva
    $e = [Array]::IndexOf($d, [byte]0, [int]$o)
    [Text.Encoding]::ASCII.GetString($d, $o, $e - $o)
}

# DependentLoadFlags: IMAGE_LOAD_CONFIG_DIRECTORY64 offset 78, present when its size is 80 or more.
$lc = PeDir 10
if ($lc[0] -eq 0) { Fail "$Exe has no load config" }
$o = Off $lc[0]
if ((U32 $o) -lt 80) { Fail "$Exe's load config is too short for DependentLoadFlags" }
$flags = U16 ($o + 78)
if ($flags -ne 0x800) { Fail ("$Exe's DependentLoadFlags is 0x{0:X}, not 0x800 (LOAD_LIBRARY_SEARCH_SYSTEM32)" -f $flags) }

$imports = New-Object System.Collections.Generic.List[string]
$imp = PeDir 1
if ($imp[0] -ne 0) {
    $o = Off $imp[0]
    while ((U32 ($o + 12)) -ne 0) { $imports.Add((CStr (U32 ($o + 12)))); $o += 20 }
}
$delay = PeDir 13
if ($delay[0] -ne 0) {
    $o = Off $delay[0]
    while ((U32 ($o + 4)) -ne 0) { $imports.Add((CStr (U32 ($o + 4)))); $o += 32 }
}
if (-not ($imports | Where-Object { $_ -ieq "kernel32.dll" })) { Fail "$Exe's import table was not read: $($imports -join ', ')" }
$sys = Join-Path $env:SystemRoot "System32"
$bad = @($imports | Where-Object {
    $l = $_.ToLowerInvariant()
    # The same list as tests/pe.rs `redistributable`: the dynamic CRT's API sets count too.
    $redist = $l -match '^(vcruntime|msvcp|concrt|vccorlib|ucrtbase|api-ms-win-crt-)'
    $apiSet = $l.StartsWith("api-ms-") -or $l.StartsWith("ext-ms-")
    $redist -or -not ($apiSet -or (Test-Path -LiteralPath (Join-Path $sys $l) -PathType Leaf))
})
if ($bad.Count -gt 0) { Fail "$Exe imports DLLs outside System32 or a redistributable runtime: $($bad -join ', ')" }
exit 0
