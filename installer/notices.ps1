# THIRD-PARTY-NOTICES.txt: the licence of every crate VibeTrace ships, with the licence texts the
# crates themselves carry. build.ps1 runs it after the release build, so the list matches
# Cargo.lock; the installer puts the file next to VibeTrace.exe.
#   notices.ps1 -Out <file> [-Report]
# What ships: the resolve graph from vibetrace over normal dependencies (no dev or build
# dependencies) for x86_64-pc-windows-msvc, VibeTrace's own crate left out (LICENSE covers them).
# The texts: each crate's top-level LICENSE*, LICENCE*, COPYING*, NOTICE*, COPYRIGHT* and
# UNLICENSE* files, and the file `license-file` names; identical texts are printed once, with
# every crate that carries them. A file such a text points at by path (aws-lc-sys: "See
# third_party/fiat/LICENSE.") comes too, from wherever it sits in the crate; for one the crate
# doesn't carry, $pointedAt names what stands in or why none is needed. A crate with none gets its REUSE LICENSES\<id> file, or else the
# standard SPDX text of its licence (licenses\ beside this script) with its authors as the
# copyright line.
param([Parameter(Mandatory)][string]$Out, [switch]$Report)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

Push-Location $root
try {
    # What a release build links: cargo tree resolves features as the build does (cargo
    # metadata's graph is the union of every feature anyone asks for, dev dependencies' too).
    # Proc macros run in the compiler and never ship, and neither does what only they use.
    $tree = cargo tree --offline --locked -e normal,no-proc-macro --target x86_64-pc-windows-msvc -p vibetrace --prefix none -f "{p}"
    if ($LASTEXITCODE -ne 0) { throw "cargo tree failed" }
    $json = cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed" }
} finally { Pop-Location }
$m = $json | ConvertFrom-Json -AsHashtable
$linked = @{}
foreach ($line in $tree) { if ($line -match '^(\S+) v(\S+)') { $linked["$($Matches[1]) $($Matches[2])"] = $true } }
$own = @($m.workspace_members)
$shipped = @($m.packages | Where-Object { $linked.ContainsKey("$($_.name) $($_.version)") -and $own -notcontains $_.id } | Sort-Object { $_.name }, { $_.version })
if ($shipped.Count -lt 100) { throw "only $($shipped.Count) crates found: cargo tree's output changed?" }

$namePattern = '^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|UNLICENSE)([-_.].*)?$'
$groups = [ordered]@{}   # text -> list of "name version (licence)"
$missing = @()
$needed = @()
# Files a crate's licence points at but the crate doesn't carry, "<crate> <path>" -> what stands in:
# "header:<file in the crate>" puts that file's opening comment (its copyright and licence) in the
# notices; anything else is the reason none is needed (-Report lists it).
$pointedAt = @{
    "aws-lc-sys third_party/jitterentropy/jitterentropy-library/LICENSE" = "header:aws-lc/third_party/jitterentropy/jitterentropy-library/src/jitterentropy-base.c"
    "aws-lc-sys third_party/s2n-bignum/s2n-bignum-imported/LICENSE" = "Apache-2.0 OR ISC OR MIT-0: all three texts are in the crate's LICENSE"
    "aws-lc-sys third_party/googletest/LICENSE" = "not linked: tests only (the crate's LICENSE says so)"
    "aws-lc-sys third_party/wycheproof_testvectors/LICENSE" = "not linked: test vectors only (the crate's LICENSE says so)"
    "rustls-webpki third-party/chromium/LICENSE" = "not linked: upstream's test data, not in the crate"
}
$unresolved = @()
foreach ($p in $shipped) {
    $dir = Split-Path -Parent $p.manifest_path
    $files = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -match $namePattern })
    if ($p.license_file) {
        $lf = Join-Path $dir $p.license_file
        if ((Test-Path -LiteralPath $lf -PathType Leaf) -and -not ($files | Where-Object { $_.FullName -eq (Resolve-Path -LiteralPath $lf).Path })) { $files += Get-Item -LiteralPath $lf }
    }
    $licence = if ($p.license) { $p.license } else { "see its licence file" }
    $label = "$($p.name) $($p.version) ($licence)"
    $texts = @()
    foreach ($f in ($files | Sort-Object Name)) {
        $texts += ([IO.File]::ReadAllText($f.FullName) -replace "`r`n", "`n").Trim()
    }
    # A licence text that points at another file by path ("See third_party/fiat/LICENSE."): that
    # file too, found anywhere in the crate by the end of its path (X15DEP-6). One the crate doesn't
    # carry needs a line in $pointedAt, or the build stops.
    $refs = @($texts | ForEach-Object { [regex]::Matches($_, '(?<![\w./:-])((?:[\w.-]+/)+(?:LICEN[CS]E|COPYING)[\w-]*(?:\.(?:txt|md))?)') } | ForEach-Object { $_.Groups[1].Value -replace '^(\./)+', '' } | Sort-Object -Unique)
    if ($refs.Count) {
        $skipLen = (Get-Item -LiteralPath $dir).FullName.TrimEnd('\').Length + 1
        $all = @(Get-ChildItem -LiteralPath $dir -Recurse -File | ForEach-Object { [pscustomobject]@{ Rel = $_.FullName.Substring($skipLen).Replace('\', '/'); Full = $_.FullName } })
        foreach ($ref in $refs) {
            $found = @($all | Where-Object { $_.Rel -ieq $ref -or $_.Rel.EndsWith("/$ref", [StringComparison]::OrdinalIgnoreCase) })
            if ($found.Count) {
                foreach ($f in $found) { $texts += ([IO.File]::ReadAllText($f.Full) -replace "`r`n", "`n").Trim() }
                continue
            }
            $why = $pointedAt["$($p.name) $ref"]
            if (-not $why) { $unresolved += "$($p.name) $($p.version): its licence points at $ref, which it doesn't carry"; continue }
            if ($why -like "header:*") {
                $src = Join-Path $dir $why.Substring(7)
                if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { $unresolved += "$($p.name) $($p.version): no $($why.Substring(7)) (for $ref)"; continue }
                $body = [IO.File]::ReadAllText($src) -replace "`r`n", "`n"
                $m = [regex]::Match($body, '^\s*/\*(.*?)\*/', 'Singleline')
                if (-not $m.Success) { $unresolved += "$($p.name) $($p.version): $($why.Substring(7)) opens with no comment (for $ref)"; continue }
                $header = (($m.Groups[1].Value -split "`n" | ForEach-Object { $_ -replace '^\s?\*\s?', '' }) -join "`n").Trim()
                $texts += "$ref is not in the crate; this is the copyright and licence header of $($why.Substring(7)):`n`n$header"
            } elseif ($Report) { "  {0} {1}: {2}: {3}" -f $p.name, $p.version, $ref, $why }
        }
    }
    # The licence VibeTrace takes it under: of "A OR B", MIT when offered, else the first; every
    # part of an AND. (Slint: GPL-3.0-only.)
    $chosen = @()
    if ($p.license) {
        $options = @($p.license -split '\s+OR\s+|/' | ForEach-Object { $_.Trim().Trim('(', ')').Trim() } | Where-Object { $_ })
        $pick = if ($options -contains "MIT") { "MIT" } else { $options[0] }
        $chosen = @($pick -split '\s+AND\s+' | ForEach-Object { ($_.Trim().Trim('(', ')') -split '\s+WITH\s+')[0].Trim() })
    }
    if (-not $texts.Count) {
        # REUSE layout: LICENSES\<id>.txt or .md.
        foreach ($id in $chosen) {
            $f = @("$id.txt", "$id.md") | ForEach-Object { Join-Path $dir "LICENSES\$_" } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if ($f) { $texts += ([IO.File]::ReadAllText($f) -replace "`r`n", "`n").Trim() }
        }
    }
    if (-not $texts.Count) {
        $missing += $p
        $authors = if ($p.authors) { ($p.authors | ForEach-Object { $_ -replace '\s*<[^>]*>', '' }) -join ', ' } else { "the $($p.name) authors" }
        foreach ($id in $chosen) {
            $std = Join-Path $PSScriptRoot "licenses\$id.txt"
            if (-not (Test-Path -LiteralPath $std)) { $needed += "licenses\$id.txt"; continue }
            $t = ([IO.File]::ReadAllText($std) -replace "`r`n", "`n").Trim()
            $texts += if ($t.Contains("<year> <copyright holders>")) { $t.Replace("<year> <copyright holders>", $authors) } else { "Copyright (c) $authors`n`n$t" }
        }
    }
    foreach ($t in $texts) {
        if (-not $groups.Contains($t)) { $groups[$t] = [System.Collections.Generic.List[string]]::new() }
        if (-not $groups[$t].Contains($label)) { $groups[$t].Add($label) }
    }
}

if ($needed.Count) { throw "standard licence texts missing:`n  " + (($needed | Sort-Object -Unique) -join "`n  ") }
if ($unresolved.Count) { throw "licence files pointed at but not found (add the file's stand-in to `$pointedAt):`n  " + ($unresolved -join "`n  ") }
if ($Report) {
    "shipped crates: $($shipped.Count); distinct texts: $($groups.Count); with no text of their own: $($missing.Count)"
    $missing | ForEach-Object { "  {0} {1}: {2}" -f $_.name, $_.version, $_.license }
}

$rule = "-" * 78
$sb = [Text.StringBuilder]::new()
[void]$sb.Append("VibeTrace includes the third-party software listed below. VibeTrace itself is licensed under the`nGNU Affero General Public License v3.0 (LICENSE). Slint is used under its GPL-3.0 option.`n")
[void]$sb.Append("`nThe Rust standard library is linked in (MIT OR Apache-2.0, the Rust Project Developers),`nand so is the Microsoft C runtime (static CRT, under the Visual Studio license terms).`n")
[void]$sb.Append("`n$rule`nCrates ($($shipped.Count))`n$rule`n")
foreach ($p in $shipped) { [void]$sb.Append("$($p.name) $($p.version): $(if ($p.license) { $p.license } else { 'see its licence file' })`n") }
foreach ($t in $groups.Keys) {
    [void]$sb.Append("`n$rule`n$($groups[$t] -join "`n")`n$rule`n`n$t`n")
}
New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
[IO.File]::WriteAllText($Out, ($sb.ToString() -replace "`n", "`r`n"), [Text.UTF8Encoding]::new($false))
if ($Report) { "wrote $Out ($((Get-Item $Out).Length) bytes)" }
