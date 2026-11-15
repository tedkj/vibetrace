# The release list for About's "Check this install": adds this version's
# files (their SHA-256) to installer\releases\vibetrace.json, sets "latest", and prints the
# minisign command that signs it. It never signs anything itself: Ted runs that command with the
# release key, then uploads the list and its .minisig to https://getvibeware.com/releases/.
#
#   release-list.ps1 -Uninstaller <uninstall.exe from a test install of this version's setup>
#       [-Exe <bundled exe>] [-Version <x.y.z>] [-List <json>] [-Key <minisign secret key>]
#
# A version already in the list keeps its hashes: a published release never changes, so other
# files for it are refused (bump the version instead).
param(
    [string]$Exe = "",
    [Parameter(Mandatory = $true)][string]$Uninstaller,
    [string]$Version = "",
    [string]$List = "",
    [string]$Key = "<the release key>"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
$app = "VibeTrace"
if ($Exe -eq "") { $Exe = "$root\target\release\bundle\$app.exe" }
if ($List -eq "") { $List = "$PSScriptRoot\releases\vibetrace.json" }
if ($Version -eq "") {
    $Version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
}
if ($Version -cnotmatch '^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}\z') { throw "not a release version: $Version" }

# Versions ordered as the app orders them (check::compare, review RAB-6): the three numbers
# each by value, a pre-release before its release, two pre-releases part by part (digits by
# value and before words, words by their text, the shorter first). A version the app wouldn't
# read (check::version) stops the script. The patterns end in \z, not $: in .NET, $ also matches
# before a final line break, which would go into the list's JSON raw (review RRAB-4).
function Ver([string]$v) {
    if ($v.Length -gt 32 -or -not ($v -cmatch '^([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})(?:-([A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*))?\z')) { throw "not a version number: $v" }
    return @{ Nums = @([long]$Matches[1], [long]$Matches[2], [long]$Matches[3]); Pre = $Matches[4] }
}
function ComparePart([string]$x, [string]$y) {
    $xn = $x -cmatch '^[0-9]+\z'; $yn = $y -cmatch '^[0-9]+\z'
    if ($xn -and $yn) {
        $x = $x.TrimStart('0'); $y = $y.TrimStart('0')
        if ($x.Length -ne $y.Length) { return [Math]::Sign($x.Length - $y.Length) }
        return [Math]::Sign([string]::CompareOrdinal($x, $y))
    }
    if ($xn) { return -1 }
    if ($yn) { return 1 }
    return [Math]::Sign([string]::CompareOrdinal($x, $y))
}
function CompareVersion([string]$a, [string]$b) {
    $va = Ver $a; $vb = Ver $b
    for ($i = 0; $i -lt 3; $i++) {
        if ($va.Nums[$i] -ne $vb.Nums[$i]) { return [Math]::Sign($va.Nums[$i] - $vb.Nums[$i]) }
    }
    if (-not $va.Pre -and -not $vb.Pre) { return 0 }
    if (-not $vb.Pre) { return -1 }
    if (-not $va.Pre) { return 1 }
    $pa = $va.Pre.Split('.'); $pb = $vb.Pre.Split('.')
    for ($i = 0; $i -lt [Math]::Min($pa.Count, $pb.Count); $i++) {
        $c = ComparePart $pa[$i] $pb[$i]
        if ($c -ne 0) { return $c }
    }
    return [Math]::Sign($pa.Count - $pb.Count)
}

# .NET's SHA-256, not Get-FileHash: under Windows PowerShell started from pwsh 7 the module
# path can hide that cmdlet.
function Sha256([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "no file at $path" }
    $s = [IO.File]::OpenRead($path)
    try { $h = [Security.Cryptography.SHA256]::Create().ComputeHash($s) } finally { $s.Dispose() }
    return (($h | ForEach-Object { $_.ToString("x2") }) -join "")
}
$files = [ordered]@{ "$app.exe" = (Sha256 $Exe); "uninstall.exe" = (Sha256 $Uninstaller) }

# version -> (file name -> hash), as the list has it now.
$releases = @{}
$latest = $Version
if (Test-Path -LiteralPath $List) {
    $old = Get-Content -LiteralPath $List -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($old.app -ne $app) { throw "$List is the list of $($old.app), not $app" }
    $latest = $old.latest
    foreach ($v in $old.releases.PSObject.Properties) {
        $entry = [ordered]@{}
        foreach ($f in $v.Value.PSObject.Properties) { $entry[$f.Name] = [string]$f.Value }
        $releases[$v.Name] = $entry
    }
}
if ($releases.ContainsKey($Version)) {
    $had = $releases[$Version]
    foreach ($name in $files.Keys) {
        if ($had[$name] -ne $files[$name]) { throw "$Version is in the list already with another $name. A published release never changes: bump the version." }
    }
}
$releases[$Version] = $files
if ((CompareVersion $Version $latest) -gt 0) { $latest = $Version }

# Written by hand: one stable layout (versions in order), UTF-8 without a BOM, LF line ends.
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('{')
$lines.Add("  ""app"": ""$app"",")
$lines.Add("  ""latest"": ""$latest"",")
$lines.Add('  "releases": {')
# In the app's order (an insertion sort: a list has a handful of versions).
$versions = New-Object System.Collections.Generic.List[string]
foreach ($v in $releases.Keys) {
    $at = 0
    while ($at -lt $versions.Count -and (CompareVersion $versions[$at] $v) -le 0) { $at++ }
    $versions.Insert($at, $v)
}
for ($i = 0; $i -lt $versions.Count; $i++) {
    $v = $versions[$i]
    $lines.Add("    ""$v"": {")
    $names = @($releases[$v].Keys)
    for ($j = 0; $j -lt $names.Count; $j++) {
        $comma = if ($j -lt $names.Count - 1) { "," } else { "" }
        $lines.Add("      ""$($names[$j])"": ""$($releases[$v][$names[$j]])""$comma")
    }
    $comma = if ($i -lt $versions.Count - 1) { "," } else { "" }
    $lines.Add("    }$comma")
}
$lines.Add('  }')
$lines.Add('}')
New-Item -ItemType Directory -Force (Split-Path -Parent $List) | Out-Null
[IO.File]::WriteAllText($List, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))

"$List`: $app $Version added, latest $latest"
"Sign it (minisign asks for the key's password), then upload both files to https://getvibeware.com/releases/:"
"  minisign -S -s ""$Key"" -m ""$List"""
