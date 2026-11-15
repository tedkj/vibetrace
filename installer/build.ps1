# Build the release exe and its installer: target\release\bundle\VibeTrace_<version>_x64-setup.exe.
# Never with dev hooks.
#   build.ps1 [-Sign | -TestSign] [-SignConfig <sign.json>]
# -Sign signs the exe, the uninstaller and the installer with the Certum certificate (sign.ps1;
# SimplySign Desktop connected); off by
# default, and without it nothing is signed or checked for a signature. Every signature counts
# against Certum's monthly cap: sign releases, not dev builds. Certum's Open Source certificate
# signs open source only: never -Sign an app whose repository isn't public yet.
# -TestSign does the same with a config's throwaway test certificate (testPfx), for tests only;
# -Sign refuses such a config, so a release can't be test-signed by accident.
param(
    [switch]$Sign,
    [switch]$TestSign,
    [string]$SignConfig = "$env:USERPROFILE\.vibeware\sign.json"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

if ($TestSign) { $Sign = $true }
if ($Sign) {
    if (-not (Test-Path -LiteralPath $SignConfig -PathType Leaf)) { throw "-Sign: no signing config at $SignConfig" }
    $testPfx = $null -ne (Get-Content -LiteralPath $SignConfig -Raw | ConvertFrom-Json).testPfx
    if ($testPfx -and -not $TestSign) { throw "-Sign: $SignConfig has a testPfx, a throwaway test certificate, which never signs a release (-TestSign builds a test-signed installer)" }
    if ($TestSign -and -not $testPfx) { throw "-TestSign: $SignConfig has no testPfx (a throwaway test certificate)" }
}

# makensis is the official NSIS 3.13 (nsis-3.13.zip from SourceForge, SHA-256 ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8),
# unpacked to _tools\nsis-3.13 in the folder that holds this repository, and that whole folder must hash as pinned (TreeHash
# below), so a changed, missing or added file stops the build: a DLL planted in Bin\, a header,
# a plugin, a stub. makensis reads its stubs and plugins from NSISDIR when that is set, and
# nsisconf.nsh from NSISCONFDIR: neither may be. /NOCONFIG keeps it from reading any nsisconf.nsh
# (its own, or one in %APPDATA%). An .nsh beside app.nsi would win over NSIS's own header of that
# name, and one in a subfolder too (MUI2.nsh includes Pages\Directory.nsh by a relative path,
# review RP1), so installer\ holds none at any depth, hidden ones included, and no junction or link
# to look past. Checked before cargo, and again right before makensis runs.
$Nsis = Join-Path (Split-Path $root -Parent) "_tools\nsis-3.13"
$makensis = "$Nsis\Bin\makensis.exe"
$NsisTreeSha256 = "81083599E7C4E4B30E52429E896FCC58A7F050749F6F043394843A13BBE9F927"
# SHA-256 over the "relative/path<TAB>SHA-256<LF>" lines (UTF-8, upper-case hex, sorted by ordinal)
# of every file under $dir, hidden ones too.
function TreeHash([string]$dir) {
    $skip = (Get-Item -LiteralPath $dir).FullName.TrimEnd('\').Length + 1
    [string[]]$lines = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Force | ForEach-Object {
        "{0}`t{1}`n" -f $_.FullName.Substring($skip).Replace('\', '/'), (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    })
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes(-join $lines))) -Algorithm SHA256).Hash
}
function AssertNsis {
    foreach ($v in "NSISDIR", "NSISCONFDIR") {
        if ($null -ne [Environment]::GetEnvironmentVariable($v)) { throw "$v is set: makensis would read its stubs or config from there. Unset it." }
    }
    $skip = (Get-Item -LiteralPath $PSScriptRoot).FullName.TrimEnd('\').Length + 1
    $nsh = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Filter *.nsh -Force | ForEach-Object { $_.FullName.Substring($skip) })
    if ($nsh.Count -ne 0) { throw "installer\ holds $($nsh -join ', '): an .nsh there, at any depth (MUI2.nsh includes Pages\Directory.nsh by a relative path), would win over NSIS's own header of that name. Remove it." }
    $links = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Force -Attributes ReparsePoint | ForEach-Object { $_.FullName.Substring($skip) })
    if ($links.Count -ne 0) { throw "installer\ holds $($links -join ', '), a junction or link, which the .nsh check can't look through. Remove it." }
    if (-not (Test-Path -LiteralPath $makensis -PathType Leaf)) { throw "no $makensis (the official NSIS 3.13, nsis-3.13.zip unpacked there: README, Building the installer)" }
    $h = TreeHash $Nsis
    if ($h -ne $NsisTreeSha256) { throw "$Nsis's tree hash is $h, not the pinned ${NsisTreeSha256}: not the official NSIS 3.13 (a file changed, missing or added), not run" }
}
AssertNsis

$version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$parts = ($version -split '[.+-]')[0..2] | ForEach-Object { [int]$_ }
$version4 = "{0}.{1}.{2}.0" -f $parts[0], $parts[1], $parts[2]

# DLL hardening (VibeLink R-LINK-3): no RUSTFLAGS that would drop the static CRT; the bundled exe
# is checked below.
& "$PSScriptRoot\check.ps1"
if ($LASTEXITCODE -ne 0) { throw "the build environment would drop the DLL hardening" }

# No user name or build path in the exe (installer-audit IA1): rustc writes the source path of
# every panic location into it (the dependencies' under the cargo folder, slint's generated
# include under target\), and cl the C sources' __FILE__. Each folder is remapped to a neutral
# prefix through --config, which cargo joins with .cargo/config.toml's rustflags (a RUSTFLAGS
# variable would replace them, +crt-static with them); the last matching remap wins, so the
# profile goes first. cl trims the cargo folder in the 8.3 form a C build may use (aws-lc).
# `check.ps1 -Paths` fails the build if any such path is left. --locked: the build uses
# Cargo.lock as committed, never a re-resolved one (IA2).
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$env:USERPROFILE\.cargo" }
$rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { "$env:USERPROFILE\.rustup" }
$remaps = @("$env:USERPROFILE=/home", "$cargoHome=/cargo", "$rustupHome=/rustup", "$root=/src")
if (@($remaps | Where-Object { $_.Contains("'") }).Count -gt 0) { throw "a build folder's path holds a ' (a TOML literal string can't): $($remaps -join ', ')" }
$remapConfig = "target.x86_64-pc-windows-msvc.rustflags=[" + (($remaps | ForEach-Object { "'--remap-path-prefix=$_'" }) -join ",") + "]"
$fso = New-Object -ComObject Scripting.FileSystemObject
foreach ($d in @($cargoHome, $fso.GetFolder($cargoHome).ShortPath)) { if (-not $d.Contains(" ")) { $env:CFLAGS = ("$env:CFLAGS /d1trimfile:$d\").Trim() } }

Push-Location $root
try {
    cargo build --release --locked --config $remapConfig --bin vibetrace
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
} finally { Pop-Location }

$bundle = "$root\target\release\bundle"
New-Item -ItemType Directory -Force $bundle | Out-Null
$exe = "$bundle\VibeTrace.exe"
Copy-Item "$root\target\release\vibetrace.exe" $exe -Force
# Signed before the check, so the check reads the exe that ships; sign.ps1 runs in its own Windows
# PowerShell, as under makensis.
if ($Sign) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot\sign.ps1" -Config $SignConfig -File $exe
    if ($LASTEXITCODE -ne 0) { throw "signing the exe failed" }
}
& "$PSScriptRoot\check.ps1" -Exe $exe
if ($LASTEXITCODE -ne 0) { throw "the release exe lacks the DLL hardening: not bundled" }
& "$PSScriptRoot\check.ps1" -Paths $exe
if ($LASTEXITCODE -ne 0) { throw "the release exe holds a user name or build path: not bundled" }
# VibeTrace's licence and the third-party notices go next to the exe: notices.ps1 lists the crates
# this build linked (Cargo.lock as committed) with their licence texts.
$notices = "$bundle\THIRD-PARTY-NOTICES.txt"
& "$PSScriptRoot\notices.ps1" -Out $notices
$out = "$bundle\VibeTrace_${version}_x64-setup.exe"

# With -Sign, app.nsi's !uninstfinalize signs the uninstaller (and keeps a copy here) and its
# !finalize the installer, each through sign.ps1; without it makensis gets no SIGN define.
$uninst = "$bundle\uninstall.exe"
$signDefines = @()
if ($Sign) {
    if (Test-Path -LiteralPath $uninst) { Remove-Item -LiteralPath $uninst }
    $signDefines = @("/DSIGN=$SignConfig", "/DSIGNED_UNINSTALLER=$uninst")
}

try {
    Push-Location $PSScriptRoot
    try {
        AssertNsis
        & $makensis /NOCONFIG /V2 "/DVERSION=$version" "/DVERSION4=$version4" "/DEXE=$exe" "/DLICENSE=$root\LICENSE" "/DNOTICES=$notices" "/DOUTFILE=$out" @signDefines app.nsi
        if ($LASTEXITCODE -ne 0) { throw "makensis failed" }
    } finally { Pop-Location }

    # All three signed, by one certificate; valid (a trusted chain), or with -TestSign also the
    # test certificate's untrusted root (UnknownError).
    if ($Sign) {
        $signer = $null
        foreach ($f in @($exe, $uninst, $out)) {
            if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "-Sign: $f is missing" }
            $s = Get-AuthenticodeSignature -LiteralPath $f
            if (-not $s.SignerCertificate) { throw "-Sign: $f is not signed ($($s.Status))" }
            $ok = $s.Status -eq "Valid" -or ($TestSign -and $s.Status -eq "UnknownError")
            if (-not $ok) { throw "-Sign: $f's signature is $($s.Status): $($s.StatusMessage)" }
            if ($signer -and $s.SignerCertificate.Thumbprint -ne $signer) { throw "-Sign: $f is signed by another certificate" }
            $signer = $s.SignerCertificate.Thumbprint
            "signed  {0}  ({1}, {2})" -f $f, $s.SignerCertificate.Subject, $s.Status
        }
    }
} catch {
    # makensis writes the installer before !finalize signs it: a failed -Sign build leaves none.
    if ($Sign -and (Test-Path -LiteralPath $out)) { Remove-Item -LiteralPath $out }
    throw
}

"{0}  {1:N0} bytes" -f $out, (Get-Item $out).Length
