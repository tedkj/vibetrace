# Signs one file for a release with the Certum code signing certificate (SimplySign in the cloud).
# build.ps1 -Sign runs it on the bundled exe; makensis runs it (app.nsi's !uninstfinalize and
# !finalize) on the uninstaller before it is packed and on the finished installer.
#   sign.ps1 -Config <sign.json> -File <file> [-Keep <path>]
# -Keep: a copy of the signed file there (the uninstaller, for build.ps1's check).
# Exit 0 once the file carries a signature, 1 (with the reason on stderr) when it does not.
#
# The config lives outside every repo (%USERPROFILE%\.vibeware\sign.json) and holds no secret:
#   signtool    signtool.exe (Windows SDK)
#   thumbprint  the SHA-1 thumbprint of the code signing certificate in Cert:\CurrentUser\My;
#               SimplySign Desktop puts it there while it is connected, the key stays in the cloud
#   timestamp   the RFC 3161 timestamp server; left out: http://time.certum.pl
#   testPfx     tests only, in place of thumbprint: a throwaway self-signed PFX without a
#               password; only with it may timestamp be "" (no timestamp, no network)
# Digests are SHA-256 (file and timestamp). Windows PowerShell 5.1.
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$File,
    [string]$Keep = ""
)
$ErrorActionPreference = "Stop"
# Always its own Windows PowerShell process (build.ps1 and makensis start it by its full path).
# Started from PowerShell 7 by anything but PowerShell 7 itself (makensis under a pwsh build.ps1),
# it inherits pwsh's PSModulePath, whose modules it can't load (no signature or JSON cmdlets):
# the built-in ones only.
$env:PSModulePath = "$PSHOME\Modules"

function Fail([string]$why) {
    [Console]::Error.WriteLine("sign.ps1: $why")
    exit 1
}

function Field($cfg, [string]$name) {
    $p = $cfg.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

function ExistingFile($cfg, [string]$name) {
    $v = Field $cfg $name
    if (-not ($v -is [string]) -or $v -eq "") { Fail "$Config has no `"$name`"" }
    if (-not (Test-Path -LiteralPath $v -PathType Leaf)) { Fail "$Config's `"$name`" is not a file: $v" }
    return $v
}

try {
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { Fail "no signing config at $Config" }
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { Fail "no file to sign at $File" }
    $cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json

    $signtool = ExistingFile $cfg "signtool"
    $test = $null -ne (Field $cfg "testPfx")
    $thumbprint = Field $cfg "thumbprint"
    if ($test -and $null -ne $thumbprint) { Fail "$Config has testPfx and thumbprint: one or the other" }
    $timestamp = Field $cfg "timestamp"
    if ($null -eq $timestamp) { $timestamp = "http://time.certum.pl" }
    if (-not ($timestamp -is [string])) { Fail "$Config's `"timestamp`" is not a string" }
    if ($timestamp -eq "") {
        # The certificate lives a year: a signature without a timestamp dies with it.
        if (-not $test) { Fail "$Config has no timestamp server, which only a test certificate may skip" }
    } elseif ($timestamp -notmatch '^https?://[^\s"]+$') {
        Fail "$Config's `"timestamp`" is not an http(s) URL: $timestamp"
    }

    $a = @("sign", "/fd", "SHA256")
    if ($timestamp -ne "") { $a += @("/tr", $timestamp, "/td", "SHA256") }
    if ($test) {
        $a += @("/f", (ExistingFile $cfg "testPfx"))
    } else {
        if (-not ($thumbprint -is [string]) -or $thumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
            Fail "$Config has no `"thumbprint`" (40 hex digits)"
        }
        $cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) { Fail "certificate $thumbprint is not in Cert:\CurrentUser\My: is SimplySign Desktop connected?" }
        if (-not $cert.HasPrivateKey) { Fail "certificate $thumbprint has no private key here: is SimplySign Desktop connected?" }
        if ($cert.NotAfter -lt (Get-Date)) { Fail "certificate $thumbprint expired $($cert.NotAfter)" }
        $a += @("/s", "My", "/sha1", $thumbprint)
    }
    & $signtool @a $File
    if ($LASTEXITCODE -ne 0) { Fail "signtool failed ($LASTEXITCODE) on $File" }

    $s = Get-AuthenticodeSignature -LiteralPath $File
    if (-not $s.SignerCertificate) { Fail "$File carries no signature after signtool ($($s.Status))" }
    if (-not $test -and $s.SignerCertificate.Thumbprint -ne $thumbprint.ToUpperInvariant()) {
        Fail "$File is signed by $($s.SignerCertificate.Thumbprint), not $thumbprint"
    }
    if ($timestamp -ne "" -and -not $s.TimeStamperCertificate) { Fail "$File's signature has no timestamp" }
    if ($Keep -ne "") { Copy-Item -LiteralPath $File -Destination $Keep -Force }
} catch {
    Fail "$_"
}
exit 0
