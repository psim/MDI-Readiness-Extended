# [w87] The active power scheme must come from powercfg's SUCCESS LINE, not from any GUID in its output.
#
# powercfg /getactivescheme prints exactly one line on success - "<label>: <guid>  (<name>)" - where
# only the LABEL is localised. The reader matched ": <guid> (<name>)" ANYWHERE in the output, and an
# error message is free to contain both. Measured with a stubbed powercfg:
#
#   "ERROR: powercfg.exe was blocked by policy: 8c5e7fda-...-a6e23a8c635c (High performance)"
#       -> isPowerSchemeOk = TRUE. A server whose scheme could not be read at all was certified
#          as correctly configured.
#   "ERROR: ... blocked by application-control policy. Activity ID: {01234567-...} (Corporate WDAC policy)"
#       -> isPowerSchemeOk = FALSE, and the generated remediation wrote powercfg /setactive onto that
#          server. Changing a production power plan on the strength of a GUID scraped out of an error
#          message is the expensive kind of wrong answer.
#
# The second failure came from the classifier as well as the matcher: its "unreadable" test was
# "contains no GUID at all", which an unrelated Activity ID satisfies, so the output fell through to
# the else branch and was reported as a WRONG scheme rather than an unread one.
#
# Probe: MDI-AB\live\w87-power-guiderror.ps1

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# Set-Item -Path function:script: is mandatory here. A `function global:` would NOT override the
# script's own copy and every case below would silently test the real remote command instead.
$script:powercfgOutput = $null
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile)
    $script:powercfgOutput
}

function Get-Scheme {
    param($Output)
    $script:powercfgOutput = $Output
    Get-mdiPowerScheme -ComputerName 'dc1.contoso.com'
}
# Does the generated remediation script write a power-plan change for this reading?
function Test-WritesPowercfg {
    param($SchemeValue)
    $srv = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        PowerSettings = $SchemeValue
        NtlmAuditing = $true; AdvancedAuditing = $true; RequiredPorts = $true; TimeSync = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com')
        DomainControllers = @($srv); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); SkippedAreas = @()
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
    }
    $dir = Join-Path $env:TEMP ('mdipwr-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $dir -Force)
    try {
        $f = Join-Path $dir 'Fix.ps1'
        New-mdiRemediationScript -ReportData $report -FilePath $f 3>$null 4>$null 6>$null | Out-Null
        if (-not (Test-Path $f)) { return $false }
        ([IO.File]::ReadAllText($f)) -match 'powercfg\.exe /setactive'
    } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

$highGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'

'[w87] an ERROR carrying the High-performance GUID is NOT a passing power scheme'
$r = Get-Scheme ('ERROR: powercfg.exe was blocked by policy: {0} (High performance)' -f $highGuid)
Assert-That 'the reading is not measured' ([string] $r.isPowerSchemeOk -eq 'N/A') "(got '$($r.isPowerSchemeOk)')"
Assert-That '  ...and is NOT reported as correctly configured' ($r.isPowerSchemeOk -ne $true) "(got '$($r.isPowerSchemeOk)')"
Assert-That '  ...and no power-plan change is generated' (-not (Test-WritesPowercfg -SchemeValue $r.isPowerSchemeOk))

'[w87] an ERROR carrying an UNRELATED GUID is not a failing power scheme either'
# This one is worse than a false green: it wrote powercfg /setactive onto a production server whose
# scheme had never been read.
$r2 = Get-Scheme 'ERROR: powercfg.exe was blocked by application-control policy. Activity ID: {01234567-89ab-cdef-0123-456789abcdef} (Corporate WDAC policy)'
Assert-That 'the reading is not measured' ([string] $r2.isPowerSchemeOk -eq 'N/A') "(got '$($r2.isPowerSchemeOk)')"
Assert-That '  ...and is NOT reported as a wrong scheme' ($r2.isPowerSchemeOk -ne $false) "(got '$($r2.isPowerSchemeOk)')"
Assert-That '  ...and no power-plan change is generated' (-not (Test-WritesPowercfg -SchemeValue $r2.isPowerSchemeOk))

'[w87] CONTROL - a genuine success line is still read, in every locale'
# Without these, returning N/A unconditionally would satisfy everything above.
$ok1 = Get-Scheme ('Power Scheme GUID: {0}  (High performance)' -f $highGuid)
Assert-That 'en-US High performance passes' ($ok1.isPowerSchemeOk -eq $true) "(got '$($ok1.isPowerSchemeOk)')"
$ok2 = Get-Scheme ('Power Scheme GUID: {0}  (Yuksek performans)' -f $highGuid.ToUpperInvariant())
Assert-That 'an UPPER-CASE GUID passes' ($ok2.isPowerSchemeOk -eq $true) "(got '$($ok2.isPowerSchemeOk)')"
$ok3 = Get-Scheme ('Energieschema-GUID: {0}  (Hochstleistung)' -f $highGuid)
Assert-That 'a localised LABEL passes' ($ok3.isPowerSchemeOk -eq $true) "(got '$($ok3.isPowerSchemeOk)')"

'[w87] CONTROL - a genuine WRONG scheme is still failed, and still remediated'
$bal = Get-Scheme 'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)'
Assert-That 'Balanced is a measured failure' ($bal.isPowerSchemeOk -eq $false) "(got '$($bal.isPowerSchemeOk)')"
Assert-That '  ...and IS remediated' (Test-WritesPowercfg -SchemeValue $bal.isPowerSchemeOk) '(the real fix was dropped)'

'[w87] CONTROL - genuinely unreadable output is still not measured'
$n1 = Get-Scheme $null
Assert-That 'no response is not measured' ([string] $n1.isPowerSchemeOk -eq 'N/A') "(got '$($n1.isPowerSchemeOk)')"
$n2 = Get-Scheme 'Zugriff verweigert: powercfg.exe wurde durch die Richtlinie blockiert'
Assert-That 'a non-English error with no GUID is not measured' ([string] $n2.isPowerSchemeOk -eq 'N/A') "(got '$($n2.isPowerSchemeOk)')"

'[w87] CONTROL - the success line is still found among other output lines'
# Invoke-mdiRemoteCommand returns an ARRAY of lines whenever the redirected file holds more than one,
# and a stderr warning or a banner ahead of the scheme line is ordinary.
$multi = Get-Scheme @('WARNING: something noisy', ('Power Scheme GUID: {0}  (High performance)' -f $highGuid), '')
Assert-That 'a success line preceded by noise still passes' ($multi.isPowerSchemeOk -eq $true) "(got '$($multi.isPowerSchemeOk)')"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
