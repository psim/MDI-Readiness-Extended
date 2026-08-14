<#
    An unmeasured thing is never presented as a measurement.

    Two surfaces, one shape. Both print or generate a claim about something that was never observed,
    because a comparison against an absent or $null tri-state quietly landed on the "measured" side.

    1. The capacity tab. FullBusyWindow is a boolean on a server that was SAMPLED. A server whose
       capacity could not be read at all - Get-mdiCapacityPlanning's notSized path returns details
       carrying only Status and Detail - has no such property, and $null -eq $false is FALSE. So the
       "partial window" test missed it and the tab printed the reassurance "Sampled over a full busy
       window. The sample was long enough to take the highest rolling 15-minute average" directly
       above a row reading "Missing core data - Unable to read the processor information over WMI".
       Reachable from any -CapacityPlanning run where WMI to a domain controller fails.

    2. The generated remediation script. $blockedNnr was filtered with '-not $_.Success', which is
       TRUE for a probe whose Success normalised to $null - a probe that produced no result - so a
       record nobody measured could be written out as an explicit New-NetFirewallRule. That is an
       operator opening a port on a domain controller on the strength of a measurement that does not
       exist.

    These drive the REAL functions and assert on the HTML and the generated file, never on a
    reimplementation.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# ----------------------------------------------------------------------------------------------
Write-Host 'Capacity: a server that could not be sampled is never called "fully sampled"' -ForegroundColor Cyan

function New-CapacityServer {
    param($Fqdn, $Details)
    $o = [PSCustomObject]@{ FQDN = $Fqdn; Domain = 'contoso.com'; Details = [PSCustomObject]@{} }
    $o.Details | Add-Member -NotePropertyName CapacityDetails -NotePropertyValue $Details -Force
    $o
}
# The shape the REAL producer emits when the host cannot be read. Built to match, and pinned below
# against the real function so it cannot drift into a shape the script never produces.
$notSizedDetails = [PSCustomObject]@{ Status = 'Missing core data'; Detail = 'Unable to read the processor information over WMI' }
$fullDetails = [PSCustomObject]@{
    Status = 'Supported'; Detail = 'ok'; FullBusyWindow = $true; SampleSeconds = 900
    BusyPacketsPerSec = 100; AveragePacketsPerSec = 90; PeakPacketsPerSec = 120
}
$partialDetails = [PSCustomObject]@{
    Status = 'Supported'; Detail = 'ok'; FullBusyWindow = $false; SampleSeconds = 30
    BusyPacketsPerSec = 100; AveragePacketsPerSec = 90; PeakPacketsPerSec = 120
}

function Get-CapacityCallout {
    param([object[]] $Server)
    $html = (Get-mdiCapacityHtml -Server $Server) -join "`n"
    $m = [regex]::Match($html, '<div class="callout (\w+)"><span class="ico">[^<]*</span><div class="body"><b>([^<]*)</b>')
    if (-not $m.Success) { return [PSCustomObject]@{ Tone = '(none)'; Head = '(none)'; Html = $html } }
    [PSCustomObject]@{ Tone = $m.Groups[1].Value; Head = $m.Groups[2].Value; Html = $html }
}

$onlyUnsampled = Get-CapacityCallout @((New-CapacityServer 'dc1.contoso.com' $notSizedDetails))
Assert-That 'an unsampled server does not print "Sampled over a full busy window"' (
    $onlyUnsampled.Head -notmatch 'Sampled over a full busy window') "(head '$($onlyUnsampled.Head)')"
Assert-That '  ...it says the server could not be sampled' (
    $onlyUnsampled.Head -match 'could not be sampled') "(head '$($onlyUnsampled.Head)')"
Assert-That '  ...and is not toned info' ($onlyUnsampled.Tone -ne 'info') "(tone '$($onlyUnsampled.Tone)')"
Assert-That '  ...and the reassuring rolling-average sentence is absent entirely' (
    $onlyUnsampled.Html -notmatch 'highest rolling')

# One unsampled among sampled ones must still be disclosed - this is the mixed estate case.
$mixed = Get-CapacityCallout @(
    (New-CapacityServer 'dc1.contoso.com' $notSizedDetails)
    (New-CapacityServer 'dc2.contoso.com' $fullDetails)
)
Assert-That 'one unsampled server among sampled ones is still disclosed' (
    $mixed.Head -match 'could not be sampled') "(head '$($mixed.Head)')"
Assert-That '  ...and names how many of how many' ($mixed.Head -match '1 of 2') "(head '$($mixed.Head)')"

# Controls: the two genuine states must keep their existing wording, or the tone carries no meaning.
$full = Get-CapacityCallout @((New-CapacityServer 'dc1.contoso.com' $fullDetails))
Assert-That 'a genuinely full busy window still reads "Sampled over a full busy window"' (
    $full.Head -match 'Sampled over a full busy window' -and $full.Tone -eq 'info') "(tone '$($full.Tone)' head '$($full.Head)')"
$partial = Get-CapacityCallout @((New-CapacityServer 'dc1.contoso.com' $partialDetails))
Assert-That 'a genuinely partial window still reads "Estimate only"' (
    $partial.Head -match 'Estimate only' -and $partial.Tone -eq 'warn') "(tone '$($partial.Tone)' head '$($partial.Head)')"
# A partial window beside an unsampled server: BOTH facts must be stated. Making these mutually
# exclusive branches let one short-sampled server suppress the disclosure for every server that
# could not be read at all - the tab then showed only "This run sampled only 5 second(s) per
# server", a claim about every server, above a row reading "Missing core data". The earlier version
# of this assertion checked only the tone and the absence of the rolling-average sentence, which
# both still held, so it passed while the defect was live.
$partialPlusUnsampled = Get-CapacityCallout @(
    (New-CapacityServer 'dc1.contoso.com' $partialDetails)
    (New-CapacityServer 'dc2.contoso.com' $notSizedDetails)
)
Assert-That 'a partial window is not silenced by an unsampled server' (
    $partialPlusUnsampled.Tone -eq 'warn' -and $partialPlusUnsampled.Html -notmatch 'highest rolling')
Assert-That '  ...the short-sample caveat is still shown' (
    $partialPlusUnsampled.Html -match 'Estimate only') "(html head '$($partialPlusUnsampled.Head)')"
Assert-That '  ...AND the unsampled server is still disclosed beside it' (
    $partialPlusUnsampled.Html -match 'could not be sampled') "(html head '$($partialPlusUnsampled.Head)')"
Assert-That '  ...naming 1 of 2' ($partialPlusUnsampled.Html -match '1 of 2 server\(s\) could not be sampled')
# The duration is a fact about the servers that WERE sampled, and may not be asserted of the others.
Assert-That '  ...and the duration is not claimed of every server' (
    $partialPlusUnsampled.Html -notmatch 'second\(s\)</b> per server') "(claims per server)"

# The shape above must be the shape the REAL producer emits, or the test pins a fiction.
$realNotSized = $null
try {
    Set-Item -Path function:script:Get-mdiWmiValue -Value { param($ComputerName, $Class, $Property) $null } -ErrorAction SilentlyContinue
    $realNotSized = Get-mdiCapacityPlanning -ComputerName 'no-such-host.invalid' -DurationSeconds 1 -ErrorAction SilentlyContinue
} catch { $realNotSized = $null }
if ($realNotSized -and $realNotSized.details) {
    Assert-That 'the real unreadable-host result carries no FullBusyWindow property' (
        $realNotSized.details.FullBusyWindow -isnot [bool]) "(got '$($realNotSized.details.FullBusyWindow)')"
} else {
    Write-Host '  SKIP  real producer not exercised in this environment' -ForegroundColor DarkYellow
}

# ----------------------------------------------------------------------------------------------
Write-Host 'Remediation: no firewall rule for an NNR probe that produced no result' -ForegroundColor Cyan

function New-NnrServer {
    param([object[]] $Results)
    $o = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; Comment = $null
        SensorVersion = '2.240.0.0'; Addresses = @('10.0.0.10'); IP = '10.0.0.10'
        Details = [PSCustomObject]@{}
    }
    $o | Add-Member -NotePropertyName RequiredPorts -NotePropertyValue $false -Force
    $o.Details | Add-Member -NotePropertyName RequiredPortsDetails -NotePropertyValue ([PSCustomObject]@{ Results = $Results }) -Force
    $o
}
# The NNR record shape the script's own probe planner emits: an AtLeastOne requirement, no Server
# field (Get-mdiPortResultRecord stamps that from the owning server).
function New-NnrRecord {
    param($Port, $Protocol, $Success, $Detail)
    [PSCustomObject]@{
        Id = ('nnr-{0}-{1}' -f $Protocol, $Port); Group = 'NNR'; Scope = 'NetworkDevice'
        Requirement = 'AtLeastOne'; Protocol = $Protocol; Port = $Port
        Target = 'peer.contoso.com'; TargetIP = '10.0.0.9'
        Applicable = $true; Success = $Success; Detail = $Detail
    }
}
function Get-NnrRuleNames {
    param([object[]] $Results)
    $rep = [PSCustomObject]@{
        DomainControllers   = @((New-NnrServer $Results))
        CAServers           = @(); EntraConnectServers = @()
        DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    }
    $out = Join-Path ([IO.Path]::GetTempPath()) ('mdi-nnr-test-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    try {
        $null = New-mdiRemediationScript -ReportData $rep -FilePath $out
        $script = if (Test-Path $out) { [IO.File]::ReadAllText($out) } else { '' }
        @([regex]::Matches($script, 'MDI-NNR-[A-Za-z]+-In') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
}

# A measured failure and an unmeasured probe on the SAME target. Only the measured one may be acted on.
$mixedRules = Get-NnrRuleNames @(
    (New-NnrRecord 135 'TCP' $false 'Connection refused')
    (New-NnrRecord 137 'UDP' $null 'Probe returned no result')
)
Assert-That 'the measured RPC failure still produces its firewall rule' (
    $mixedRules -contains 'MDI-NNR-RPC-In') "(got: $($mixedRules -join ', '))"
Assert-That 'the unmeasured NetBIOS probe produces NO firewall rule' (
    $mixedRules -notcontains 'MDI-NNR-NetBIOS-In') "(got: $($mixedRules -join ', '))"

# Control: a probe that never ran and says so must also produce nothing.
$untestedRules = Get-NnrRuleNames @((New-NnrRecord 137 'UDP' $null 'Not tested - no reachable target'))
Assert-That 'an explicitly not-tested probe produces no rule' ($untestedRules.Count -eq 0) "(got: $($untestedRules -join ', '))"

# Control: a target that resolved on another method is not unresolvable, so nothing is emitted.
$resolvedRules = Get-NnrRuleNames @(
    (New-NnrRecord 135 'TCP' $false 'Connection refused')
    (New-NnrRecord 137 'UDP' $true 'Resolved')
)
Assert-That 'a target resolvable by another method produces no rule' ($resolvedRules.Count -eq 0) "(got: $($resolvedRules -join ', '))"

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
