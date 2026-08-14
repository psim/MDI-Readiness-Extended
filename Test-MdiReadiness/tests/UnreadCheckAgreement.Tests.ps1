<#
    The score card and the issues table count the same unread checks.

    Both are answering "which checks could not be read on this server". Get-mdiUnreadCheckName is the
    shared helper that exists so they agree, and the statistics call it with -ExcludeName
    RequiredPorts because the EFFECTIVE view resolves that check from the probe records instead - the
    stored 'N/A' summary is superseded the moment a real measurement exists, and counting both would
    charge the same check twice.

    The issue list did not call the helper. It repeated the helper's Where-Object body verbatim,
    minus the single '$_.Name -notin $ExcludeName' line. So a server whose stored RequiredPorts
    summary read 'N/A' while its probe records resolved the measurement to a genuine blocked port
    produced BOTH findings at once:

        [High] Not measured | Required Ports could not be read on this server, so its state is unknown
        [High] Network      | A required network probe was measured as blocked: TCP/389 ...

    Two High findings for one fault, an exit code of 2 where the fault count is 1, and a score card
    reporting ChecksUnread = 0 directly above an issues table asserting the check was never read.

    The dangerous direction matters more than the duplicate: a genuinely unmeasured RequiredPorts -
    stored 'N/A' with no probe records at all - must STILL be reported and must still keep the run
    out of READY. The verdict's own untested-probe guard only fires when records exist, so removing
    the stored-'N/A' path without care would have deleted the only cover for that case.
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

function New-PortRecord {
    param($Success, $Detail)
    [PSCustomObject]@{
        Id = 'p-TCP-389'; Group = 'Ports'; Scope = 'DomainController'; Requirement = 'Required'
        Protocol = 'TCP'; Port = 389; Target = 'dc2.contoso.com'; TargetIP = '10.0.0.2'
        Applicable = $true; Success = $Success; Detail = $Detail
    }
}
function New-Server {
    param($Results, $StoredPorts = 'N/A')
    $o = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; Comment = $null
        SensorVersion = '2.240.0.0'; Addresses = @('10.0.0.10'); IP = '10.0.0.10'
        Details = [PSCustomObject]@{}
    }
    foreach ($n in 'NtlmAuditing', 'AdvancedAuditing', 'PowerSettings', 'TimeSync') {
        $o | Add-Member -NotePropertyName $n -NotePropertyValue $true -Force
    }
    $o | Add-Member -NotePropertyName RequiredPorts -NotePropertyValue $StoredPorts -Force
    $o.Details | Add-Member -NotePropertyName RequiredPortsDetails -NotePropertyValue ([PSCustomObject]@{ Results = $Results }) -Force
    $o
}
function Get-Facts {
    param($Server)
    $rep = [PSCustomObject]@{
        DomainControllers = @($Server); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    }
    $st = Get-mdiReportStatistics -ReportData $rep
    $issues = @(Get-mdiIssueList -Statistics $st -ReportData $rep)
    [PSCustomObject]@{
        Unread = [int] $st.ChecksUnread
        Issues = $issues.Count
        PortsUnread = @($issues | Where-Object { $_.Area -eq 'Not measured' -and $_.Issue -match 'Required Ports' }).Count
        NetworkFindings = @($issues | Where-Object { $_.Area -eq 'Network' }).Count
        Verdict = (Test-mdiReadinessResult -ReportData $rep 3>$null)
    }
}

Write-Host 'A resolved measurement supersedes the stored N/A summary' -ForegroundColor Cyan
$resolvedBlocked = Get-Facts (New-Server @((New-PortRecord $false 'Connection failed (timed out after 1500 ms)')))
Assert-That 'the measured blocked port is reported' ($resolvedBlocked.NetworkFindings -ge 1)
Assert-That '  ...and it is NOT also reported as could-not-be-read' (
    $resolvedBlocked.PortsUnread -eq 0) "(got $($resolvedBlocked.PortsUnread))"
Assert-That '  ...one fault produces exactly one finding' (
    $resolvedBlocked.Issues -eq 1) "(got $($resolvedBlocked.Issues))"
Assert-That '  ...and the score card agrees the check was measured' (
    $resolvedBlocked.Unread -eq 0) "(ChecksUnread=$($resolvedBlocked.Unread))"
Assert-That '  ...the run is still not ready' ($resolvedBlocked.Verdict -eq $false)

Write-Host 'A genuinely unmeasured check is still reported (the guard)' -ForegroundColor Cyan
$noRecords = Get-Facts (New-Server @())
Assert-That 'stored N/A with NO probe records is reported as unread' (
    $noRecords.PortsUnread -ge 1) "(got $($noRecords.PortsUnread))"
Assert-That '  ...the score card counts it too' ($noRecords.Unread -ge 1) "(ChecksUnread=$($noRecords.Unread))"
Assert-That '  ...and it keeps the run out of READY' ($noRecords.Verdict -eq $false)

Write-Host 'The two surfaces agree on every shape' -ForegroundColor Cyan
# The invariant, stated directly: if the statistics say a check was unread, the issues table must
# name one; if they say nothing was unread, the table must not claim otherwise.
foreach ($case in @(
        @{ Label = 'resolved to blocked'; Server = (New-Server @((New-PortRecord $false 'Connection failed'))) }
        @{ Label = 'resolved to open'; Server = (New-Server @((New-PortRecord $true 'Open'))) }
        @{ Label = 'no records at all'; Server = (New-Server @()) }
        @{ Label = 'stored summary is a real bool'; Server = (New-Server @((New-PortRecord $true 'Open')) $true) }
    )) {
    $f = Get-Facts $case.Server
    Assert-That ('{0}: statistics and issue list agree about unread' -f $case.Label) (
        ($f.Unread -gt 0) -eq ($f.PortsUnread -gt 0)) `
        "(ChecksUnread=$($f.Unread) portsUnreadFindings=$($f.PortsUnread))"
}

Write-Host 'The unread predicate exists in ONE place' -ForegroundColor Cyan
# Both surfaces must route through the shared helper. A second longhand copy is how they drifted.
$srv = New-Server @()
$viaHelper = @(Get-mdiUnreadCheckName -Server $srv -ExcludeName $script:mdiRequiredPortsCheckName)
Assert-That 'the helper honours ExcludeName' ($viaHelper -notcontains 'RequiredPorts') "(got: $($viaHelper -join ', '))"
$viaHelperNoExclude = @(Get-mdiUnreadCheckName -Server $srv)
Assert-That '  ...and includes it when not excluded' ($viaHelperNoExclude -contains 'RequiredPorts') "(got: $($viaHelperNoExclude -join ', '))"

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
