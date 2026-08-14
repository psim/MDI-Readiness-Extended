<#
    A clock that is wrong by more than 68 years must be reported as WRONG, not as unmeasured.

    A skew is the difference between two DateTime values. Expressed in seconds it does not fit in an
    Int32 past 68 years, and expressed in minutes it does not fit past ~4085 years. Those casts sat
    inside the try block in Get-mdiTimeSync, so the overflow was swallowed by the catch that exists
    for "the WMI read failed" and the function returned isTimeSyncOk = 'N/A'.

    That is the single worst outcome this check can produce. 'N/A' means UNMEASURED everywhere
    downstream: Test-mdiCheckFailed returns $false for it, so no issue is raised; the remediation
    generator emits no w32tm /resync for the server; and Get-mdiTimeSyncHtml renders a grey
    "Not tested". A dead CMOS battery reading 1601-01-01, a reset RTC, and a BIOS year rollover to
    2106 are the three commonest ways a real domain controller's clock goes wrong by that much - so
    the worse the clock, the quieter the report, and the raw .NET conversion message was printed to
    the operator as though it were an RPC error.

    These tests assert the BEHAVIOUR - the verdict, the sign, the rendered row - and never the text
    of the script. A grep-style test would pass with the [int] casts restored.
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

# The remote clock is dictated exactly. Get-WmiObject is a cmdlet, so a function of the same name
# shadows it for the duration of this file.
$script:fakeRemoteUtc = [datetime]::UtcNow
function global:Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $ErrorAction)
    if ($script:fakeRemoteUtc -eq $null) { throw 'The RPC server is unavailable.' }
    [PSCustomObject]@{ LocalDateTime = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($script:fakeRemoteUtc.ToLocalTime()) }
}
function Get-Clock([datetime] $RemoteUtc) {
    $script:fakeRemoteUtc = $RemoteUtc
    Get-mdiTimeSync -ComputerName 'dc1.contoso.com' -MaxSkewMinutes 5
}

Write-Host 'A clock beyond the Int32 seconds range is still a MEASURED failure' -ForegroundColor Cyan

# The control. If this does not hold, nothing below means anything.
$good = Get-Clock ([datetime]::UtcNow)
Assert-That 'a synchronised clock still passes' ($good.isTimeSyncOk -eq $true) "got '$($good.isTimeSyncOk)'"

$drift = Get-Clock ([datetime]::UtcNow.AddMinutes(6))
Assert-That 'ordinary six-minute drift is still a measured failure' ($drift.isTimeSyncOk -eq $false) "got '$($drift.isTimeSyncOk)'"

# 68 years is where [int] seconds overflows. Each of these is a real, observed hardware fault.
$cases = @(
    @{ Name = 'dead CMOS battery (1601-01-01)'; Utc = [datetime]'1601-01-01T00:00:00Z' }
    @{ Name = 'reset RTC (1980-01-01)'; Utc = [datetime]'1980-01-01T00:00:00Z' }
    @{ Name = 'BIOS year rollover (2106-01-01)'; Utc = [datetime]'2106-01-01T00:00:00Z' }
    @{ Name = 'the largest representable clock (9999-12-31)'; Utc = [datetime]'9999-12-31T00:00:00Z' }
)
foreach ($c in $cases) {
    $r = Get-Clock $c.Utc
    # The verdict must be the BOOLEAN $false, never the string 'N/A'. -eq $false is not enough on its
    # own in PowerShell, so the type is asserted too: 'N/A' -eq $false is $false, but so is $null.
    Assert-That ("$($c.Name) is a measured failure, not 'N/A'") `
    ($r.isTimeSyncOk -is [bool] -and $r.isTimeSyncOk -eq $false) "got '$($r.isTimeSyncOk)' of type $(if ($null -eq $r.isTimeSyncOk) { '<null>' } else { $r.isTimeSyncOk.GetType().Name })"

    # A measured result carries the measurement. The catch path omits SkewSeconds entirely, so its
    # presence proves the try block completed rather than being unwound by the overflow.
    Assert-That "  ...and it reports a skew at all" `
    ($null -ne $r.details.PSObject.Properties['SkewSeconds']) 'SkewSeconds is absent, so the catch block ran'

    # The detail must describe a clock difference, not a failed read. This is what the operator sees.
    Assert-That "  ...and the detail blames the clock, not the connection" `
    ($r.details.Detail -like 'Clock differs by*') "got '$($r.details.Detail)'"

    # The raw .NET conversion message must never reach the report.
    Assert-That "  ...and no System.Int32 conversion error leaks into the report" `
    ($r.details.Detail -notmatch 'System\.Int32') "got '$($r.details.Detail)'"
}

Write-Host 'The sign of a very large skew still tells the operator which way the clock is wrong' -ForegroundColor Cyan
$behind = Get-Clock ([datetime]'1601-01-01T00:00:00Z')
$ahead = Get-Clock ([datetime]'2106-01-01T00:00:00Z')
Assert-That 'a clock centuries BEHIND reports a negative skew' ($behind.details.SkewSeconds -lt 0) "got $($behind.details.SkewSeconds)"
Assert-That 'a clock decades AHEAD reports a positive skew' ($ahead.details.SkewSeconds -gt 0) "got $($ahead.details.SkewSeconds)"
# 1601 is ~13.4e9 seconds away: the magnitude must survive, not be truncated or wrapped into range.
Assert-That 'the magnitude is not truncated into the Int32 range' `
([math]::Abs([double] $behind.details.SkewSeconds) -gt [int]::MaxValue) "got $($behind.details.SkewSeconds)"

Write-Host 'A read that genuinely failed is still reported as unmeasured' -ForegroundColor Cyan
# The catch block must keep doing its job: this is the regression the [long] change could have caused.
$script:fakeRemoteUtc = $null
$unread = Get-mdiTimeSync -ComputerName 'dc1.contoso.com' -MaxSkewMinutes 5
Assert-That "an unreachable clock is still 'N/A', not a measured failure" ($unread.isTimeSyncOk -eq 'N/A') "got '$($unread.isTimeSyncOk)'"
Assert-That '  ...and carries no skew' ($null -eq $unread.details.PSObject.Properties['SkewSeconds']) 'SkewSeconds should be absent'

Write-Host 'The HTML row for a centuries-wrong clock renders red with the measured skew' -ForegroundColor Cyan
$dead = Get-Clock ([datetime]'1601-01-01T00:00:00Z')
$srv = [PSCustomObject]@{
    FQDN     = 'dc-dead.contoso.com'
    TimeSync = $dead.isTimeSyncOk
    Details  = [PSCustomObject]@{ TimeSyncDetails = $dead.details }
}
# Building the report must not throw: re-narrowing the Int64 skew to [int] in the renderer would
# lose the whole HTML file rather than one cell.
$html = $null
$renderError = $null
try { $html = Get-mdiTimeSyncHtml -Server @($srv) } catch { $renderError = $_.Exception.Message }
Assert-That 'the time-sync table renders without throwing' ($null -eq $renderError) "threw: $renderError"
Assert-That '  ...and the row is red, not a grey "Not tested"' ($html -match '<td class="red">No</td>') "got: $html"
Assert-That '  ...and the skew cell carries the measured value, not "n/a"' ($html -match '<td class="red">-\d{6,} s</td>') "got: $html"
Assert-That '  ...and the remote clock that was read is shown' ($html -match '1601-01-01') "got: $html"

# The unreadable clock must still render grey, so the two states remain distinguishable in the table.
$script:fakeRemoteUtc = $null
$unreadSync = Get-mdiTimeSync -ComputerName 'dc2.contoso.com' -MaxSkewMinutes 5
$srv2 = [PSCustomObject]@{
    FQDN     = 'dc-unreachable.contoso.com'
    TimeSync = $unreadSync.isTimeSyncOk
    Details  = [PSCustomObject]@{ TimeSyncDetails = $unreadSync.details }
}
$html2 = Get-mdiTimeSyncHtml -Server @($srv2)
Assert-That 'an unreadable clock still renders grey "Not tested"' ($html2 -match 'muted-cell">Not tested<') "got: $html2"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
