<#
    The console line, the score card and the issue list describe the same run.

    Two defects, one shape: a run raised a finding and failed its verdict while the console and the
    score card reported a perfect score, because the thing the finding was about never entered the
    check denominator.

    1. Deleted Objects. The four domain-level checks were tabulated TWICE - once for the score, once
       for the issue list - and the two copies disagreed about one flag. RoleMayBeAbsent was $true in
       the scoring copy and $false in the issue list, so a domain whose Deleted Objects permission
       returned 'N/A' was scored as a PASSED check while the issue list called it unverified: the
       console read "1 issue(s) found: 7/7 checks passed" and the card read 100%, over a High
       finding. The verdict - a third reader of the same fact - agreed with the issue list, which is
       what identified the scoring copy as the outlier. Reachable on a default run with no
       -DirectoryServiceAccount when the DACL is readable.
    2. Forest discovery. A forest whose domains could not be enumerated raises a finding and fails
       the verdict, but the unmeasured SCOPE was in neither the numerator nor the denominator, so
       the same "7/7 checks passed" appeared. Reachable on any -Forest run where enumeration fails.

    The invariant these pin: if the issue list is non-empty for a reason of measurement, the score
    must not read 100%.
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

function New-PassingDc {
    param($Fqdn = 'dc1.contoso.com')
    $o = [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; Unreachable = $false; Comment = $null
        Details = [PSCustomObject]@{}
    }
    foreach ($n in 'NtlmAuditing', 'AdvancedAuditing', 'PowerSettings', 'TimeSync', 'SensorHealth', 'RootCertificates', 'CapacitySufficient') {
        $o | Add-Member -NotePropertyName $n -NotePropertyValue $true -Force
    }
    $o
}

# The measured-but-'N/A' Deleted Objects shape the producer emits on a default run with no DSA.
function New-DomainAuditing {
    param($DeletedValue, $DeletedMeasured)
    [PSCustomObject]@{
        Domain                 = 'contoso.com'
        ObjectAuditing         = [PSCustomObject]@{ isObjectAuditingOk = $true }
        ObjectAuditingMeasured = $true
        ExchangeAuditing       = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        ExchangeAuditingMeasured = $true
        AdfsAuditing           = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        AdfsAuditingMeasured   = $true
        DeletedObjects         = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $DeletedValue }
        DeletedObjectsMeasured = $DeletedMeasured
    }
}

function Get-RunFacts {
    param($Report)
    $st = Get-mdiReportStatistics -ReportData $Report
    $issues = @(Get-mdiIssueList -Statistics $st -ReportData $Report)
    $den = Get-mdiCoverageDenominator -Measured $st.ChecksTotal -Unread $st.ChecksUnread
    [PSCustomObject]@{
        Passed = [int] $st.ChecksPassed
        Denominator = [int] $den
        Unread = [int] $st.ChecksUnread
        Percent = [int] [math]::Floor((Get-mdiCoveragePercent -Passed $st.ChecksPassed -Measured $st.ChecksTotal -Unread $st.ChecksUnread))
        Issues = $issues.Count
        Verdict = (Test-mdiReadinessResult -ReportData $Report 3>$null)
    }
}

Write-Host 'An N/A domain check is not a passed check' -ForegroundColor Cyan
$repNa = [PSCustomObject]@{
    DomainControllers   = @((New-PassingDc))
    CAServers           = @(); EntraConnectServers = @()
    DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    DomainAuditing      = @((New-DomainAuditing 'N/A' $true))
}
$na = Get-RunFacts $repNa
Assert-That 'a measured-N/A Deleted Objects raises a finding' ($na.Issues -ge 1) "(issues=$($na.Issues))"
Assert-That '  ...and the run is not ready' ($na.Verdict -eq $false)
Assert-That '  ...so the score is NOT 100%' ($na.Percent -ne 100) "(pct=$($na.Percent) $($na.Passed)/$($na.Denominator))"
Assert-That '  ...it is counted as unread, not as a pass' ($na.Unread -ge 1) "(unread=$($na.Unread))"
Assert-That '  ...and the denominator still includes it' ($na.Denominator -gt $na.Passed) "($($na.Passed)/$($na.Denominator))"

# Control: a genuinely passing domain must still read 100%, or the tone carries no information.
$repOk = [PSCustomObject]@{
    DomainControllers   = @((New-PassingDc))
    CAServers           = @(); EntraConnectServers = @()
    DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    DomainAuditing      = @((New-DomainAuditing $true $true))
}
$ok = Get-RunFacts $repOk
Assert-That 'a fully measured, fully passing run still reads 100%' ($ok.Percent -eq 100) "(pct=$($ok.Percent))"
Assert-That '  ...with no findings' ($ok.Issues -eq 0) "(issues=$($ok.Issues))"

# AD FS and Exchange may legitimately be absent, and 'N/A' there must NOT be charged.
$repAbsentRole = [PSCustomObject]@{
    DomainControllers   = @((New-PassingDc))
    CAServers           = @(); EntraConnectServers = @()
    DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    DomainAuditing      = @([PSCustomObject]@{
            Domain = 'contoso.com'
            ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
            ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
            AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
            DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }; DeletedObjectsMeasured = $true
        })
}
$absent = Get-RunFacts $repAbsentRole
Assert-That "an absent AD FS/Exchange role is still a legitimate 'N/A' and is not charged" (
    $absent.Percent -eq 100 -and $absent.Issues -eq 0) "(pct=$($absent.Percent) issues=$($absent.Issues))"

# The two tabulations must come from ONE definition, so they cannot drift again.
$defs = @(Get-mdiDomainCheckDefinition -Domain (New-DomainAuditing 'N/A' $true))
Assert-That 'the domain check definition is shared and has four checks' ($defs.Count -eq 4)
$deleted = @($defs | Where-Object { $_.Name -eq 'Deleted Objects container permission' })
Assert-That '  ...and Deleted Objects is not a role that may be absent' (
    $deleted.Count -eq 1 -and $deleted[0].RoleMayBeAbsent -eq $false)
$adfs = @($defs | Where-Object { $_.Name -eq 'AD FS auditing' })
Assert-That '  ...while AD FS is' ($adfs[0].RoleMayBeAbsent -eq $true)

Write-Host 'An incomplete forest enumeration is unmeasured scope' -ForegroundColor Cyan
$repForest = [PSCustomObject]@{
    DomainControllers   = @((New-PassingDc))
    CAServers           = @(); EntraConnectServers = @()
    DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    DomainAuditing      = @((New-DomainAuditing $true $true))
    ForestDiscovery     = [PSCustomObject]@{ Complete = $false; Error = 'access denied enumerating domains' }
}
$forest = Get-RunFacts $repForest
Assert-That 'an incomplete forest discovery raises a finding' ($forest.Issues -ge 1) "(issues=$($forest.Issues))"
Assert-That '  ...and the run is not ready' ($forest.Verdict -eq $false)
Assert-That '  ...so the score is NOT 100%' ($forest.Percent -ne 100) "(pct=$($forest.Percent) $($forest.Passed)/$($forest.Denominator))"
Assert-That '  ...the unmeasured scope is charged to the denominator' (
    $forest.Denominator -gt $forest.Passed) "($($forest.Passed)/$($forest.Denominator))"
# Control: a COMPLETE forest discovery must not be charged.
$repForestOk = [PSCustomObject]@{
    DomainControllers   = @((New-PassingDc))
    CAServers           = @(); EntraConnectServers = @()
    DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    DomainAuditing      = @((New-DomainAuditing $true $true))
    ForestDiscovery     = [PSCustomObject]@{ Complete = $true; Error = '' }
}
$forestOk = Get-RunFacts $repForestOk
Assert-That 'a complete forest discovery is not charged' (
    $forestOk.Percent -eq 100 -and $forestOk.Issues -eq 0) "(pct=$($forestOk.Percent) issues=$($forestOk.Issues))"
# A report with no ForestDiscovery at all (not a -Forest run) must be unaffected.
Assert-That 'a run without forest discovery is unaffected' ($ok.Percent -eq 100)

Write-Host 'The invariant: a finding about measurement forbids a perfect score' -ForegroundColor Cyan
foreach ($case in @(
        @{ Label = 'measured-N/A deleted objects'; Facts = $na }
        @{ Label = 'incomplete forest discovery'; Facts = $forest }
    )) {
    Assert-That ('{0}: issues>0 implies score<100' -f $case.Label) (
        -not ($case.Facts.Issues -gt 0 -and $case.Facts.Percent -eq 100)) `
        "(issues=$($case.Facts.Issues) pct=$($case.Facts.Percent))"
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
