# A Network Name Resolution target the operator named by hand, which resolved to no address, was
# reported as "not measured" by the issue list and the verdict while the score card beside it read
# 100% - "All checks passed" - in green.
#
# NnrUnresolvedTargets is the FIFTH gap of a family the script had already closed four times:
#
#   unreachable server            -> charged one unread   (fixed)
#   forest not fully enumerated   -> charged one unread   (fixed)
#   unexamined domain             -> charged one unread   (fixed)
#   LdapPlanGapDomains            -> charged one unread   (fixed)
#   NnrUnresolvedTargets          -> NOT CHARGED          (this test)
#
# Measured on the shipped Get-mdiReportStatistics and a real report written by Set-MdiReadinessReport,
# three runs differing ONLY in NnrUnresolvedTargets (none / one / two):
#
#   issues            0            1                     2
#   verdict           READY        NOT READY             NOT READY
#   score card        ok 100%      ok 100%               ok 100%     <-- byte-identical
#   ready tile        All passed   All passed            All passed  <-- byte-identical
#   console           7/7          7/7                   7/7         <-- byte-identical
#
# The reader is told the run is not ready and shown a green, unqualified 100% on the same page.
#
# This is NOT reachable by the estate-failure rule that fixed the KPI strip: there ChecksTotal exceeds
# ChecksPassed, so the gap can be inferred downstream from the score card's own two numbers. Here
# ChecksPassed and ChecksTotal are BOTH 7 - the check is not failed, it is MISSING - so it can only be
# corrected by adding it to the denominator in the statistics, which is what this test pins.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$source = [IO.File]::ReadAllText($target)
$source = $source -replace '(?m)^\s*#Requires.*$', ''
$source = $source -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$main = $source.IndexOf('#region Main')
if ($main -lt 1) { throw 'Could not isolate the canonical function definitions.' }
Invoke-Expression $source.Substring(0, $main)
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$outDir = Join-Path ([IO.Path]::GetTempPath()) ('nnrgap-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
[void] (New-Item -ItemType Directory -Path $outDir -Force)

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-CleanServer {
    [PSCustomObject]@{
        FQDN = 'dc1.contoso.test'; Domain = 'contoso.test'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        ServerRequirements = $true; AdvancedAuditing = $true; NtlmAuditing = $true
        Details = [ordered]@{}
    }
}

function New-CleanDomain {
    [PSCustomObject]@{
        Domain = 'contoso.test'
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true; Measured = $true }
        ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A'; Measured = $true }
        ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A'; Measured = $true }
        AdfsAuditingMeasured = $true
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; Measured = $true; NotAsserted = $false }
        DeletedObjectsMeasured = $true
        SchemaVersion = [PSCustomObject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
    }
}

function New-Report {
    param([string[]] $UnresolvedTarget = @(), [string[]] $LdapGap = @(), [switch] $WithUnreachable)
    $dcs = @(New-CleanServer)
    if ($WithUnreachable) {
        $dcs += [PSCustomObject]@{
            FQDN = 'dc2.contoso.test'; Domain = 'contoso.test'
            Unreachable = $true; PartialFailure = $false; IsPlaceholder = $false
            Details = [ordered]@{}
        }
    }
    [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.test'; Forest = 'contoso.test'
        ForestDiscovery = [PSCustomObject]@{
            Name = 'contoso.test'; Domains = @('contoso.test'); Method = 'stub'; Complete = $true; Error = $null
        }
        DomainsInScope = @('contoso.test')
        LdapPlanGapDomains = @($LdapGap)
        NnrUnresolvedTargets = @($UnresolvedTarget)
        NnrTargetComputer = @($UnresolvedTarget)
        MaxNnrTargets = 5
        DomainControllers = $dcs
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(New-CleanDomain)
        DomainSchemaVersion = [PSCustomObject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
        SkippedAreas = @()
    }
}

function Get-Card {
    param([string] $Html, [string] $Label)
    $pattern = '<div class="kpi ([^"]+)"><span class="kpi-label">' + [regex]::Escape($Label) +
    '</span><span class="kpi-value">([^<]*)</span><span class="kpi-sub">([^<]*)</span>'
    $m = [regex]::Match($Html, $pattern)
    '{0} | {1} | {2}' -f $m.Groups[1].Value, $m.Groups[2].Value, [Net.WebUtility]::HtmlDecode($m.Groups[3].Value)
}

function Get-RenderedHtml {
    param($Report)
    Get-ChildItem -LiteralPath $outDir -File -ErrorAction SilentlyContinue | Remove-Item -Force
    [void] (Set-MdiReadinessReport -Domain $Report.Domain -Path $outDir -ReportData $Report -SkipTrend 3>$null 4>$null)
    [IO.File]::ReadAllText((Get-ChildItem -LiteralPath $outDir -Filter '*.html' | Select-Object -First 1).FullName)
}

$populations = @(
    @{ Name = 'none unresolved'; Targets = @(); Extra = 0 }
    @{ Name = 'one unresolved'; Targets = @('missing1.contoso.test'); Extra = 1 }
    @{ Name = 'two unresolved'; Targets = @('missing1.contoso.test', 'missing2.contoso.test'); Extra = 2 }
)

'[nnr accounting] an unresolved target the operator named is charged to the denominator'
$stats = @{}
foreach ($p in $populations) {
    $s = Get-mdiReportStatistics -ReportData (New-Report -UnresolvedTarget $p.Targets)
    $stats[$p.Name] = $s
    Assert-That ("{0}: ChecksUnread = {1}" -f $p.Name, $p.Extra) (
        [int] $s.ChecksUnread -eq [int] $p.Extra) "(got $($s.ChecksUnread))"
    # The numerator must NOT move - nothing new passed, and inflating it would hide the gap again.
    Assert-That ("{0}: ChecksPassed stays 7" -f $p.Name) ([int] $s.ChecksPassed -eq 7) "(got $($s.ChecksPassed))"
    $den = Get-mdiCoverageDenominator -Measured $s.ChecksTotal -Unread $s.ChecksUnread
    Assert-That ("{0}: denominator is 7 + {1}" -f $p.Name, $p.Extra) (
        [int] $den -eq (7 + [int] $p.Extra)) "(got $den)"
}

''
'[nnr accounting] duplicates are one gap, blanks are none'
# The property is de-duplicated at source; charging per raw entry would give the operator two lines and
# two denominator slots for one hole.
$dup = Get-mdiReportStatistics -ReportData (New-Report -UnresolvedTarget @('dupe.contoso.test', 'dupe.contoso.test', ' dupe.contoso.test '))
Assert-That 'a target named three times is charged once' ([int] $dup.ChecksUnread -eq 1) "(got $($dup.ChecksUnread))"
$blank = Get-mdiReportStatistics -ReportData (New-Report -UnresolvedTarget @('', '   '))
Assert-That 'blank entries are not charged at all' ([int] $blank.ChecksUnread -eq 0) "(got $($blank.ChecksUnread))"

''
'[nnr accounting] the score card stops claiming everything passed'
foreach ($p in $populations) {
    $html = Get-RenderedHtml (New-Report -UnresolvedTarget $p.Targets)
    $score = Get-Card -Html $html -Label 'Overall check score'
    $ready = Get-Card -Html $html -Label 'Servers fully ready'
    "    $($p.Name): score=[$score] ready=[$ready]"
    if ([int] $p.Extra -eq 0) {
        Assert-That ("{0}: a clean run still reads ok 100%" -f $p.Name) ($score -match '^ok \| 100%')
        Assert-That ("{0}: a clean run still says All checks passed" -f $p.Name) ($ready -match 'All checks passed')
    } else {
        # THE DEFECT: both of these were byte-identical to the clean run.
        Assert-That ("{0}: the score card is no longer an unqualified 100%" -f $p.Name) (
            $score -notmatch '100%') "(score card still claims a clean sweep: $score)"
        Assert-That ("{0}: the score card says how many were not measured" -f $p.Name) (
            $score -match ('{0} not measured' -f $p.Extra)) "(got $score)"
        Assert-That ("{0}: the ready tile no longer says All checks passed" -f $p.Name) (
            $ready -notmatch 'All checks passed') "(got $ready)"
        Assert-That ("{0}: the ready tile names the unit that was missed" -f $p.Name) (
            $ready -match ('{0} check\(s\) not measured' -f $p.Extra)) "(got $ready)"
    }
}

''
'[nnr accounting] the console agrees with the score card'
foreach ($p in $populations) {
    $s = $stats[$p.Name]
    $den = Get-mdiCoverageDenominator -Measured $s.ChecksTotal -Unread $s.ChecksUnread
    $line = '{0}/{1} checks passed' -f $s.ChecksPassed, $den
    Assert-That ("{0}: console reads '7/{1} checks passed'" -f $p.Name, (7 + [int] $p.Extra)) (
        $line -eq ('7/{0} checks passed' -f (7 + [int] $p.Extra))) "(got '$line')"
}

''
'[nnr accounting] the verdict and the issue list were always right and stay right'
# These two surfaces already reported the gap correctly before the fix. A fix that changed them would
# have traded one inconsistency for another.
foreach ($p in $populations) {
    $report = New-Report -UnresolvedTarget $p.Targets
    $issues = @(Get-mdiIssueList -Statistics $stats[$p.Name] -ReportData $report)
    $notMeasured = @($issues | Where-Object { $_.Area -eq 'Not measured' })
    Assert-That ("{0}: {1} 'Not measured' issue(s)" -f $p.Name, $p.Extra) (
        $notMeasured.Count -eq [int] $p.Extra) "(got $($notMeasured.Count))"
    $ready = Test-mdiReadinessResult -ReportData $report 3>$null 4>$null
    Assert-That ("{0}: verdict ready = {1}" -f $p.Name, ([int] $p.Extra -eq 0)) (
        [bool] $ready -eq ([int] $p.Extra -eq 0)) "(got $ready)"
    foreach ($t in $p.Targets) {
        Assert-That ("{0}: the issue names {1}" -f $p.Name, $t) (
            @($notMeasured | Where-Object { [string] $_.Server -eq $t }).Count -eq 1)
    }
}

''
'[nnr accounting] the gaps already charged are still charged exactly once'
# Guards against a fix that double-charges, or that charges the NNR gap by widening a sibling block.
$ldapOnly = Get-mdiReportStatistics -ReportData (New-Report -LdapGap @('gap.contoso.test'))
Assert-That 'an LDAP plan gap alone still charges exactly 1' ([int] $ldapOnly.ChecksUnread -eq 1) "(got $($ldapOnly.ChecksUnread))"
$both = Get-mdiReportStatistics -ReportData (New-Report -UnresolvedTarget @('missing1.contoso.test') -LdapGap @('gap.contoso.test'))
Assert-That 'an LDAP gap plus an NNR gap charges 2, not 1 and not 4' ([int] $both.ChecksUnread -eq 2) "(got $($both.ChecksUnread))"
$unreach = Get-mdiReportStatistics -ReportData (New-Report -UnresolvedTarget @('missing1.contoso.test') -WithUnreachable)
Assert-That 'an unreachable server plus an NNR gap charges 2' ([int] $unreach.ChecksUnread -eq 2) "(got $($unreach.ChecksUnread))"

''
'[nnr accounting] the invariant, over every population'
# The one rule the whole family of fixes exists to keep.
foreach ($p in $populations) {
    $s = $stats[$p.Name]
    $html = Get-RenderedHtml (New-Report -UnresolvedTarget $p.Targets)
    $claimsCleanSweep = ((Get-Card -Html $html -Label 'Servers fully ready') -match 'All checks passed')
    $everythingReallyPassed = ([int] $s.ChecksUnread -eq 0) -and ([int] $s.ChecksPassed -eq [int] $s.ChecksTotal)
    Assert-That ("{0}: 'All checks passed' only when everything really passed" -f $p.Name) (
        (-not $claimsCleanSweep) -or $everythingReallyPassed) "(claims=$claimsCleanSweep unread=$($s.ChecksUnread))"
    Assert-That ("{0}: never green while the run is not ready" -f $p.Name) (
        (-not $claimsCleanSweep) -or ([int] $p.Extra -eq 0)) "(claims=$claimsCleanSweep extra=$($p.Extra))"
}

Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
