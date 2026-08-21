<#
    An empty ForestDiscovery collection was certified complete by the verdict and dropped by the page.

    Forest discovery normally writes one record carrying Complete. A report can also carry that field
    as a COLLECTION - the code anticipates one record per forest - and the product states its own rule
    for the empty case in prose: "A PRESENT BUT EMPTY collection is incomplete: the field exists and
    nothing in it said the enumeration finished."

    That rule was enforced on two surfaces and silently defeated on the other two, because the four
    consumers do not receive the report the same way. Get-mdiReportStatistics and Get-mdiIssueList
    declare [object] $ReportData and Main calls them with the report itself. Set-MdiReadinessReport and
    Test-mdiReadinessResult declare [object[]], so the report is WRAPPED IN AN ARRAY and every
    $ReportData.<Prop> inside them is MEMBER ENUMERATION rather than a property read. Member
    enumeration turns an empty collection into $null, and the incompleteness predicate reads $null as
    "complete" - it returns before ever reaching the empty-collection branch.

    Measured on the shipped code, one variable, everything else a healthy two-domain estate:

        ForestDiscovery      score-incomplete  console issues  PAGE issues  READY
        Complete = $true     False             0               0            True
        Complete = $false    True              1               1            False
        empty list @()       True              1               0            TRUE   <-- the defect

    So a run reported READY over a forest that nothing said was enumerated; the console counted a High
    "Forest discovery" finding that the HTML page did not contain; and -FailOnIssues, which reads that
    same verdict, passed.

    Pinned here: on the empty-collection shape the score charges it incomplete, a forest-discovery
    finding is raised, an unread check is counted, and READY is refused. Controls confirm a complete
    record is still left alone and a Complete=$false record still behaves exactly as before, so the
    fix cannot be a blanket "charge everything".

    The page's issue list cannot be exercised without running the whole report writer, so the
    declaration that causes the divergence is pinned STRUCTURALLY instead: the file must contain no
    remaining [object[]] $ReportData. That is what catches a half-applied fix, where one of the two
    declarations is corrected and the other is left behind.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
# Sibling first: the suite copies the test and the product script into one flat isolated directory, so
# the copy beside this file is the one under test. A stale copy above that directory would otherwise be
# preferred to it. The parent fallback lets the file also run straight from the repository.
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = [IO.Path]::GetFullPath($target)
$text = [IO.File]::ReadAllText($target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray
    } else {
        $script:failed++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}

Write-Host 'EmptyForestDiscoveryDoesNotReachReady.Tests.ps1' -ForegroundColor Cyan

# NOTHING IS REBOUND LOCALLY HERE, DELIBERATELY. An earlier draft of this file wrapped each call in
# a local helper declaring [object] or [object[]] to "reproduce" the two shipped contracts. That was
# worthless: the array wrapping then happened in the TEST, so the assertions were true by
# construction and stayed red no matter what the product declared. Measured - with BOTH product
# declarations corrected the file still reported 8 passed / 5 failed, identical to the unfixed
# baseline. A test that cannot go green when the defect is fixed pins nothing.
#
# Every call below therefore goes STRAIGHT to the real function, so the product's OWN parameter
# declaration is what binds the report. That is the thing under test.

$domains = @('contoso.com', 'child.contoso.com')
function New-Dc {
    param([string] $Domain)
    [PSCustomObject]@{
        FQDN = "dc.$Domain"; Domain = $Domain; Unreachable = $false; PartialFailure = $false
        OSVersion = $true; AdvancedAuditing = $true; PowerSettings = $true; NtlmAuditing = $true
        Details = [PSCustomObject]@{}
    }
}
function New-Audit {
    param([string] $Domain)
    [PSCustomObject]@{
        Domain = $Domain
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
    }
}
function New-Report {
    param($Discovery)
    [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        ForestDiscovery = $Discovery; DomainsInScope = $domains
        DomainControllers = @($domains | ForEach-Object { New-Dc -Domain $_ })
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @($domains | ForEach-Object { New-Audit -Domain $_ })
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
        MaxNnrTargets = 0; SkippedAreas = @()
    }
}

function Measure-Surfaces {
    param($Discovery)
    $report = New-Report -Discovery $Discovery
    $stats = Get-mdiReportStatistics -ReportData $report 3>$null
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
    [PSCustomObject]@{
        # The score's own reading, through Get-mdiReportStatistics' [object] parameter.
        ScoreIncomplete = [bool] (Test-mdiForestEnumerationIncomplete -ReportData $report)
        # The findings, same contract.
        ForestFindings = @($issues | Where-Object { [string] $_.Area -eq 'Forest discovery' }).Count
        ChecksUnread = [int] $stats.ChecksUnread
        # THE LOAD-BEARING ONE. Test-mdiReadinessResult is called exactly as Main calls it at 21682.
        # While it declares [object[]] the report is wrapped, $ReportData.ForestDiscovery becomes
        # member enumeration, @() reads back as $null and the empty-collection branch is skipped.
        # Correct the declaration and this value changes - which is precisely why it belongs here
        # rather than behind a local wrapper.
        Ready = [bool] (Test-mdiReadinessResult -ReportData $report 3>$null)
    }
}

$completeRec = [PSCustomObject]@{ Name = 'contoso.com'; Domains = $domains; Method = 'ADWS'; Complete = $true; Error = $null }
$incompleteRec = [PSCustomObject]@{ Name = 'contoso.com'; Domains = $domains; Method = 'None'; Complete = $false; Error = 'ADWS and LDAP both failed' }

# ---- CONTROL: a genuinely complete record is left alone ------------------------------------------
$ok = Measure-Surfaces -Discovery $completeRec
Write-Host ('  RAW complete   score={0} findings={1} unread={2} ready={3}' -f
    $ok.ScoreIncomplete, $ok.ForestFindings, $ok.ChecksUnread, $ok.Ready)
Assert-True 'a complete forest record is not charged incomplete' (-not $ok.ScoreIncomplete) ("score={0}" -f $ok.ScoreIncomplete)
Assert-True 'a complete forest record raises no forest-discovery finding' ($ok.ForestFindings -eq 0) ("findings={0}" -f $ok.ForestFindings)
Assert-True 'a complete forest record still reaches READY' ($ok.Ready -eq $true) ("ready={0}" -f $ok.Ready)

# ---- CONTROL: Complete=$false still behaves exactly as it did ------------------------------------
$bad = Measure-Surfaces -Discovery $incompleteRec
Write-Host ('  RAW incomplete score={0} findings={1} unread={2} ready={3}' -f
    $bad.ScoreIncomplete, $bad.ForestFindings, $bad.ChecksUnread, $bad.Ready)
Assert-True 'an incomplete forest record is charged incomplete' ($bad.ScoreIncomplete) ("score={0}" -f $bad.ScoreIncomplete)
Assert-True 'an incomplete forest record raises one forest-discovery finding' ($bad.ForestFindings -eq 1) ("findings={0}" -f $bad.ForestFindings)
Assert-True 'an incomplete forest record blocks READY' ($bad.Ready -eq $false) ("ready={0}" -f $bad.Ready)

# ---- THE DEFECT: a PRESENT BUT EMPTY collection --------------------------------------------------
$empty = Measure-Surfaces -Discovery @()
Write-Host ('  RAW empty      score={0} findings={1} unread={2} ready={3}' -f
    $empty.ScoreIncomplete, $empty.ForestFindings, $empty.ChecksUnread, $empty.Ready)
Assert-True 'an empty ForestDiscovery collection is charged incomplete by the score' (
    $empty.ScoreIncomplete -eq $true
) ("score={0}" -f $empty.ScoreIncomplete)
Assert-True 'an empty ForestDiscovery collection raises a forest-discovery finding' (
    $empty.ForestFindings -eq 1
) ("findings={0}" -f $empty.ForestFindings)
Assert-True 'an empty ForestDiscovery collection is charged an unread check' (
    $empty.ChecksUnread -ge 1
) ("unread={0}" -f $empty.ChecksUnread)
# THE ONE THAT FAILS ON THE SHIPPED CODE. Test-mdiReadinessResult declares [object[]], so the report
# is wrapped, @() reads back as $null and the verdict certifies a forest nothing said was enumerated.
Assert-True 'an empty ForestDiscovery collection blocks READY' (
    $empty.Ready -eq $false
) ("ready={0} - the verdict certified a forest that the score and the findings both charged" -f $empty.Ready)

# ---- STRUCTURAL: the two declarations that cause it ----------------------------------------------
# The page's issue list receives the report from Set-MdiReadinessReport, so its binding cannot be
# exercised without running the whole report writer. It is pinned here instead, on the source: the
# defect IS the declaration, and a half-applied fix leaves one of these behind. Checked against the
# same file this test loaded.
$declPattern = '\[Parameter\(Mandatory = \$true\)\]\s*\[object\[\]\]\s*\$ReportData'
$declHits = @([regex]::Matches($text, $declPattern))
$declOwners = @(
    $ls = $text -split "`r?`n"
    for ($i = 0; $i -lt $ls.Count; $i++) {
        if ($ls[$i] -match '\[object\[\]\]\s*\$ReportData') {
            for ($j = $i; $j -ge 0; $j--) { if ($ls[$j] -match '^function\s+([\w-]+)') { $matches[1]; break } }
        }
    }
)
Write-Host ('  RAW declarations still [object[]]: {0}{1}' -f $declHits.Count,
    $(if ($declOwners.Count) { ' -> ' + ($declOwners -join ', ') } else { '' }))
Assert-True 'no report consumer still declares [object[]] $ReportData' (
    $declHits.Count -eq 0
) ("{0} remain: {1} - each one re-creates the divergence in its own surface" -f $declHits.Count, ($declOwners -join ', '))

Write-Host ("  {0} passed, {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed -gt 0) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
