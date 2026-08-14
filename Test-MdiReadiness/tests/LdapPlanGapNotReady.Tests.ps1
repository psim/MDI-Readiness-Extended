# [w80] A domain that produced no LDAP probe target must not pass as READY.
#
# Discovery runs twice: once to build the shared LDAP/NNR port plan, and again per role for the
# readiness checks. A domain that failed the FIRST pass contributes no LDAP target, so no sensor is
# ever asked whether it can reach that domain's controllers. If the SECOND pass then succeeds, the
# domain appears in the report fully examined.
#
# Main already detected this, warned "It will be reported as unverified rather than ready", and wrote
# the domains onto the report under LdapPlanGapDomains with the comment "Recorded here so the issue
# list and the verdict can both see it". Neither consumer was ever written: Test-mdiReadinessResult
# returned READY, Get-mdiIssueList returned an empty list, and -FailOnIssues exited 0 over a
# sensor-to-domain path nobody had measured.
#
# These assertions drive the REAL Test-mdiReadinessResult and the REAL Get-mdiIssueList. Removing
# either consumer turns them red - see MDI-AB\live\mutate-w80-ldapgap.ps1.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
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

function New-CleanServer {
    param([string] $Fqdn, [string] $Domain)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true
        RequiredPorts = $true
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() }
        }
    }
}

function New-CleanDomainAudit {
    param([string] $Domain)
    [PSCustomObject]@{
        Domain = $Domain
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; NotAsserted = $false }; DeletedObjectsMeasured = $true
    }
}

# A report in which EVERYTHING passed. Only LdapPlanGapDomains varies between cases, so any change in
# the verdict is attributable to it alone and to nothing else.
function New-Report {
    param([string[]] $GapDomains = @(), [string[]] $ScopedDomains = @('contoso.com', 'child.contoso.com'), [switch] $ChildProducedNoServers)
    $servers = @(foreach ($d in $ScopedDomains) {
            if ($ChildProducedNoServers -and $d -eq 'child.contoso.com') { continue }
            New-CleanServer -Fqdn ('dc-{0}' -f $d) -Domain $d
        })
    [PSCustomObject]@{
        ScriptVersion      = 'test'
        Domain             = 'contoso.com'
        Forest             = 'contoso.com'
        DomainsInScope     = $ScopedDomains
        LdapPlanGapDomains = $GapDomains
        DomainControllers  = $servers
        CAServers          = @()
        EntraConnectServers = @()
        DomainAuditing     = @($ScopedDomains | ForEach-Object { New-CleanDomainAudit -Domain $_ })
        ForestDiscovery    = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        SkippedAreas       = @()
    }
}

function Get-Outcome {
    param([object] $Report)
    $verdict = Test-mdiReadinessResult -ReportData $Report 3>$null 4>$null
    $stats = Get-mdiReportStatistics -ReportData $Report
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData $Report)
    [PSCustomObject]@{ Ready = [bool] $verdict; Issues = $issues; Count = $issues.Count }
}

'[w80] a clean report with no LDAP plan gap is still READY'
# The control. Without it, a fix that simply returned "not ready" always would look correct here.
$clean = Get-Outcome -Report (New-Report)
Assert-That 'a fully clean forest run is READY' ($clean.Ready) "(issues: $(($clean.Issues | ForEach-Object { $_.Issue }) -join ' | '))"
Assert-That 'a fully clean forest run raises no issue' ($clean.Count -eq 0) "(count $($clean.Count))"

'[w80] a domain with no LDAP probe target loses READY'
$gap = Get-Outcome -Report (New-Report -GapDomains @('child.contoso.com'))
Assert-That 'the verdict is NOT ready when a domain has no LDAP probe target' (-not $gap.Ready)
Assert-That 'the issue list is not empty' ($gap.Count -gt 0) "(count $($gap.Count))"

$named = @($gap.Issues | Where-Object { [string] $_.Server -eq 'child.contoso.com' -and [string] $_.Issue -match 'LDAP probe target' })
Assert-That 'the gap domain is named in the issue list' ($named.Count -eq 1) `
    "(matched $($named.Count) of: $(($gap.Issues | ForEach-Object { "$($_.Server)/$($_.Area)" }) -join ', '))"
Assert-That "the gap is filed as 'Not measured', not as an observed failure" `
    ($named.Count -eq 1 -and [string] $named[0].Area -eq 'Not measured') "(area '$(if ($named.Count) { $named[0].Area })')"
Assert-That 'the finding says no sensor was asked' `
    ($named.Count -eq 1 -and [string] $named[0].Issue -match 'no sensor was asked') "(text '$(if ($named.Count) { $named[0].Issue })')"

'[w80] the verdict and the issue list cannot diverge'
# The invariant Get-mdiIssueList was written to protect: never "not ready" over an empty table.
foreach ($case in @(
        @{ Name = 'no gap'; Report = (New-Report) },
        @{ Name = 'one gap'; Report = (New-Report -GapDomains @('child.contoso.com')) },
        @{ Name = 'two gaps'; Report = (New-Report -GapDomains @('child.contoso.com', 'contoso.com')) }
    )) {
    $o = Get-Outcome -Report $case.Report
    $consistent = ($o.Ready -and $o.Count -eq 0) -or ((-not $o.Ready) -and $o.Count -gt 0)
    Assert-That "  verdict and issue list agree ($($case.Name))" $consistent "(ready=$($o.Ready) issues=$($o.Count))"
}

'[w80] every gap domain is reported, not just the first'
$two = Get-Outcome -Report (New-Report -GapDomains @('child.contoso.com', 'other.contoso.com') -ScopedDomains @('contoso.com', 'child.contoso.com', 'other.contoso.com'))
$twoNamed = @($two.Issues | Where-Object { [string] $_.Issue -match 'LDAP probe target' })
Assert-That 'both gap domains produce a finding' ($twoNamed.Count -eq 2) `
    "(got $($twoNamed.Count): $(($twoNamed | ForEach-Object { $_.Server }) -join ', '))"

'[w80] blank entries are not reported as domains'
# @() with an empty string in it must not manufacture a finding against a nameless domain, and must
# not cost the run its READY verdict either.
$blank = Get-Outcome -Report (New-Report -GapDomains @('', '   ', $null))
Assert-That 'a blank gap list does not raise a phantom finding' ($blank.Count -eq 0) `
    "(issues: $(($blank.Issues | ForEach-Object { "'$($_.Server)'" }) -join ', '))"
Assert-That 'a blank gap list does not cost the run its READY verdict' ($blank.Ready)

'[w80] a gap domain that produced no servers is reported once, not twice'
# child.contoso.com is both in the gap list AND unexamined. It already has a Discovery finding; a
# second line for the same hole is noise the operator has to reconcile.
$dup = Get-Outcome -Report (New-Report -GapDomains @('child.contoso.com') -ChildProducedNoServers)
$childLines = @($dup.Issues | Where-Object { [string] $_.Server -eq 'child.contoso.com' })
Assert-That 'the doubly-affected domain gets exactly one finding' ($childLines.Count -eq 1) `
    "(got $($childLines.Count): $(($childLines | ForEach-Object { $_.Area }) -join ', '))"
Assert-That 'and the run is still not READY' (-not $dup.Ready)

'[w80] a trailing dot does not create a duplicate finding'
$dotted = Get-Outcome -Report (New-Report -GapDomains @('child.contoso.com.') -ChildProducedNoServers)
$dottedChild = @($dotted.Issues | Where-Object { [string] $_.Server -match '^child\.contoso\.com\.?$' })
Assert-That 'a trailing-dot spelling is reconciled with the unexamined list' ($dottedChild.Count -eq 1) `
    "(got $($dottedChild.Count): $(($dottedChild | ForEach-Object { "$($_.Server)/$($_.Area)" }) -join ', '))"

'[w80] the field survives into the JSON document'
$json = New-Report -GapDomains @('child.contoso.com') | ConvertTo-Json -Depth 7
Assert-That 'LdapPlanGapDomains is present in the emitted report' ($json -match 'LdapPlanGapDomains')

'[w80] main still tells the operator what it did'
Assert-That 'the warning promising "unverified rather than ready" is still there' `
    ($full -match 'reported as unverified rather than ready')
Assert-That 'the verdict function reads the field' `
    ($full.Substring($full.IndexOf('function Test-mdiReadinessResult')) -match 'LdapPlanGap')
Assert-That 'the issue list function reads the field' `
    (($full.Substring($full.IndexOf('function Get-mdiIssueList'), $full.IndexOf('function Test-mdiReadinessResult') - $full.IndexOf('function Get-mdiIssueList'))) -match 'LdapPlanGapDomains')

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
