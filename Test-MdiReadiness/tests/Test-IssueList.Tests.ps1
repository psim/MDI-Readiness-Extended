<#
    Verifies that the issue list is the single source of truth for "what is wrong".

    Three parts of the same report used to disagree: the hero banner said "action required", the
    Issues table said "no issues were found", and the console printed its own, different, number. The
    count came from (ChecksTotal - ChecksPassed), which counts FAILED CHECKS, while the table listed
    FINDINGS - and one failed RequiredPorts check expands into one finding per blocked port. They are
    now built from one function, and these assertions hold it to that.

    The suite also pins the comma-operator behaviour of the return value. Writing ", @($issues)" to
    stop PowerShell unrolling the array made every caller - all of which wrap the call in @() - see a
    SINGLE element that was itself the array: the console reported "1 issue" no matter how many there
    were, and the HTML rendered one row whose every cell held all the values joined together.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))
# EVERY script-scoped constant is loaded, not a hand-maintained list. The list went stale the moment a
# new constant was added: $script:mdiPortNotTestedPattern was null in the harness, and "-notmatch $null"
# treats the pattern as an empty string, which matches everything - so a filter meant to exclude
# untested probes silently excluded ALL of them and the suite failed for a reason that had nothing to
# do with the script.
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}
foreach ($constant in @()) {
    $assignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -eq ('$script:{0}' -f $constant) }, $true)[0]
    if ($null -eq $assignment) { throw "Could not find `$script:$constant" }
    . ([scriptblock]::Create($assignment.Extent.Text))
}

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

function New-Report {
    param([object[]] $Servers, [object[]] $DomainAuditing = @(), [string[]] $Scope = @('contoso.com'), [object] $Forest = $null)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainControllers = @($Servers); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = $Scope; DomainAuditing = @($DomainAuditing); ForestDiscovery = $Forest
        DomainAdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DomainObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
        DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    }
}

Write-Host "`n[1] Each finding is a separate object" -ForegroundColor Yellow
# The comma-operator regression, in the exact shape it took.
$srv = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; PartialFailure = $false; Unreachable = $false
    AdvancedAuditing = $false; NtlmAuditing = 'N/A'; PowerSettings = 'N/A'; SensorVersion = 'N/A'
}
$rd = New-Report -Servers @($srv)
$stats = Get-mdiReportStatistics -ReportData $rd
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $rd)
Assert-That 'three findings are three objects' ($issues.Count -eq 3) "(got $($issues.Count))"
Assert-That 'each finding has a scalar Area' (@($issues | Where-Object { $_.Area -is [array] }).Count -eq 0)
Assert-That 'each finding has a scalar Issue' (@($issues | Where-Object { $_.Issue -is [array] }).Count -eq 0)

Write-Host "`n[2] Unread checks appear as findings, labelled as unmeasured" -ForegroundColor Yellow
# The verdict refuses to call a run ready while any check is unread, so the reader must be told which
# ones. Labelled 'Not measured' rather than 'failed': nobody should reconfigure an unread setting.
$unread = @($issues | Where-Object { $_.Area -eq 'Not measured' })
Assert-That 'both unread checks are listed' ($unread.Count -eq 2) "(got $($unread.Count))"
Assert-That 'the unread wording does not say failed' (
    @($unread | Where-Object { [string] $_.Issue -match 'failed' }).Count -eq 0)
Assert-That 'the genuinely failed check still says failed' (
    @($issues | Where-Object { [string] $_.Issue -match 'Advanced Auditing check failed' }).Count -eq 1)

Write-Host "`n[3] The count matches the unread statistic" -ForegroundColor Yellow
Assert-That 'unread findings equal ChecksUnread' ($unread.Count -eq [int] $stats.ChecksUnread) `
    "(findings $($unread.Count) vs stat $($stats.ChecksUnread))"

Write-Host "`n[4] A clean forest produces no findings at all" -ForegroundColor Yellow
# The other direction matters just as much: a healthy estate must not grow phantom issues.
$clean = [PSCustomObject]@{
    FQDN = 'dc-ok.contoso.com'; Domain = 'contoso.com'; PartialFailure = $false; Unreachable = $false
    AdvancedAuditing = $true; NtlmAuditing = $true; SensorVersion = 'N/A'; MachineType = 'Azure'
}
$cleanRd = New-Report -Servers @($clean) -DomainAuditing @([PSCustomObject]@{
        Domain = 'contoso.com'
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
    })
$cleanStats = Get-mdiReportStatistics -ReportData $cleanRd
$cleanIssues = @(Get-mdiIssueList -Statistics $cleanStats -ReportData $cleanRd)
Assert-That 'a clean forest has no findings' ($cleanIssues.Count -eq 0) "(got $($cleanIssues.Count))"
Assert-That 'a clean forest is ready' ((Test-mdiReadinessResult -ReportData $cleanRd) -eq $true)
Assert-That 'a role absent from the forest is not a finding' (
    @($cleanIssues | Where-Object { [string] $_.Area -eq 'Directory auditing' }).Count -eq 0)

Write-Host "`n[5] Domain-level findings appear, so the table is never empty on a red verdict" -ForegroundColor Yellow
# These live on the report, not on a server, so a list built only from servers was EMPTY while the
# banner said action required - the reader was told something was wrong and shown nothing.
$badDomain = New-Report -Servers @($clean) -DomainAuditing @([PSCustomObject]@{
        Domain = 'child.contoso.com'
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $false }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $false
    })
$badStats = Get-mdiReportStatistics -ReportData $badDomain
$badIssues = @(Get-mdiIssueList -Statistics $badStats -ReportData $badDomain)
Assert-That 'a misconfigured domain is a finding' (
    @($badIssues | Where-Object { [string] $_.Issue -match 'Object auditing is not configured' }).Count -eq 1)
Assert-That 'an unread domain check is a finding' (
    @($badIssues | Where-Object { [string] $_.Issue -match 'AD FS auditing could not be read' }).Count -eq 1)
Assert-That 'the verdict agrees it is not ready' ((Test-mdiReadinessResult -ReportData $badDomain) -eq $false)

Write-Host "`n[6] An incomplete forest is a finding" -ForegroundColor Yellow
$degraded = New-Report -Servers @($clean) -Forest ([PSCustomObject]@{
        Name = 'contoso.com'; Method = 'None'; Complete = $false; Error = 'ADWS and LDAP both failed'
    })
$degradedStats = Get-mdiReportStatistics -ReportData $degraded
$degradedIssues = @(Get-mdiIssueList -Statistics $degradedStats -ReportData $degraded)
Assert-That 'a degraded forest scan is a finding' (
    @($degradedIssues | Where-Object { [string] $_.Area -eq 'Forest discovery' }).Count -eq 1)
Assert-That 'the verdict agrees it is not ready' ((Test-mdiReadinessResult -ReportData $degraded) -eq $false)

Write-Host "`n[7] An empty scan is a finding, not silence" -ForegroundColor Yellow
# A scan that enumerated nothing failed to LOOK, not to find. It must never read as a clean result.
$empty = New-Report -Servers @()
$emptyStats = Get-mdiReportStatistics -ReportData $empty
$emptyIssues = @(Get-mdiIssueList -Statistics $emptyStats -ReportData $empty)
Assert-That 'an empty scan produces at least one finding' ($emptyIssues.Count -gt 0) "(got $($emptyIssues.Count))"
Assert-That 'an empty scan is not ready' ((Test-mdiReadinessResult -ReportData $empty) -eq $false)

Write-Host "`n[8] A domain that produced no servers is a finding" -ForegroundColor Yellow
$missing = New-Report -Servers @($clean) -Scope @('contoso.com', 'orphan.contoso.com')
$missingStats = Get-mdiReportStatistics -ReportData $missing
$missingIssues = @(Get-mdiIssueList -Statistics $missingStats -ReportData $missing)
Assert-That 'the unexamined domain is named' (
    @($missingIssues | Where-Object { [string] $_.Server -eq 'orphan.contoso.com' }).Count -eq 1)
Assert-That 'the verdict agrees it is not ready' ((Test-mdiReadinessResult -ReportData $missing) -eq $false)

Write-Host "`n[9] Every verdict input has a corresponding finding" -ForegroundColor Yellow
# The contract: if the run is not ready, the operator can always see why.
foreach ($case in @(
        @{ Name = 'unreachable server'; Report = (New-Report -Servers @([PSCustomObject]@{
                        FQDN = 'dead.contoso.com'; Domain = 'contoso.com'; PartialFailure = $false; Unreachable = $true
                        Comment = 'Server is not available: ICMP, TCP 135 and WMI all failed'
                    })) }
        @{ Name = 'unread check'; Report = $rd }
        @{ Name = 'misconfigured domain'; Report = $badDomain }
        @{ Name = 'incomplete forest'; Report = $degraded }
        @{ Name = 'unexamined domain'; Report = $missing }
        @{ Name = 'empty scan'; Report = $empty }
    )) {
    $s = Get-mdiReportStatistics -ReportData $case.Report
    $i = @(Get-mdiIssueList -Statistics $s -ReportData $case.Report)
    $v = Test-mdiReadinessResult -ReportData $case.Report
    Assert-That ('{0}: not ready AND at least one finding' -f $case.Name) (
        $v -eq $false -and $i.Count -gt 0) "(ready=$v findings=$($i.Count))"
}

Write-Host "`n[10] The return value is never re-wrapped by a caller" -ForegroundColor Yellow
# Comments are stripped first: the comment explaining this bug quotes the offending expression, and
# a plain text search matched its own documentation rather than any code.
$codeOnly = New-Object System.Text.StringBuilder (Get-Content $scriptPath -Raw)
foreach ($comment in @($tokens | Where-Object { $_.Kind -eq 'Comment' } | Sort-Object { $_.Extent.StartOffset } -Descending)) {
    [void] $codeOnly.Remove($comment.Extent.StartOffset, $comment.Extent.EndOffset - $comment.Extent.StartOffset)
}
$code = $codeOnly.ToString()
Assert-That 'the function does not use the comma operator' (
    $code -notmatch ',\s*@\(\$issues\.ToArray\(\)\)')
Assert-That 'every call site wraps in @()' (
    ([regex]::Matches($code, '@\(Get-mdiIssueList')).Count -ge 2)

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
