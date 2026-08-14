# [w100] A run that is NOT READY must never present an empty issue table.
#
# Every per-server rule in Get-mdiIssueList iterates the checks a server carries, so a server that
# carries NONE contributes nothing to the list - while the verdict correctly refuses to call it ready,
# because a server nobody measured is not a server that passed.
#
# Measured on the shipped functions: one REACHABLE domain controller with no check properties, and
# four passing domain checks:
#
#   verdict            NOT READY
#   hero               "Action required"
#   -FailOnIssues      exit 1
#   issue table        0 rows
#   console            "0 issue(s) found: 4/4 checks passed across 1 server(s)."
#
# The operator is told to act, told that every check passed, and given nothing to act on - on the one
# surface the report itself tells them to start with. The exit code says failure while the issue count
# driving it is zero.
#
# The row is filed under 'Not measured', not as a failure: nothing was observed to fail, the server
# produced no evidence at all. Placeholders and unreachable servers already have their own rows and
# must not gain a second one, and a partial failure must not be reported twice.

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

function New-PassingDomainRow {
    $chk = { param($Field) $o = [PSCustomObject]@{ Measured = $true; Detail = 'Configured' }
        $o | Add-Member -NotePropertyName $Field -NotePropertyValue $true; $o }
    [PSCustomObject]@{
        Domain = 'silent.example'
        ObjectAuditing = (& $chk 'isObjectAuditingOk'); ObjectAuditingMeasured = $true
        ExchangeAuditing = (& $chk 'isExchangeAuditingOk'); ExchangeAuditingMeasured = $true
        AdfsAuditing = (& $chk 'isAdfsAuditingOk'); AdfsAuditingMeasured = $true
        DeletedObjects = (& $chk 'isDeletedObjectsPermissionOk'); DeletedObjectsMeasured = $true
    }
}

function Get-Surfaces {
    param([object[]] $Servers)
    $report = [PSCustomObject]@{
        DomainsInScope = @('silent.example')
        DomainControllers = $Servers
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @((New-PassingDomainRow))
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $issues = @(Get-mdiIssueList -ReportData $report -Statistics $stats)
    [PSCustomObject]@{
        Ready = (Test-mdiReadinessResult -ReportData $report)
        Issues = $issues
        Count = $issues.Count
        Stats = $stats
    }
}

# A server the scan REACHED - not unreachable, not partial, not a placeholder - that carries no
# readiness check properties at all.
$silent = [PSCustomObject]@{
    FQDN = 'dc1.silent.example'; Domain = 'silent.example'
    Unreachable = $false; PartialFailure = $false
    OperatingSystem = 'Windows Server 2022'
    Details = [PSCustomObject]@{ }
}

'[w100] the fixture really is a silent, reachable server'
$r = Get-Surfaces -Servers @($silent)
Assert-That 'it carries no readiness checks' (@(Get-mdiCheckProperty -Server $silent).Count -eq 0) `
    "($(@(Get-mdiCheckProperty -Server $silent).Count) check(s) - the fixture is not silent and tests nothing)"
Assert-That 'and it is counted as a reachable server' ([int] $r.Stats.TotalServers -eq 1) "(TotalServers $($r.Stats.TotalServers))"

'[w100] not ready and an empty issue table cannot both be true'
Assert-That 'the verdict is NOT ready' (-not $r.Ready) "(Ready $($r.Ready))"
Assert-That 'so the issue list is NOT empty' ($r.Count -ge 1) "($($r.Count) issue row(s))"
Assert-That 'and a row names the server' (@($r.Issues | Where-Object { [string] $_.Server -eq 'dc1.silent.example' }).Count -ge 1) `
    "(rows: $(@($r.Issues | ForEach-Object { '{0}/{1}' -f $_.Area, $_.Server }) -join '; '))"
Assert-That 'the row carries actionable text, not a blank cell' `
    (@($r.Issues | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.Issue) }).Count -eq $r.Count) `
    "(rows: $(@($r.Issues | ForEach-Object { '[{0}]' -f $_.Issue }) -join '; '))"

'[w100] it is reported as UNMEASURED, not as a measured failure'
# The distinction drives what the operator does next: re-measure, versus remediate a setting that was
# observed to be wrong. Nothing here was observed at all.
Assert-That "the row is filed under 'Not measured'" `
    (@($r.Issues | Where-Object { [string] $_.Area -eq 'Not measured' }).Count -ge 1) `
    "(areas: $(@($r.Issues | ForEach-Object { [string] $_.Area }) -join ', '))"

'[w100] controls: servers that already have their own row do not get a second one'
$unreachable = [PSCustomObject]@{
    FQDN = 'dc2.silent.example'; Domain = 'silent.example'
    Unreachable = $true; PartialFailure = $false; Comment = 'Server is not available: ICMP'
    Details = [PSCustomObject]@{ }
}
$ru = Get-Surfaces -Servers @($unreachable)
Assert-That 'an unreachable server produces exactly one row' `
    (@($ru.Issues | Where-Object { [string] $_.Server -eq 'dc2.silent.example' }).Count -eq 1) `
    "($(@($ru.Issues | Where-Object { [string] $_.Server -eq 'dc2.silent.example' }).Count) rows)"

$partial = [PSCustomObject]@{
    FQDN = 'dc3.silent.example'; Domain = 'silent.example'
    Unreachable = $false; PartialFailure = $true; Comment = 'Testing stopped early: RPC unavailable'
    Details = [PSCustomObject]@{ }
}
$rp = Get-Surfaces -Servers @($partial)
Assert-That 'a partial scan produces exactly one row, not two' `
    (@($rp.Issues | Where-Object { [string] $_.Server -eq 'dc3.silent.example' }).Count -eq 1) `
    "($(@($rp.Issues | Where-Object { [string] $_.Server -eq 'dc3.silent.example' }).Count) rows: $(@($rp.Issues | ForEach-Object { $_.Issue }) -join ' | '))"

$placeholder = [PSCustomObject]@{
    FQDN = 'Domain controller (not named) 1 of 1 - silent.example'; Domain = 'silent.example'
    Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true
    Comment = 'A domain controller record carries no name'
    Details = [PSCustomObject]@{ }
}
$rph = Get-Surfaces -Servers @($placeholder)
Assert-That 'a discovery placeholder produces exactly one row, not two' `
    (@($rph.Issues | Where-Object { [string] $_.Server -match 'not named' }).Count -eq 1) `
    "($(@($rph.Issues | Where-Object { [string] $_.Server -match 'not named' }).Count) rows)"

'[w100] control: a fully measured server raises nothing'
$healthy = [PSCustomObject]@{
    FQDN = 'dc4.silent.example'; Domain = 'silent.example'
    Unreachable = $false; PartialFailure = $false
    NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true
    Details = [PSCustomObject]@{ }
}
$rh = Get-Surfaces -Servers @($healthy)
Assert-That 'a measured, passing server produces no issue row' ($rh.Count -eq 0) `
    "($($rh.Count): $(@($rh.Issues | ForEach-Object { '{0}/{1}' -f $_.Area, $_.Issue }) -join '; '))"
Assert-That 'and that run is ready' ($rh.Ready -eq $true) "(Ready $($rh.Ready))"

''
"NotReadyNeedsAnIssueRow: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
