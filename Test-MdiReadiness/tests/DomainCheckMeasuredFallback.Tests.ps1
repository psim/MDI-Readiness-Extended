# [w95] "Was this domain check measured?" must be answered the same way by every surface.
#
# The four domain-level checks carry their Measured flag in TWO places: a row-level companion
# property (ObjectAuditingMeasured, ExchangeAuditingMeasured, ...) and a Measured property on the
# RESULT object itself, which is what the producers actually set. Every consumer read only the
# companion. The legacy row shape - still produced by the shipped fallback path - carries no
# companions, so Measured came back $null, every downstream test of the form "$check.Measured -eq
# $false" was false, and the check was treated as MEASURED.
#
# Measured on the shipped functions with isExchangeAuditingOk = 'N/A' and Measured = $false on the
# result object (an unreadable SACL - access denied or SeSecurityPrivilege missing - which is a GAP):
#
#   modern row shape : scored unread, 1 issue, verdict NOT READY          <- correct
#   legacy row shape : scored PASSED, unread 1 -> 0, 0 issues, READY      <- the same fact, inverted
#
# So an audit configuration nobody could read was reported as a passing check and the run was
# certified ready. The two shapes now agree on the score, the unread count, the issue list and the
# verdict.
#
# NOTE the HTML cell text is deliberately NOT asserted here: in the legacy shape it still reads
# "Not applicable" rather than "Not tested". That is a separate, narrower defect about wording; this
# file pins the part that changes the verdict.

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

# An unreadable SACL exactly as the producers emit it: the value is 'N/A' AND the result object says
# it was not measured. 'N/A' alone is ambiguous - it also means "this role is not in the forest" -
# and Measured is the only thing that tells the two apart.
function New-UnreadableExchange {
    [PSCustomObject]@{
        isExchangeAuditingOk = 'N/A'
        Measured = $false
        Detail = 'Not tested - the SACL could not be read'
    }
}
function New-PassingCheck {
    param([string] $Field)
    $o = [PSCustomObject]@{ Measured = $true; Detail = 'Configured' }
    $o | Add-Member -NotePropertyName $Field -NotePropertyValue $true
    $o
}

function New-Dc {
    [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false
        NtlmAuditing = $true
        Details = [PSCustomObject]@{ }
    }
}

# MODERN shape: the row carries the companion properties.
$modernRow = [PSCustomObject]@{
    Domain = 'contoso.com'
    ObjectAuditing = (New-PassingCheck 'isObjectAuditingOk')
    ObjectAuditingMeasured = $true
    ExchangeAuditing = (New-UnreadableExchange)
    ExchangeAuditingMeasured = $false
    AdfsAuditing = (New-PassingCheck 'isAdfsAuditingOk')
    AdfsAuditingMeasured = $true
    DeletedObjects = (New-PassingCheck 'isDeletedObjectsPermissionOk')
    DeletedObjectsMeasured = $true
}

# LEGACY shape: identical facts, NO companion properties. Only the result objects carry Measured.
$legacyRow = [PSCustomObject]@{
    Domain = 'contoso.com'
    ObjectAuditing = (New-PassingCheck 'isObjectAuditingOk')
    ExchangeAuditing = (New-UnreadableExchange)
    AdfsAuditing = (New-PassingCheck 'isAdfsAuditingOk')
    DeletedObjects = (New-PassingCheck 'isDeletedObjectsPermissionOk')
}

function Get-Surfaces {
    param($DomainRow)
    $report = [PSCustomObject]@{
        DomainsInScope = @('contoso.com')
        DomainControllers = @((New-Dc))
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @($DomainRow)
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    [PSCustomObject]@{
        Unread = [int] $stats.ChecksUnread
        Passed = [int] $stats.ChecksPassed
        Issues = @(Get-mdiIssueList -ReportData $report -Statistics $stats).Count
        Ready  = (Test-mdiReadinessResult -ReportData $report)
    }
}

$modern = Get-Surfaces -DomainRow $modernRow
$legacy = Get-Surfaces -DomainRow $legacyRow

'[w95] the fixture is the one that matters'
Assert-That 'the definition table resolves Measured from the RESULT object when no companion exists' `
    (@(Get-mdiDomainCheckDefinition -Domain $legacyRow | Where-Object { $_.Measured -eq $false }).Count -eq 1) `
    "(unmeasured checks found: $(@(Get-mdiDomainCheckDefinition -Domain $legacyRow | Where-Object { $_.Measured -eq $false }).Count))"
Assert-That 'and still prefers the companion when one IS present' `
    (@(Get-mdiDomainCheckDefinition -Domain $modernRow | Where-Object { $_.Measured -eq $false }).Count -eq 1) `
    "(unmeasured checks found: $(@(Get-mdiDomainCheckDefinition -Domain $modernRow | Where-Object { $_.Measured -eq $false }).Count))"

'[w95] an unreadable SACL is never a passing check'
Assert-That 'the legacy shape charges it as unread' ($legacy.Unread -ge 1) "(unread $($legacy.Unread))"
Assert-That 'the legacy shape raises an issue for it' ($legacy.Issues -ge 1) "(issues $($legacy.Issues))"
Assert-That 'and the legacy shape is NOT ready' (-not $legacy.Ready) "(Ready $($legacy.Ready))"

'[w95] both row shapes describe the same estate the same way'
Assert-That 'unread counts agree' ($legacy.Unread -eq $modern.Unread) "(legacy $($legacy.Unread) vs modern $($modern.Unread))"
Assert-That 'passed counts agree' ($legacy.Passed -eq $modern.Passed) "(legacy $($legacy.Passed) vs modern $($modern.Passed))"
Assert-That 'issue counts agree' ($legacy.Issues -eq $modern.Issues) "(legacy $($legacy.Issues) vs modern $($modern.Issues))"
Assert-That 'verdicts agree' ($legacy.Ready -eq $modern.Ready) "(legacy $($legacy.Ready) vs modern $($modern.Ready))"

'[w95] control: a fully readable domain is still allowed to pass'
$goodRow = [PSCustomObject]@{
    Domain = 'contoso.com'
    ObjectAuditing = (New-PassingCheck 'isObjectAuditingOk')
    ExchangeAuditing = (New-PassingCheck 'isExchangeAuditingOk')
    AdfsAuditing = (New-PassingCheck 'isAdfsAuditingOk')
    DeletedObjects = (New-PassingCheck 'isDeletedObjectsPermissionOk')
}
$good = Get-Surfaces -DomainRow $goodRow
Assert-That 'a readable domain charges no unread domain check' `
    (@(Get-mdiDomainCheckDefinition -Domain $goodRow | Where-Object { $_.Measured -eq $false }).Count -eq 0) `
    "(unmeasured $(@(Get-mdiDomainCheckDefinition -Domain $goodRow | Where-Object { $_.Measured -eq $false }).Count))"
Assert-That 'and the guard does not block its verdict' ($good.Ready -eq $true) "(Ready $($good.Ready))"

'[w95] control: a report carrying neither companion nor Measured is still accepted'
# Reports written before Measured existed carry no flag anywhere. They must resolve to $null - "no
# information either way" - not to $false, or every historical report would be reported unverified.
$ancientRow = [PSCustomObject]@{
    Domain = 'contoso.com'
    ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
    ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
}
Assert-That 'a flagless legacy report is not declared unmeasured' `
    (@(Get-mdiDomainCheckDefinition -Domain $ancientRow | Where-Object { $_.Measured -eq $false }).Count -eq 0) `
    "(unmeasured $(@(Get-mdiDomainCheckDefinition -Domain $ancientRow | Where-Object { $_.Measured -eq $false }).Count))"
Assert-That 'and it is still allowed to be ready' ((Get-Surfaces -DomainRow $ancientRow).Ready -eq $true) ''

''
"DomainCheckMeasuredFallback: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
