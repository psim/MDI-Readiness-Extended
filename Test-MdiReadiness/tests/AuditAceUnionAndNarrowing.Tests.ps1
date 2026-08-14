<#
    Test-mdiAuditAceSatisfied decides whether the audit ACEs read from a directory object satisfy one
    expected audit entry. It was wrong in BOTH directions at once, and the two errors hid each other:
    it rejected SACLs that were correct and accepted SACLs that were not.

    TOO STRICT - each applied ACE was tested ALONE. Success and Failure are routinely written as two
    separate ACEs; it is what the Windows "Auditing" tab produces when an administrator adds a Success
    entry and a Failure entry, and what dsacls reports back. Neither half satisfied an expected
    Success+Failure row on its own, so a correctly configured domain reported
    "Exchange auditing is not configured on this domain" as a MEASURED failure, failed the verdict,
    drew a red HTML cell, and was handed remediation advice to rewrite a SACL that was already right.

    TOO LOOSE - AceFlagsValue was a required-bits SUBSET test, on the reasoning that a real ACE is
    routinely broader than the minimum and being broader is not a defect. That is true of every flag
    except two: NoPropagateInherit (0x04) limits inheritance to immediate children, and InheritOnly
    (0x08) removes the object itself. Both make an ACE NARROWER. Every expected row asks for
    ContainerInherit (the shipped rows are AceFlags 194), so a SACL carrying either flag does NOT
    deliver the required subtree coverage - and it was reported as correctly configured. A false green
    on a detection-coverage check is the most expensive answer this tool can give.

    The union must also not be flat. Crediting Success from one ACE and Failure from another and then
    applying the combined access mask to both would let mask 32 on Success plus mask 16 on Failure
    satisfy a requirement for mask 32 on BOTH - coverage the SACL does not actually provide. Each
    required audit flag has to stand on its own evidence.
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

$emptyGuid = '00000000-0000-0000-0000-000000000000'
# The shipped Exchange expectation: Everyone, mask 32, Success+Failure, ContainerInherit.
function New-Expected {
    param([int] $Mask = 32, [int] $Audit = 3, [int] $AceFlags = 194, [string] $Class = '')
    [PSCustomObject]@{
        SecurityIdentifier    = 'S-1-1-0'
        AccessMask            = $Mask
        AuditFlagsValue       = $Audit
        AceFlagsValue         = $AceFlags
        InheritedObjectAceType = $Class
    }
}
function New-Ace {
    param([int] $Mask = 32, [int] $Audit = 3, [int] $AceFlags = 194, [string] $Class = '',
        [string] $ObjectAce = '', $ObjectAceFlags = 0, [string] $Sid = 'S-1-1-0')
    [PSCustomObject]@{
        SecurityIdentifier     = $Sid
        AccessMask             = $Mask
        AuditFlagsValue        = $Audit
        AceFlagsValue          = $AceFlags
        InheritedObjectAceType = $Class
        ObjectAceType          = $ObjectAce
        ObjectAceFlags         = $ObjectAceFlags
    }
}

Write-Host 'CONTROLS - the behaviour that was already correct must not move' -ForegroundColor Cyan
Assert-That 'one ACE carrying Success+Failure satisfies it' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace))
Assert-That 'a broader ACE (extra audit flags) still satisfies it' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Audit 1) -Applied @(New-Ace -Audit 3))
Assert-That 'a broader ACE (extra access rights) still satisfies it' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 32) -Applied @(New-Ace -Mask 48))
Assert-That 'an INHERITED ACE (extra Inherited bit, 210) still satisfies it' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace -AceFlags 210))
Assert-That 'an ACE with no ContainerInherit does NOT satisfy it' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace -AceFlags 192)) -eq $false)
Assert-That 'an ACE for a DIFFERENT trustee does NOT satisfy it' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace -Sid 'S-1-5-11')) -eq $false)
Assert-That 'an empty applied set does NOT satisfy it' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @()) -eq $false)
# An unrestricted ACE covers every class; one naming a different class does not.
$userClass = 'bf967aba-0de6-11d0-a285-00aa003049e2'
$groupClass = 'bf967a9c-0de6-11d0-a285-00aa003049e2'
Assert-That 'an ACE restricted to no class satisfies a per-class row' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Class $userClass) -Applied @(New-Ace -Class ''))
Assert-That 'an all-zero GUID counts as unrestricted too' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Class $userClass) -Applied @(New-Ace -Class $emptyGuid))
Assert-That 'an ACE naming a DIFFERENT class does not' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected -Class $userClass) -Applied @(New-Ace -Class $groupClass)) -eq $false)
# A property-scoped ACE audits only that property and must not satisfy an unrestricted requirement.
Assert-That 'a property-scoped ACE does NOT satisfy an unrestricted row' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace -ObjectAce 'e48d0154-bcf8-11d1-8702-00c04fb96050' -ObjectAceFlags 1)) -eq $false)

Write-Host 'DEFECT A (too strict) - Success and Failure split across two ACEs' -ForegroundColor Cyan
$splitAudit = @(
    (New-Ace -Audit 1),   # Success only
    (New-Ace -Audit 2)    # Failure only
)
Assert-That 'two complementary ACEs together satisfy Success+Failure' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Audit 3) -Applied $splitAudit)
# ...and the access mask unions across ACEs the same way.
$splitMask = @(
    (New-Ace -Mask 16),
    (New-Ace -Mask 32)
)
Assert-That 'two ACEs together supply a combined access mask' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 48) -Applied $splitMask)
# Only ACEs that actually qualify may contribute to the union.
Assert-That '  ...but a DIFFERENT trustee cannot contribute to the union' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 48) -Applied @((New-Ace -Mask 16), (New-Ace -Mask 32 -Sid 'S-1-5-11'))) -eq $false)
Assert-That '  ...nor can an ACE lacking ContainerInherit' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 48) -Applied @((New-Ace -Mask 16), (New-Ace -Mask 32 -AceFlags 192))) -eq $false)
Assert-That '  ...nor can an ACE naming a different class' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 48 -Class $userClass) -Applied @((New-Ace -Mask 16 -Class $userClass), (New-Ace -Mask 32 -Class $groupClass))) -eq $false)

Write-Host '  the union is PER AUDIT FLAG - evidence for Success is not borrowed for Failure' -ForegroundColor Cyan
# Success carries mask 32 (WriteProperty); Failure carries only mask 16 (ReadProperty). These are
# DISTINCT bits, not a hierarchy - 32 does not contain 16 - so a requirement for either mask on BOTH
# flags is unmet, and each is satisfied only on the flag whose own ACE actually carries it.
$lopsided = @(
    (New-Ace -Mask 32 -Audit 1),
    (New-Ace -Mask 16 -Audit 2)
)
Assert-That 'mask 32 on Success + mask 16 on Failure does NOT satisfy mask 32 on both' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 32 -Audit 3) -Applied $lopsided) -eq $false)
Assert-That '  ...nor mask 16 on both' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 16 -Audit 3) -Applied $lopsided) -eq $false)
Assert-That '  ...while it DOES satisfy mask 32 on Success alone' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 32 -Audit 1) -Applied $lopsided)
Assert-That '  ...and mask 16 on Failure alone' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Mask 16 -Audit 2) -Applied $lopsided)

Write-Host 'DEFECT B (too loose) - narrowing inheritance flags are not supersets' -ForegroundColor Cyan
# 198 = 194 + NoPropagateInherit(4): only immediate children are audited, not the subtree.
Assert-That 'NoPropagateInherit does NOT satisfy a ContainerInherit row' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace -AceFlags 198)) -eq $false)
# 202 = 194 + InheritOnly(8): the object itself is not audited.
Assert-That 'InheritOnly does NOT satisfy a ContainerInherit row' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace -AceFlags 202)) -eq $false)
Assert-That 'both narrowing flags together do not either' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected) -Applied @(New-Ace -AceFlags 206)) -eq $false)
# A narrowed ACE must not be able to contribute to a union either.
Assert-That 'a narrowed ACE cannot complete a split Success/Failure pair' `
((Test-mdiAuditAceSatisfied -Expected (New-Expected -Audit 3) -Applied @((New-Ace -Audit 1), (New-Ace -Audit 2 -AceFlags 198))) -eq $false)
Assert-That '  ...while an un-narrowed one can' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -Audit 3) -Applied @((New-Ace -Audit 1), (New-Ace -Audit 2)))
# The rule is relative to the EXPECTED row, so a row that deliberately asks for the flag still matches.
Assert-That 'an expected row that ASKS for InheritOnly is matched by an ACE carrying it' `
(Test-mdiAuditAceSatisfied -Expected (New-Expected -AceFlags 202) -Applied @(New-Ace -AceFlags 202))

Write-Host 'END TO END - a real domain whose SACL splits Success and Failure' -ForegroundColor Cyan
# Driven through the real producer's comparison, exactly as Get-mdiExchangeAuditing does it.
$expectedRows = @(New-Expected -Mask 32 -Audit 3 -AceFlags 194)
$appliedSplit = @((New-Ace -Mask 32 -Audit 1), (New-Ace -Mask 32 -Audit 2))
$isOk = @($expectedRows | Where-Object { Test-mdiAuditAceSatisfied -Expected $_ -Applied $appliedSplit }).Count -eq @($expectedRows).Count
Assert-That 'the domain is reported as CONFIGURED' ($isOk -eq $true)

$row = [PSCustomObject][ordered]@{
    Domain                   = 'contoso.com'
    ObjectAuditing           = [PSCustomObject]@{ isObjectAuditingOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured   = $true
    ExchangeAuditing         = [PSCustomObject]@{ isExchangeAuditingOk = $isOk; Measured = $true; details = $appliedSplit }
    ExchangeAuditingMeasured = $true
    AdfsAuditing             = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A'; details = [PSCustomObject]@{ Detail = 'no adfs' } }
    AdfsAuditingMeasured     = $true
    DeletedObjects           = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; Measured = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    DeletedObjectsMeasured   = $true
}
$report = [PSCustomObject]@{
    Domain              = 'contoso.com'
    Forest              = 'contoso.com'
    DomainsInScope      = @('contoso.com')
    DomainControllers   = @([PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2022'
            AdvancedAuditing = $true; NtlmAuditing = $true; Unreachable = $false
        })
    CAServers           = @()
    EntraConnectServers = @()
    DomainAuditing      = @($row)
}
$stats = Get-mdiReportStatistics -ReportData $report
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report | Where-Object { [string] $_.Issue -like '*Exchange*' })
Assert-That '  ...no Exchange finding is raised' ($issues.Count -eq 0) "got: $(@($issues | ForEach-Object { $_.Issue }) -join ' | ')"
Assert-That '  ...and the run is READY' ((Test-mdiReadinessResult -ReportData $report) -eq $true)

# The control: the same estate with a genuinely narrowed SACL must still fail.
$appliedNarrow = @(New-Ace -Mask 32 -Audit 3 -AceFlags 198)
$isOkNarrow = @($expectedRows | Where-Object { Test-mdiAuditAceSatisfied -Expected $_ -Applied $appliedNarrow }).Count -eq @($expectedRows).Count
Assert-That 'a NoPropagateInherit SACL is reported as NOT configured' ($isOkNarrow -eq $false)
$row2 = $row.PSObject.Copy()
$row2.ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $isOkNarrow; Measured = $true; details = $appliedNarrow }
$report2 = $report.PSObject.Copy(); $report2.DomainAuditing = @($row2)
$stats2 = Get-mdiReportStatistics -ReportData $report2
$issues2 = @(Get-mdiIssueList -Statistics $stats2 -ReportData $report2 | Where-Object { [string] $_.Issue -like '*Exchange*' })
Assert-That '  ...raises a High finding' (@($issues2 | Where-Object { $_.Severity -eq 'High' }).Count -ge 1) "got $($issues2.Count)"
Assert-That '  ...and the run is NOT READY' ((Test-mdiReadinessResult -ReportData $report2) -eq $false)

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
