<#
    A correctly configured domain was reported as having no object auditing, because of how Windows
    writes the SACL rather than because of anything wrong with it.

    Test-mdiAuditAceSatisfied gates which applied ACEs count as EVIDENCE for an expected row before
    unioning what they audit. The gate required every bit of the expected AceFlagsValue to be present
    on a single applied ACE:

        ((([int] $_.AceFlagsValue) -band ([int] $Expected.AceFlagsValue)) -eq [int] $Expected.AceFlagsValue)

    The shipped expected rows carry AceFlags 194 = ContainerInherit (2) + SuccessfulAccess (64) +
    FailedAccess (128). Those last two are the ACE-HEADER spelling of the audit TYPE, so requiring both
    on one ACE demanded that a single entry audit success AND failure.

    Windows does not write it that way. Adding a Success entry and a Failure entry on the Auditing tab
    produces TWO ACEs - AceFlags 66 and AceFlags 130 - and dsacls reports them back the same way.
    Neither carries both bits, so neither passed the gate; and because the gate runs FIRST, the
    per-audit-flag union further down the function - which exists precisely to handle split ACEs, and
    whose comment says so - never saw them at all.

    Measured before the fix: the combined single-ACE form satisfied the row, the identical coverage
    split across two ACEs did not. The operator saw "object auditing is not configured", a failed
    verdict, and remediation advice to rewrite the SACL on the domain root of a domain that was
    already auditing exactly what was asked of it.

    The fix excludes only the two audit-type bits from the STRUCTURAL gate. Which audit types are
    actually delivered is still proven per required flag from AuditFlagsValue, so a SACL that provides
    Success but not Failure still fails - asserted below, because a fix that turned this into a false
    green would be worse than the false red it replaced.
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

# Raw ACE header bits, as Windows encodes them.
$CONTAINER_INHERIT = 0x02
$NO_PROPAGATE      = 0x04
$INHERIT_ONLY      = 0x08
$INHERITED         = 0x10
$SUCCESSFUL_ACCESS = 0x40
$FAILED_ACCESS     = 0x80
$USER_CLASS = 'bf967aba-0de6-11d0-a285-00aa003049e2'

# The shipped expected row shape.
$expected = [PSCustomObject]@{
    SecurityIdentifier     = 'S-1-1-0'
    AceFlagsValue          = $CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS -bor $FAILED_ACCESS   # 194
    AuditFlagsValue        = 3                                                                # Success + Failure
    AccessMask             = 32
    InheritedObjectAceType = $USER_CLASS
    ObjectAceType          = ''
    ObjectAceFlags         = $null
}

function New-AuditAce {
    param(
        [int] $AceFlags,
        [int] $AuditFlags,
        [int] $Mask = 32,
        [string] $Class = $USER_CLASS,
        [string] $ObjectAceType = '',
        $ObjectAceFlags = $null
    )
    [PSCustomObject]@{
        SecurityIdentifier     = 'S-1-1-0'
        AceFlagsValue          = $AceFlags
        AuditFlagsValue        = $AuditFlags
        AccessMask             = $Mask
        InheritedObjectAceType = $Class
        ObjectAceType          = $ObjectAceType
        ObjectAceFlags         = $ObjectAceFlags
    }
}

Write-Host 'Success and Failure written as two ACEs is the same coverage as one' -ForegroundColor Cyan
$combined = @(New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS -bor $FAILED_ACCESS) -AuditFlags 3)
Assert-That 'one ACE auditing both success and failure satisfies the row' (Test-mdiAuditAceSatisfied -Expected $expected -Applied $combined)

# Exactly what the Windows Auditing tab produces.
$split = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2
)
Assert-That 'the same coverage split across two ACEs also satisfies it' (Test-mdiAuditAceSatisfied -Expected $expected -Applied $split) 'a correctly configured domain reads as unconfigured'

# Order must not matter; a SACL is not sorted for our convenience.
$splitReversed = @($split[1], $split[0])
Assert-That '  ...in either order' (Test-mdiAuditAceSatisfied -Expected $expected -Applied $splitReversed)

# Inherited from a parent container adds bit 16 to both.
$splitInherited = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS -bor $INHERITED) -AuditFlags 1
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS -bor $INHERITED) -AuditFlags 2
)
Assert-That '  ...and when both are inherited from a parent' (Test-mdiAuditAceSatisfied -Expected $expected -Applied $splitInherited)

Write-Host 'Partial coverage is still a failure' -ForegroundColor Cyan
# This is the half that must NOT become permissive. Coverage is proven from AuditFlagsValue per
# required flag, so evidence for Success cannot stand in for Failure.
$successOnly = @(New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1)
Assert-That 'auditing Success but not Failure does not satisfy it' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $successOnly)) 'a partially audited domain would read as configured'

$failureOnly = @(New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2)
Assert-That 'auditing Failure but not Success does not satisfy it' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $failureOnly))

# The access mask must stand on its own evidence for EACH audit flag - Success at mask 32 plus
# Failure at mask 16 does not deliver mask 32 on both.
$mismatchedMasks = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1 -Mask 32
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2 -Mask 16
)
Assert-That 'a mask present on Success only does not count for Failure' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $mismatchedMasks)) 'evidence was borrowed across audit flags'

Write-Host 'The structural requirements still gate the match' -ForegroundColor Cyan
# Excluding the audit-type bits must not weaken the inheritance and scope terms.
$noContainerInherit = @(
    New-AuditAce -AceFlags $SUCCESSFUL_ACCESS -AuditFlags 1
    New-AuditAce -AceFlags $FAILED_ACCESS -AuditFlags 2
)
Assert-That 'ACEs without ContainerInherit do not satisfy it' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $noContainerInherit)) 'the subtree is not audited'

$narrowed = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS -bor $NO_PROPAGATE) -AuditFlags 1
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS -bor $NO_PROPAGATE) -AuditFlags 2
)
Assert-That 'NoPropagateInherit still disqualifies' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $narrowed)) 'coverage stops at immediate children'

Write-Host 'InheritOnly is judged against the scope the row asks for' -ForegroundColor Cyan
# This expected row is restricted to a descendant CLASS, so it never covered the object the SACL sits
# on: the domain root is a domainDNS object, not a user. InheritOnly removes nothing the row asked for,
# and it is exactly what Windows writes for "Applies to: Descendant User objects" (raw AceFlags 74).
# Rejecting it reported a correctly configured domain as unaudited - see
# AuditAceDescendantClassInheritOnly.Tests.ps1, which proves the shape from real .NET-built ACEs.
$inheritOnly = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS -bor $INHERIT_ONLY) -AuditFlags 1
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS -bor $INHERIT_ONLY) -AuditFlags 2
)
Assert-That 'InheritOnly satisfies a row restricted to a descendant class' (Test-mdiAuditAceSatisfied -Expected $expected -Applied $inheritOnly) 'the shape Windows actually writes reads as unconfigured'

# ...but a row that is NOT class-restricted (the Exchange and AD FS rows) does cover its own object, so
# InheritOnly genuinely removes required coverage there and must still disqualify.
$expectedUnrestricted = [PSCustomObject]@{
    SecurityIdentifier     = 'S-1-1-0'
    AceFlagsValue          = $CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS -bor $FAILED_ACCESS
    AuditFlagsValue        = 3
    AccessMask             = 32
    InheritedObjectAceType = ''
    ObjectAceType          = ''
    ObjectAceFlags         = $null
}
$inheritOnlyUnrestricted = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS -bor $INHERIT_ONLY) -AuditFlags 1 -Class ''
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS -bor $INHERIT_ONLY) -AuditFlags 2 -Class ''
)
Assert-That 'InheritOnly still disqualifies a row that covers its own object' (-not (Test-mdiAuditAceSatisfied -Expected $expectedUnrestricted -Applied $inheritOnlyUnrestricted)) 'the object itself is not audited'

$selfAndDescUnrestricted = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1 -Class ''
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2 -Class ''
)
Assert-That '  ...and is satisfied without it' (Test-mdiAuditAceSatisfied -Expected $expectedUnrestricted -Applied $selfAndDescUnrestricted)

$wrongSid = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2
) | ForEach-Object { $_.SecurityIdentifier = 'S-1-5-32-544'; $_ }
Assert-That 'a different trustee still disqualifies' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $wrongSid))

$wrongClass = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1 -Class 'bf967a9c-0de6-11d0-a285-00aa003049e2'
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2 -Class 'bf967a9c-0de6-11d0-a285-00aa003049e2'
)
Assert-That 'ACEs scoped to a different class still disqualify' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $wrongClass)) 'auditing groups says nothing about users'

# A property-scoped ACE audits only that property and must not satisfy an unrestricted requirement.
$propertyScoped = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1 -ObjectAceType '77b5b886-944a-11d1-aebd-0000f80367c1' -ObjectAceFlags 1
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2 -ObjectAceType '77b5b886-944a-11d1-aebd-0000f80367c1' -ObjectAceFlags 1
)
Assert-That 'property-scoped ACEs still disqualify' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $propertyScoped)) 'only one attribute is audited'

Write-Host 'An unrestricted ACE still satisfies a class-specific row' -ForegroundColor Cyan
# Auditing ALL descendant objects is stricter than auditing one class, so it must still pass.
$unrestricted = @(
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $SUCCESSFUL_ACCESS) -AuditFlags 1 -Class ''
    New-AuditAce -AceFlags ($CONTAINER_INHERIT -bor $FAILED_ACCESS) -AuditFlags 2 -Class ''
)
Assert-That 'ACEs covering every class satisfy the row' (Test-mdiAuditAceSatisfied -Expected $expected -Applied $unrestricted)

Write-Host 'Nothing at all is still nothing' -ForegroundColor Cyan
Assert-That 'an empty SACL does not satisfy the row' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied @()))

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
