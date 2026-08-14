<#
    A healthy domain, audited exactly the way Microsoft's own procedure tells you to audit it, was
    reported as having no directory object auditing at all.

    The six shipped ObjectAuditing rows each name a descendant CLASS:

        S-1-1-0,852331,1,2,bf967aba-0de6-11d0-a285-00aa003049e2,Descendant User Objects
        ...

    The documented way to satisfy them is the Auditing tab (or dsacls) with "Applies to: Descendant
    <Class> objects". That does not produce raw AceFlags 2. Windows writes ContainerInherit +
    InheritOnly, raw AceFlags 74 with Success, because the ACE is scoped to a child class and the
    domain root is a domainDNS object - not a user, group, computer, MSA, gMSA or dMSA. InheritOnly is
    how Windows says "this entry is for the descendants I named, not for this object".

    Test-mdiAuditAceSatisfied treated InheritOnly (0x08) as NARROWING unconditionally and rejected every
    ACE carrying it. Measured before the fix: 0 of the 6 shipped rows could be satisfied by the ACEs the
    documented procedure creates. The operator was told directory object auditing was not configured,
    the run failed its verdict, and remediation offered to rewrite a domain-root SACL that was already
    correct.

    InheritOnly is now judged against the SCOPE of the expected row. A row restricted to a descendant
    class never covered the object itself, so InheritOnly costs it nothing. A row that is NOT
    class-restricted - the Exchange and AD FS rows - does cover its own object, so InheritOnly there
    still removes required coverage and must still fail. Both halves are asserted below, because a fix
    that turned this into a false green would be worse than the false red it replaced.

    These ACEs are built with System.DirectoryServices and round-tripped through a real
    RawSecurityDescriptor rather than hand-written as literals, so the test asserts against the bytes
    Windows actually produces. If the shipped expected rows change, this test follows them.
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

# Build a SACL the way Windows does, then read it back as the script's own ACE shape.
function New-RealAuditAce {
    param(
        [int] $AccessMask,
        [int] $AuditFlags,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance] $Inheritance,
        [string] $Class = ''
    )

    $identity = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $rights = [System.DirectoryServices.ActiveDirectoryRights] $AccessMask
    $flags = [System.Security.AccessControl.AuditFlags] $AuditFlags

    $rule = if ([string]::IsNullOrWhiteSpace($Class)) {
        New-Object System.DirectoryServices.ActiveDirectoryAuditRule($identity, $rights, $flags, $Inheritance)
    } else {
        New-Object System.DirectoryServices.ActiveDirectoryAuditRule($identity, $rights, $flags, $Inheritance, ([guid] $Class))
    }
    $security.AddAuditRule($rule)

    [byte[]] $binary = $security.GetSecurityDescriptorBinaryForm()
    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($binary, 0)
    @($descriptor.SystemAcl) | Select-Object *,
    @{N = 'AuditFlagsValue'; E = { [int] $_.AuditFlags } },
    @{N = 'AceFlagsValue'; E = { [int] $_.AceFlags } }
}

$INHERIT_ONLY = 0x08
$NO_PROPAGATE = 0x04

Write-Host 'Every shipped descendant row is satisfied by the ACE the documented procedure creates' -ForegroundColor Cyan

$expectedRows = @($settings.ObjectAuditing | ConvertFrom-Csv)
Assert-That 'the shipped ObjectAuditing rows are all class-restricted' (
    @($expectedRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.InheritedObjectAceType) }).Count -eq @($expectedRows).Count)

$satisfied = 0
$sawInheritOnly = 0
foreach ($row in $expectedRows) {
    $applied = @(New-RealAuditAce -AccessMask ([int] $row.AccessMask) -AuditFlags ([int] $row.AuditFlagsValue) `
            -Inheritance Descendents -Class ([string] $row.InheritedObjectAceType))

    # Guard the premise: if Windows ever stops setting InheritOnly for a descendant-scoped rule this
    # test would silently stop testing anything.
    if ((([int] $applied[0].AceFlagsValue) -band $INHERIT_ONLY) -eq $INHERIT_ONLY) { $sawInheritOnly++ }
    if (Test-mdiAuditAceSatisfied -Expected $row -Applied $applied) { $satisfied++ }
}

Assert-That 'Windows sets InheritOnly on every descendant-scoped audit rule' ($sawInheritOnly -eq @($expectedRows).Count) "only $sawInheritOnly of $(@($expectedRows).Count) carried it"
Assert-That "all $(@($expectedRows).Count) descendant rows are satisfied" ($satisfied -eq @($expectedRows).Count) "only $satisfied of $(@($expectedRows).Count) matched - a correctly audited domain reads as unconfigured"

Write-Host 'Coverage that is genuinely missing still fails' -ForegroundColor Cyan

$firstRow = $expectedRows[0]

# NoPropagateInherit really does stop at immediate children, whatever the row's scope.
$noPropagate = @(New-RealAuditAce -AccessMask ([int] $firstRow.AccessMask) -AuditFlags ([int] $firstRow.AuditFlagsValue) `
        -Inheritance SelfAndChildren -Class ([string] $firstRow.InheritedObjectAceType))
Assert-That 'NoPropagateInherit is present on the SelfAndChildren rule' ((([int] $noPropagate[0].AceFlagsValue) -band $NO_PROPAGATE) -eq $NO_PROPAGATE)
Assert-That 'NoPropagateInherit still disqualifies' (-not (Test-mdiAuditAceSatisfied -Expected $firstRow -Applied $noPropagate)) 'the subtree below the first level is not audited'

# A different class says nothing about the class the row asked for.
$wrongClass = @(New-RealAuditAce -AccessMask ([int] $firstRow.AccessMask) -AuditFlags ([int] $firstRow.AuditFlagsValue) `
        -Inheritance Descendents -Class '00299570-246d-11d0-a768-00aa006e0529')
Assert-That 'a descendant rule on another class still disqualifies' (-not (Test-mdiAuditAceSatisfied -Expected $firstRow -Applied $wrongClass))

# The required access mask still has to be delivered.
$thinMask = @(New-RealAuditAce -AccessMask 32 -AuditFlags ([int] $firstRow.AuditFlagsValue) `
        -Inheritance Descendents -Class ([string] $firstRow.InheritedObjectAceType))
Assert-That 'an insufficient access mask still disqualifies' (-not (Test-mdiAuditAceSatisfied -Expected $firstRow -Applied $thinMask))

Assert-That 'an empty SACL still disqualifies' (-not (Test-mdiAuditAceSatisfied -Expected $firstRow -Applied @()))

Write-Host 'A row that covers its own object still rejects InheritOnly' -ForegroundColor Cyan
# The Exchange and AD FS rows carry no InheritedObjectAceType, so they DO ask for the object itself.
foreach ($name in 'ExchangeAuditing', 'ADFSAuditing') {
    $row = @($settings.$name | ConvertFrom-Csv)[0]
    Assert-That "$name is not class-restricted" ([string]::IsNullOrWhiteSpace([string] $row.InheritedObjectAceType))

    $selfAndDescendants = @(New-RealAuditAce -AccessMask ([int] $row.AccessMask) -AuditFlags ([int] $row.AuditFlagsValue) -Inheritance All)
    Assert-That "$name is satisfied when the object itself is audited" (Test-mdiAuditAceSatisfied -Expected $row -Applied $selfAndDescendants)

    $descendantsOnly = @(New-RealAuditAce -AccessMask ([int] $row.AccessMask) -AuditFlags ([int] $row.AuditFlagsValue) -Inheritance Descendents)
    Assert-That "  ...and $name carries InheritOnly when scoped to descendants" ((([int] $descendantsOnly[0].AceFlagsValue) -band $INHERIT_ONLY) -eq $INHERIT_ONLY)
    Assert-That "  ...and $name still fails when the object itself is skipped" (-not (Test-mdiAuditAceSatisfied -Expected $row -Applied $descendantsOnly)) 'a real coverage gap would read as configured'
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
