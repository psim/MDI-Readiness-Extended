<#
    Every Active Directory GROUP was classified as a non-group, which recreated the destructive false
    red that Get-mdiPrincipalKind exists to prevent.

    objectClass is MULTI-VALUED in AD. A group returns @('top', 'group'); a user returns
    @('top', 'person', 'organizationalPerson', 'user'). The test was

        if ([string] $principal.objectClass -eq 'group')

    and casting a collection to [string] joins its elements with a space, so the comparison was
    'top group' -eq 'group' - false for every group that has ever existed. The single-valued shape
    that makes the cast look correct does not occur against a real directory.

    The consequence is not cosmetic. The Deleted Objects check reduces the container DACL to trustee
    strings and expands the ones that are GROUPS to see whether the Directory Service Account holds
    its grant through membership. With every group classified NonGroup, a DSA delegated through a
    domain group - the recommended shape, and the default state because the container carries an ACE
    for BUILTIN\Administrators - produced output byte-for-byte identical to a DSA with no grant at
    all: "The Directory Service Account does not have read access", a High finding, and a generated
    dsacls /takeownership + re-grant against a production system container to repair a delegation
    that was perfectly intact.

    These assertions are BEHAVIOURAL: they call the real Get-mdiPrincipalKind with its directory
    dependencies stubbed at SCRIPT scope (the only scope it calls) and assert the classification.
    Note that `function global:Get-ADObject` would NOT override the internal call.
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

# A domain SID, deliberately outside the BUILTIN S-1-5-32-* range that short-circuits to Group before
# the directory is ever consulted - otherwise this file would prove nothing about the lookup.
$script:stubSid = 'S-1-5-21-1111111111-2222222222-3333333333-1108'
Set-Item -Path function:script:Resolve-mdiPrincipalSid -Value { param($Name) $script:stubSid }

function Get-Kind {
    param([object] $ObjectClass)
    $script:stubObjectClass = $ObjectClass
    Set-Item -Path function:script:Get-ADObject -Value {
        param($Server, $Filter, $Properties, $ErrorAction)
        [PSCustomObject]@{ objectClass = $script:stubObjectClass }
    }
    Get-mdiPrincipalKind -Name 'CONTOSO\MDI-Readers' -Domain 'contoso.com'
}

Write-Host 'The shape Active Directory actually returns' -ForegroundColor Cyan
# These are the real objectClass values, not simplified ones.
Assert-That 'a group @(top, group) is a Group' ((Get-Kind @('top', 'group')) -eq 'Group') "got '$(Get-Kind @('top','group'))'"
Assert-That 'a universal/global group is a Group' ((Get-Kind @('top', 'group')) -eq 'Group')
Assert-That 'a user is a NonGroup' ((Get-Kind @('top', 'person', 'organizationalPerson', 'user')) -eq 'NonGroup') "got '$(Get-Kind @('top','person','organizationalPerson','user'))'"
Assert-That 'a computer is a NonGroup' ((Get-Kind @('top', 'person', 'organizationalPerson', 'user', 'computer')) -eq 'NonGroup')
Assert-That 'an MSA is a NonGroup' ((Get-Kind @('top', 'person', 'organizationalPerson', 'user', 'computer', 'msDS-GroupManagedServiceAccount')) -eq 'NonGroup')

Write-Host 'Class-name matching is case-insensitive, as LDAP is' -ForegroundColor Cyan
# AD returns the schema's casing, which is not guaranteed across schema extensions or trusts.
Assert-That "@(top, Group) is a Group" ((Get-Kind @('top', 'Group')) -eq 'Group') "got '$(Get-Kind @('top','Group'))'"
Assert-That "@(top, GROUP) is a Group" ((Get-Kind @('top', 'GROUP')) -eq 'Group') "got '$(Get-Kind @('top','GROUP'))'"

Write-Host 'Order within the collection does not matter' -ForegroundColor Cyan
# The structural class is conventionally last, but nothing in LDAP guarantees the ordering.
Assert-That "@(group, top) is a Group" ((Get-Kind @('group', 'top')) -eq 'Group') "got '$(Get-Kind @('group','top'))'"

Write-Host 'A single-valued response still works' -ForegroundColor Cyan
# Some directory shims flatten a one-element collection; that path must not regress.
Assert-That "'group' is a Group" ((Get-Kind 'group') -eq 'Group') "got '$(Get-Kind 'group')'"
Assert-That "'user' is a NonGroup" ((Get-Kind 'user') -eq 'NonGroup') "got '$(Get-Kind 'user')'"

Write-Host 'A class merely CONTAINING the word group is not a group' -ForegroundColor Cyan
# The fix must be a set membership test, not a substring match - msDS-GroupManagedServiceAccount is a
# user-like object and classifying it as a group would send the Deleted Objects check expanding it.
Assert-That 'msDS-GroupManagedServiceAccount alone is a NonGroup' ((Get-Kind @('top', 'msDS-GroupManagedServiceAccount')) -eq 'NonGroup') "got '$(Get-Kind @('top','msDS-GroupManagedServiceAccount'))'"
Assert-That 'groupPolicyContainer is a NonGroup' ((Get-Kind @('top', 'container', 'groupPolicyContainer')) -eq 'NonGroup') "got '$(Get-Kind @('top','container','groupPolicyContainer'))'"

Write-Host 'Unknown stays distinct from NonGroup' -ForegroundColor Cyan
# 'Unknown' is not 'NonGroup': treating an unresolvable trustee as a proven non-group is what
# recreates the destructive false red whenever directory access is imperfect.
Set-Item -Path function:script:Resolve-mdiPrincipalSid -Value { param($Name) $null }
Assert-That 'an unresolvable name is Unknown' ((Get-mdiPrincipalKind -Name 'CONTOSO\ghost' -Domain 'contoso.com') -eq 'Unknown')
Set-Item -Path function:script:Resolve-mdiPrincipalSid -Value { param($Name) $script:stubSid }
Assert-That 'an empty name is Unknown' ((Get-mdiPrincipalKind -Name '' -Domain 'contoso.com') -eq 'Unknown')
Assert-That 'no domain to query is Unknown' ((Get-mdiPrincipalKind -Name 'CONTOSO\MDI-Readers' -Domain '') -eq 'Unknown')

# A directory that refuses the query must not be reported as a proven non-group either.
Set-Item -Path function:script:Get-ADObject -Value {
    param($Server, $Filter, $Properties, $ErrorAction)
    throw [System.UnauthorizedAccessException]::new('Access is denied')
}
Assert-That 'a refused directory query is Unknown' ((Get-mdiPrincipalKind -Name 'CONTOSO\MDI-Readers' -Domain 'contoso.com') -eq 'Unknown')

# An object that simply is not there is Unknown, not NonGroup.
Set-Item -Path function:script:Get-ADObject -Value { param($Server, $Filter, $Properties, $ErrorAction) $null }
Assert-That 'a missing object is Unknown' ((Get-mdiPrincipalKind -Name 'CONTOSO\MDI-Readers' -Domain 'contoso.com') -eq 'Unknown')

Write-Host 'BUILTIN aliases are groups without consulting the directory' -ForegroundColor Cyan
# S-1-5-32-* are aliases, i.e. groups, and must classify even when the directory is unreachable -
# BUILTIN\Administrators is the default grant on the Deleted Objects container.
Set-Item -Path function:script:Resolve-mdiPrincipalSid -Value { param($Name) 'S-1-5-32-544' }
Set-Item -Path function:script:Get-ADObject -Value {
    param($Server, $Filter, $Properties, $ErrorAction)
    throw 'the directory must not be consulted for a BUILTIN alias'
}
Assert-That 'BUILTIN\Administrators is a Group' ((Get-mdiPrincipalKind -Name 'BUILTIN\Administrators' -Domain 'contoso.com') -eq 'Group')
Assert-That '  ...even with no domain to query' ((Get-mdiPrincipalKind -Name 'BUILTIN\Administrators' -Domain '') -eq 'Group')

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
