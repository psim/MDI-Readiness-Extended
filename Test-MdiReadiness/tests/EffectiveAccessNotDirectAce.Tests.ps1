<#
    An unmatched Directory Service Account is not the same fact as a missing grant.

    Get-mdiDeletedObjectsPermission reduces the Deleted Objects container DACL to a set of qualifying
    trustee strings and matches the requested DSA against them by SID or name. It does not expand
    group membership - and it never said so. A DSA that holds the grant THROUGH a group produced
    output byte-for-byte identical to a DSA with no grant at all:

        status=False measured=True
        "The Directory Service Account does not have read access. Grant it with: dsacls ..."
        High finding, verdict NOT READY, and a generated remediation running
        dsacls.exe $container /takeownership followed by a re-grant

    That is the recommended delegation shape, and it is also the DEFAULT: CN=Deleted Objects carries
    an ACE for BUILTIN\Administrators on every domain, so any DSA in Administrators or Domain Admins
    already reads the container. The tool measured "is the DSA a direct trustee" and reported it as
    "the DSA does not have read access" - a claim about EFFECTIVE access it never computed - then
    offered to take ownership of a production system container to repair a delegation that was intact.

    The fix classifies the HOLDERS rather than only the requested account, and follows the function's
    own precedent for an ambiguous identity match: a holder that is a group, or one whose type cannot
    be established, makes the answer unmeasured ('N/A' + Measured = $false), not a failure.

    Invariants pinned here, all behavioural - the real producer, the real domain-check state, the real
    verdict, the real issue list and the real remediation generator:

      1. no qualifying holder at all is STILL a hard measured failure, with remediation  (guard kept)
      2. a holder verifiably not a group is STILL a hard measured failure, with remediation (guard kept)
      3. a direct verified grant is STILL a pass, with no remediation                     (guard kept)
      4. a GROUP holder is unmeasured, NOT READY, and emits NO dsacls
      5. a holder of UNKNOWN type is unmeasured too - failure to classify is not proof of a user
      6. the detail text tells the operator NOT to re-grant
      7. a definite failure still beats an unverified one when several accounts are asked about
      8. the remediation generator refuses a False that is flagged unmeasured
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$dn = 'CN=Deleted Objects,DC=contoso,DC=com'

# Only the two directory reads are stubbed. Set-Item function:script: - a `function global:` does not
# override a function the script defined for itself and the stub would never be called.
Set-Item -Path function:script:Get-ADRootDSE -Value {
    param($Server, $ErrorAction)
    [PSCustomObject]@{ defaultNamingContext = 'DC=contoso,DC=com' }
}

$script:aceSet = @()
$script:principalClass = @{}
$script:classifyThrows = $false
Set-Item -Path function:script:Get-ADObject -Value {
    param($Identity, $Server, $Filter, $Properties, $ErrorAction, [switch] $IncludeDeletedObjects)
    # The holder classifier asks by objectSid filter; the container read asks by Identity.
    if ($Filter) {
        # The directory is unreachable, the trust cannot be queried, or rights are denied. This is
        # the MOST COMMON real reason a classification fails, and it is a different code path from a
        # lookup that simply returns nothing.
        if ($script:classifyThrows) { throw 'The server is not operational' }
        $sid = ([string] $Filter -replace "^.*objectSid -eq '", '') -replace "'.*$", ''
        if ($script:principalClass.ContainsKey($sid)) {
            return [PSCustomObject]@{ objectClass = $script:principalClass[$sid] }
        }
        return $null
    }
    [PSCustomObject]@{
        DistinguishedName    = $dn
        nTSecurityDescriptor = [PSCustomObject]@{ Access = $script:aceSet }
    }
}

# The ACE shape nTSecurityDescriptor.Access yields, and exactly what the real reducer consumes.
function New-Ace {
    param([string] $Identity, [string] $Rights = 'GenericRead', [string] $Type = 'Allow')
    [PSCustomObject]@{
        IdentityReference     = $Identity
        ActiveDirectoryRights = $Rights
        AccessControlType     = $Type
        PropagationFlags      = 'None'
        ObjectType            = [guid]::Empty
    }
}

function Invoke-Check {
    param([string[]] $Trustee, [string[]] $Dsa, [hashtable] $Class = @{}, [switch] $ClassifyThrows)
    $script:aceSet = @(foreach ($t in $Trustee) { New-Ace -Identity $t })
    $script:principalClass = $Class
    $script:classifyThrows = [bool] $ClassifyThrows
    try { Get-mdiDeletedObjectsPermission -Domain 'contoso.com' -DirectoryServiceAccount $Dsa 3>$null 4>$null }
    finally { $script:classifyThrows = $false }
}

function Get-Remediation {
    param($Result)
    $report = [PSCustomObject]@{
        DomainControllers = @()
        DomainAuditing    = @([PSCustomObject]@{
                Domain = 'contoso.com'
                DeletedObjects = $Result
                DeletedObjectsMeasured = $Result.Measured
            })
    }
    $out = Join-Path ([IO.Path]::GetTempPath()) ('mdi-w39-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    try {
        New-mdiRemediationScript -ReportData $report -FilePath $out 3>$null 4>$null 6>$null | Out-Null
        if (Test-Path -LiteralPath $out) { [IO.File]::ReadAllText($out) } else { '' }
    } finally {
        if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host 'Effective access is not the same as a direct ACE' -ForegroundColor Cyan

# --- GUARDS THAT MUST NOT WEAKEN -------------------------------------------------------------------

# 1. Nobody holds the right at all. This is the genuine "not configured" case and is handled before
#    any holder classification happens. It must stay a hard, measured, remediable failure.
$none = Invoke-Check -Trustee @() -Dsa @('NT AUTHORITY\Authenticated Users')
Assert-That 'no qualifying holder is still a measured failure' (
    [string] $none.isDeletedObjectsPermissionOk -eq 'False' -and $none.Measured -eq $true
) ("status=$([string] $none.isDeletedObjectsPermissionOk) measured=$($none.Measured)")
Assert-That 'no qualifying holder still generates the dsacls remediation' (
    (Get-Remediation $none) -match 'takeownership'
) 'expected dsacls /takeownership'

# 2. A holder that is verifiably NOT a group. The ACL was genuinely searched and the DSA genuinely
#    absent, so this remains a real measurement.
$sysSid = (New-Object System.Security.Principal.NTAccount('NT AUTHORITY\SYSTEM')).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value
$nonGroup = Invoke-Check -Trustee @('NT AUTHORITY\SYSTEM') -Dsa @('NT AUTHORITY\Authenticated Users') `
    -Class @{ $sysSid = 'user' }
Assert-That 'a verifiably non-group holder is still a measured failure' (
    [string] $nonGroup.isDeletedObjectsPermissionOk -eq 'False' -and $nonGroup.Measured -eq $true
) ("status=$([string] $nonGroup.isDeletedObjectsPermissionOk) measured=$($nonGroup.Measured)")
Assert-That 'a verifiably non-group holder still generates remediation' (
    (Get-Remediation $nonGroup) -match 'takeownership'
) 'expected dsacls /takeownership'

# 3. A direct, verified grant is still a pass and still generates nothing.
$direct = Invoke-Check -Trustee @('NT AUTHORITY\Authenticated Users') -Dsa @('NT AUTHORITY\Authenticated Users')
Assert-That 'a direct verified grant is still a pass' (
    $direct.isDeletedObjectsPermissionOk -eq $true -and $direct.Measured -eq $true
) ("status=$([string] $direct.isDeletedObjectsPermissionOk)")
Assert-That 'a direct verified grant generates no remediation' (
    (Get-Remediation $direct) -notmatch 'takeownership'
) 'unexpected dsacls'

# --- THE DEFECT ------------------------------------------------------------------------------------

# 4. The grant is held by a BUILTIN group the DSA belongs to. Every principal in the BUILTIN SID
#    namespace is an alias, so this is decided without any directory lookup at all.
$viaGroup = Invoke-Check -Trustee @('BUILTIN\Users') -Dsa @('NT AUTHORITY\Authenticated Users')
Assert-That 'a group-held grant is NOT reported as a measured failure' (
    [string] $viaGroup.isDeletedObjectsPermissionOk -ne 'False'
) ("status=$([string] $viaGroup.isDeletedObjectsPermissionOk)")
Assert-That 'a group-held grant is unmeasured' (
    [string] $viaGroup.isDeletedObjectsPermissionOk -eq 'N/A' -and $viaGroup.Measured -eq $false
) ("status=$([string] $viaGroup.isDeletedObjectsPermissionOk) measured=$($viaGroup.Measured)")
Assert-That 'a group-held grant names the holder' (
    [string] $viaGroup.details.Detail -like '*BUILTIN\Users*'
) ("detail=$([string] $viaGroup.details.Detail)")
Assert-That 'a group-held grant tells the operator NOT to re-grant' (
    [string] $viaGroup.details.Detail -match 'not|NOT' -and
    [string] $viaGroup.details.Detail -notlike '*does not have read access*'
) ("detail=$([string] $viaGroup.details.Detail)")
Assert-That 'a group-held grant generates NO destructive remediation' (
    (Get-Remediation $viaGroup) -notmatch 'takeownership'
) 'dsacls /takeownership was generated over an unverified result'

# The default shape on every domain: the container is held by BUILTIN\Administrators.
$viaAdmins = Invoke-Check -Trustee @('BUILTIN\Administrators') -Dsa @('NT AUTHORITY\Authenticated Users')
Assert-That 'the default BUILTIN\Administrators holder is unmeasured, not a failure' (
    [string] $viaAdmins.isDeletedObjectsPermissionOk -eq 'N/A' -and $viaAdmins.Measured -eq $false
) ("status=$([string] $viaAdmins.isDeletedObjectsPermissionOk) measured=$($viaAdmins.Measured)")

# 5. A domain group, classified by the directory lookup rather than by SID prefix.
$grpSid = 'S-1-5-21-111-222-333-4444'
$viaDomainGroup = Invoke-Check -Trustee @($grpSid) -Dsa @('NT AUTHORITY\Authenticated Users') `
    -Class @{ $grpSid = 'group' }
Assert-That 'a domain group holder is unmeasured' (
    [string] $viaDomainGroup.isDeletedObjectsPermissionOk -eq 'N/A' -and $viaDomainGroup.Measured -eq $false
) ("status=$([string] $viaDomainGroup.isDeletedObjectsPermissionOk) measured=$($viaDomainGroup.Measured)")

# 6. A holder whose type CANNOT be established - an orphaned SID, a foreign principal, a trust this
#    host cannot query. "Not proven to be a group" is not "proven to be a user", and treating it as
#    one puts the destructive remediation back whenever directory access is imperfect.
$unknownSid = 'S-1-5-21-111-222-333-5555'
$viaUnknown = Invoke-Check -Trustee @($unknownSid) -Dsa @('NT AUTHORITY\Authenticated Users') -Class @{}
Assert-That 'an unclassifiable holder is unmeasured, not a failure' (
    [string] $viaUnknown.isDeletedObjectsPermissionOk -eq 'N/A' -and $viaUnknown.Measured -eq $false
) ("status=$([string] $viaUnknown.isDeletedObjectsPermissionOk) measured=$($viaUnknown.Measured)")
Assert-That 'an unclassifiable holder generates no destructive remediation' (
    (Get-Remediation $viaUnknown) -notmatch 'takeownership'
) 'dsacls /takeownership was generated over an unclassified holder'

# 6b. The classification lookup THROWS - the directory is unreachable, the trust cannot be queried,
#     or the read is denied. This is a different code path from a lookup that returns nothing, and it
#     is the most common real reason classification fails, so it gets its own case: returning
#     'NonGroup' from the catch would put the destructive false red back on every imperfect network.
$throwSid = 'S-1-5-21-111-222-333-6666'
$viaThrow = Invoke-Check -Trustee @($throwSid) -Dsa @('NT AUTHORITY\Authenticated Users') -ClassifyThrows
Assert-That 'a holder whose lookup THROWS is unmeasured, not a failure' (
    [string] $viaThrow.isDeletedObjectsPermissionOk -eq 'N/A' -and $viaThrow.Measured -eq $false
) ("status=$([string] $viaThrow.isDeletedObjectsPermissionOk) measured=$($viaThrow.Measured)")
Assert-That 'a holder whose lookup THROWS generates no destructive remediation' (
    (Get-Remediation $viaThrow) -notmatch 'takeownership'
) 'dsacls /takeownership was generated after a failed classification'

# --- 7. Precedence: a definite failure still beats an unverified one -------------------------------
# Two accounts asked about at once: one genuinely absent against a verifiably non-group holder, one
# that cannot be resolved at all. The definite failure must win, or an unresolvable second account
# silently masks the first account's real gap.
$mixed = Invoke-Check -Trustee @('NT AUTHORITY\SYSTEM') `
    -Dsa @('NT AUTHORITY\Authenticated Users', 'NO_SUCH_DOMAIN\w39-not-a-principal') `
    -Class @{ $sysSid = 'user' }
Assert-That 'a definite failure still wins over an unresolvable account' (
    [string] $mixed.isDeletedObjectsPermissionOk -eq 'False'
) ("status=$([string] $mixed.isDeletedObjectsPermissionOk)")

# --- 8. The unmeasured result travels correctly through every consumer -----------------------------
$report = [PSCustomObject]@{
    DomainControllers = @([PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
            NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true; Details = [ordered]@{}
        })
    CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com')
    ForestDiscovery = [PSCustomObject]@{ Complete = $true }
    DomainAuditing = @([PSCustomObject]@{
            Domain = 'contoso.com'
            ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
            ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
            AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
            DeletedObjects = $viaGroup
            DeletedObjectsMeasured = $viaGroup.Measured
        })
}
$state = @(Get-mdiDomainCheckState -ReportData $report | Where-Object { $_.Name -like 'Deleted*' })
Assert-That 'the score treats a group-held grant as unread, not as a pass or a fail' (
    $state.Count -eq 1 -and $null -eq $state[0].Value
) ("state=$([string] $state[0].Value)")
$verdict = Test-mdiReadinessResult -ReportData $report 3>$null
Assert-That 'the run is still NOT READY on an unverified grant' (-not $verdict) "verdict=$verdict"
$stats = Get-mdiReportStatistics -ReportData $report
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report | Where-Object { [string] $_.Issue -like '*Deleted Objects*' })
Assert-That 'the finding says unverified rather than misconfigured' (
    $issues.Count -eq 1 -and [string] $issues[0].Issue -notlike '*is not configured*'
) ("issue=$(if ($issues.Count) { [string] $issues[0].Issue })")

# --- 9. The generator refuses a self-contradictory imported report ----------------------------------
# False while also recording that nothing was measured. The current producer cannot emit that, but an
# imported or hand-edited report can, and this branch runs dsacls /takeownership in production.
$contradictory = [PSCustomObject]@{
    isDeletedObjectsPermissionOk = $false
    Measured = $false
    details = [PSCustomObject]@{ Container = $dn; Detail = 'imported'; Trustees = @() }
}
Assert-That 'a False flagged unmeasured generates no destructive remediation' (
    (Get-Remediation $contradictory) -notmatch 'takeownership'
) 'dsacls /takeownership was generated over an explicitly unmeasured result'

# A legacy report predating the Measured flag keeps its remediation.
$legacy = [PSCustomObject]@{
    DomainControllers = @()
    DomainAuditing = @([PSCustomObject]@{
            Domain = 'contoso.com'
            DeletedObjects = [PSCustomObject]@{
                isDeletedObjectsPermissionOk = $false
                details = [PSCustomObject]@{ Container = $dn; Detail = 'legacy'; Trustees = @() }
            }
        })
}
$legacyOut = Join-Path ([IO.Path]::GetTempPath()) ('mdi-w39-legacy-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
New-mdiRemediationScript -ReportData $legacy -FilePath $legacyOut 3>$null 4>$null 6>$null | Out-Null
$legacyText = if (Test-Path -LiteralPath $legacyOut) { [IO.File]::ReadAllText($legacyOut) } else { '' }
Remove-Item -LiteralPath $legacyOut -Force -ErrorAction SilentlyContinue
Assert-That 'a legacy report with no Measured flag still gets its remediation' (
    $legacyText -match 'takeownership'
) 'legacy remediation was lost'

# --- 10. The classifier itself ----------------------------------------------------------------------
Assert-That 'BUILTIN aliases are groups without any directory lookup' (
    (Get-mdiPrincipalKind -Name 'BUILTIN\Administrators' -Domain 'contoso.com') -eq 'Group' -and
    (Get-mdiPrincipalKind -Name 'BUILTIN\Users' -Domain 'contoso.com') -eq 'Group'
)
Assert-That 'an unresolvable principal is Unknown, never NonGroup' (
    (Get-mdiPrincipalKind -Name 'NO_SUCH_DOMAIN\w39-not-a-principal' -Domain 'contoso.com') -eq 'Unknown'
)
Assert-That 'an empty trustee is Unknown' ((Get-mdiPrincipalKind -Name ([string] $null) -Domain 'contoso.com') -eq 'Unknown')
$script:principalClass = @{ $sysSid = 'user' }
Assert-That 'a directory-classified user is NonGroup' (
    (Get-mdiPrincipalKind -Name 'NT AUTHORITY\SYSTEM' -Domain 'contoso.com') -eq 'NonGroup'
)
$script:principalClass = @{}
$script:classifyThrows = $true
Assert-That 'a lookup that THROWS is Unknown, not NonGroup' (
    (Get-mdiPrincipalKind -Name 'NT AUTHORITY\SYSTEM' -Domain 'contoso.com') -eq 'Unknown'
)
$script:classifyThrows = $false
Assert-That 'a lookup that returns nothing is Unknown, not NonGroup' (
    (Get-mdiPrincipalKind -Name 'NT AUTHORITY\SYSTEM' -Domain 'contoso.com') -eq 'Unknown'
)

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
