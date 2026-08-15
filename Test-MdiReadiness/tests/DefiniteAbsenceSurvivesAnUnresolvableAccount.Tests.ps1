<#
    A MEASURED MISSING GRANT WAS RE-LABELLED "NOT A FINDING" BY AN UNRELATED SECOND ACCOUNT.

    Get-mdiDeletedObjectsPermission accepts MORE THAN ONE -DirectoryServiceAccount, and the three
    values it returns about one DACL have to agree with each other:

        isDeletedObjectsPermissionOk  the verdict
        Measured                      whether that verdict is a measurement
        details.Detail                the sentence the operator reads

    The verdict already applied the right precedence - "a DEFINITE failure still beats an unverified
    one", so an account that resolved to a SID, was compared against a DACL that had been read in
    full, and was genuinely not on it, produced $false no matter what the other accounts did.

    Measured and Detail did not follow it. Both were driven by $unresolvableAccount alone, so ONE
    account the machine could not resolve - an ordinary thing, the DSA living in a trusted forest
    this computer cannot reach - rewrote the answer for the other one:

        isDeletedObjectsPermissionOk : False
        Measured                     : False
        Detail                       : "...this check could not be completed - it is NOT a finding
                                        that the grant is missing."

    A verdict of False, described as not being a finding, and marked as never measured.

    The damage lands in the generated remediation script. New-mdiRemediationScript gates its dsacls
    block on `DeletedObjectsMeasured -ne $false`, so the real missing grant fell through to the
    "could not be verified" branch: a Write-Warning telling the operator to go and check by hand a
    permission the scan had already proved was absent, and NO dsacls line anywhere in the file. The
    finding was also marked covered as merely unverified, so it did not reappear under "needs manual
    attention" either. Silently dropped from both surfaces at once.

    These assertions drive the shipped producer with only the outermost directory boundary stubbed,
    then feed its real output into the shipped remediation generator, because the defect is precisely
    that the producer and its consumer disagreed about the same fact.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# --- the directory boundary, and nothing above it ----------------------------------------------
# Read access is held by NT AUTHORITY\SYSTEM only: a principal that resolves on any Windows machine,
# so Get-mdiPrincipalKind gets a real SID for it and then asks the fake directory for its class. The
# class comes back as a user, which makes the holder verifiably NonGroup - the condition under which
# an unmatched account is a MEASURED absence rather than a possible transitive grant.
$script:aclAce = @(
    [PSCustomObject]@{
        IdentityReference     = 'NT AUTHORITY\SYSTEM'
        AccessControlType     = 'Allow'
        ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
        PropagationFlags      = 'None'
        ObjectType            = [guid]::Empty
    })

$script:daclReads = 0
Set-Item -Path function:script:Get-ADRootDSE -Value {
    param([string] $Server, $ErrorAction)
    [PSCustomObject]@{ defaultNamingContext = 'DC=contoso,DC=com' }
}
Set-Item -Path function:script:Get-ADObject -Value {
    param($Identity, [string] $Server, [string] $Filter, [string[]] $Properties,
        [switch] $IncludeDeletedObjects, $ErrorAction)
    if ($Filter) {
        # Get-mdiPrincipalKind asking for the objectClass behind a trustee SID.
        return [PSCustomObject]@{ objectClass = @('top', 'person', 'organizationalPerson', 'user') }
    }
    $script:daclReads++
    [PSCustomObject]@{
        DistinguishedName    = [string] $Identity
        nTSecurityDescriptor = [PSCustomObject]@{ Access = $script:aclAce }
    }
}

# Resolvable and genuinely absent: a well-formed SID from a domain that does not exist here still
# passes Resolve-mdiPrincipalSid (it IS a SID), so the ACL is genuinely searched for it and it is
# genuinely not there. Unresolvable: a UPN in a forest this machine cannot reach.
$absentAccount = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$unresolvable = 'svc-mdi@fabrikam.invalid'

function Invoke-Permission {
    param([string[]] $Account)
    $before = $script:daclReads
    $r = Get-mdiDeletedObjectsPermission -Domain 'contoso.com' -DirectoryServiceAccount $Account 3>$null
    if ($script:daclReads -le $before) { throw 'the DACL reader stub was never called - the probe measured nothing' }
    $r
}

# The harness has to be reaching the real reader before any assertion below means anything.
$onAcl = Invoke-Permission -Account @('NT AUTHORITY\SYSTEM')
if ($onAcl.isDeletedObjectsPermissionOk -ne $true) {
    throw "the on-ACL control did not pass - the harness is not reaching the reader ($($onAcl.isDeletedObjectsPermissionOk))"
}
# And the two single-account cases have to behave as the fix assumes, or the mixed case proves nothing.
$absentOnly = Invoke-Permission -Account @($absentAccount)
if ($absentOnly.isDeletedObjectsPermissionOk -ne $false) {
    throw "the resolvable-absent control is not a definite failure ($($absentOnly.isDeletedObjectsPermissionOk))"
}
$unresolvableOnly = Invoke-Permission -Account @($unresolvable)
if ([string] $unresolvableOnly.isDeletedObjectsPermissionOk -ne 'N/A') {
    throw "the unresolvable control is not N/A ($($unresolvableOnly.isDeletedObjectsPermissionOk))"
}

Write-Host 'A definite absence stays a measured finding when another account cannot be resolved' -ForegroundColor Cyan
$mixed = Invoke-Permission -Account @($unresolvable, $absentAccount)

Assert-That 'the verdict is still a definite failure' (
    $mixed.isDeletedObjectsPermissionOk -eq $false) "ok=$($mixed.isDeletedObjectsPermissionOk)"
Assert-That 'and it is reported as MEASURED' (
    $mixed.Measured -eq $true) "measured=$($mixed.Measured)"
Assert-That 'the detail does not deny the finding it just made' (
    [string] $mixed.details.Detail -notmatch 'NOT a finding that the grant is missing') (
    "detail=$($mixed.details.Detail)")
Assert-That 'the detail states the missing grant' (
    [string] $mixed.details.Detail -match 'does not have read access') "detail=$($mixed.details.Detail)"
Assert-That 'and it still names the account it could NOT check' (
    [string] $mixed.details.Detail -match [regex]::Escape($unresolvable)) "detail=$($mixed.details.Detail)"

Write-Host ''
Write-Host 'The order the accounts are given in cannot change the answer' -ForegroundColor Cyan
$reversed = Invoke-Permission -Account @($absentAccount, $unresolvable)
Assert-That 'absent-first gives the same verdict' (
    $reversed.isDeletedObjectsPermissionOk -eq $false) "ok=$($reversed.isDeletedObjectsPermissionOk)"
Assert-That 'absent-first is measured too' ($reversed.Measured -eq $true) "measured=$($reversed.Measured)"

Write-Host ''
Write-Host 'CONTROLS - a run with nothing definite must still be honest about being unmeasured' -ForegroundColor Cyan
Assert-That 'CONTROL: unresolvable alone is still N/A' (
    [string] $unresolvableOnly.isDeletedObjectsPermissionOk -eq 'N/A') (
    "ok=$($unresolvableOnly.isDeletedObjectsPermissionOk)")
Assert-That 'CONTROL: unresolvable alone is still NOT measured' (
    $unresolvableOnly.Measured -eq $false) "measured=$($unresolvableOnly.Measured)"
Assert-That 'CONTROL: unresolvable alone still says it is not a finding' (
    [string] $unresolvableOnly.details.Detail -match 'NOT a finding that the grant is missing') (
    "detail=$($unresolvableOnly.details.Detail)")
Assert-That 'CONTROL: the resolvable absence alone is measured' (
    $absentOnly.Measured -eq $true) "measured=$($absentOnly.Measured)"
Assert-That 'CONTROL: an account that IS on the ACL still passes and is measured' (
    $onAcl.isDeletedObjectsPermissionOk -eq $true -and $onAcl.Measured -eq $true) (
    "ok=$($onAcl.isDeletedObjectsPermissionOk) measured=$($onAcl.Measured)")

Write-Host ''
Write-Host 'The generated remediation script must repair the grant it proved was missing' -ForegroundColor Cyan
# The consumer is driven with the producer's REAL output, because the defect was the two disagreeing.
function New-RemediationText {
    param($Permission)
    $reportData = [PSCustomObject]@{
        Domain               = 'contoso.com'
        Forest               = 'contoso.com'
        DomainsInScope       = @('contoso.com')
        DomainControllers    = @()
        CAServers            = @()
        EntraConnectServers  = @()
        DomainAuditing       = @(
            [PSCustomObject]@{
                Domain                   = 'contoso.com'
                ObjectAuditing           = [PSCustomObject]@{ isObjectAuditingOk = $true }
                ObjectAuditingMeasured   = $true
                ExchangeAuditing         = [PSCustomObject]@{ isExchangeAuditingOk = $true }
                ExchangeAuditingMeasured = $true
                AdfsAuditing             = [PSCustomObject]@{ isAdfsAuditingOk = $true }
                AdfsAuditingMeasured     = $true
                DeletedObjects           = $Permission
                DeletedObjectsMeasured   = [bool] $Permission.Measured
            })
    }
    $file = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remed-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    # Written for real and read back, rather than intercepting the writer: the generator resolves the
    # path it was given after writing, so a captured write leaves it resolving a file that never
    # existed. The temp file is removed in the finally block, so nothing is left behind either way.
    try {
        [void] (New-mdiRemediationScript -ReportData $reportData -FilePath $file 3>$null)
        if (-not (Test-Path $file)) { throw 'the remediation generator produced no file' }
        $written = [IO.File]::ReadAllText($file)
    } finally {
        if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
    }
    if ([string]::IsNullOrEmpty($written)) { throw 'the remediation generator produced nothing' }
    $written
}

$remediation = New-RemediationText -Permission $mixed
Assert-That 'the dsacls grant is emitted' (
    $remediation -match 'dsacls\.exe \$container /G') 'no dsacls /G in the generated script'
Assert-That 'it does not take the "could not be verified" branch instead' (
    $remediation -notmatch 'Deleted Objects container permissions \(could not be verified\)') (
    'the unverified region was emitted for a measured failure')
Assert-That 'the generated script does not tell the operator it is unverified' (
    $remediation -notmatch 'could not be read on contoso\.com, so it is unverified') (
    'the unverified warning was emitted for a measured failure')

# CONTROL: a genuinely unmeasured result must still take the unverified branch and must NEVER run
# dsacls /takeownership against a production system container on the strength of a guess.
$unverifiedRemediation = New-RemediationText -Permission $unresolvableOnly
Assert-That 'CONTROL: a genuinely unmeasured result emits no dsacls' (
    $unverifiedRemediation -notmatch 'dsacls\.exe') 'dsacls was emitted for an unmeasured result'
Assert-That 'CONTROL: a genuinely unmeasured result still warns it is unverified' (
    $unverifiedRemediation -match 'could not be verified') 'the unverified region was not emitted'

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
