<#
    A NAME THAT IDENTIFIES NOBODY MATCHES NOBODY.

    Get-mdiMatchingTrustee decides whether an ACL trustee refers to the same principal as an
    operator-supplied directory service account. When neither side's SID resolves - the ORDINARY
    condition across a forest trust this computer cannot query, which is exactly what this fallback
    exists for - it compares the leaf of each name:

        $accountLeaf   = ($Account   -replace '^.*\\', '') -replace '@.*$', ''
        $candidateLeaf = ($candidate -replace '^.*\\', '') -replace '@.*$', ''
        if ([string]::Equals($candidateLeaf, $accountLeaf, [StringComparison]::OrdinalIgnoreCase)) {
            [PSCustomObject]@{ Trustee = $candidate; Confidence = 'Ambiguous' }
        }

    The guard above the comparison rejects a candidate that is $null, empty or whitespace. It does NOT
    reject a DOMAIN PREFIX WITH NO ACCOUNT. 'FABCORP\' is not whitespace, so it passes the guard, and
    its leaf is the EMPTY STRING. So is the leaf of 'MDILAB\', 'fabrikam.local\', '@fabrikam.local',
    '\' and '@'. Two empty leaves compare EQUAL, so a name that identifies nobody was returned as a
    candidate for a DIFFERENT name that also identifies nobody.

    Measured on the shipped matcher:

        -Account 'FABCORP\'        -Trustee @('MDILAB\')        ->  MDILAB\ [Ambiguous]
        -Account 'FABCORP\'        -Trustee @('CONTOSO\')       ->  CONTOSO\ [Ambiguous]
        -Account 'FABCORP\'        -Trustee @('fabrikam.local\')->  fabrikam.local\ [Ambiguous]
        -Account '@fabrikam.local' -Trustee @('@mdilab.local')  ->  @mdilab.local [Ambiguous]

    and driven through the real caller, Get-mdiDeletedObjectsPermission, with only the directory
    readers shadowed, the operator is told:

        status N/A
        "A trustee with the same account name was found but its identity could not be confirmed by
         SID, so this is not proof of a grant ... Unconfirmed: CONTOSO\ (requested FABCORP\).
         Verify on a domain controller with: dsacls ..."

    No account name was found on either side. The honest branch already exists and is reached the
    moment a leaf is non-blank - 'FABCORP\' against 'FABCORP\svc-mdi' correctly reports "The requested
    account could not be resolved to a SID on this computer" - so the defect is not the fallback, it is
    the missing blank test on the two leaves. The verdict is N/A either way, which is why this is a
    FALSE DIAGNOSIS rather than a false green: it sends the operator to dsacls to hunt a same-named
    trustee that does not exist, on a container whose DACL was read perfectly well.

    The function's own header says 'Ambiguous' appears "only where the tool genuinely cannot tell".
    Matching FABCORP\ to CONTOSO\ is not a case of not being able to tell.

    The disjoint namespace is what makes the shape ordinary rather than contrived: FABCORP is the
    NetBIOS name of fabrikam.local and is not its first DNS label, so a truncated, half-parsed or
    hand-edited entry on the cross-forest side is a domain prefix with the account lost.

    WHY THIS SURVIVED: the closest existing test,
    BlankDsaEntryCannotCostTheAccountBesideIt.Tests.ps1, SHADOWS Get-mdiMatchingTrustee, so the real
    leaf comparison has never been exercised through the caller. This test deliberately does NOT
    shadow it - only the directory readers and Get-mdiEffectiveDaclTrustee are replaced - so both the
    matcher and the sentence the operator reads are pinned.
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

Write-Host 'A name that identifies nobody matches nobody' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------
# THE MATCHER. Every spelling whose leaf is empty, on both sides. None of these resolve to a SID on a
# test host, which is precisely the cross-forest condition the leaf fallback is written for.
# ---------------------------------------------------------------------------------------------------
$emptyLeafNames = @('FABCORP\', 'MDILAB\', 'fabrikam.local\', '@fabrikam.local', '@mdilab.local', '\', '@',
    # WHITESPACE leaves, not merely empty ones. A blank test written as `-eq ''` instead of
    # IsNullOrWhiteSpace lets these through: 'FABCORP\ ' and 'MDILAB\ ' both reduce to ' ', neither is
    # the empty string, and ' ' equals ' ' - so the pair below is the one that catches that weakening.
    'FABCORP\ ', 'MDILAB\ ', 'fabrikam.local\   ', '@fabrikam.local ')
foreach ($account in $emptyLeafNames) {
    foreach ($trustee in $emptyLeafNames) {
        if ($trustee -eq $account) { continue }
        $matched = @(Get-mdiMatchingTrustee -Trustee @($trustee) -Account $account)
        Assert-That ("'{0}' is not matched to '{1}'" -f $account, $trustee) ($matched.Count -eq 0) `
        ("got {0}" -f (($matched | ForEach-Object { '{0}[{1}]' -f $_.Trustee, $_.Confidence }) -join ', '))
    }
}

# An empty-leaf account must not pick anything out of a populated ACL either.
$realAcl = @('FABCORP\svc-mdi', 'MDILAB\svc-mdi', 'svc-mdi@fabrikam.local', 'BUILTIN\Administrators')
foreach ($account in @('FABCORP\', 'fabrikam.local\', '@fabrikam.local', '\', '@')) {
    $matched = @(Get-mdiMatchingTrustee -Trustee $realAcl -Account $account)
    Assert-That ("'{0}' matches nothing on a populated ACL" -f $account) ($matched.Count -eq 0) `
    ("got {0}" -f (($matched | ForEach-Object { $_.Trustee }) -join ', '))
}

# And a real account must not be matched to an empty-leaf trustee sitting on the ACL.
foreach ($trustee in @('FABCORP\', 'MDILAB\', '@mdilab.local', '\')) {
    $matched = @(Get-mdiMatchingTrustee -Trustee @($trustee) -Account 'FABCORP\svc-mdi')
    Assert-That ("a real account is not matched to '{0}'" -f $trustee) ($matched.Count -eq 0) `
    ("got {0}" -f (($matched | ForEach-Object { $_.Trustee }) -join ', '))
}

# ---------------------------------------------------------------------------------------------------
# THE FALLBACK MUST SURVIVE. This is the behaviour the leaf comparison exists to provide, and a fix
# that simply stopped matching would be as wrong as the defect. One account, every legitimate
# cross-forest spelling.
# ---------------------------------------------------------------------------------------------------
$spellings = @('FABCORP\svc-mdi', 'fabrikam.local\svc-mdi', 'svc-mdi@fabrikam.local', 'MDILAB\svc-mdi', 'svc-mdi')
foreach ($asked in @('FABCORP\svc-mdi', 'svc-mdi@fabrikam.local', 'svc-mdi')) {
    $matched = @(Get-mdiMatchingTrustee -Trustee $spellings -Account $asked)
    Assert-That ("'{0}' still matches every spelling of itself" -f $asked) ($matched.Count -eq $spellings.Count) `
    ("got {0} of {1}" -f $matched.Count, $spellings.Count)
    $exact = @($matched | Where-Object { $_.Trustee -eq $asked })
    Assert-That ("'{0}' matches itself as Verified" -f $asked) `
    ($exact.Count -eq 1 -and $exact[0].Confidence -eq 'Verified') ("got {0}" -f ($exact.Confidence -join ','))
}

# A genuinely different account is still not matched.
$matched = @(Get-mdiMatchingTrustee -Trustee @('MDILAB\other', 'FABCORP\someone') -Account 'FABCORP\svc-mdi')
Assert-That 'a different account is still not matched' ($matched.Count -eq 0) `
("got {0}" -f (($matched | ForEach-Object { $_.Trustee }) -join ', '))

# The blanks the guard already rejected must stay rejected.
foreach ($trustee in @($null, '', '   ')) {
    $label = if ($null -eq $trustee) { '$null' } elseif ($trustee -eq '') { "''" } else { 'whitespace' }
    $matched = @(Get-mdiMatchingTrustee -Trustee @($trustee) -Account 'FABCORP\svc-mdi')
    Assert-That ("a {0} trustee is still rejected" -f $label) ($matched.Count -eq 0)
}

# ---------------------------------------------------------------------------------------------------
# THE SENTENCE THE OPERATOR READS. Driven through the REAL caller with the REAL matcher; only the
# directory readers and the DACL reducer are shadowed, so the leaf comparison is genuinely exercised.
# ---------------------------------------------------------------------------------------------------
$script:grantedTrustee = 'MDILAB\'
function Get-ADRootDSE { param($Server, $ErrorAction) [PSCustomObject]@{ defaultNamingContext = 'DC=fabrikam,DC=local' } }
function Get-ADObject {
    param($Identity, $Server, [switch] $IncludeDeletedObjects, $Properties, $Filter, $ErrorAction)
    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
}
function Get-mdiEffectiveDaclTrustee { param($Ace, $RequiredMask, [switch] $ResolveSid) @($script:grantedTrustee) }

function Invoke-Case {
    param([string] $Granted, [string] $Account)
    $script:grantedTrustee = $Granted
    $result = Get-mdiDeletedObjectsPermission -Domain 'fabrikam.local' -DirectoryServiceAccount @($Account)
    [PSCustomObject]@{
        Status = [string] $result.isDeletedObjectsPermissionOk
        Detail = [string] $result.details.Detail
    }
}

foreach ($case in @(
        @{ Granted = 'MDILAB\'; Account = 'FABCORP\' }
        @{ Granted = 'CONTOSO\'; Account = 'FABCORP\' }
        @{ Granted = 'fabrikam.local\'; Account = 'FABCORP\' }
        @{ Granted = '@mdilab.local'; Account = '@fabrikam.local' }
    )) {
    $r = Invoke-Case -Granted $case.Granted -Account $case.Account
    Assert-That ("'{0}' vs '{1}' claims no same-named trustee" -f $case.Account, $case.Granted) `
    ($r.Detail -notmatch 'trustee with the same account name was found') ("said: {0}" -f $r.Detail)
    Assert-That ("'{0}' vs '{1}' does not name it as Unconfirmed" -f $case.Account, $case.Granted) `
    ($r.Detail -notmatch [regex]::Escape($case.Granted + ' (requested')) ("said: {0}" -f $r.Detail)
    # It is still not a finding that the grant is missing - the account genuinely could not be resolved.
    Assert-That ("'{0}' vs '{1}' stays unmeasured, not a failure" -f $case.Account, $case.Granted) `
    ($r.Status -eq 'N/A') ("status {0}" -f $r.Status)
}

# The honest branch, which already existed, must be the one that is reached.
$honest = Invoke-Case -Granted 'FABCORP\svc-mdi' -Account 'FABCORP\'
Assert-That 'an unresolvable account is reported as unresolvable' `
($honest.Detail -match 'could not be resolved to a SID') ("said: {0}" -f $honest.Detail)

# A REAL same-named trustee must still produce the ambiguity warning - the message is correct there.
$realAmbiguous = Invoke-Case -Granted 'MDILAB\svc-mdi' -Account 'FABCORP\svc-mdi'
Assert-That 'a genuinely same-named trustee is still reported as unconfirmed' `
($realAmbiguous.Detail -match 'trustee with the same account name was found') ("said: {0}" -f $realAmbiguous.Detail)

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $(if ($script:fail) { 1 } else { 0 })
