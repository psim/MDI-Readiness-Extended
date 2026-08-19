<#
    IDENTICAL TEXT THAT NAMES NOBODY IS NOT A VERIFIED GRANT.

    Get-mdiMatchingTrustee decides whether an ACL trustee refers to the same principal as an
    operator-supplied directory service account, and its answer is the whole of the Deleted Objects
    permission check. The caller, Get-mdiDeletedObjectsPermission, reads it like this:

        if (@($matched | Where-Object { $_.Confidence -eq 'Verified' }).Count -gt 0) { continue }

    ONE 'Verified' row satisfies the account outright: no failure, no ambiguity, the check PASSES.

    The first branch of the matcher's loop was:

        $candidate = [string] $item
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        # Identical text is the same principal whatever the resolver says.
        if ($candidate -eq $Account) {
            [PSCustomObject]@{ Trustee = $candidate; Confidence = 'Verified' }
            continue
        }

    "Identical text is the same principal" is true for a NAME. It is not true for a string that is not
    a name. The rule that a leaf naming nobody matches nobody was already stated in this function and
    already enforced - but only further down, guarding the leaf-comparison fallback, which returns the
    WEAKER 'Ambiguous'. The identical-text branch above it reached no guard at all, so the fix caught
    the claim the caller reports as unmeasured and missed the claim the caller reports as a PASS.

    Two strings that name nobody are never DIFFERENT text when they come from one source read twice -
    the operator's -DirectoryServiceAccount and the DACL trustee both carrying the same truncated
    spelling. Measured on the shipped matcher, account and trustee identical:

        -Account 'FABCORP\'         -Trustee @('FABCORP\')          ->  FABCORP\ [Verified]
        -Account 'MDILAB\'          -Trustee @('MDILAB\')           ->  MDILAB\ [Verified]
        -Account 'fabrikam.local\'  -Trustee @('fabrikam.local\')   ->  fabrikam.local\ [Verified]
        -Account '@fabrikam.local'  -Trustee @('@fabrikam.local')   ->  @fabrikam.local [Verified]
        -Account '\'                -Trustee @('\')                 ->  \ [Verified]
        -Account '@'                -Trustee @('@')                 ->  @ [Verified]

    Six of six nobody-naming shapes verified, and through the caller's rule each one reads
    "SATISFIED - the check PASSES". The operator is told the Directory Service Account is correctly
    delegated on the Deleted Objects container when NO ACCOUNT WAS NAMED ON EITHER SIDE and nothing
    was ever compared. That is a FALSE GREEN, and a worse one than the 'Ambiguous' case that was
    fixed: the customer believes MDI can enumerate deleted objects when it may not be able to at all.

    The disjoint namespace is what makes the shape ordinary rather than contrived, in the function's
    own words: FABCORP is the NetBIOS name of fabrikam.local and is NOT its first DNS label, so a
    truncated or half-parsed entry on the cross-forest side is a domain prefix with the account lost.
    The caller's own comment records where the operator's side comes from - "An operator builds this
    list by hand, from a config file or a CSV, so a trailing comma, an empty line read with
    Get-Content or an empty cell all produce the breaking shape" - and one malformed source read into
    both the ACL request and the ACL itself produces the two sides IDENTICALLY.

    WHY THIS SURVIVED: the sibling test that pins the same rule,
    NameThatIdentifiesNobodyMatchesNobody.Tests.ps1, iterates every pair of empty-leaf spellings and
    then explicitly skips the one pair this defect lives in:

        foreach ($account in $emptyLeafNames) {
            foreach ($trustee in $emptyLeafNames) {
                if ($trustee -eq $account) { continue }      <-- the identical pair, never tested

    So the whole nobody-names-nobody family was covered EXCEPT the identical case, which is the only
    one that reaches the Verified branch.

    THE FIX: the leaf is reduced and the nobody test applied ABOVE every branch, so the rule holds for
    identical text, for the SID comparison and for the leaf fallback alike.

    WHAT MUST NOT REGRESS, pinned below alongside: identical text naming a REAL principal must still
    verify, an unequal real name must still not match, and a real name in a different domain must
    still come back Ambiguous rather than Verified.
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

Write-Host 'Identical text that names nobody is not a verified grant' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------
# THE DEFECT. The account and the trustee carry the SAME spelling, and that spelling names nobody.
# None of these resolve to a SID on any host, which is the cross-forest condition the fallback exists
# for - so the identical-text branch is the only branch that can answer, and it must answer "no".
# Whitespace leaves are included as well as empty ones: a blank test written as `-eq ''` rather than
# IsNullOrWhiteSpace lets 'FABCORP\ ' through, and 'FABCORP\ ' -eq 'FABCORP\ ' is still identical.
# ---------------------------------------------------------------------------------------------------
$namesNobody = @(
    'FABCORP\', 'MDILAB\', 'fabrikam.local\', 'mdilab.local\',
    '@fabrikam.local', '@mdilab.local', '\', '@',
    'FABCORP\ ', 'MDILAB\   ', '@fabrikam.local ', 'fabrikam.local\ '
)
foreach ($n in $namesNobody) {
    $matched = @(Get-mdiMatchingTrustee -Trustee @($n) -Account $n)
    Assert-That ("identical '{0}' on both sides matches nothing" -f $n) ($matched.Count -eq 0) `
    ("got {0}" -f (($matched | ForEach-Object { '{0}[{1}]' -f $_.Trustee, $_.Confidence }) -join ', '))
}

# The claim the caller acts on, stated directly: no Verified row may exist for any of them.
foreach ($n in $namesNobody) {
    $matched = @(Get-mdiMatchingTrustee -Trustee @($n) -Account $n)
    $verified = @($matched | Where-Object { $_.Confidence -eq 'Verified' })
    Assert-That ("identical '{0}' produces no Verified row" -f $n) ($verified.Count -eq 0) `
    ("got {0}" -f (($verified | ForEach-Object { $_.Trustee }) -join ', '))
}

# The same spelling sitting on a populated ACL alongside real trustees must still find nothing: the
# real entries cannot rescue it and the identical entry must not satisfy it.
$aclWithBoth = @('FABCORP\svc-mdi', 'MDILAB\svc-mdi', 'BUILTIN\Administrators', 'FABCORP\', '@fabrikam.local', '\')
foreach ($n in @('FABCORP\', '@fabrikam.local', '\')) {
    $matched = @(Get-mdiMatchingTrustee -Trustee $aclWithBoth -Account $n)
    Assert-That ("'{0}' finds nothing on an ACL that also contains it verbatim" -f $n) ($matched.Count -eq 0) `
    ("got {0}" -f (($matched | ForEach-Object { '{0}[{1}]' -f $_.Trustee, $_.Confidence }) -join ', '))
}

# And a nobody-naming trustee on the ACL must not satisfy a REAL requested account.
foreach ($n in @('FABCORP\', 'MDILAB\', '@fabrikam.local', '\', '@')) {
    $matched = @(Get-mdiMatchingTrustee -Trustee @($n) -Account 'FABCORP\svc-mdi')
    Assert-That ("a real account is not satisfied by '{0}' on the ACL" -f $n) ($matched.Count -eq 0) `
    ("got {0}" -f (($matched | ForEach-Object { $_.Trustee }) -join ', '))
}

# ---------------------------------------------------------------------------------------------------
# THE BRANCH MUST SURVIVE. Identical text naming a REAL principal is still the same principal, and the
# rest of the matcher must be untouched. A fix that refuses these has broken the function instead of
# repairing it - which is the direction a blanket guard would fail in.
# ---------------------------------------------------------------------------------------------------
foreach ($n in @('FABCORP\svc-mdi', 'MDILAB\svc-mdi', 'svc-mdi@fabrikam.local', 'svc-mdi',
        'BUILTIN\Administrators', 'S-1-5-21-1111111111-2222222222-3333333333-1234')) {
    $matched = @(Get-mdiMatchingTrustee -Trustee @($n) -Account $n)
    $verified = @($matched | Where-Object { $_.Confidence -eq 'Verified' })
    Assert-That ("identical real name '{0}' still verifies" -f $n) ($verified.Count -eq 1) `
    ("got {0}" -f (($matched | ForEach-Object { '{0}[{1}]' -f $_.Trustee, $_.Confidence }) -join ', '))
}

# A different real account must still not be matched - the substring defect this function was written
# to remove must not come back through the reordering.
$matched = @(Get-mdiMatchingTrustee -Trustee @('FABCORP\svc-mdi-old') -Account 'FABCORP\svc-mdi')
Assert-That 'svc-mdi is not satisfied by svc-mdi-old' ($matched.Count -eq 0) `
("got {0}" -f (($matched | ForEach-Object { $_.Trustee }) -join ', '))

# The honest middle answer must still be reachable: the same leaf in a different domain, neither side
# resolvable, is Ambiguous - not Verified and not absent.
$matched = @(Get-mdiMatchingTrustee -Trustee @('MDILAB\svc-mdi') -Account 'FABCORP\svc-mdi')
$ambiguous = @($matched | Where-Object { $_.Confidence -eq 'Ambiguous' })
Assert-That 'a same-leaf cross-domain trustee is still Ambiguous' ($ambiguous.Count -eq 1) `
("got {0}" -f (($matched | ForEach-Object { '{0}[{1}]' -f $_.Trustee, $_.Confidence }) -join ', '))

# A real account must still pick its own entry out of a populated cross-forest ACL.
$matched = @(Get-mdiMatchingTrustee -Trustee $aclWithBoth -Account 'FABCORP\svc-mdi')
$verified = @($matched | Where-Object { $_.Confidence -eq 'Verified' })
Assert-That 'a real account still verifies against a populated cross-forest ACL' ($verified.Count -eq 1) `
("got {0}" -f (($matched | ForEach-Object { '{0}[{1}]' -f $_.Trustee, $_.Confidence }) -join ', '))

# A blank or absent trustee list must still be handled without matching anything.
foreach ($list in @(@(), @(''), @($null), @('   '))) {
    $matched = @(Get-mdiMatchingTrustee -Trustee $list -Account 'FABCORP\svc-mdi')
    Assert-That ("an empty trustee list matches nothing ({0} element(s))" -f @($list).Count) ($matched.Count -eq 0) `
    ("got {0}" -f (($matched | ForEach-Object { $_.Trustee }) -join ', '))
}

Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
