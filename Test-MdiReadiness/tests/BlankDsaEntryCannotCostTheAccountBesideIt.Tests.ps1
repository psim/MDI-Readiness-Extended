# A BLANK ENTRY IN -DirectoryServiceAccount MUST NOT DESTROY THE ACCOUNT BESIDE IT.
#
# Get-mdiDeletedObjectsPermission declares
#
#     [Parameter(Mandatory = $false)] [string[]] $DirectoryServiceAccount = $null
#
# and gated the whole assertion on `if (-not $DirectoryServiceAccount)`. `-not` on a [string[]] is
# not the question "did the operator name an account": for a MULTI-element array PowerShell tests the
# ARRAY, which is true whatever its elements are. So a list containing a blank sailed through the
# guard, and the loop then passed that blank to
#
#     Get-mdiMatchingTrustee -Trustee $granted -Account $dsa
#
# whose -Account is [Parameter(Mandatory = $true)] [string]. A mandatory string parameter REJECTS THE
# EMPTY STRING AT BIND TIME. That is a terminating error, not a skipped element, and it is raised
# inside the loop - so it does not cost the blank, it costs the REAL account standing beside it. The
# outer try catches it and the check is reported as
#
#     "Unable to read the Deleted Objects container: Cannot bind argument to parameter 'Account'..."
#
# which blames the directory and sends the operator to check READ_CONTROL and run dsacls against a
# container whose DACL had in fact just been read in full.
#
# MEASURED on the shipped function against a live domain, using BUILTIN\Administrators because it
# genuinely IS on that container's DACL:
#
#     @('BUILTIN\Administrators')          status=True  'has read access to the Deleted Objects container'
#     @('BUILTIN\Administrators', '')      status=N/A   'Unable to read the Deleted Objects container: Cannot bind argument...'
#     @('', 'BUILTIN\Administrators')      status=N/A   same
#     @($null, 'BUILTIN\Administrators')   status=N/A   same
#
# A verified pass replaced by an unmeasured verdict with a misattributed cause, from one blank list
# element. @('') ALONE is safe - a single-element array is truthy according to its element - which is
# exactly why this survived: the one blank shape anybody would think to try is the one that worked.
# An operator builds this list by hand, from a config file or a CSV, so a trailing comma, an empty
# line read with Get-Content or an empty cell all produce the breaking shape.
#
# This is the fifth list parameter in the script to ask a raw truthiness question of a [string[]];
# the others are the three role scanners and Resolve-mdiNnrTarget, and Test-mdiNoNameSupplied was
# written for exactly this.
#
# The test drives the REAL function with the directory readers shadowed, and the shadow of
# Get-mdiMatchingTrustee keeps the REAL mandatory [string] signature so the bind-time rejection is
# reproduced faithfully rather than simulated.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$script:grantedTrustee = 'BUILTIN\Administrators'

# Directory readers shadowed so the function reaches its status branch with a readable DACL. The
# DirectorySearcher path fails on a machine with no directory and falls through to this one.
function Get-ADRootDSE { param($Server, $ErrorAction) [PSCustomObject]@{ defaultNamingContext = 'DC=fabrikam,DC=local' } }
function Get-ADObject {
    # -IncludeDeletedObjects is a SWITCH on the real cmdlet. Declaring it as a value parameter made
    # the shipped call fail to bind, the fallback threw, $granted stayed empty and every case landed
    # on the "descriptor was not returned" path - which looked exactly like the product refusing to
    # read the DACL. The first run of this test reported six failures for that reason alone.
    param(
        $Identity, $Server, [switch] $IncludeDeletedObjects, $Properties, $Filter, $ErrorAction
    )
    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
}
function Get-mdiEffectiveDaclTrustee { param($Ace, $RequiredMask, [switch] $ResolveSid) @($script:grantedTrustee) }

# The accounts the loop actually reaches. The signature is the SHIPPED one on purpose: a mandatory
# [string] rejects '' at bind time, so a blank that reaches here throws exactly as it does in
# production instead of being quietly recorded.
$script:seenAccounts = New-Object System.Collections.ArrayList
function Get-mdiMatchingTrustee {
    param (
        [Parameter(Mandatory = $false)] [AllowNull()] [string[]] $Trustee,
        [Parameter(Mandatory = $true)] [string] $Account
    )
    [void] $script:seenAccounts.Add($Account)
    if ($Account -eq $script:grantedTrustee) { [PSCustomObject]@{ Trustee = $Account; Confidence = 'Verified' } }
}

function Invoke-Case {
    param($Accounts)
    $script:seenAccounts.Clear()
    $threw = $null
    $result = $null
    try { $result = Get-mdiDeletedObjectsPermission -Domain 'fabrikam.local' -DirectoryServiceAccount $Accounts }
    catch { $threw = $_.Exception.Message }
    [PSCustomObject]@{
        Status = $(if ($null -eq $result) { '<threw>' } else { [string] $result.isDeletedObjectsPermissionOk })
        Detail = $(if ($null -eq $result) { [string] $threw } else { [string] $result.details.Detail })
        Seen   = @($script:seenAccounts.ToArray())
        Threw  = $threw
    }
}

'[baseline] the granted account on its own must pass'
$base = Invoke-Case -Accounts @($script:grantedTrustee)
Assert-That 'a granted account is reported as having read access' ($base.Status -eq 'True') "(got '$($base.Status)' - $($base.Detail))"
Assert-That '  ...and the loop saw exactly that one account' (@($base.Seen).Count -eq 1 -and $base.Seen[0] -eq $script:grantedTrustee)

'[the defect] a blank beside the granted account must not destroy the pass'
foreach ($shape in @(
        @{ Label = "granted + ''"; A = @($script:grantedTrustee, '') }
        @{ Label = "'' + granted"; A = @('', $script:grantedTrustee) }
        @{ Label = 'granted + $null'; A = @($script:grantedTrustee, $null) }
        @{ Label = 'granted + whitespace'; A = @($script:grantedTrustee, '   ') }
    )) {
    $r = Invoke-Case -Accounts $shape.A
    Assert-That ("{0,-24} still reports the grant" -f $shape.Label) ($r.Status -eq 'True') "(got '$($r.Status)' - $($r.Detail))"
    Assert-That ("{0,-24}   ...and no blank ever reached Get-mdiMatchingTrustee" -f $shape.Label) (
        @($r.Seen | Where-Object { [string]::IsNullOrWhiteSpace([string] $_) }).Count -eq 0
    ) "(saw: $(@($r.Seen | ForEach-Object { "'$_'" }) -join ', '))"
    Assert-That ("{0,-24}   ...and nothing was blamed on the container" -f $shape.Label) (
        [string] $r.Detail -notmatch 'Unable to read the Deleted Objects container'
    ) "($($r.Detail))"
}

'[no account named] a list of nothing but blanks asserts nothing'
foreach ($shape in @(
        @{ Label = "@('')"; A = @('') }
        @{ Label = "@('','')"; A = @('', '') }
        @{ Label = 'all null'; A = @($null, $null) }
        @{ Label = 'all whitespace'; A = @('  ', ' ') }
    )) {
    $r = Invoke-Case -Accounts $shape.A
    Assert-That ("{0,-16} is not asserted against" -f $shape.Label) ($r.Status -eq 'N/A') "(got '$($r.Status)')"
    Assert-That ("{0,-16}   ...and the matcher was never called" -f $shape.Label) (@($r.Seen).Count -eq 0) "(saw $(@($r.Seen).Count))"
}

'[why blanks must never be passed] the shipped matcher signature rejects them'
# Not a simulation: this is the real function from the loaded product script.
. ([scriptblock]::Create(($text -split "(?m)^function Get-mdiMatchingTrustee \{" )[0])) 2>$null | Out-Null
$realMatcherThrew = $false
try {
    $realDef = [regex]::Match($text, '(?ms)^function Get-mdiMatchingTrustee \{.*?\n\}').Value
    $probe = [scriptblock]::Create($realDef + "`nGet-mdiMatchingTrustee -Trustee @('X') -Account ''")
    & $probe | Out-Null
} catch { $realMatcherThrew = $true }
Assert-That 'Get-mdiMatchingTrustee -Account '''' is a terminating bind error' $realMatcherThrew

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
