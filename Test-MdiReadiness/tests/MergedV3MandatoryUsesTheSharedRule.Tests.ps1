<#
    Behavioural regression test: the two-role v3.x merge decides "is this check mandatory?" with
    THE shared definition, so an All-class failure cannot vanish and an unreadable Requirement
    cannot become a blocker.

    Test-mdiRequirementIsMandatory is the single definition of which Requirement classes block the
    verdict. Its own header records that this test had been written inline as `-eq 'Required'` and
    that the inline spelling is wrong in TWO opposite directions at once:

        - 'All' ranks 3 on the requirement scale - "every one must pass, and a measured failure
          blocks the verdict" - and an inline `-eq 'Required'` silently DROPS it.
        - PowerShell's -eq coerces its RIGHT operand to the LEFT operand's type, so when Requirement
          arrives as the BOOLEAN $true - which ConvertFrom-Json produces from "Requirement":true -
          `$true -eq 'Required'` evaluates 'Required' AS A BOOLEAN, finds a non-empty string, and
          returns TRUE. A value nobody could read is promoted to a blocking requirement.

    Merge-mdiSensorV3ReadyDetails, which merges the two role passes over one host, was left on the
    inline literal on BOTH of its verdict filters - Blockers and UnknownChecks. Merge-mdiSensorV3Check
    carries Requirement through UNNORMALISED (it keeps the RAW value of whichever side ranks higher),
    so whatever the checks arrived carrying is exactly what those filters saw. Measured on the
    shipped functions, one v3.x check per row, the same check from both roles:

        Requirement    IsMandatory   became a blocker   became an unknown
        'Required'     True          True               True     ok
        'All'          True          FALSE              FALSE    dropped from BOTH surfaces
        $true          False         TRUE               TRUE     promoted to blocking
        'Optional'     False         False              False    ok

    So a measured FAILURE of an All-class check was not a blocker, and an UNREAD one was not even
    counted as an unknown - it left the merge with no trace on either disclosure surface, which is
    the "losing part of the estate must never improve the headline" rule this file is built on.
    In the other direction a Requirement nobody could read was charged as a blocking failure.

    Both shapes are ordinary rather than contrived on this path: the merge runs whenever one host is
    discovered under two roles (a domain controller that is also a CA or an AD FS server), and this
    branch's own sibling exists for "the earlier-version and foreign reports" - blobs that made a
    JSON round trip, which is precisely what turns "Requirement":true into the boolean $true.

    Pinned here: every Requirement shape classifies the same way in the merge as
    Test-mdiRequirementIsMandatory classifies it, for BOTH the Blockers filter and the UnknownChecks
    filter; 'All' and 'Required' are treated alike; a boolean, a number, $null, an empty string and
    a whitespace-padded 'Required' are none of them mandatory; and the merge stays commutative.
#>

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:failed++; Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red }
}

$checkName = 'LDAPS 636 to dcfab01.fabrikam.local'

function New-Check {
    param($Requirement, $Status, [string] $Detail)
    [pscustomobject]@{
        Name        = $checkName
        Requirement = $Requirement
        Status      = $Status
        Detail      = $Detail
        Remediable  = $true
        Measured    = $true
    }
}

function New-Blob {
    param($Check)
    [pscustomobject]@{
        SensorState        = 'NotInstalled'
        SensorV2Version    = ''
        MigrationEligible  = $true
        Blockers           = @()
        ActionableBlockers = @()
        UnknownChecks      = @()
        Checks             = @($Check)
    }
}

function Merge-TwoRoles {
    param($Check)
    Merge-mdiSensorV3ReadyDetails -First (New-Blob $Check) -Second (New-Blob $Check) -FirstRank 1 -SecondRank 1
}

function Get-BlockerFlag {
    # A MEASURED failure of this check: did the merge publish it as a blocker?
    param($Requirement)
    $merged = Merge-TwoRoles (New-Check $Requirement $false 'Connection refused')
    [bool] (@($merged.Blockers).Count -gt 0)
}

function Get-UnknownFlag {
    # An UNREAD check: did the merge publish it as an unknown?
    param($Requirement)
    $merged = Merge-TwoRoles (New-Check $Requirement 'N/A' 'Not tested - the port could not be probed')
    [bool] (@($merged.UnknownChecks).Count -gt 0)
}

function Format-Value {
    param($Value)
    ("'{0}' [{1}]" -f $Value, $(if ($null -eq $Value) { 'null' } else { $Value.GetType().Name }))
}

# Every Requirement shape the merge can actually be handed, mandatory ones first.
$shapes = @(
    @{ Label = "'Required'"; Value = 'Required' }
    @{ Label = "'All'"; Value = 'All' }
    @{ Label = "'AtLeastOne'"; Value = 'AtLeastOne' }
    @{ Label = "'Recommended'"; Value = 'Recommended' }
    @{ Label = "'Optional'"; Value = 'Optional' }
    @{ Label = '$true'; Value = $true }
    @{ Label = '$false'; Value = $false }
    @{ Label = '$null'; Value = $null }
    @{ Label = "''"; Value = '' }
    @{ Label = "' Required ' (padded)"; Value = ' Required ' }
    @{ Label = '636 (int)'; Value = 636 }
    @{ Label = "'nonsense'"; Value = 'nonsense' }
)

# --- The merge agrees with the one definition, on both disclosure surfaces ----------------------
# This is the whole defect: the merge answered "is this mandatory?" with its own inline copy of a
# rule that already exists in exactly one place, and the copy had drifted in both directions.
foreach ($shape in $shapes) {
    $expected = [bool] (Test-mdiRequirementIsMandatory -Requirement $shape.Value)

    $isBlocker = Get-BlockerFlag $shape.Value
    Assert-True ("Requirement={0}: a measured failure blocks the verdict exactly when the shared definition says it is mandatory ({1})" -f $shape.Label, $expected) `
        ($isBlocker -eq $expected) ("IsMandatory={0} but Blockers present={1}" -f $expected, $isBlocker)

    $isUnknown = Get-UnknownFlag $shape.Value
    Assert-True ("Requirement={0}: an unread check is counted as an unknown exactly when the shared definition says it is mandatory ({1})" -f $shape.Label, $expected) `
        ($isUnknown -eq $expected) ("IsMandatory={0} but UnknownChecks present={1}" -f $expected, $isUnknown)
}

# --- 'All' is mandatory, and losing it must never improve the headline --------------------------
# The direction the inline literal DROPPED. An All-class check that was measured failing has to
# reach Blockers, and one that was never read has to reach UnknownChecks.
$allFailure = Merge-TwoRoles (New-Check 'All' $false 'Connection refused')
Assert-True "an All-class check measured FAILING is published as a blocker" `
    (@($allFailure.Blockers).Count -gt 0) `
    ("Blockers={0}" -f (@($allFailure.Blockers) -join '; '))
Assert-True "and the blocker message names the check that failed" `
    (@($allFailure.Blockers | Where-Object { [string] $_ -like ('*{0}*' -f $checkName) }).Count -gt 0) `
    ("Blockers={0}" -f (@($allFailure.Blockers) -join '; '))

$allUnread = Merge-TwoRoles (New-Check 'All' 'N/A' 'Not tested - the port could not be probed')
Assert-True "an All-class check that was never read is published as an unknown" `
    (@($allUnread.UnknownChecks).Count -gt 0) `
    ("UnknownChecks={0}" -f (@($allUnread.UnknownChecks) -join '; '))
Assert-True "and it is NOT also reported as a measured blocker" `
    (@($allUnread.Blockers).Count -eq 0) `
    ("Blockers={0}" -f (@($allUnread.Blockers) -join '; '))

# 'All' and 'Required' rank alike, so they must classify alike on both surfaces.
Assert-True "'All' and 'Required' produce the same blocker verdict" `
    ((Get-BlockerFlag 'All') -eq (Get-BlockerFlag 'Required')) `
    ("All={0} Required={1}" -f (Get-BlockerFlag 'All'), (Get-BlockerFlag 'Required'))
Assert-True "'All' and 'Required' produce the same unknown verdict" `
    ((Get-UnknownFlag 'All') -eq (Get-UnknownFlag 'Required')) `
    ("All={0} Required={1}" -f (Get-UnknownFlag 'All'), (Get-UnknownFlag 'Required'))

# --- A value nobody could read is not a requirement --------------------------------------------
# The direction the inline literal PROMOTED: `$true -eq 'Required'` is TRUE in PowerShell, so a
# Requirement that survived a JSON round trip as a boolean was charged as a blocking failure.
Assert-True 'the raw coercion this pins is real - $true -eq ''Required'' is TRUE in PowerShell' `
    ($true -eq 'Required')
Assert-True 'and the inline spelling really did drop All - ''All'' -eq ''Required'' is FALSE' `
    (-not ('All' -eq 'Required'))

foreach ($unreadable in @($true, $false, $null, '', ' Required ', 636, 'nonsense')) {
    $label = Format-Value $unreadable
    Assert-True ("an unreadable Requirement {0} is not promoted to a blocker" -f $label) `
        (-not (Get-BlockerFlag $unreadable)) $label
    Assert-True ("an unreadable Requirement {0} is not counted as a required unknown" -f $label) `
        (-not (Get-UnknownFlag $unreadable)) $label
}

# --- The merge still carries the raw value, so the fix is in the TEST not in a normalisation -----
# Pinned deliberately: if a later change starts normalising Requirement inside Merge-mdiSensorV3Check
# instead, this assertion documents that the filters above were fixed on their own terms.
$rawCarried = Merge-mdiSensorV3Check -First (New-Check $true $false 'd') -Second (New-Check $true $false 'd')
Assert-True 'Merge-mdiSensorV3Check carries an unreadable Requirement through unchanged' `
    ($rawCarried.Requirement -is [bool]) (Format-Value $rawCarried.Requirement)

# --- Mixed roles: the stronger requirement wins and is classified by the shared rule ------------
# One role read the probe as 'All', the other could not read the field at all. The stronger value
# has to win the merge AND be treated as mandatory.
$mixed = Merge-mdiSensorV3ReadyDetails `
    -First (New-Blob (New-Check 'All' $false 'Connection refused')) `
    -Second (New-Blob (New-Check $true $false 'Connection refused')) -FirstRank 1 -SecondRank 1
Assert-True 'a role reporting All and a role reporting an unreadable value merge to a blocker' `
    (@($mixed.Blockers).Count -gt 0) ("Blockers={0}" -f (@($mixed.Blockers) -join '; '))

$mixedReverse = Merge-mdiSensorV3ReadyDetails `
    -First (New-Blob (New-Check $true $false 'Connection refused')) `
    -Second (New-Blob (New-Check 'All' $false 'Connection refused')) -FirstRank 1 -SecondRank 1
Assert-True 'and the merge is commutative - the same two roles in the other order agree' `
    ((@($mixed.Blockers).Count) -eq (@($mixedReverse.Blockers).Count)) `
    ("forward={0} reverse={1}" -f @($mixed.Blockers).Count, @($mixedReverse.Blockers).Count)

# --- An Optional check is still advisory, so the fix did not simply widen the net ---------------
$optionalFailure = Merge-TwoRoles (New-Check 'Optional' $false 'Connection refused')
Assert-True 'an Optional check measured failing is still not a blocker' `
    (@($optionalFailure.Blockers).Count -eq 0) `
    ("Blockers={0}" -f (@($optionalFailure.Blockers) -join '; '))

$recommendedUnread = Merge-TwoRoles (New-Check 'Recommended' 'N/A' 'Not tested - the port could not be probed')
Assert-True 'a Recommended check that was never read is still not a required unknown' `
    (@($recommendedUnread.UnknownChecks).Count -eq 0) `
    ("UnknownChecks={0}" -f (@($recommendedUnread.UnknownChecks) -join '; '))

# --- A Required check still behaves exactly as it always did -----------------------------------
$requiredFailure = Merge-TwoRoles (New-Check 'Required' $false 'Connection refused')
Assert-True 'a Required check measured failing is still a blocker' `
    (@($requiredFailure.Blockers).Count -gt 0) `
    ("Blockers={0}" -f (@($requiredFailure.Blockers) -join '; '))

$requiredPass = Merge-TwoRoles (New-Check 'Required' $true 'Connected')
Assert-True 'a Required check that PASSED is neither a blocker nor an unknown' `
    ((@($requiredPass.Blockers).Count -eq 0) -and (@($requiredPass.UnknownChecks).Count -eq 0)) `
    ("Blockers={0} UnknownChecks={1}" -f (@($requiredPass.Blockers) -join '; '), (@($requiredPass.UnknownChecks) -join '; '))

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
