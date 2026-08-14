<#
    Merging two roles must not MANUFACTURE a v3.x blocker classification neither role ever made.

    Get-mdiV3ActionableBlocker draws a deliberate line between two answers that read back identically
    once you fetch the value ($null for both), and so must be told apart on the CONTAINER:

        ActionableBlockers ABSENT           -> never classified: fall back to Blockers, surface them
        ActionableBlockers PRESENT + EMPTY  -> classified: none of these are work worth doing, drop them

    Merge-mdiSensorV3ReadyDetails unioned the two STORED lists directly:

        @(@($First.ActionableBlockers) + @($Second.ActionableBlockers)) | Where-Object { $_ } ...

    Reading an absent property yields $null, so two blobs that BOTH omitted it produced an EMPTY array -
    and then wrote it into the merged object, where it is PRESENT. That flips "never classified" into
    "classified, nothing to do" and deletes every real blocker from BOTH surfaces of the remediation
    script at once: the v3.x section is skipped AND the advisory drops the findings. Measured on the
    shipped functions before the fix, two legacy roles each carrying one real blocker:

        legacy-single-role  resolved=1  blockers-in-script=True   v3-section=True
        legacy-two-roles    resolved=0  blockers-in-script=FALSE  v3-section=FALSE   <- both deleted
        current-two-roles   resolved=2  blockers-in-script=True   v3-section=True

    The single-role case is right only because the function returns $First untouched when there is no
    second role; it takes TWO roles to reach the union. And this branch runs ONLY when neither side
    carries any Checks - which is precisely the earlier-version and foreign-tool reports that are the
    ones missing the property in the first place, the exact population the fallback exists to protect.

    Each side is now RESOLVED through Get-mdiV3ActionableBlocker before the union - one computation per
    fact - so a side that never carried the classification still contributes its blockers.

    Asserted end-to-end through the REAL Merge-mdiServerByFqdn and New-mdiRemediationScript: what is
    being protected is that the operator can still SEE the finding in the generated script.

    The controls carry equal weight. An ARCHITECTURAL blob - a member server that is not eligible at
    all, which really does carry blockers with a deliberately empty actionable list - must STAY
    suppressed. A fix that surfaced those would put back the permanent nothing-you-can-do noise the
    empty list exists to remove, and would be just as wrong in the other direction.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mdi-mergelegacy-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
[void][IO.Directory]::CreateDirectory($scratch)

$blockerA = 'Defender for Endpoint onboarding: Not onboarded to Defender for Endpoint'
$blockerB = 'Operating system update: July 2026 cumulative update is missing'
$architecturalBlocker = 'Server role: a member server is not eligible for the v3.x sensor'

# A report written by an EARLIER VERSION of this script, or by another tool: it has Blockers and no
# ActionableBlockers property at all. No Checks either, which is what routes the merge down the
# union branch rather than recomputing from the checks.
function New-LegacyV3Detail {
    param([string] $Blocker)
    [PSCustomObject]@{
        SensorState       = 'v2.x sensor running'
        SensorV2Version   = '2.245.0'
        MigrationEligible = $false
        Blockers          = @($Blocker)
        UnknownChecks     = @()
        Checks            = @()
    }
}

# The current producer's shape: the classification is present and means what it says.
function New-ClassifiedV3Detail {
    param([string[]] $Blockers, [string[]] $Actionable)
    [PSCustomObject]@{
        SensorState        = 'v2.x sensor running'
        SensorV2Version    = '2.245.0'
        MigrationEligible  = $false
        Blockers           = @($Blockers)
        ActionableBlockers = @($Actionable)
        UnknownChecks      = @()
        Checks             = @()
    }
}

function New-RoleRow {
    param([string] $Role, [object] $Detail)
    $details = [ordered]@{}
    $details.Add('SensorV3ReadyDetails', $Detail)
    [PSCustomObject]@{
        FQDN           = 'dc1.contoso.com'
        Domain         = 'contoso.com'
        Role           = $Role
        Unreachable    = $false
        PartialFailure = $false
        IsPlaceholder  = $false
        SensorV3Ready  = $false
        Details        = $details
    }
}

function New-Report {
    param([object[]] $Dcs, [object[]] $Cas)
    [PSCustomObject]@{
        ScriptVersion        = 'test'
        Domain               = 'contoso.com'
        Forest               = 'contoso.com'
        DomainsInScope       = @('contoso.com')
        DomainControllers    = @($Dcs)
        CAServers            = @($Cas)
        EntraConnectServers  = @()
        DomainAuditing       = @()
        LdapPlanGapDomains   = @()
        NnrUnresolvedTargets = @()
        NnrTargetComputer    = @()
    }
}

function Get-MergedDetail {
    param([object] $Report)
    $all = @(@($Report.DomainControllers) + @($Report.CAServers) + @($Report.EntraConnectServers))
    $merged = @(Merge-mdiServerByFqdn -Server $all)
    Get-mdiDetailValue -Details $merged[0].Details -Name 'SensorV3ReadyDetails'
}

# The surface the operator actually experiences: the generated remediation script.
function Get-RemediationText {
    param([object] $Report, [string] $Name)
    $outputPath = Join-Path $scratch ($Name + '-remediation.ps1')
    $generated = New-mdiRemediationScript -ReportData $Report -FilePath $outputPath
    [IO.File]::ReadAllText($generated.Path)
}

'[the defect] two legacy roles must not silence each other'
$legacyReport = New-Report -Dcs @(New-RoleRow 'DomainController' (New-LegacyV3Detail $blockerA)) `
    -Cas @(New-RoleRow 'CertificationAuthority' (New-LegacyV3Detail $blockerB))
$legacyDetail = Get-MergedDetail $legacyReport
$legacyResolved = @(Get-mdiV3ActionableBlocker -Detail $legacyDetail)
Assert-That 'both legacy blockers survive the merge as actionable' ($legacyResolved.Count -eq 2) "(resolved=$($legacyResolved.Count))"
$legacyText = Get-RemediationText $legacyReport 'legacy-two-roles'
Assert-That "the first role's blocker reaches the remediation script" ($legacyText.Contains($blockerA))
Assert-That "the second role's blocker reaches the remediation script" ($legacyText.Contains($blockerB))
Assert-That 'the v3.x prerequisites section is emitted' ($legacyText.Contains('#region Sensor v3.x prerequisites'))

'[the mechanism] merging must not invent a classification neither role made'
# Pinned directly: this is the trap the fix removes, and it is invisible from the value alone because
# absent and present-but-empty both read back as $null.
$mergedHasProperty = $null -ne $legacyDetail.PSObject.Properties['ActionableBlockers']
$mergedStored = @($legacyDetail.ActionableBlockers | Where-Object { $_ })
Assert-That 'a merged blob never claims "classified, nothing actionable" while carrying real blockers' (
    (@($legacyDetail.Blockers | Where-Object { $_ }).Count -eq 0) -or (-not $mergedHasProperty) -or ($mergedStored.Count -gt 0)
) "(hasProperty=$mergedHasProperty stored=$($mergedStored.Count) blockers=$(@($legacyDetail.Blockers | Where-Object { $_ }).Count))"

'[single-role control] one legacy role was already correct and must stay correct'
$singleReport = New-Report -Dcs @(New-RoleRow 'DomainController' (New-LegacyV3Detail $blockerA)) -Cas @()
$singleResolved = @(Get-mdiV3ActionableBlocker -Detail (Get-MergedDetail $singleReport))
Assert-That 'a single legacy role still resolves its blocker' ($singleResolved.Count -eq 1) "(resolved=$($singleResolved.Count))"
Assert-That 'one role and two roles agree that the blocker is actionable' (
    ($singleResolved.Count -gt 0) -and ($legacyResolved.Count -gt 0)
) "(single=$($singleResolved.Count) two=$($legacyResolved.Count))"

'[architectural control] a deliberately EMPTY classification must stay suppressed'
# A member server is not eligible at all, so its blockers are not work anyone can do. Surfacing these
# would restore the permanent unfixable noise the empty list exists to remove.
$archReport = New-Report -Dcs @(New-RoleRow 'DomainController' (New-ClassifiedV3Detail @($architecturalBlocker) @())) `
    -Cas @(New-RoleRow 'CertificationAuthority' (New-ClassifiedV3Detail @($architecturalBlocker) @()))
$archResolved = @(Get-mdiV3ActionableBlocker -Detail (Get-MergedDetail $archReport))
Assert-That 'two architectural roles resolve to nothing actionable' ($archResolved.Count -eq 0) "(resolved=$($archResolved.Count))"
$archText = Get-RemediationText $archReport 'architectural-two-roles'
Assert-That 'no v3.x section is emitted for an architectural-only server' (-not $archText.Contains('#region Sensor v3.x prerequisites'))

'[current-shape control] two classified roles keep merging exactly as before'
$currentReport = New-Report -Dcs @(New-RoleRow 'DomainController' (New-ClassifiedV3Detail @($blockerA) @($blockerA))) `
    -Cas @(New-RoleRow 'CertificationAuthority' (New-ClassifiedV3Detail @($blockerB) @($blockerB)))
$currentResolved = @(Get-mdiV3ActionableBlocker -Detail (Get-MergedDetail $currentReport))
Assert-That 'both classified blockers survive' ($currentResolved.Count -eq 2) "(resolved=$($currentResolved.Count))"
$currentText = Get-RemediationText $currentReport 'current-two-roles'
Assert-That 'both classified blockers reach the remediation script' (
    $currentText.Contains($blockerA) -and $currentText.Contains($blockerB)
)

'[mixed control] an unclassified role must not be silenced by a classified one'
# Deleting a finding that was real costs the operator the finding; carrying an architectural one costs
# them a line to read. The unclassified side must win.
$mixedReport = New-Report -Dcs @(New-RoleRow 'DomainController' (New-LegacyV3Detail $blockerA)) `
    -Cas @(New-RoleRow 'CertificationAuthority' (New-ClassifiedV3Detail @($architecturalBlocker) @()))
$mixedResolved = @(Get-mdiV3ActionableBlocker -Detail (Get-MergedDetail $mixedReport))
Assert-That 'the unclassified blocker survives beside an empty classification' ($mixedResolved -contains $blockerA) "(resolved=$($mixedResolved -join '|'))"

'[order independence] the merge promises the same result whichever role is discovered first'
# The function documents this, and it is how the sibling defect in this same merge was found.
$reversedReport = New-Report -Dcs @(New-RoleRow 'DomainController' (New-LegacyV3Detail $blockerB)) `
    -Cas @(New-RoleRow 'CertificationAuthority' (New-LegacyV3Detail $blockerA))
$reversedResolved = @(Get-mdiV3ActionableBlocker -Detail (Get-MergedDetail $reversedReport))
Assert-That 'reversing the discovery order resolves the same blockers' (
    (@($reversedResolved | Sort-Object) -join '|') -eq (@($legacyResolved | Sort-Object) -join '|')
) "(forward=$($legacyResolved -join '|') reversed=$($reversedResolved -join '|'))"

'[no orphan advisory] a server with blockers must never generate a script that mentions none of them'
foreach ($case in @(
        @{ N = 'legacy'; T = $legacyText; B = @($blockerA, $blockerB) },
        @{ N = 'current'; T = $currentText; B = @($blockerA, $blockerB) }
    )) {
    $found = @($case.B | Where-Object { $case.T.Contains($_) }).Count
    Assert-That "the $($case.N) case surfaces every one of its blockers" ($found -eq $case.B.Count) "(found=$found of $($case.B.Count))"
}

Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
