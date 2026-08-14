# [w86] A v3.x blocker measured under EITHER role of a multi-role host must survive the FQDN merge.
#
# A small estate routinely runs the certification authority ON a domain controller. Each discovery pass
# scans that host independently and Merge-mdiServerByFqdn folds the rows into one.
#
# SensorV3ReadyDetails was merged by SWAPPING THE WHOLE BLOB, ranked only on the single top-level
# $srv.SensorV3Ready value the blob is named after. The nested Checks / Blockers / ActionableBlockers /
# UnknownChecks arrays were never consulted, and on an EQUAL rank the tie-break compared the STRINGIFIED
# blob - in which every one of those arrays renders as the literal text "System.Object[]".
#
# Two passes that each measured a DIFFERENT v3.x blocker both report SensorV3Ready = $false, so they
# tie on rank, and their stringified blobs are character-for-character identical. CompareOrdinal
# returned 0, "stored wins", and the second pass's measured blocker was DELETED - from the report, from
# the issue list, and from the generated remediation script. Reversing the discovery order deleted the
# other one instead, contradicting the merge's own documented promise that "the result is identical
# whichever order the roles are merged in".
#
# RequiredPortsDetails already had the correct treatment next door (Merge-mdiRequiredPortsDetails).
#
# BEHAVIOURAL, not textual: every assertion below runs the REAL Merge-mdiServerByFqdn and reads the
# merged object, and the actionable list is read through the REAL Get-mdiV3ActionableBlocker - the
# function the remediation script actually calls. Nothing here greps the source.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
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

# The producer's exact check shape, including its derived Measured rule (the $addCheck scriptblock).
function New-V3Check {
    param([string] $Name, [object] $Status, [string] $Detail, [string] $Requirement = 'Required', [bool] $Remediable = $true)
    [PSCustomObject]@{
        Name = $Name; Requirement = $Requirement; Status = $Status; Detail = $Detail
        Remediable = $Remediable; Measured = -not ($Detail -like 'Not tested*')
    }
}

# The producer's exact details object, with the derived lists computed by the producer's own rules.
function New-V3Detail {
    param([string] $SensorState = 'v2.x sensor running', [string] $V2Version = '2.245.0', [object[]] $Checks, [bool] $Eligible = $false)
    $blockers = @($Checks | Where-Object { $_.Requirement -eq 'Required' -and $_.Status -eq $false })
    $unknowns = @($Checks | Where-Object { $_.Requirement -eq 'Required' -and $_.Measured -ne $true })
    $architectural = @($blockers | Where-Object { -not $_.Remediable })
    [PSCustomObject]@{
        SensorState        = $SensorState
        SensorV2Version    = $V2Version
        MigrationEligible  = $Eligible
        Blockers           = @(foreach ($b in $blockers) { [string] $b.Name + ': ' + [string] $b.Detail })
        ActionableBlockers = @(if ($architectural.Count -eq 0) { foreach ($b in $blockers) { [string] $b.Name + ': ' + [string] $b.Detail } })
        UnknownChecks      = @(foreach ($u in $unknowns) { [string] $u.Name })
        Checks             = $Checks
    }
}

function New-V3Server {
    param([string] $Role, $V3Ready, $Detail, [string] $Fqdn = 'dc1.contoso.com')
    $d = [ordered]@{}
    $d.Add('SensorV3ReadyDetails', $Detail)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; Role = $Role
        Unreachable = $false; PartialFailure = $false
        SensorV3Ready = $V3Ready
        Details = [PSCustomObject]$d
    }
}

function Get-MergedV3 {
    param([object[]] $Server)
    $merged = @(Merge-mdiServerByFqdn -Server $Server)
    $v3 = $merged[0].Details.SensorV3ReadyDetails
    [PSCustomObject]@{
        Rows       = $merged.Count
        Blockers   = @($v3.Blockers)
        Actionable = @(Get-mdiV3ActionableBlocker -Detail $v3)
        Checks     = @($v3.Checks)
        Unknown    = @($v3.UnknownChecks)
        Detail     = $v3
    }
}

$mdeName = 'Defender for Endpoint onboarding'
$svcName = 'Sensor service state'
$osName = 'Operating system version'
$mdeText = $mdeName + ': Not onboarded to Defender for Endpoint'
$svcText = $svcName + ': The sensor service is stopped'

function New-DcPass {
    New-V3Server -Role 'DomainController' -V3Ready $false -Detail (New-V3Detail -Checks @(
            (New-V3Check -Name $mdeName -Status $false -Detail 'Not onboarded to Defender for Endpoint')
            (New-V3Check -Name $osName -Status $true -Detail 'Windows Server 2022')
        ))
}
function New-CaPass {
    New-V3Server -Role 'CertificationAuthority' -V3Ready $false -Detail (New-V3Detail -Checks @(
            (New-V3Check -Name $svcName -Status $false -Detail 'The sensor service is stopped')
            (New-V3Check -Name $osName -Status $true -Detail 'Windows Server 2022')
        ))
}

'[w86] CONTROL: a single-role host is untouched by the merge'
# Without this, a merge that simply discarded everything would satisfy the assertions below.
$solo = Get-MergedV3 -Server @((New-DcPass))
Assert-That 'one role produces one row' ($solo.Rows -eq 1) "(got $($solo.Rows))"
Assert-That 'its blocker is intact' (@($solo.Blockers) -contains $mdeText) "(got: $(@($solo.Blockers) -join ' | '))"
Assert-That 'its checks are intact' (@($solo.Checks).Count -eq 2) "(got $(@($solo.Checks).Count))"
Assert-That 'its actionable blocker is intact' (@($solo.Actionable).Count -eq 1) "(got $(@($solo.Actionable).Count))"

''
'[w86] a blocker measured under EITHER role survives, in EITHER discovery order'
$forward = Get-MergedV3 -Server @((New-DcPass), (New-CaPass))
$reverse = Get-MergedV3 -Server @((New-CaPass), (New-DcPass))

Assert-That 'the two roles still merge to ONE row' (($forward.Rows -eq 1) -and ($reverse.Rows -eq 1)) "(fwd $($forward.Rows), rev $($reverse.Rows))"
Assert-That 'the DC-pass blocker survives, DC discovered first' (@($forward.Blockers) -contains $mdeText) "(got: $(@($forward.Blockers) -join ' | '))"
Assert-That 'the CA-pass blocker survives, DC discovered first' (@($forward.Blockers) -contains $svcText) "(got: $(@($forward.Blockers) -join ' | '))"
Assert-That 'the DC-pass blocker survives, CA discovered first' (@($reverse.Blockers) -contains $mdeText) "(got: $(@($reverse.Blockers) -join ' | '))"
Assert-That 'the CA-pass blocker survives, CA discovered first' (@($reverse.Blockers) -contains $svcText) "(got: $(@($reverse.Blockers) -join ' | '))"

# The remediation script reads this list, not Blockers. A blocker that survives into Blockers but not
# into ActionableBlockers is still missing from the generated script.
Assert-That 'the remediation advisory raises BOTH blockers' (@($forward.Actionable).Count -eq 2) "(got $(@($forward.Actionable).Count): $(@($forward.Actionable) -join ' | '))"
Assert-That 'the remediation advisory is order-independent' (((@($forward.Actionable) | Sort-Object) -join '|') -eq ((@($reverse.Actionable) | Sort-Object) -join '|')) `
    "(fwd [$(@($forward.Actionable) -join ' | ')] rev [$(@($reverse.Actionable) -join ' | ')])"

''
'[w86] the merge is COMMUTATIVE - the documented invariant of Merge-mdiServerByFqdn'
Assert-That 'Blockers are identical whichever role is merged first' `
    (((@($forward.Blockers) | Sort-Object) -join '|') -eq ((@($reverse.Blockers) | Sort-Object) -join '|')) `
    "(fwd [$(@($forward.Blockers) -join ' | ')] rev [$(@($reverse.Blockers) -join ' | ')])"
$fwdChecks = (@($forward.Checks | ForEach-Object { '{0}={1}' -f $_.Name, $_.Status }) -join '|')
$revChecks = (@($reverse.Checks | ForEach-Object { '{0}={1}' -f $_.Name, $_.Status }) -join '|')
Assert-That 'the merged Checks are identical, in the same order' ($fwdChecks -eq $revChecks) "(fwd [$fwdChecks] rev [$revChecks])"

''
'[w86] both failing checks are present in the merged Checks array'
# The v3 comparison table renders from Checks, so a blocker that survives in Blockers while its check
# vanished from Checks puts the table and the findings on the same page in contradiction.
$failed = @($forward.Checks | Where-Object { $_.Status -eq $false } | ForEach-Object { [string] $_.Name })
Assert-That 'the DC-pass failing check is in Checks' (@($failed) -contains $mdeName) "(failed: $(@($failed) -join ','))"
Assert-That 'the CA-pass failing check is in Checks' (@($failed) -contains $svcName) "(failed: $(@($failed) -join ','))"
Assert-That 'the shared passing check is not duplicated' (@($forward.Checks | Where-Object { $_.Name -eq $osName }).Count -eq 1) `
    "(got $(@($forward.Checks | Where-Object { $_.Name -eq $osName }).Count))"

''
'[w86] a check one role could not read is not claimed as measured by the other'
# Same tri-state contract as Merge-mdiCheckValue: both roles look at the SAME machine, so one of them
# failing to read a setting means that setting is not reliably known.
$unreadCa = New-V3Server -Role 'CertificationAuthority' -V3Ready 'N/A' -Detail (
    New-V3Detail -SensorState 'Not determined (the server could not be queried)' -V2Version '' -Checks @(
        (New-V3Check -Name $mdeName -Status 'N/A' -Detail 'Not tested - the server could not be read')
        (New-V3Check -Name $osName -Status 'N/A' -Detail 'Not tested - the server could not be read')
    ))
$mixed = Get-MergedV3 -Server @((New-DcPass), $unreadCa)
$mixedRev = Get-MergedV3 -Server @($unreadCa, (New-DcPass))
$mde = @($mixed.Checks | Where-Object { $_.Name -eq $mdeName })[0]
$mdeRev = @($mixedRev.Checks | Where-Object { $_.Name -eq $mdeName })[0]
$os = @($mixed.Checks | Where-Object { $_.Name -eq $osName })[0]

Assert-That 'a measured FAILURE survives a pass that could not read it' ($mde.Status -eq $false) "(got '$($mde.Status)')"
Assert-That 'and its explanation is the failure, not the unread text' ($mde.Detail -notlike 'Not tested*') "(got '$($mde.Detail)')"
Assert-That 'and Measured agrees with that explanation' ($mde.Measured -eq $true) "(Measured=$($mde.Measured) Detail='$($mde.Detail)')"
Assert-That 'that survival is order-independent' (([string] $mde.Status -eq [string] $mdeRev.Status) -and ([string] $mde.Detail -eq [string] $mdeRev.Detail)) `
    "(rev Status='$($mdeRev.Status)' Detail='$($mdeRev.Detail)')"
Assert-That 'a PASS one role could not read stays unmeasured' ([string] $os.Status -eq 'N/A') "(got '$($os.Status)')"
Assert-That 'and its Measured flag agrees with its status' ($os.Measured -eq $false) "(Measured=$($os.Measured) Detail='$($os.Detail)')"
Assert-That 'the unread check is listed in UnknownChecks' (@($mixed.Unknown) -contains $osName) "(got: $(@($mixed.Unknown) -join ','))"

''
'[w86] an architectural blocker in either role suppresses the whole actionable list'
# Get-mdiV3ActionableBlocker drops every blocker once one of them is unactionable, so Remediable must
# survive the merge or the remediation script raises work nobody can ever complete.
$archCa = New-V3Server -Role 'CertificationAuthority' -V3Ready $false -Detail (New-V3Detail -Checks @(
        (New-V3Check -Name 'Server role' -Status $false -Detail 'Not a domain controller' -Remediable $false)
        (New-V3Check -Name $osName -Status $true -Detail 'Windows Server 2022')
    ))
$arch = Get-MergedV3 -Server @((New-DcPass), $archCa)
$archRev = Get-MergedV3 -Server @($archCa, (New-DcPass))
Assert-That 'the architectural blocker is still reported' (@($arch.Blockers).Count -eq 2) "(got $(@($arch.Blockers).Count): $(@($arch.Blockers) -join ' | '))"
Assert-That 'nothing is offered as actionable' (@($arch.Actionable).Count -eq 0) "(got $(@($arch.Actionable).Count): $(@($arch.Actionable) -join ' | '))"
Assert-That 'and that is order-independent' (@($archRev.Actionable).Count -eq 0) "(got $(@($archRev.Actionable).Count))"

# The case above never makes the two roles disagree about the SAME check, so it does not exercise the
# per-check Remediable merge at all - a mutation that made Remediable first-role-wins survived it.
# Here BOTH roles measure the same check as failed and only one of them classifies it architectural.
# Taking the first role's classification would promote a failure nobody can act on into work the
# remediation script raises on every run for ever.
$archSameCa = New-V3Server -Role 'CertificationAuthority' -V3Ready $false -Detail (New-V3Detail -Checks @(
        (New-V3Check -Name $mdeName -Status $false -Detail 'Not onboarded to Defender for Endpoint' -Remediable $false)
        (New-V3Check -Name $osName -Status $true -Detail 'Windows Server 2022')
    ))
$sameFwd = Get-MergedV3 -Server @((New-DcPass), $archSameCa)
$sameRev = Get-MergedV3 -Server @($archSameCa, (New-DcPass))
$sameCheck = @($sameFwd.Checks | Where-Object { $_.Name -eq $mdeName })[0]
Assert-That 'a check architectural in EITHER role merges as architectural' ($sameCheck.Remediable -eq $false) "(Remediable=$($sameCheck.Remediable))"
Assert-That 'so it is not offered as actionable work' (@($sameFwd.Actionable).Count -eq 0) "(got $(@($sameFwd.Actionable).Count): $(@($sameFwd.Actionable) -join ' | '))"
Assert-That 'and that classification is order-independent' (@($sameRev.Actionable).Count -eq 0) "(got $(@($sameRev.Actionable).Count): $(@($sameRev.Actionable) -join ' | '))"
Assert-That 'the blocker itself is still reported either way' ((@($sameFwd.Blockers) -contains $mdeText) -and (@($sameRev.Blockers) -contains $mdeText)) `
    "(fwd: $(@($sameFwd.Blockers) -join ' | ') rev: $(@($sameRev.Blockers) -join ' | '))"

''
'[w86] MigrationEligible is only asserted when BOTH roles assert it'
$eligibleChecks = @((New-V3Check -Name $osName -Status $true -Detail 'Windows Server 2022'))
$elig1 = New-V3Server -Role 'DomainController' -V3Ready $true -Detail (New-V3Detail -Checks $eligibleChecks -Eligible $true)
$elig2 = New-V3Server -Role 'CertificationAuthority' -V3Ready $true -Detail (New-V3Detail -Checks $eligibleChecks -Eligible $true)
$notElig = New-V3Server -Role 'CertificationAuthority' -V3Ready $true -Detail (New-V3Detail -Checks $eligibleChecks -Eligible $false)
Assert-That 'both roles eligible stays eligible' ((Get-MergedV3 -Server @($elig1, $elig2)).Detail.MigrationEligible -eq $true)
Assert-That 'one role not eligible is not eligible' ((Get-MergedV3 -Server @($elig1, $notElig)).Detail.MigrationEligible -eq $false)
Assert-That 'and that is order-independent' ((Get-MergedV3 -Server @($notElig, $elig1)).Detail.MigrationEligible -eq $false)

''
'[w86] a details blob carrying no Checks at all is not wiped'
# An older report, or another tool, can carry Blockers with no Checks to recompute them from. There is
# nothing to derive, so the stored lists are unioned: losing a finding is worse than carrying a stale one.
$legacyA = New-V3Server -Role 'DomainController' -V3Ready $false -Detail ([PSCustomObject]@{
        SensorState = 'v2.x sensor running'; SensorV2Version = '2.245.0'; MigrationEligible = $false
        Blockers = @('legacy blocker A'); ActionableBlockers = @('legacy blocker A'); UnknownChecks = @(); Checks = @()
    })
$legacyB = New-V3Server -Role 'CertificationAuthority' -V3Ready $false -Detail ([PSCustomObject]@{
        SensorState = 'v2.x sensor running'; SensorV2Version = '2.245.0'; MigrationEligible = $false
        Blockers = @('legacy blocker B'); ActionableBlockers = @('legacy blocker B'); UnknownChecks = @(); Checks = @()
    })
$legacy = Get-MergedV3 -Server @($legacyA, $legacyB)
$legacyRev = Get-MergedV3 -Server @($legacyB, $legacyA)
Assert-That 'a legacy blob keeps both roles blockers' ((@($legacy.Blockers) -contains 'legacy blocker A') -and (@($legacy.Blockers) -contains 'legacy blocker B')) `
    "(got: $(@($legacy.Blockers) -join ' | '))"
Assert-That 'and that is order-independent' (((@($legacy.Blockers) | Sort-Object) -join '|') -eq ((@($legacyRev.Blockers) | Sort-Object) -join '|')) `
    "(rev: $(@($legacyRev.Blockers) -join ' | '))"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
