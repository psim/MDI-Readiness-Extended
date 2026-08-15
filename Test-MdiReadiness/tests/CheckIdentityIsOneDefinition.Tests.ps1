# The MERGE answered "what is a readiness check?" differently from Get-mdiCheckProperty, and the
# disagreement let a descriptive field become an invented FAILING prerequisite.
#
# $script:mdiCheckName exists for one reason, stated in its own doc comment: a string is ambiguous, so
# promoting any string that happens to read 'True' or 'False' turned a descriptive field into a fake
# failing check - "a server carrying SiteName='False' was reported as failing a Site Name check that
# does not exist". Get-mdiCheckProperty applies that whitelist. Merge-mdiServerByFqdn did not: it
# decided on parseability alone, with no name test, AND wrote the merged value back as a REAL [bool].
# Get-mdiCheckProperty accepts a real boolean from any property - by design, so a check added later
# needs no list entry - so the coerced value sailed straight past the whitelist. The merge laundered a
# descriptive string past the guard built to stop it.
#
# Measured before the fix: a multi-role controller whose two role rows carried SiteName 'False' and
# 'True' went from 1 of 1 passed and READY to 2 checks, 1 issue, "Site Name check failed", NOT READY,
# and its exported JSON field changed TYPE from string to boolean. Role order made no difference.
#
# This is the main path: merging is what happens to every host that is both a domain controller and a
# certification authority. The unknown-property premise is the codebase's own stated model - the
# whitelist doc says the informational list "cannot know about a field a future version, another tool,
# or a hand-edited report adds".
#
# NOTE ON SCOPE. Get-mdiUnreadCheckName has the same asymmetry in its 'N/A' branch, and narrowing that
# too was tried and REVERTED: it makes a check reporting 'N/A' that is not on the list vanish from the
# unread count, which is a false green. UnreadCheckColumn.Tests.ps1 and Test-PartialFailure.Tests.ps1
# pin the wide behaviour there deliberately. Over-reporting a gap is the safe direction; silently
# rewriting a stored value's TYPE is not, which is why only the merge is narrowed here.

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

function New-Row {
    param($Extra = @{})
    $o = [ordered]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        PowerSettings = $true
        Details = [PSCustomObject]@{}
    }
    foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
    [PSCustomObject] $o
}

function New-Report {
    param($Server)
    [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com'); DomainControllers = @($Server)
        CAServers = @(); EntraConnectServers = @(); DomainAuditing = @(); SkippedAreas = @()
    }
}

function Measure-Row {
    param($Server)
    $rep = New-Report $Server
    $stats = Get-mdiReportStatistics -ReportData $rep 3>$null
    [PSCustomObject]@{
        Checks = @(Get-mdiCheckProperty -Server $Server | ForEach-Object { [string] $_.Name })
        Unread = @(Get-mdiUnreadCheckName -Server $Server)
        Passed = $stats.ChecksPassed
        Total  = $stats.ChecksTotal
        Issues = @(Get-mdiIssueList -Statistics $stats -ReportData $rep)
        Ready  = (Test-mdiReadinessResult -ReportData $rep)
    }
}

'[check identity] the unread count deliberately stays wide'
$control = Measure-Row (New-Row)
Assert-That 'baseline: one real check, measured, ready' (
    $control.Total -eq 1 -and $control.Passed -eq 1 -and $control.Unread.Count -eq 0 -and $control.Issues.Count -eq 0 -and $control.Ready
) "(total $($control.Total) passed $($control.Passed) unread $($control.Unread.Count) issues $($control.Issues.Count) ready $($control.Ready))"

# Pinned as a DELIBERATE choice, not an accident: an unknown property holding 'N/A' is charged as an
# unmeasured check. Narrowing this to $script:mdiCheckName was tried and reverted because it makes a
# check reporting 'N/A' that is not on the list vanish from the count - a false green. Over-reporting
# a gap is the safe direction. If this ever fires on a real descriptive field, the fix is to add that
# field to $script:mdiInformationalProperty, NOT to narrow the test.
$na = Measure-Row (New-Row @{ SiteName = 'N/A' })
Assert-That 'an unknown property holding N/A is still charged as unread' ($na.Unread -contains 'SiteName') "(unread: $($na.Unread -join ','))"
Assert-That '  ...and a descriptive field on the informational list is not' (
    (Measure-Row (New-Row @{ SensorVersion = 'N/A' })).Unread.Count -eq 0
) "(unread: $((Measure-Row (New-Row @{ SensorVersion = 'N/A' })).Unread -join ','))"

''
'[check identity] a REAL check holding N/A is still counted as unread'
# The narrowing must not hide a genuine gap - that would be the false green this whole codebase is
# built to prevent. Every known check name is exercised, not just one.
$everyCheck = @('OSVersion', 'AdvancedAuditing', 'NtlmAuditing', 'PowerSettings', 'SensorHealth',
    'SensorV3Ready', 'TimeSync', 'CAAuditing', 'CapacitySufficient', 'RootCertificates', 'ServerRequirements')
foreach ($checkName in $everyCheck) {
    $row = New-Row @{ $checkName = 'N/A' }
    $m = Measure-Row $row
    Assert-That ("a real check '{0}' stored as N/A is still unread" -f $checkName) (
        $m.Unread -contains $checkName
    ) "(unread: $($m.Unread -join ','))"
}
# ...and an unmeasured real check must still cost the verdict.
$realUnread = Measure-Row (New-Row @{ AdvancedAuditing = 'N/A' })
Assert-That 'an unmeasured real check still produces a finding' ($realUnread.Issues.Count -gt 0) "(issues: $($realUnread.Issues.Count))"
Assert-That 'an unmeasured real check still costs the verdict' (-not $realUnread.Ready)

''
'[check identity] role merging does not coerce a descriptive field into a boolean check'
# The merge is what happens to every host that is both a DC and a CA. Two role rows disagree on a
# descriptive value that happens to read like a boolean.
function Merge-Pair {
    param($First, $Second)
    @(Merge-mdiServerByFqdn -Server @(
            (New-Row @{ SiteName = $First }),
            (New-Row @{ SiteName = $Second })
        ))[0]
}
$mergedFalseTrue = Merge-Pair 'False' 'True'
$mergedTrueFalse = Merge-Pair 'True' 'False'
$mergedMixed     = Merge-Pair 'Branch-West' 'False'

Assert-That 'the merged descriptive value keeps its STRING type' (
    $mergedFalseTrue.SiteName -is [string]
) "(got $($mergedFalseTrue.SiteName.GetType().FullName))"
Assert-That '  ...in the reverse role order too' ($mergedTrueFalse.SiteName -is [string]) "(got $($mergedTrueFalse.SiteName.GetType().FullName))"
Assert-That '  ...and when only one side looks boolean' ($mergedMixed.SiteName -is [string]) "(got $($mergedMixed.SiteName.GetType().FullName))"
Assert-That 'a non-boolean descriptive value survives the merge intact' ([string] $mergedMixed.SiteName -eq 'Branch-West') "(got [$($mergedMixed.SiteName)])"

$mergedStats = Measure-Row $mergedFalseTrue
Assert-That 'the descriptive field is not promoted to a check' ($mergedStats.Checks -notcontains 'SiteName') "(checks: $($mergedStats.Checks -join ','))"
Assert-That 'the check total is unchanged by the merge' ($mergedStats.Total -eq 1) "(got $($mergedStats.Total))"
Assert-That 'no issue is invented by the merge' ($mergedStats.Issues.Count -eq 0) "(issues: $(($mergedStats.Issues | ForEach-Object { $_.Issue }) -join ' | '))"
Assert-That 'the merged server is still READY' $mergedStats.Ready

''
'[check identity] role merging still merges REAL checks pessimistically'
# The narrowing must not break the merge the function exists for: a failure under either role has to
# survive, including when both roles stored the check as a string, which a JSON round trip produces.
function Merge-Check {
    param($Name, $First, $Second)
    @(Merge-mdiServerByFqdn -Server @(
            (New-Row @{ $Name = $First }),
            (New-Row @{ $Name = $Second })
        ))[0]
}
$boolMerge = Merge-Check 'AdvancedAuditing' $true $false
Assert-That 'a real boolean failure wins over a pass' ([string] $boolMerge.AdvancedAuditing -eq 'False') "(got [$($boolMerge.AdvancedAuditing)])"
$strMerge = Merge-Check 'AdvancedAuditing' 'True' 'False'
Assert-That 'a STRING failure wins over a string pass' ((ConvertTo-mdiBoolean $strMerge.AdvancedAuditing) -eq $false) "(got [$($strMerge.AdvancedAuditing)])"
$strMergeRev = Merge-Check 'AdvancedAuditing' 'False' 'True'
Assert-That '  ...in either role order' ((ConvertTo-mdiBoolean $strMergeRev.AdvancedAuditing) -eq $false) "(got [$($strMergeRev.AdvancedAuditing)])"
$naMerge = Merge-Check 'AdvancedAuditing' 'N/A' $true
Assert-That 'an unmeasured real check beats a measured pass' ([string] $naMerge.AdvancedAuditing -eq 'N/A') "(got [$($naMerge.AdvancedAuditing)])"
$naMergeRev = Merge-Check 'AdvancedAuditing' $true 'N/A'
Assert-That '  ...in either role order' ([string] $naMergeRev.AdvancedAuditing -eq 'N/A') "(got [$($naMergeRev.AdvancedAuditing)])"
# A real boolean on an UNLISTED property is still a check wherever it appears - that is deliberate, so
# a check added in a later version works without touching the list.
$futureMerge = @(Merge-mdiServerByFqdn -Server @(
        (New-Row @{ FutureCheck = $true }),
        (New-Row @{ FutureCheck = $false })
    ))[0]
Assert-That 'a real boolean on an unlisted property is still merged as a check' (
    ($futureMerge.FutureCheck -is [bool]) -and ($futureMerge.FutureCheck -eq $false)
) "(got [$($futureMerge.FutureCheck)] of type $($futureMerge.FutureCheck.GetType().FullName))"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
