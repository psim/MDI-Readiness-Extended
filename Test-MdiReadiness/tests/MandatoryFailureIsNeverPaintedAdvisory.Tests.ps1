<#
    A MANDATORY check that failed is never PAINTED AS ADVISORY on the prerequisite chart.

    Get-mdiRequirementRank is the single obligation scale this file owns - 3 Required/All, 2
    AtLeastOne, 1 Recommended, 0 Optional or unrecognised - and it was fixed to normalise its input so
    that ' Required ' ranks 3 like the word it is.

    Get-mdiSensorV3Html did not route through it. It carried a private copy of the same decision:

        $class = switch ($check.Requirement) {
            'Required'    { 'red' }
            'Recommended' { 'amber' }
            default       { 'amber' }
        }

    A raw comparison against the literal word, so anything not spelled exactly 'Required' fell to the
    default arm and was painted amber - the colour this report uses for advisory. Measured on the
    shipped function, one failing check, nothing differing but the spelling of its requirement:

        Requirement     rank   cell
        'Required'      3      red
        ' Required'     3      AMBER
        'Required '     3      AMBER
        "Required`r"    3      AMBER
        'All'           3      AMBER

    Two separate populations reach that default arm:

      * PADDED SPELLINGS. Checks arrive from $srv.Details.SensorV3ReadyDetails.Checks, read back
        across the base64/JSON boundary the plan is serialised through. This file already documents
        that merged, hand-edited and foreign-tool reports deliver shapes the product never wrote on
        this very field - "the number 636, or 'Required.'" - and a padded or line-ending-terminated
        spelling is that same population. It is also the only member of it that is a CORRECT,
        unambiguous requirement, so it is the one that must not be discarded.

      * 'All'. No boundary needed at all. It is in the shipped ports table, it ranks 3 by contract,
        and the default arm painted it advisory.

    After the rank was fixed the two surfaces actively CONTRADICTED each other: the run treated the
    check as mandatory - rank 3, so it gated READY and blocked the verdict - while the chart a reader
    opens the report to look at coloured it amber, the shade this report reserves for "should".
    Nothing disclosed the disagreement, because each surface was self-consistent.

    The colour now comes from the scale, so the two cannot drift apart again. The mapping is otherwise
    unchanged: AtLeastOne and Recommended stay amber exactly as before.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path -LiteralPath $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$target = (Resolve-Path -LiteralPath $target).ProviderPath
Write-Host ("  LOADED  {0}" -f $target) -ForegroundColor DarkGray

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-CheckServer {
    param([object] $Requirement, [object] $Status = $false, [object] $Measured = $true)
    [PSCustomObject]@{
        FQDN    = 'dc1.mdilab.local'
        Details = [PSCustomObject]@{
            SensorV3ReadyDetails = [PSCustomObject]@{
                SensorState = 'Running'
                Checks      = @([PSCustomObject]@{
                        Name = 'Probe check'; Requirement = $Requirement
                        Status = $Status; Measured = $Measured; Detail = 'refused'
                    })
            }
            RequiredPortsDetails = [PSCustomObject]@{ ProbedFrom = 'dc1' }
        }
    }
}

function Get-FailCellClass {
    param([object] $Requirement)
    $html = (Get-mdiSensorV3Html -Server @(New-CheckServer -Requirement $Requirement)) -join ''
    if ($html -match '<td class="([a-z\-]+)"[^>]*>Fail</td>') { return $Matches[1] }
    return '(no fail cell)'
}

Write-Host ''
Write-Host '[1] a mandatory failure is painted red however its requirement is spelled' -ForegroundColor Cyan

# The whole point: these are the SAME requirement, and the report must say so.
foreach ($spelling in @('Required', ' Required', 'Required ', '  Required  ', "Required`r", "Required`n", "`tRequired")) {
    $shown = "'" + ($spelling -replace "`r", '\r' -replace "`n", '\n' -replace "`t", '\t') + "'"
    Assert-That "a failing $shown check is red, not advisory" `
        ((Get-FailCellClass -Requirement $spelling) -eq 'red') "(got '$(Get-FailCellClass -Requirement $spelling)')"
}

# 'All' ranks 3 by the scale's own contract and needs no boundary to arrive that way.
Assert-That "a failing 'All' check is red, not advisory" `
    ((Get-FailCellClass -Requirement 'All') -eq 'red') "(got '$(Get-FailCellClass -Requirement 'All')')"

Write-Host ''
Write-Host '[2] the chart agrees with the obligation scale, for every spelling' -ForegroundColor Cyan

# The disagreement is the defect, so it is asserted directly rather than inferred from a colour.
foreach ($spelling in @('Required', ' Required', 'Required ', "Required`r", 'All', ' All ',
        'AtLeastOne', ' AtLeastOne', 'Recommended', ' Recommended', 'Optional', 'Migration', '')) {
    $rank = Get-mdiRequirementRank -Requirement $spelling
    $class = Get-FailCellClass -Requirement $spelling
    $shown = "'" + ($spelling -replace "`r", '\r') + "'"
    $agrees = if ($rank -ge 3) { $class -eq 'red' } else { $class -eq 'amber' }
    Assert-That "chart and scale agree for $shown (rank $rank)" $agrees "(rank=$rank class=$class)"
}

Write-Host ''
Write-Host '[3] the advisory mapping is unchanged' -ForegroundColor Cyan

# Guards the fix against over-reach: nothing below rank 3 may become red.
foreach ($spelling in @('AtLeastOne', 'Recommended', 'Optional', 'Migration', 'nonsense', '', '   ')) {
    $shown = "'" + $spelling + "'"
    Assert-That "$shown stays amber" ((Get-FailCellClass -Requirement $spelling) -eq 'amber') `
        "(got '$(Get-FailCellClass -Requirement $spelling)')"
}

# An unreadable value must not be promoted by trimming - the rank contract says so, and the colour
# follows it.
foreach ($odd in @(636, 'Required.', $true)) {
    Assert-That "an unreadable requirement ($odd) stays amber" `
        ((Get-FailCellClass -Requirement $odd) -eq 'amber') "(got '$(Get-FailCellClass -Requirement $odd)')"
}

Write-Host ''
Write-Host '[4] passing and unmeasured checks are untouched by the colour rule' -ForegroundColor Cyan

# The colour arm is only reached by a FAILING check. A pass must stay green and an unmeasured check
# must stay "Not tested", whatever the requirement says, or this fix would have moved a different cell.
$passHtml = (Get-mdiSensorV3Html -Server @(New-CheckServer -Requirement ' Required ' -Status $true)) -join ''
Assert-That 'a passing mandatory check is still green' ($passHtml -match '<td class="green"[^>]*>Pass</td>')

$unmeasuredHtml = (Get-mdiSensorV3Html -Server @(New-CheckServer -Requirement ' Required ' -Measured $false)) -join ''
Assert-That 'an unmeasured mandatory check is still Not tested' ($unmeasuredHtml -match 'Not tested')
Assert-That 'an unmeasured mandatory check is not painted as a failure' ($unmeasuredHtml -notmatch '>Fail</td>')

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
