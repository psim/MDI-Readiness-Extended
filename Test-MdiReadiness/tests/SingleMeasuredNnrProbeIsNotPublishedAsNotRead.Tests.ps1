# [w106] A method with exactly ONE measured probe must not be published as "not read".
#
# The name resolution method chart splits each method's records into the ones that were MEASURED and
# the ones that never ran, so that a method nobody could probe is drawn neutral instead of as a red
# zero. The split was written as an if used as an EXPRESSION:
#
#     $measured = if ($unnamedNnrMethod) { @() } else { @($grp.Group | Where-Object { ... }) }
#
# An if used that way sends the chosen branch's output down the pipeline, and a pipeline UNROLLS a
# one-element array. So whenever a method had exactly ONE measured probe - far and away the commonest
# shape in a real report, since most estates probe one NNR method per target - $measured stopped being
# a collection and became the RECORD ITSELF, a PSCustomObject. PSCustomObject has no Count property
# and does not take PowerShell's scalar-Count fallback, so $measured.Count was $null, not 1. The bar
# was then built from
#
#     Total  = $measured.Count            -> $null
#     Unread = @($grp.Group).Count - $null -> the WHOLE group
#
# and a probe that had genuinely run and genuinely failed was published as never having been read.
# Measured on the shipped functions, one NNR record with Applicable $true, Success $false and
# Detail 'Connection timed out' - a probe that ran, and failed - rendered as
#
#     <div class="bar-fill na" ...>   0/1 (0%)  <span class="muted">1 not read</span>
#
# a neutral grey bar asserting nothing, instead of a red measured failure, on the one chart the report
# itself tells the operator to open for the "Low success rate of active name resolution" health alert.
# With one measured probe beside one that never ran, the same arithmetic reported "2 not read" out of
# two records when only one of them was actually unread.
#
# This is the project's own defect family inverted. Every other defect here has been a value that was
# never read coming back looking like a measurement; this one is a value that WAS read coming back
# looking as though it never was. Both put a number in front of an operator that nothing measured.
#
# The fix wraps the WHOLE if in @(), which is the only form that survives the unroll - wrapping the
# branches alone does not, because the unroll happens after the branch has been chosen.
#
# What this file pins:
#   * a single measured NNR failure is drawn RED and carries no "not read" text;
#   * a single measured NNR success is drawn as a success, 1/1, and carries no "not read" text;
#   * one measured probe beside one that never ran reports exactly ONE unread, not two;
#   * a method whose probes genuinely all went unmeasured is still neutral and still says so;
#   * a method whose NAME could not be read is still neutral, still stated, and still says so;
#   * a method with two measured probes - the shape the defect could not reach - is unchanged.

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

# Success is an [object] and Detail is a parameter because "did this probe produce a result" is
# exactly what the split under test turns on. A record is MEASURED when Applicable is $true, Success
# is a real boolean and Detail is not one of the "never ran" markers.
function New-NnrResult {
    param([string] $Id, [object] $Name, [string] $Target, [object] $Success, [string] $Detail = 'probe complete')
    [PSCustomObject]@{
        Id          = $Id
        Name        = $Name
        Protocol    = 'UDP'
        Port        = 137
        Scope       = 'NetworkDevice'
        Group       = 'NNR'
        Requirement = 'AtLeastOne'
        Target      = $Target
        TargetIP    = '10.10.1.51'
        Applicable  = $true
        Success     = $Success
        Detail      = $Detail
    }
}

# The real report path, not a hand-built statistics object: Get-mdiReportStatistics decides which
# records count as primary NNR and Get-mdiOverviewHtml draws the chart, so both are exercised.
function Get-NnrChart {
    param([object[]] $Results)
    $dc = [PSCustomObject]@{
        FQDN           = 'dcfab01.fabrikam.local'
        Domain         = 'fabrikam.local'
        Unreachable    = $false
        PartialFailure = $false
        Details        = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $Results } }
    }
    $report = [PSCustomObject]@{
        DomainsInScope      = @('fabrikam.local')
        DomainControllers   = @($dc)
        CAServers           = @()
        EntraConnectServers = @()
        DomainAuditing      = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report

    $marker = '<h3>Name resolution success rate by method</h3>'
    $at = $html.IndexOf($marker)
    $section = if ($at -lt 0) { '' } else {
        $end = $html.IndexOf('</section>', $at)
        if ($end -lt 0) { $end = $html.Length }
        $html.Substring($at, $end - $at)
    }
    # Captured up to and including the VALUE span. A non-greedy match stopping at the first
    # "</div></div>" ends inside bar-track and cuts the caption off entirely, which would make every
    # caption assertion below read an empty string and pass against a broken script.
    $rows = @([regex]::Matches($section, '<div class="bar-row">.*?<div class="bar-value">.*?</div></div>') | ForEach-Object { $_.Value })

    $bars = @(foreach ($row in $rows) {
            $label = ''
            $lm = [regex]::Match($row, '<div class="bar-label"[^>]*>(.*?)</div>')
            if ($lm.Success) { $label = ($lm.Groups[1].Value -replace '<[^>]+>', '') }
            # A bar can hold TWO bar-fill divs: the primary tone and a hard-coded 'na' unread segment.
            # The FIRST one inside the track is the tone; a looser match reports every partial bar 'na'.
            $tone = ''
            $tm = [regex]::Match($row, '<div class="bar-track"><div class="bar-fill ([a-z]+)"')
            if ($tm.Success) { $tone = $tm.Groups[1].Value }
            $caption = ''
            $cm = [regex]::Match($row, '<div class="bar-value">(.*?)</div>')
            if ($cm.Success) { $caption = (($cm.Groups[1].Value -replace '<[^>]+>', ' ') -replace '\s+', ' ').Trim() }
            [PSCustomObject]@{ Label = $label; Tone = $tone; Caption = $caption }
        })
    [PSCustomObject]@{ Html = $html; Section = $section; Bars = $bars }
}

function Show-Bars { param($Chart) (@($Chart.Bars | ForEach-Object { '{0}[{1}]{2}' -f $_.Label, $_.Tone, $_.Caption }) -join ' | ') }

# ---------------------------------------------------------------------------------------------
'[w106] a single measured NNR failure is a measured failure, not an unread probe'
$oneFailure = Get-NnrChart -Results @(
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws1.fabrikam.local' -Success $false -Detail 'Connection timed out')
)
$failBar = @($oneFailure.Bars)[0]

Assert-That 'a single measured method draws exactly one bar' (@($oneFailure.Bars).Count -eq 1) `
    "($(Show-Bars $oneFailure))"
Assert-That 'a single measured NNR failure claims nothing was unread' `
    ($failBar.Caption -notmatch 'not read') "caption=[$($failBar.Caption)]"
Assert-That 'a single measured NNR failure is drawn as a failure, not neutral' `
    ($failBar.Tone -eq 'bad') "tone=[$($failBar.Tone)] caption=[$($failBar.Caption)]"
Assert-That 'a single measured NNR failure counts its one probe in the denominator' `
    ($failBar.Caption -match '^0/1\b') "caption=[$($failBar.Caption)]"

# ---------------------------------------------------------------------------------------------
'[w106] a single measured NNR success survives the same arithmetic'
$oneSuccess = Get-NnrChart -Results @(
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws1.fabrikam.local' -Success $true)
)
$okBar = @($oneSuccess.Bars)[0]

Assert-That 'a single measured NNR success claims nothing was unread' `
    ($okBar.Caption -notmatch 'not read') "caption=[$($okBar.Caption)]"
Assert-That 'a single measured NNR success is drawn as a success, not neutral' `
    ($okBar.Tone -ne 'na' -and $okBar.Tone -ne '') "tone=[$($okBar.Tone)] caption=[$($okBar.Caption)]"
Assert-That 'a single measured NNR success reports one of one' `
    ($okBar.Caption -match '^1/1\b') "caption=[$($okBar.Caption)]"

# ---------------------------------------------------------------------------------------------
# The sharpest case: one probe ran, one did not. The report must say ONE was unread. Under the defect
# the measured one unrolled to a scalar, Total went $null and the whole group - both records - was
# published as unread, so the page contradicted itself about a probe it had actually performed.
'[w106] one measured probe beside one that never ran reports exactly one unread'
$mixed = Get-NnrChart -Results @(
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws1.fabrikam.local' -Success $false -Detail 'Connection timed out')
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws2.fabrikam.local' -Success $null -Detail 'Not tested - access is denied')
)
$mixedBar = @($mixed.Bars)[0]

Assert-That 'a mixed method still draws a single bar' (@($mixed.Bars).Count -eq 1) "($(Show-Bars $mixed))"
Assert-That 'a mixed method reports ONE unread probe, not the whole group' `
    ($mixedBar.Caption -match '\b1 not read\b') "caption=[$($mixedBar.Caption)]"
Assert-That 'a mixed method does not report both of its probes unread' `
    ($mixedBar.Caption -notmatch '\b2 not read\b') "caption=[$($mixedBar.Caption)]"
Assert-That 'a mixed method still counts both probes in the denominator' `
    ($mixedBar.Caption -match '^0/2\b') "caption=[$($mixedBar.Caption)]"

# ---------------------------------------------------------------------------------------------
# Control. The unread path is the reason the split exists at all, so the fix must not have quietly
# removed it: a method that really was never measured must still be neutral and must still say so.
'[w106] control: a method that genuinely never ran is still neutral and still declares it'
$neverRan = Get-NnrChart -Results @(
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws1.fabrikam.local' -Success $null -Detail 'Not tested - access is denied')
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws2.fabrikam.local' -Success $null -Detail 'Not tested - access is denied')
)
$neverBar = @($neverRan.Bars)[0]

Assert-That 'an all-unmeasured method is toned neutral' ($neverBar.Tone -eq 'na') `
    "tone=[$($neverBar.Tone)] caption=[$($neverBar.Caption)]"
Assert-That 'an all-unmeasured method declares what was not read' `
    ($neverBar.Caption -match '\b2 not read\b') "caption=[$($neverBar.Caption)]"
Assert-That 'an all-unmeasured method is never drawn as a measured failure' `
    ($neverBar.Tone -ne 'bad') "tone=[$($neverBar.Tone)] caption=[$($neverBar.Caption)]"

# ---------------------------------------------------------------------------------------------
# Control for the other branch of the same if: a method whose NAME could not be read takes the @()
# branch, which the unroll turns into $null just as readily. It must stay stated and stay neutral.
'[w106] control: a method whose name could not be read is stated, neutral, and declares it'
$unnamed = Get-NnrChart -Results @(
    (New-NnrResult -Id 'NnrNetBios' -Name $null -Target 'ws1.fabrikam.local' -Success $false -Detail 'Connection timed out')
)
$unnamedBar = @($unnamed.Bars)[0]

Assert-That 'an unreadable method name is stated rather than left blank' `
    ($unnamedBar.Label -match 'unidentified') "label=[$($unnamedBar.Label)]"
Assert-That 'an unreadable method name is toned neutral, never as a measured failure' `
    ($unnamedBar.Tone -eq 'na') "tone=[$($unnamedBar.Tone)] caption=[$($unnamedBar.Caption)]"
Assert-That 'an unreadable method name declares that nothing was read for it' `
    ($unnamedBar.Caption -match 'not read') "caption=[$($unnamedBar.Caption)]"

# ---------------------------------------------------------------------------------------------
# Control for the shape the defect could NOT reach: two measured probes stay a real array through the
# unroll, so this case was always right and must remain right after the fix.
'[w106] control: a method with two measured probes is unchanged'
$twoMeasured = Get-NnrChart -Results @(
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws1.fabrikam.local' -Success $true)
    (New-NnrResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Target 'ws2.fabrikam.local' -Success $false -Detail 'Connection timed out')
)
$twoBar = @($twoMeasured.Bars)[0]

Assert-That 'two measured probes report one of two' ($twoBar.Caption -match '^1/2\b') `
    "caption=[$($twoBar.Caption)]"
Assert-That 'two measured probes claim nothing was unread' ($twoBar.Caption -notmatch 'not read') `
    "caption=[$($twoBar.Caption)]"

# ---------------------------------------------------------------------------------------------
"RESULT: $($script:pass) passed / $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
