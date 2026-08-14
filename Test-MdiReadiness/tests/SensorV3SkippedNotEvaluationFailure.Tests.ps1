<#
    An area the operator deliberately switched off must not be reported as a failure to evaluate.

    "N server(s) could not be evaluated" is a statement that something went WRONG. With
    -SkipSensorV3Readiness nothing went wrong: every reachable server legitimately carries no v3
    detail because the run was told not to collect it. All of them therefore landed in V3Unevaluated,
    and the Overview tile rendered an amber "1 server(s) could not be evaluated" while four other
    surfaces on the same page described the same fact correctly - the hero banner said "All
    prerequisites met (not examined: Sensor v3.x readiness)", the console line carried the same
    suffix, the JSON listed the area in SkippedAreas, and the v3 tab itself said the validation was
    skipped. The only surface calling it a problem was the one in the KPI strip, which is the part a
    reader takes at a glance.

    The neutral branch this needs already existed - V3Evaluated -eq 0 with nothing unevaluated
    renders 'Not evaluated' in the 'na' tone - so the fix routes the skipped case to it rather than
    inventing new behaviour.

    Keyed off the SAME SkippedAreas collection the verdict suffix and console line are built from, so
    the tile cannot drift from them: this test pins that agreement rather than the wording alone.

    The controls matter as much as the defect case. Suppressing the amber unconditionally would also
    "fix" this and would hide a REAL evaluation failure - a server whose v3 readiness genuinely could
    not be read on a run where the area was NOT skipped must still warn, and a fully measured estate
    must still read green.
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

$V3AREA = 'Sensor v3.x readiness'

function New-Dc {
    param([string] $Fqdn = 'dc1.contoso.com', $V3Detail = $null, $V3Ready = $null)
    $details = [PSCustomObject]@{}
    if ($null -ne $V3Detail) { $details | Add-Member -NotePropertyName SensorV3ReadyDetails -NotePropertyValue $V3Detail }
    $o = [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false; Comment = ''
        Details = $details
        AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true
    }
    if ($null -ne $V3Ready) { $o | Add-Member -NotePropertyName SensorV3Ready -NotePropertyValue $V3Ready }
    $o
}

function New-Report {
    param($Dcs, [string[]] $Skipped = @())
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($Dcs); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
        SkippedAreas = @($Skipped)
    }
}

function Get-V3Kpi {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $html = (Get-mdiOverviewHtml -Statistics $stats -ReportData $Report) -join ''
    $tone = if ($html -match 'class="kpi (ok|bad|warn|na|info)"><span class="kpi-label">Sensor v3\.x ready') { $Matches[1] } else { '?' }
    $sub = if ($html -match 'Sensor v3\.x ready</span><span class="kpi-value">([^<]*)</span><span class="kpi-sub">([^<]*)') { $Matches[2] } else { '?' }
    [PSCustomObject]@{ Tone = $tone; Sub = $sub }
}

'[sensor v3 KPI] an explicitly skipped area is not reported as an evaluation failure'
# Exactly the estate a -SkipSensorV3Readiness run produces: reachable servers, no v3 detail on any of
# them, and the area named in SkippedAreas.
$skipped = Get-V3Kpi (New-Report @((New-Dc -Fqdn 'dc1.contoso.com'), (New-Dc -Fqdn 'dc2.contoso.com')) -Skipped @($V3AREA))
Assert-That 'the skipped tile does not claim servers could not be evaluated' `
    ($skipped.Sub -notmatch 'could not be evaluated') "(sub '$($skipped.Sub)')"
Assert-That '  ...and is not painted as a warning' ($skipped.Tone -ne 'warn') "(tone '$($skipped.Tone)')"
Assert-That '  ...and says the area was skipped' ($skipped.Sub -match 'skipped') "(sub '$($skipped.Sub)')"

'[sensor v3 KPI] a genuine evaluation failure on a NON-skipped run still warns'
# Same estate, same absent detail - but the area was NOT skipped, so this really is a failure to
# evaluate and must keep its amber. This is the assertion that stops the fix being a blanket mute.
$notSkipped = Get-V3Kpi (New-Report @((New-Dc -Fqdn 'dc1.contoso.com'), (New-Dc -Fqdn 'dc2.contoso.com')))
Assert-That 'an unevaluated estate that was NOT skipped still reports it' `
    ($notSkipped.Sub -match 'could not be evaluated') "(sub '$($notSkipped.Sub)')"
Assert-That '  ...and is still painted as a warning' ($notSkipped.Tone -eq 'warn') "(tone '$($notSkipped.Tone)')"

'[sensor v3 KPI] the two runs really do differ only by the skip flag'
Assert-That 'the skipped and non-skipped tiles are not identical' `
    ($skipped.Sub -ne $notSkipped.Sub) "(both '$($skipped.Sub)')"

'[sensor v3 KPI] a measured, ready estate still reads green'
$v3Detail = [PSCustomObject]@{ Ready = $true }
$measured = Get-V3Kpi (New-Report @((New-Dc -Fqdn 'dc1.contoso.com' -V3Detail $v3Detail -V3Ready $true)))
Assert-That 'a measured v3-ready estate is painted ok' ($measured.Tone -eq 'ok') "(tone '$($measured.Tone)')"
Assert-That '  ...and does not claim anything was skipped' ($measured.Sub -notmatch 'skipped') "(sub '$($measured.Sub)')"
Assert-That '  ...and does not claim an evaluation failure' `
    ($measured.Sub -notmatch 'could not be evaluated') "(sub '$($measured.Sub)')"

'[sensor v3 KPI] the tile agrees with the surface the verdict suffix is built from'
# The tile must key off SkippedAreas, not off a private copy of the switch, or the two drift.
$other = Get-V3Kpi (New-Report @((New-Dc -Fqdn 'dc1.contoso.com')) -Skipped @('Network ports'))
Assert-That 'a DIFFERENT skipped area does not silence the v3 tile' `
    ($other.Sub -match 'could not be evaluated') "(sub '$($other.Sub)')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
