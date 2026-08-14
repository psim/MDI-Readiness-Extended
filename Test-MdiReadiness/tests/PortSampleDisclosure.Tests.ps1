<#
    A sampled population is never presented as the estate.

    Network port probing is deliberately bounded: -MaxLdapTargetsPerDomain selects that many domain
    controllers per domain, and it DEFAULTS TO 2. That bound is correct engineering - probing every
    controller from every controller does not finish on a large forest - and it was wrong reporting.
    On any domain with more than two controllers an ordinary run probes a SAMPLE, and the card read

        Required ports open   8/8   No required port blocked

    with nothing anywhere saying that two hosts of four had been visited. An operator who came to
    this card from an alert about blocked traffic would conclude the estate was clean.

    This is the same illusion the NNR card was corrected for, and it is fixed the same way: state the
    sample. The NNR wording is the precedent and is asserted here too, so the two cards cannot drift.
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

function New-PortRecord {
    param($Target, $Port = 389, $Success = $true)
    [PSCustomObject]@{
        Id = ('p-TCP-{0}' -f $Port); Group = 'Ports'; Scope = 'DomainController'; Requirement = 'Required'
        Protocol = 'TCP'; Port = $Port; Target = $Target; TargetIP = '10.0.0.9'
        Applicable = $true; Success = $Success; Detail = $(if ($Success) { 'Open' } else { 'Connection refused' })
    }
}
# $ProbedCount domain controllers actually probed, out of $TotalCount in the domain.
function New-SampledReport {
    param($TotalCount, $ProbedCount, $Success = $true)
    $dcs = @(1..$TotalCount | ForEach-Object {
            $fqdn = 'dc{0}.contoso.com' -f $_
            $o = [PSCustomObject]@{
                FQDN = $fqdn; Domain = 'contoso.com'; Unreachable = $false; Comment = $null
                SensorVersion = '2.240.0.0'; Details = [PSCustomObject]@{}
            }
            $o | Add-Member -NotePropertyName NtlmAuditing -NotePropertyValue $true -Force
            $o
        })
    # Only the first probing DC carries records, and they name $ProbedCount distinct targets.
    $records = @(1..$ProbedCount | ForEach-Object { New-PortRecord -Target ('dc{0}.contoso.com' -f $_) -Success $Success })
    $dcs[0] | Add-Member -NotePropertyName RequiredPorts -NotePropertyValue $Success -Force
    $dcs[0].Details | Add-Member -NotePropertyName RequiredPortsDetails -NotePropertyValue ([PSCustomObject]@{ Results = $records }) -Force
    [PSCustomObject]@{
        DomainControllers = $dcs; CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    }
}
function Get-PortsCard {
    param($Report)
    $st = Get-mdiReportStatistics -ReportData $Report
    $html = (Get-mdiOverviewHtml -Statistics $st -ReportData $Report) -join "`n"
    $m = [regex]::Match($html, '<div class="kpi (\w+)"><span class="kpi-label">Required ports open</span><span class="kpi-value">(.*?)</span><span class="kpi-sub">(.*?)</span></div>')
    [PSCustomObject]@{
        Tone = $m.Groups[1].Value; Value = $m.Groups[2].Value; Sub = $m.Groups[3].Value
        Scope = [int] $st.PortCandidateHostCount; Probed = [int] $st.PortDistinctTargetCount
    }
}

Write-Host 'A sampled port probe says it sampled' -ForegroundColor Cyan
$sampled = Get-PortsCard (New-SampledReport -TotalCount 4 -ProbedCount 2)
Assert-That 'the statistics know the estate is bigger than the sample' (
    $sampled.Scope -eq 4 -and $sampled.Probed -eq 2) "(scope=$($sampled.Scope) probed=$($sampled.Probed))"
Assert-That 'the card discloses that it sampled' ($sampled.Sub -match 'in scope were probed') "(sub '$($sampled.Sub)')"
Assert-That '  ...naming how many of how many' ($sampled.Sub -match '2 of 4 host\(s\)') "(sub '$($sampled.Sub)')"
Assert-That '  ...and pointing at the parameter that widens it' (
    $sampled.Sub -match '-MaxLdapTargetsPerDomain') "(sub '$($sampled.Sub)')"
Assert-That '  ...and it no longer claims the estate is clean outright' (
    $sampled.Sub -notmatch '^No required port blocked$') "(sub '$($sampled.Sub)')"

Write-Host 'A complete probe makes no sampling claim' -ForegroundColor Cyan
# Over-disclosing is its own defect: a card that always says "sampled" tells the reader nothing.
$complete = Get-PortsCard (New-SampledReport -TotalCount 2 -ProbedCount 2)
Assert-That 'a fully probed estate says nothing about sampling' (
    $complete.Sub -notmatch 'in scope were probed') "(sub '$($complete.Sub)')"
Assert-That '  ...and still reads clean' ($complete.Sub -match 'No required port blocked') "(sub '$($complete.Sub)')"
Assert-That '  ...with an ok tone' ($complete.Tone -eq 'ok') "(tone '$($complete.Tone)')"

Write-Host 'A real failure is still the headline' -ForegroundColor Cyan
# The sample clause must not displace the thing the operator has to act on.
$failing = Get-PortsCard (New-SampledReport -TotalCount 4 -ProbedCount 2 -Success $false)
Assert-That 'a measured blocked port is still named first' (
    $failing.Sub -match 'required port\(s\) blocked') "(sub '$($failing.Sub)')"
Assert-That '  ...and the sample is disclosed alongside it' (
    $failing.Sub -match 'in scope were probed') "(sub '$($failing.Sub)')"
Assert-That '  ...and the card is still red' ($failing.Tone -eq 'bad') "(tone '$($failing.Tone)')"

Write-Host 'A run that probed nothing is unaffected' -ForegroundColor Cyan
$none = [PSCustomObject]@{
    DomainControllers = @([PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; Comment = $null
            NtlmAuditing = $true; Details = [PSCustomObject]@{}
        })
    CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
}
$noneCard = Get-PortsCard $none
Assert-That '-SkipNetworkPorts style run still reads Not evaluated' (
    $noneCard.Sub -eq 'Not evaluated') "(sub '$($noneCard.Sub)')"
Assert-That '  ...and makes no sampling claim' ($noneCard.Sub -notmatch 'in scope were probed')

Write-Host 'The NNR card keeps its own disclosure' -ForegroundColor Cyan
# The two cards answer the same question about different populations; if one loses its wording the
# other must not be silently covering for it.
Assert-That 'the NNR sample wording still exists in the source' (
    $text -match 'raise -MaxNnrTargets to widen it')
Assert-That 'the ports sample wording exists too' (
    $text -match 'raise -MaxLdapTargetsPerDomain to widen it')

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
