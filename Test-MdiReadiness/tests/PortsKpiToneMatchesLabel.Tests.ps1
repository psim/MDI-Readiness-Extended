<#
    Behavioural regression test: an amber KPI card must name its own cause.

    The "Required ports open" card took its TONE from every blocked probe - Required, Recommended and
    the AtLeastOne NNR group alike - while its headline and sub-label described Required probes only.
    So a run with a recommended probe shut rendered an amber card reading "No required port blocked":
    a warning whose own text tells the reader nothing is wrong.

    That is the live lab's permanent state, not a corner case - 54/54 required open, amber, because
    four NNR NetBIOS probes and one recommended reverse-DNS lookup are shut.

    The assertions read the rendered card, never the source.
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

Write-Host 'PortsKpiToneMatchesLabel.Tests.ps1' -ForegroundColor Cyan

function New-PortServer {
    param([object[]] $Results)
    [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
        OperatingSystem = 'Windows Server 2022'; NtlmAuditing = $true
        Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom = 'dc1.contoso.com'; FailedRequired = @(); NnrFailedTargets = @()
                Results = @($Results) } }
    }
}
function New-Probe {
    param([string] $Id, [string] $Requirement, [bool] $Success, [string] $Target = 'dc2.contoso.com')
    [PSCustomObject]@{
        Id = $Id; Name = $Id; Protocol = 'TCP'; Port = 389; Scope = 'DomainController'
        Group = $(if ($Requirement -eq 'AtLeastOne') { 'NNR' } else { '' })
        Requirement = $Requirement; Target = $Target; TargetIP = '10.0.0.2'
        Applicable = $true; Success = $Success; Detail = $(if ($Success) { 'Connected' } else { 'Blocked - no response' })
    }
}
function Get-PortsCard {
    param([object[]] $Results)
    $report = [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @(New-PortServer -Results $Results); CAServers = @(); EntraConnectServers = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report
    $card = [regex]::Match($html, '<div class="kpi (?<tone>\w+)"><span class="kpi-label">Required ports open</span><span class="kpi-value">(?<value>[^<]*)</span><span class="kpi-sub">(?<sub>[^<]*)</span>')
    [PSCustomObject]@{ Tone = $card.Groups['tone'].Value; Value = $card.Groups['value'].Value; Sub = $card.Groups['sub'].Value; Stats = $stats }
}

# --- The defect: amber tone, reassuring text ---------------------------------------------------
$recommendedShut = Get-PortsCard -Results @(
    (New-Probe 'LdapTcp' 'Required' $true),
    (New-Probe 'NnrPtr' 'Recommended' $false)
)
Assert-True 'a blocked recommended probe still tones the card amber' `
    ($recommendedShut.Tone -eq 'warn') ("tone={0}" -f $recommendedShut.Tone)
Assert-True 'and the card no longer claims nothing is wrong' `
    ($recommendedShut.Sub -ne 'No required port blocked') ("sub='{0}'" -f $recommendedShut.Sub)
Assert-True 'the sub-label names the blocked non-required probes' `
    ($recommendedShut.Sub -match 'optional or recommended') ("sub='{0}'" -f $recommendedShut.Sub)
Assert-True 'the headline still describes required probes only' `
    ($recommendedShut.Value -eq '1/1') ("value={0}" -f $recommendedShut.Value)

# The COUNT in the sub-label has to be the blocked non-required probes, not some other population
# that happens to be zero here. Without this the number could name required failures - always 0 when
# this branch fires - and the card would read "0 optional or recommended probe(s) blocked", which is
# the same self-contradiction in a new costume.
$twoShut = Get-PortsCard -Results @(
    (New-Probe 'LdapTcp' 'Required' $true),
    (New-Probe 'NnrPtr' 'Recommended' $false),
    (New-Probe 'NnrNetBios' 'AtLeastOne' $false -Target 'dc3.contoso.com')
)
Assert-True 'the sub-label counts the blocked non-required probes' `
    ($twoShut.Sub -match ('^{0} optional or recommended' -f $twoShut.Stats.PortsBlocked)) `
    ("sub='{0}' PortsBlocked={1}" -f $twoShut.Sub, $twoShut.Stats.PortsBlocked)
Assert-True 'and that count is not zero when something really is blocked' `
    ($twoShut.Sub -notmatch '^0 ') ("sub='{0}'" -f $twoShut.Sub)

# The NNR AtLeastOne group is the shape the live lab actually carries.
$nnrShut = Get-PortsCard -Results @(
    (New-Probe 'LdapTcp' 'Required' $true),
    (New-Probe 'NnrNetBios' 'AtLeastOne' $false),
    (New-Probe 'NnrRpc' 'AtLeastOne' $true)
)
Assert-True 'a blocked NNR probe also names itself rather than reading as clean' `
    ($nnrShut.Tone -ne 'ok' -and $nnrShut.Sub -ne 'No required port blocked') `
    ("tone={0} sub='{1}'" -f $nnrShut.Tone, $nnrShut.Sub)

# --- Controls -----------------------------------------------------------------------------------
$allOpen = Get-PortsCard -Results @((New-Probe 'LdapTcp' 'Required' $true))
Assert-True 'control: nothing blocked reads green and says so' `
    ($allOpen.Tone -eq 'ok' -and $allOpen.Sub -eq 'No required port blocked') `
    ("tone={0} sub='{1}'" -f $allOpen.Tone, $allOpen.Sub)

$requiredShut = Get-PortsCard -Results @(
    (New-Probe 'LdapTcp' 'Required' $false),
    (New-Probe 'NnrPtr' 'Recommended' $false)
)
Assert-True 'control: a blocked REQUIRED port still dominates, red and named' `
    ($requiredShut.Tone -eq 'bad' -and $requiredShut.Sub -match 'required port\(s\) blocked') `
    ("tone={0} sub='{1}'" -f $requiredShut.Tone, $requiredShut.Sub)

$untested = Get-PortsCard -Results @(
    (New-Probe 'LdapTcp' 'Required' $true),
    [PSCustomObject]@{ Id = 'RpcTcp'; Name = 'RPC'; Protocol = 'TCP'; Port = 135; Scope = 'DomainController'
        Group = ''; Requirement = 'Required'; Target = 'dc3.contoso.com'; TargetIP = '10.0.0.3'
        Applicable = $true; Success = $null; Detail = 'Not tested - access is denied' }
)
Assert-True 'control: an untested probe is still reported as untested, not as blocked' `
    ($untested.Sub -match 'could not be tested') ("sub='{0}'" -f $untested.Sub)

# The invariant that ties it together: an amber or red card must never carry the all-clear text.
foreach ($case in @(
        @{ Label = 'recommended shut'; Card = $recommendedShut }
        @{ Label = 'NNR shut'; Card = $nnrShut }
        @{ Label = 'required shut'; Card = $requiredShut }
        @{ Label = 'untested'; Card = $untested }
    )) {
    Assert-True ("{0}: a non-green card never reads 'No required port blocked'" -f $case.Label) `
        (-not ($case.Card.Tone -in @('warn', 'bad') -and $case.Card.Sub -eq 'No required port blocked')) `
        ("tone={0} sub='{1}'" -f $case.Card.Tone, $case.Card.Sub)
}

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
