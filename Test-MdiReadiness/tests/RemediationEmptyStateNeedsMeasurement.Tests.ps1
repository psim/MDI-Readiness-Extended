<#
    The remediation panel must not claim that everything already passes on a run that measured
    nothing.

    Set-MdiReadinessReport builds the panel from $Remediation.SectionCount alone. Zero sections
    means "no fixable finding was recorded", and the panel read that as "every check that this
    script can fix already passes" - a positive statement of fact about the estate. But an estate
    whose domain controllers were ALL unreachable records no fixable finding for exactly the reason
    it records no results: nothing was ever measured. The sentence therefore rendered on a page
    whose hero verdict said "Action required", whose issues card listed five findings, and whose
    tables said "could not be read" fourteen times.

    This is the same false green as the fully-ready KPI tile, one panel further along: a LOST
    measurement must never be reported as a pass. The remediation tab is the page an operator opens
    to decide whether there is any work to do, so a false "nothing to do" here ends the
    investigation.

    Three populations, all of which produced SectionCount = 0:
      - every domain controller unreachable  (checks are charged as unread)
      - no domain controller enumerated at all
      - a domain controller reached but carrying no readable check at all

    Asserted on the RENDERED MARKUP produced by the real Set-MdiReadinessReport, and the panel is
    extracted by anchoring on its own <h3> heading rather than by taking the first .empty-state
    paragraph in the document. The issues card emits an .empty-state paragraph EARLIER in the page
    on a clean estate, so a document-order match reads the wrong card and the control comparison
    then passes for the wrong reason - which is precisely how the first version of the probe that
    found this defect misreported itself.

    The clean control carries as much weight as the defect cases: deleting the sentence outright
    would also "fix" this, and would strip the one honest reassurance the report gives a genuinely
    healthy estate. A fully measured, fully passing run must still say "already passes".
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

$CLAIM = 'every check that this script can fix already passes'

function New-Dc {
    param([string] $Fqdn, [bool] $Unreachable = $false, [string] $Comment = '', [bool] $NoChecks = $false)
    $o = [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $Unreachable; PartialFailure = $false; Comment = $Comment
        MachineType = 'Physical'; Details = [ordered]@{}
    }
    if (-not $NoChecks) {
        $value = if ($Unreachable) { 'N/A' } else { $true }
        $o | Add-Member -NotePropertyName PowerScheme -NotePropertyValue $value
        $o | Add-Member -NotePropertyName AdvancedAuditing -NotePropertyValue $value
        $o | Add-Member -NotePropertyName NtlmAuditing -NotePropertyValue $value
    }
    $o
}

function New-Report {
    param($Dcs)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($Dcs); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
        SkippedAreas = @('Network ports', 'Entra Connect servers', 'Sensor v3.x readiness')
    }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remedempty-' + [guid]::NewGuid().ToString('N').Substring(0, 8))

function Get-RemediationPanel {
    param($Report, [string] $Name)
    $dir = Join-Path $root $Name
    [void] (New-Item -ItemType Directory -Path $dir -Force)
    $SkipNetworkPorts = $true; $SkipSensorV3Readiness = $true; $SkipCA = $true; $SkipEntraConnect = $true
    $remediation = [PSCustomObject]@{ SectionCount = 0; Path = 'C:\reports\Fix-MdiReadiness-contoso.com.ps1' }
    $written = Set-MdiReadinessReport -Domain $Report.Domain -Path $dir -ReportData $Report -SkipTrend -Remediation $remediation
    $html = [IO.File]::ReadAllText([IO.Path]::GetFullPath($written))
    $stats = Get-mdiReportStatistics -ReportData $Report
    [PSCustomObject]@{
        Panel  = ([regex]::Match($html, '<h3>Remediation script</h3>(.*?)</div>', 'Singleline')).Groups[1].Value.Trim()
        Total  = [int] $stats.ChecksTotal
        Unread = [int] $stats.ChecksUnread
    }
}

try {
    '[remediation empty state] a run that measured nothing must not claim everything passes'
    foreach ($case in @(
            @{ Name = 'all-DCs-unreachable'
               Report = (New-Report @(
                    (New-Dc -Fqdn 'dc1.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable'),
                    (New-Dc -Fqdn 'dc2.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable'),
                    (New-Dc -Fqdn 'dc3.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable'))) }
            @{ Name = 'no-DCs-enumerated'; Report = (New-Report @()) }
            @{ Name = 'reachable-but-no-readable-check'
               Report = (New-Report @( (New-Dc -Fqdn 'dc1.contoso.com' -NoChecks $true) )) }
        )) {
        $r = Get-RemediationPanel -Report $case.Report -Name $case.Name
        Assert-That ("{0}: nothing was measured" -f $case.Name) ($r.Total -eq 0) "(ChecksTotal=$($r.Total))"
        Assert-That ("{0}: the panel does not claim every check already passes" -f $case.Name) `
            ($r.Panel -notmatch [regex]::Escape($CLAIM)) "(panel='$($r.Panel)')"
        Assert-That ("{0}: the panel still says something" -f $case.Name) `
            ($r.Panel -match '<p') "(panel='$($r.Panel)')"
    }

    '[remediation empty state] an unread check is named, not silently dropped'
    $unread = Get-RemediationPanel -Report (New-Report @(
            (New-Dc -Fqdn 'dc1.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable'),
            (New-Dc -Fqdn 'dc2.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable'),
            (New-Dc -Fqdn 'dc3.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable'))) -Name 'unread-named'
    Assert-That 'the unreachable estate charges unread checks' ($unread.Unread -gt 0) "(unread=$($unread.Unread))"
    Assert-That 'the panel reports that checks could not be read' `
        ($unread.Panel -match 'could not be read') "(panel='$($unread.Panel)')"
    Assert-That 'the panel states how many were not read' `
        ($unread.Panel -match ('\b' + $unread.Unread + '\b')) "(unread=$($unread.Unread) panel='$($unread.Panel)')"

    '[remediation empty state] a fully measured, fully passing estate still reads as clean'
    $control = Get-RemediationPanel -Report (New-Report @( (New-Dc -Fqdn 'dc1.contoso.com') )) -Name 'CONTROL-measured-allpass'
    Assert-That 'the control measured checks' ($control.Total -gt 0) "(ChecksTotal=$($control.Total))"
    Assert-That 'the control has nothing unread' ($control.Unread -eq 0) "(unread=$($control.Unread))"
    Assert-That 'the control still says every check already passes' `
        ($control.Panel -match [regex]::Escape($CLAIM)) "(panel='$($control.Panel)')"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
