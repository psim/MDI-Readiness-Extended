<#
    Behavioural regression tests for the two status/measurement flags that decide whether a result
    counts at all.

    Both defects here are the same shape - a raw value tested for bare truthiness, where every
    non-empty string in PowerShell is true - and both produced a FALSE RED, which on this tool means
    an administrator is sent to change a production domain controller that was already correct.

      * Unreachable carrying the STRING 'False' (what a JSON round trip through another tool
        produces) moved a server that had explicitly been RECORDED AS REACHED into the unreachable
        population: its checks vanished from the statistics, a Connectivity finding was raised, and
        the verdict flipped to not ready.

      * A port probe whose Success normalised to $null - no result at all - was counted as a MEASURED
        BLOCKED PORT, because "-not $null" is $true.

    Every assertion runs the real aggregation and reads the answer. The three surfaces an operator
    acts on - the statistics, the issue list and the verdict - are checked TOGETHER, because the
    recurring failure on this project is not that one of them is wrong, it is that they disagree.
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

Write-Host 'StatusFlagNormalisation.Tests.ps1' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------
# Unreachable
# ---------------------------------------------------------------------------------------------
function New-FlagReport {
    param($Unreachable)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @([PSCustomObject]@{
                FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $Unreachable
                OperatingSystem = 'Windows Server 2022'
                NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true
                Details = [ordered]@{}
            })
        CAServers = @(); EntraConnectServers = @()
    }
}
function Get-FlagAnswer {
    param($Unreachable)
    $report = New-FlagReport -Unreachable $Unreachable
    $stats = Get-mdiReportStatistics -ReportData $report
    [PSCustomObject]@{
        Reachable   = $stats.ReachableServers
        Unreachable = $stats.UnreachableCount
        Issues      = @(Get-mdiIssueList -Statistics $stats -ReportData $report).Count
        Ready       = (Test-mdiReadinessResult -ReportData $report)
    }
}

# A value that says "reached" - in any form the report can carry it - must leave the server measured.
foreach ($case in @(
        @{ Label = '$false'; Value = $false }
        @{ Label = "the string 'False'"; Value = 'False' }
        @{ Label = "the string '0'"; Value = '0' }
        @{ Label = '$null'; Value = $null }
        @{ Label = "an empty string"; Value = '' }
        @{ Label = 'the integer 0'; Value = 0 }
        @{ Label = "an unrecognised word"; Value = 'Unknown' }
    )) {
    $a = Get-FlagAnswer -Unreachable $case.Value
    Assert-True ("Unreachable = {0} leaves the server in the measured population" -f $case.Label) `
        ($a.Reachable -eq 1 -and $a.Unreachable -eq 0) ("reachable={0} unreachable={1}" -f $a.Reachable, $a.Unreachable)
    Assert-True ("Unreachable = {0} raises no connectivity finding" -f $case.Label) ($a.Issues -eq 0) ("issues={0}" -f $a.Issues)
    Assert-True ("Unreachable = {0} does not fail the verdict" -f $case.Label) ($a.Ready -eq $true) ("ready={0}" -f $a.Ready)
}

# A value that genuinely says "missed" must still fail the run, in every form.
foreach ($case in @(
        @{ Label = '$true'; Value = $true }
        @{ Label = "the string 'True'"; Value = 'True' }
        @{ Label = 'the integer 1'; Value = 1 }
    )) {
    $a = Get-FlagAnswer -Unreachable $case.Value
    Assert-True ("Unreachable = {0} still counts the server as missed" -f $case.Label) `
        ($a.Unreachable -eq 1 -and $a.Reachable -eq 0) ("reachable={0} unreachable={1}" -f $a.Reachable, $a.Unreachable)
    Assert-True ("Unreachable = {0} still raises a finding" -f $case.Label) ($a.Issues -ge 1) ("issues={0}" -f $a.Issues)
    Assert-True ("Unreachable = {0} still fails the verdict" -f $case.Label) ($a.Ready -eq $false) ("ready={0}" -f $a.Ready)
}

Assert-True 'the predicate rejects a null server rather than throwing' ((Test-mdiServerIsUnreachable -Server $null) -eq $false)

# ---------------------------------------------------------------------------------------------
# Port probe Success
# ---------------------------------------------------------------------------------------------
function New-PortReport {
    param($Success)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @([PSCustomObject]@{
                FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
                OperatingSystem = 'Windows Server 2022'
                # Passing checks so the ONLY variable in these cases is the port result. Without them
                # the run measures nothing at all and the verdict correctly refuses READY for a
                # different reason, which would mask what this test is asking about.
                NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true
                Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{
                        ProbedFrom = 'dc1.contoso.com'; FailedRequired = @(); NnrFailedTargets = @()
                        Results = @([PSCustomObject]@{
                                Id = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
                                Scope = 'DomainController'; Group = ''; Requirement = 'Required'
                                Target = 'dc2.contoso.com'; TargetIP = '10.0.0.2'
                                Applicable = $true; Success = $Success; Detail = 'Connected' })
                    } }
            })
        CAServers = @(); EntraConnectServers = @()
    }
}
function Get-PortAnswer {
    param($Success)
    $report = New-PortReport -Success $Success
    $stats = Get-mdiReportStatistics -ReportData $report
    [PSCustomObject]@{
        Open     = $stats.PortsOpen
        Blocked  = $stats.PortsBlocked
        Untested = $stats.PortsUntested
        Issues   = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
        Ready    = (Test-mdiReadinessResult -ReportData $report)
        Html     = (Get-mdiRequiredPortsHtml -Server @($report.DomainControllers))
    }
}

# A probe that produced no usable result measured nothing. It must never be reported as blocked -
# that is what sends an operator to open a firewall port on a probe that never ran.
foreach ($case in @(
        @{ Label = '$null'; Value = $null }
        @{ Label = "an empty string"; Value = '' }
        @{ Label = "an unrecognised word"; Value = 'Unknown' }
    )) {
    $a = Get-PortAnswer -Success $case.Value
    Assert-True ("a required probe whose Success is {0} is not counted as blocked" -f $case.Label) `
        ($a.Blocked -eq 0) ("open={0} blocked={1} untested={2}" -f $a.Open, $a.Blocked, $a.Untested)
    Assert-True ("a required probe whose Success is {0} is counted as untested" -f $case.Label) `
        ($a.Untested -eq 1) ("untested={0}" -f $a.Untested)
    Assert-True ("a required probe whose Success is {0} is not counted as open either" -f $case.Label) ($a.Open -eq 0)
    Assert-True ("a required probe whose Success is {0} does not raise a Network finding" -f $case.Label) `
        (@($a.Issues | Where-Object { [string] $_.Area -eq 'Network' }).Count -eq 0) `
        ((@($a.Issues | ForEach-Object { [string] $_.Area }) -join ',')) 
    Assert-True ("a required probe whose Success is {0} is not listed in the ports-that-need-attention table" -f $case.Label) `
        ($a.Html -notmatch 'Ports that need attention') ''
}

# The measured cases must be untouched.
$measuredFail = Get-PortAnswer -Success $false
Assert-True 'a measured blocked port is still blocked' ($measuredFail.Blocked -eq 1 -and $measuredFail.Untested -eq 0) `
    ("open={0} blocked={1} untested={2}" -f $measuredFail.Open, $measuredFail.Blocked, $measuredFail.Untested)
Assert-True 'a measured blocked port still fails the verdict' ($measuredFail.Ready -eq $false)
Assert-True 'a measured blocked port is still listed for attention' ($measuredFail.Html -match 'Ports that need attention')

$measuredOk = Get-PortAnswer -Success $true
Assert-True 'a measured open port is still open' ($measuredOk.Open -eq 1 -and $measuredOk.Blocked -eq 0 -and $measuredOk.Untested -eq 0) `
    ("open={0} blocked={1} untested={2}" -f $measuredOk.Open, $measuredOk.Blocked, $measuredOk.Untested)
Assert-True 'a measured open port keeps the run ready' ($measuredOk.Ready -eq $true)

# A JSON round trip stores booleans as strings; those are measurements and must survive as such.
$roundTripped = Get-PortAnswer -Success 'False'
Assert-True 'a round-tripped Success of the string False is still a measured block' ($roundTripped.Blocked -eq 1) `
    ("open={0} blocked={1} untested={2}" -f $roundTripped.Open, $roundTripped.Blocked, $roundTripped.Untested)
$roundTrippedOk = Get-PortAnswer -Success 'True'
Assert-True 'a round-tripped Success of the string True is still a measured pass' ($roundTrippedOk.Open -eq 1) `
    ("open={0} blocked={1} untested={2}" -f $roundTrippedOk.Open, $roundTrippedOk.Blocked, $roundTrippedOk.Untested)

Assert-True 'the measured predicate rejects a record with no boolean Success' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $true; Success = $null; Detail = 'Connected' })) -eq $false)
Assert-True 'and accepts one that carries a real result' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $true; Success = $false; Detail = 'Refused' })) -eq $true)

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
