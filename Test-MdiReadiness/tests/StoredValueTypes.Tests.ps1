<#
    Regression tests for the "a stored value is not the type the code assumed" family.

    Every one of these shipped as a false green: PowerShell treats every non-empty string as true, so a
    check recorded as the string 'False' read as a pass, and a check that was neither [bool] nor 'N/A'
    disappeared from the tally altogether.
#>

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0

function Assert-Equal {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") {
        $script:pass++
        Write-Host ('  PASS {0}' -f $Name)
    } else {
        $script:fail++
        Write-Host ('  FAIL {0} -- expected [{1}] got [{2}]' -f $Name, $Expected, $Actual) -ForegroundColor Red
    }
}

$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content $scriptPath -Raw
$text = $text -replace '(?m)^#Requires.*$', ''
$text = $text -replace '\[CmdletBinding\([^)]*\)\]', ''
$mainIndex = $text.IndexOf('#region Main')
if ($mainIndex -gt 0) { $text = $text.Substring(0, $mainIndex) }
Invoke-Expression $text

function New-Server {
    param($AdvancedAuditing = $true, $Extra = @{})
    $o = [ordered]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
        AdvancedAuditing = $AdvancedAuditing
        NtlmAuditing = $true; PowerSettings = $true; SensorHealth = $true; TimeSync = $true; RequiredPorts = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom = 'dc1'; FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
    foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
    [PSCustomObject] $o
}
function New-Report { param($S) [PSCustomObject]@{ DomainControllers = @($S); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domain = 'contoso.com' } }
function Measure-Server {
    param($Server)
    $r = New-Report $Server
    $stats = Get-mdiReportStatistics -ReportData $r
    $score = @($stats.ServerScores)[0]
    [PSCustomObject]@{
        Passed = $score.Passed; Total = $score.Total; Failed = $score.Failed; Unread = $score.Unread
        Ready = @($stats.ServerScores | Where-Object { $_.Total -gt 0 -and $_.Failed -eq 0 -and $_.Unread -eq 0 }).Count
        Issues = @(Get-mdiIssueList -Statistics $stats -ReportData $r).Count
        Verdict = Test-mdiReadinessResult -ReportData $r 3>$null
    }
}

Write-Host 'ConvertTo-mdiBoolean only promotes a value that really is a boolean'
Assert-Equal 'a real $true' $true (ConvertTo-mdiBoolean $true)
Assert-Equal 'a real $false' $false (ConvertTo-mdiBoolean $false)
Assert-Equal 'the string True' $true (ConvertTo-mdiBoolean 'True')
Assert-Equal 'the string False' $false (ConvertTo-mdiBoolean 'False')
Assert-Equal 'mixed case is still parsed' $false (ConvertTo-mdiBoolean 'fAlSe')
Assert-Equal 'surrounding whitespace is tolerated' $false (ConvertTo-mdiBoolean '  False  ')
foreach ($notBool in @('N/A', '', '   ', 'yes', 'no', '1', '0', 'Windows Server 2022', 'Wahr')) {
    Assert-Equal ("'{0}' is not a measurement" -f $notBool) $true ($null -eq (ConvertTo-mdiBoolean $notBool))
}
Assert-Equal 'null is not a measurement' $true ($null -eq (ConvertTo-mdiBoolean $null))

Write-Host 'A check stored as a string behaves exactly like the boolean it names'
$real = Measure-Server (New-Server -AdvancedAuditing $false)
$stringy = Measure-Server (New-Server -AdvancedAuditing 'False')
Assert-Equal 'the string False scores like $false' $real.Passed $stringy.Passed
Assert-Equal 'the string False has the same total' $real.Total $stringy.Total
Assert-Equal 'the string False fails like $false' $real.Failed $stringy.Failed
Assert-Equal 'the string False keeps the server out of ready' 0 $stringy.Ready
Assert-Equal 'the string False raises an issue' $true ($stringy.Issues -ge 1)
Assert-Equal 'the string False fails the verdict' $false $stringy.Verdict

$passing = Measure-Server (New-Server -AdvancedAuditing $true)
$stringyTrue = Measure-Server (New-Server -AdvancedAuditing 'True')
Assert-Equal 'the string True scores like $true' $passing.Passed $stringyTrue.Passed
Assert-Equal 'the string True is still ready' 1 $stringyTrue.Ready
Assert-Equal 'the string True passes the verdict' $true $stringyTrue.Verdict

Write-Host 'A descriptive field is never mistaken for a readiness check'
# These carry text, and 'False' in a descriptive field is a value, not a verdict. The informational
# names are excluded by name, so a scan that happened to record one of these must not lose a check or
# gain one.
$baseline = Measure-Server (New-Server)
$withDescriptive = Measure-Server (New-Server -Extra @{
        OS = 'Windows Server 2022'; MachineType = 'Physical'; SensorVersion = '2.245.0'
        CapturingComponent = 'Npcap'; IP = '10.0.0.1'; Comment = 'False'
    })
Assert-Equal 'descriptive fields do not add checks' $baseline.Total $withDescriptive.Total
Assert-Equal 'descriptive fields do not change the score' $baseline.Passed $withDescriptive.Passed
Assert-Equal 'the estate is still ready' 1 $withDescriptive.Ready

Write-Host 'The measurement decides RequiredPorts, whatever the summary flag says'
$blocked = [PSCustomObject]@{ Group = 'LDAP'; Protocol = 'TCP'; Port = 389; Target = 'dc1.contoso.com'
    TargetIP = '10.0.0.1'; Success = $false; Applicable = $true; Detail = 'Connection refused'; Requirement = 'Required' }
$srv = New-Server
$srv.Details.RequiredPortsDetails.Results = @($blocked)
$effective = @(Get-mdiEffectiveCheckProperty -Server $srv | Where-Object { $_.Name -eq 'RequiredPorts' })
Assert-Equal 'RequiredPorts appears exactly once' 1 $effective.Count
Assert-Equal 'the effective value is the measurement, not the summary' $false $effective[0].Value
$m = Measure-Server $srv
Assert-Equal 'the score records the failure' 1 $m.Failed
Assert-Equal 'the server is not ready' 0 $m.Ready
Assert-Equal 'the verdict is not ready' $false $m.Verdict

Write-Host 'The domain controller table reads the same resolver as the score'
# The table is built by a script block nested inside Set-MdiReadinessReport and closes over variables
# from that function, so it cannot be invoked standalone. It is located with the parser and its own AST
# is inspected instead: the guarantee that matters is that it resolves each check through
# Get-mdiEffectiveCheckProperty rather than reading the raw property, because reading the raw property
# is exactly what let this table paint RequiredPorts green while the score, the KPI counts, the verdict
# and the Issues table all reported it as failed.
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $null, [ref] $null)
$assignment = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$convertServerTable'
    }, $true) | Select-Object -First 1
Assert-Equal 'the server table builder was found' $true ($null -ne $assignment)
if ($assignment) {
    $blockText = $assignment.Right.Extent.Text
    Assert-Equal 'it resolves checks through the effective view' $true ($blockText -match 'Get-mdiEffectiveCheckProperty')
    Assert-Equal 'it no longer reads the raw property for check columns' $false ($blockText -match '\$cell = if \(\$null -eq \$value\)')
    # And the resolver itself must return the measurement, which is what the table now renders.
    $effectivePorts = @(Get-mdiEffectiveCheckProperty -Server $srv | Where-Object { $_.Name -eq 'RequiredPorts' })[0].Value
    Assert-Equal 'the value the table will render is the measurement' $false $effectivePorts
    $renderedPasses = @(Get-mdiEffectiveCheckProperty -Server $srv | Where-Object { $_.Value -eq $true }).Count
    Assert-Equal 'the number of passing cells matches the score' $m.Passed $renderedPasses
}

Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
