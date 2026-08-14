# Two defects where the generated remediation script and the exit code told the operator something
# that was not true.
#
# 1. Sensor-health findings the generated fix cannot resolve were marked as covered, so they were
#    absent from the script AND erased from the advisory - they vanished from both surfaces while the
#    run ended "Remediation complete", over a domain controller with no sensor installed at all.
# 2. -FailOnIssues computed the exit code twice, differently: the message used Min(count,254) and the
#    exit used Min(Max(count,1),254). A false verdict with zero generated issues announced "exiting
#    with code 0" and then exited 1.

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

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-SensorReport {
    param([string[]] $Issues)
    $dc = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        OSVersion = $true; NPCAP = $true; RequiredPorts = $true; SensorHealth = $false
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() }
            SensorHealthDetails = [PSCustomObject]@{ Installed = $true; Issues = $Issues }
        }
    }
    [PSCustomObject]@{ DomainControllers = @($dc); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @()
    }
}
function Get-Generated {
    param($Report)
    $out = Join-Path $env:TEMP ('sh-{0}.ps1' -f [guid]::NewGuid())
    New-mdiRemediationScript -ReportData $Report -FilePath $out 3>$null | Out-Null
    $g = Get-Content -LiteralPath $out -Raw
    Remove-Item $out -Force -ErrorAction SilentlyContinue
    $g
}

'[sensor health] a finding the fix cannot resolve must still reach the operator'
$notInstalled = @(
    'The AATPSensor service is not installed, although the updater is present'
    'The AATPSensorUpdater service is not installed; the sensor cannot update itself'
)
foreach ($issue in $notInstalled) {
    $g = Get-Generated (New-SensorReport @($issue))
    $advised = @($g -split "`r?`n" | Where-Object { $_ -match [regex]::Escape($issue) -and $_ -match 'Write-Host' }).Count -ge 1
    Assert-That "'$($issue.Substring(0,34))...' is surfaced" $advised
    Assert-That '  ...and the run does not claim to be complete' ($g -notmatch 'Remediation complete')
}

'[sensor health] a finding the fix DOES resolve is not repeated'
$fixable = @(
    'The AATPSensor service is Stopped (start mode: Auto)'
    'The AATPSensor service start mode is Disabled'
    'The AATPSensor service start mode is Manual, not Auto; it will not start after a reboot'
    'The AATPSensorUpdater service start mode is Manual, not Auto; it will not start after a reboot'
)
foreach ($issue in $fixable) {
    $g = Get-Generated (New-SensorReport @($issue))
    $advised = @($g -split "`r?`n" | Where-Object { $_ -match [regex]::Escape($issue) -and $_ -match 'Write-Host' }).Count -ge 1
    Assert-That "'$($issue.Substring(0,34))...' is not repeated as manual" (-not $advised)
}

'[sensor health] the emitted fix really does handle every state it claims'
$g = Get-Generated (New-SensorReport @('The AATPSensor service start mode is Manual, not Auto; it will not start after a reboot'))
Assert-That 'the fix corrects ANY non-Automatic start mode, not only Disabled' ($g -match "StartType -ne 'Automatic'")
Assert-That 'the fix starts a service that is not running' ($g -match "Status -ne 'Running'")
Assert-That 'a missing service is reported rather than passed over' ($g -match 'is not installed on')
$perr = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($g, [ref]$null, [ref]$perr)
Assert-That 'the generated script parses' (@($perr).Count -eq 0)

'[sensor health] the classifier itself'
Assert-That 'a missing service is not claimed as fixable' (
    -not (Test-mdiSensorIssueFixable -Issue 'The AATPSensor service is not installed, although the updater is present'))
Assert-That 'a stopped service is fixable' (
    Test-mdiSensorIssueFixable -Issue 'The AATPSensor service is Stopped (start mode: Auto)')
Assert-That 'a Manual start mode is fixable' (
    Test-mdiSensorIssueFixable -Issue 'The AATPSensor service start mode is Manual, not Auto; it will not start after a reboot')
Assert-That 'an empty issue is not fixable' (-not (Test-mdiSensorIssueFixable -Issue ''))
Assert-That 'a null issue is not fixable' (-not (Test-mdiSensorIssueFixable -Issue $null))

'[exit code] the message and the exit code are the same number'
# Executed as a real process, because an exit code is only observable that way.
$branch = @'
param([int]$issueCount)
$exitCode = [math]::Min([math]::Max($issueCount, 1), 254)
if ($issueCount -gt 254) {
    Write-Warning ('{0} readiness issue(s) found, exiting with code {1} (the exit code is capped at 254 because 255 means the scan did not run).' -f $issueCount, $exitCode)
} else {
    Write-Warning ('{0} readiness issue(s) found, exiting with code {1}' -f $issueCount, $exitCode)
}
exit $exitCode
'@
$branchFile = Join-Path $env:TEMP ('exitbranch-{0}.ps1' -f [guid]::NewGuid())
Set-Content -Path $branchFile -Value $branch -Encoding UTF8
try {
    foreach ($n in 0, 1, 2, 253, 254, 255, 300) {
        $msg = (& powershell -NoProfile -ExecutionPolicy Bypass -File $branchFile -issueCount $n 2>&1 | Out-String)
        $code = $LASTEXITCODE
        $said = if ($msg -match 'exiting with code (\d+)') { [int] $Matches[1] } else { -1 }
        Assert-That "$n issue(s): the message names the code actually used" ($said -eq $code) "(said $said, exited $code)"
        Assert-That "  ...and the code is never 0 for a failed verdict" ($code -ge 1)
        Assert-That "  ...and never collides with the scan-incomplete sentinel" ($code -ne 255)
    }
    # The clamp has to be visible, or 254 reads as an exact count.
    $capped = (& powershell -NoProfile -ExecutionPolicy Bypass -File $branchFile -issueCount 300 2>&1 | Out-String)
    Assert-That 'a clamped count says it was clamped' ($capped -match 'capped at 254')
    $exact = (& powershell -NoProfile -ExecutionPolicy Bypass -File $branchFile -issueCount 12 2>&1 | Out-String)
    Assert-That 'an unclamped count does not' ($exact -notmatch 'capped at 254')
} finally {
    Remove-Item $branchFile -Force -ErrorAction SilentlyContinue
}

# And the shipped branch must be the single-value form, not two separate computations.
$mainText = Get-Content -LiteralPath $target -Raw
Assert-That 'the shipping code computes the exit code once' (
    $mainText -match '\$exitCode = \[math\]::Min\(\[math\]::Max\(\$issueCount, 1\), 254\)' -and
    $mainText -match 'exit \$exitCode')

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
