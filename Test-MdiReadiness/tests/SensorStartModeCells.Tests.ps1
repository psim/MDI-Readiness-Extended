<#
    A coloured cell is an assertion, and it must agree with the finding on its own row.

    Two defects in the sensor health table, both live on a normal scan:

    1. The start mode cell was classified `if ($health.SensorStartMode -eq 'Disabled') { 'red' }
       else { 'green' }`. Only Disabled was red, so a sensor set to start MANUALLY was painted green
       on the same row whose Detail column read, in red, "The AATPSensor service start mode is
       Manual, not Auto; it will not start after a reboot". Get-mdiSensorHealth raises a finding for
       ANY non-Auto start mode and sets SensorHealth = $false, so the green cell contradicted the
       finding beside it, the KPI, the score and the verdict. A sensor that stops monitoring the
       domain controller at the next restart is precisely what that column exists to show.

    2. UpdaterStartMode was produced by Get-mdiSensorHealth (line 3267) and never rendered at all.
       An updater set to Manual raised its finding in the Detail column and was invisible in the
       table, which is the column an operator scans to find which server to fix.

    Both cells now come from one classifier that mirrors the producer's own rule: 'Auto' is healthy,
    anything else is not, and 'n/a' is neither.
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

# Built by the REAL producer so the shape cannot drift into one the script never emits.
function New-SensorServer {
    param($SensorStart = 'Auto', $UpdaterStart = 'Auto', $SensorState = 'Running', $UpdaterState = 'Running')
    $issues = New-Object System.Collections.ArrayList
    if ($SensorStart -eq 'Disabled') { [void] $issues.Add('The AATPSensor service start mode is Disabled') }
    elseif ($SensorStart -ne 'Auto') { [void] $issues.Add('The AATPSensor service start mode is ' + $SensorStart + ', not Auto; it will not start after a reboot') }
    if ($UpdaterStart -eq 'Disabled') { [void] $issues.Add('The AATPSensorUpdater service start mode is Disabled') }
    elseif ($UpdaterStart -ne 'Auto') { [void] $issues.Add('The AATPSensorUpdater service start mode is ' + $UpdaterStart + ', not Auto; it will not start after a reboot') }

    $o = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; Comment = $null
        SensorVersion = '2.240.0.0'; Details = [PSCustomObject]@{}
    }
    $o | Add-Member -NotePropertyName SensorHealth -NotePropertyValue ($issues.Count -eq 0) -Force
    $o.Details | Add-Member -NotePropertyName SensorHealthDetails -NotePropertyValue ([PSCustomObject]@{
            Installed = $true; SensorService = $SensorState; SensorStartMode = $SensorStart
            UpdaterService = $UpdaterState; UpdaterStartMode = $UpdaterStart
            Issues = $issues.ToArray()
            Detail = $(if ($issues.Count -eq 0) { 'Sensor and updater services are running' } else { $issues.ToArray() -join '; ' })
        }) -Force
    $o
}

function Get-SensorRow {
    param($Server)
    $html = (Get-mdiSensorHealthHtml -Server @($Server)) -join "`n"
    $m = [regex]::Match($html, '<tr><td class="mono">dc1\.contoso\.com</td>.*?</tr>', 'Singleline')
    if (-not $m.Success) { return '' }
    $m.Value
}
# Returns the class of the cell whose text is $Value.
function Get-CellClass {
    param($Row, $Value)
    $m = [regex]::Match($Row, '<td class="([^"]+)">' + [regex]::Escape($Value) + '</td>')
    if ($m.Success) { return $m.Groups[1].Value }
    '(absent)'
}

Write-Host 'A non-Auto start mode is never green' -ForegroundColor Cyan
$manual = Get-SensorRow (New-SensorServer -SensorStart 'Manual')
Assert-That 'the Manual sensor start mode is rendered' ($manual -match '>Manual<') "(row: $manual)"
Assert-That '  ...and its cell is NOT green' ((Get-CellClass $manual 'Manual') -ne 'green') "(class $(Get-CellClass $manual 'Manual'))"
Assert-That '  ...it is red, matching the finding on the same row' (
    (Get-CellClass $manual 'Manual') -eq 'red') "(class $(Get-CellClass $manual 'Manual'))"
Assert-That '  ...and the row still carries the red detail' ($manual -match 'will not start after a reboot')

$disabled = Get-SensorRow (New-SensorServer -SensorStart 'Disabled')
Assert-That 'a Disabled start mode is still red' ((Get-CellClass $disabled 'Disabled') -eq 'red')

Write-Host 'The updater start mode has its own cell' -ForegroundColor Cyan
$updManual = Get-SensorRow (New-SensorServer -UpdaterStart 'Manual')
Assert-That 'a Manual UPDATER start mode is rendered at all' ($updManual -match '>Manual<') "(row: $updManual)"
Assert-That '  ...and it is red' ((Get-CellClass $updManual 'Manual') -eq 'red') "(class $(Get-CellClass $updManual 'Manual'))"
Assert-That '  ...the header names the column' (
    ((Get-mdiSensorHealthHtml -Server @((New-SensorServer))) -join "`n") -match 'Updater start mode')

Write-Host 'A healthy sensor is still green throughout' -ForegroundColor Cyan
$healthy = Get-SensorRow (New-SensorServer)
Assert-That 'Auto is green' ((Get-CellClass $healthy 'Auto') -eq 'green') "(class $(Get-CellClass $healthy 'Auto'))"
Assert-That '  ...and the detail is not red' ($healthy -notmatch 'class="left red"')

Write-Host 'Every row has the same number of cells as the header' -ForegroundColor Cyan
# Adding a column is only safe if every branch was updated; a short row silently shifts the data
# under the wrong heading, which is worse than the defect being fixed.
function Get-CellCount { param($Row) ([regex]::Matches($Row, '<td[ >]')).Count }
$headerHtml = (Get-mdiSensorHealthHtml -Server @((New-SensorServer))) -join "`n"
$headerCells = ([regex]::Matches($headerHtml, '<th[ >]')).Count
Assert-That 'the header has 8 columns' ($headerCells -eq 8) "(got $headerCells)"

# The four row branches: healthy, unreadable, half-installed, and not installed.
$unreadable = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; SensorVersion = 'N/A'
    Details = [PSCustomObject]@{ SensorHealthDetails = [PSCustomObject]@{ Installed = 'N/A'; Detail = 'WMI unreadable' } }
}
$notInstalled = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; SensorVersion = 'N/A'
    Details = [PSCustomObject]@{ SensorHealthDetails = [PSCustomObject]@{ Installed = $false; Detail = 'No sensor installed' } }
}
$halfInstalled = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; SensorVersion = 'N/A'
    Details = [PSCustomObject]@{ SensorHealthDetails = [PSCustomObject]@{
            Installed = $false; SensorService = 'Not installed'; SensorStartMode = 'n/a'
            UpdaterService = 'Running'; UpdaterStartMode = 'Auto'; Detail = 'Updater present without the sensor'
        } }
}
$halfInstalled | Add-Member -NotePropertyName SensorHealth -NotePropertyValue $false -Force

foreach ($case in @(
        @{ Label = 'healthy'; Server = (New-SensorServer) }
        @{ Label = 'unreadable'; Server = $unreadable }
        @{ Label = 'not installed'; Server = $notInstalled }
        @{ Label = 'half installed'; Server = $halfInstalled }
    )) {
    $row = Get-SensorRow $case.Server
    $n = Get-CellCount $row
    Assert-That ('{0} row has 8 cells like the header' -f $case.Label) ($n -eq $headerCells) "(got $n, header $headerCells)"
}

Write-Host 'The classifier itself' -ForegroundColor Cyan
Assert-That 'Auto is green' ((Get-mdiStartModeClass -StartMode 'Auto') -eq 'green')
Assert-That 'Manual is red' ((Get-mdiStartModeClass -StartMode 'Manual') -eq 'red')
Assert-That 'Disabled is red' ((Get-mdiStartModeClass -StartMode 'Disabled') -eq 'red')
Assert-That "'n/a' is grey, not a failure" ((Get-mdiStartModeClass -StartMode 'n/a') -eq 'grey')
Assert-That "'Not installed' is grey" ((Get-mdiStartModeClass -StartMode 'Not installed') -eq 'grey')
Assert-That '$null is grey' ((Get-mdiStartModeClass -StartMode $null) -eq 'grey')
Assert-That 'an empty string is grey' ((Get-mdiStartModeClass -StartMode '') -eq 'grey')

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
