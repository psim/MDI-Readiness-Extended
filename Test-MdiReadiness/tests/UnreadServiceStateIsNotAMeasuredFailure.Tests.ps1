# A SERVICE STATE NOBODY READ WAS PAINTED RED, THE COLOUR OF A MEASURED FAILURE
#
# The sensor health card coloured its two service-state columns with an expression written inline,
# three times over:
#
#     $sensorClass = if ([string] $health.SensorService -eq 'Running') { 'green' }
#                    elseif ([string] $health.SensorService -eq 'Not installed') { 'grey' }
#                    else { 'red' }
#
# and printed the SAME rendering as the cell text. A bare [string] cast tests the RENDERING, not the
# value, so a state nobody read matched neither branch and fell through to the else: RED, which on
# this page means a measured failure. Measured on the shipped renderer with Installed reading TRUE
# and the state replaced one shape at a time - the class, and the text shown in the same cell:
#
#     ''      red  (empty)      $null   red  (empty)      '   '  red  (whitespace)
#     'N/A'   red  N/A          @{}     red  System.Collections.Hashtable
#     $true   red  True         12345   red  12345        @(..)  red  Running Stopped
#
# All eight carried the SAME class as a genuinely Stopped service, so a reader could not tell a
# service that FAILED from one nobody READ - and three of them printed a rendered .NET object to the
# operator as if it were a service state.
#
# THE SHARPEST CASE: with the server's own SensorHealth tri-state set to 'N/A' - meaning the check
# was not measured - the cell was STILL red. The page asserted a measured failure on a row whose own
# tri-state said no measurement had been taken.
#
# IT IS NOT CONTRIVED. Get-mdiSensorHealth builds the value as
#     $sensorState = if ($sensor) { [string] $sensor.State } else { 'Not installed' }
# so a service object present but carrying no State renders to '' - and '' is not the service control
# manager's 'Unknown' token, so it BYPASSES the undetermined path that function builds so carefully
# (isSensorHealthOk = 'N/A' when the SCM says Unknown) and arrives here looking like a real answer.
#
# AND THE COLUMN NEXT TO IT ALREADY GOT THIS RIGHT, which makes it a contradiction rather than a gap:
# Get-mdiStartModeClass is an extracted helper that returns grey for a blank value and for 'n/a'. So
# on ONE ROW, describing ONE service, the start-mode cell called an unread value grey while the
# service-state cell beside it called the same unread value red.
#
# THE FIX: a sibling helper, Get-mdiServiceStateClass, used at all three sites, testing the TYPE
# before comparing; and Get-mdiServiceStateText so the words and the colour cannot disagree. An
# unreadable state is 'muted-cell' and reads 'Not tested' - deliberately NOT grey, because grey on
# this page means "not applicable, there is no service", which is a different claim from "we could
# not read it". 'muted-cell' is the class the unknown-install row already uses for exactly that.
#
# WHAT THIS TEST PINS:
#   1. Every unreadable shape is muted-cell and reads 'Not tested', on BOTH columns.
#   2. The three real states are unchanged - Running green, Stopped red, Not installed grey. Without
#      this a "fix" that muted everything would pass, and muting a genuinely stopped sensor would be
#      far worse than the defect.
#   3. No rendered .NET type name is ever printed as a service state.
#   4. The half-installed branch, which carries its own copy of the expression, is covered too.
#   5. The two helpers agree with each other, and with the sibling Get-mdiStartModeClass, about what
#      "not read" means.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Srv {
    param($SensorService, $UpdaterService = 'Running', $Installed = $true, $Health = $true)
    [PSCustomObject]@{
        FQDN          = 'dcfab01.fabrikam.local'
        SensorHealth  = $Health
        SensorVersion = '2.245.0.0'
        Details       = [PSCustomObject]@{
            SensorHealthDetails = [PSCustomObject]@{
                Installed = $Installed; SensorService = $SensorService; SensorStartMode = 'Auto'
                UpdaterService = $UpdaterService; UpdaterStartMode = 'Auto'
                Detail = 'Sensor and updater services are running'
            }
        }
    }
}

# Read the CELL the operator actually looks at, by position, rather than searching the whole page.
function Get-Cell {
    param($Html, [int] $Index)
    $row = @($Html -split '<tr>' | Where-Object { $_ -match 'dcfab01' })
    if ($row.Count -eq 0) { return [PSCustomObject]@{ Class = '<no row>'; Text = '<no row>' } }
    $cells = [regex]::Matches($row[0], '<td[^>]*class="([^"]*)"[^>]*>(.*?)</td>')
    if ($cells.Count -le $Index) { return [PSCustomObject]@{ Class = '<no cell>'; Text = '<no cell>' } }
    [PSCustomObject]@{ Class = $cells[$Index].Groups[1].Value; Text = $cells[$Index].Groups[2].Value }
}

$unreadable = [ordered]@{
    'empty string' = ''; 'null' = $null; 'whitespace' = '   '; 'the token N/A' = 'N/A'
    'hashtable' = @{}; 'array' = @('Running', 'Stopped'); 'boolean' = $true; 'number' = 12345
}

''
'[unchanged] the three real states must keep their meaning'
foreach ($known in @(
        @{ State = 'Running'; Class = 'green' }
        @{ State = 'Stopped'; Class = 'red' }
        @{ State = 'Not installed'; Class = 'grey' }
        @{ State = 'Paused'; Class = 'red' }
        @{ State = 'Start Pending'; Class = 'red' }
    )) {
    $c = Get-Cell -Html (Get-mdiSensorHealthHtml -Server @(New-Srv $known.State)) -Index 2
    Assert-That "a service reading '$($known.State)' is still $($known.Class)" ($c.Class -eq $known.Class) "got $($c.Class)"
    Assert-That "a service reading '$($known.State)' still prints its own state" ($c.Text -eq $known.State) "got $($c.Text)"
}

''
'[the defect] an unread service state must not be painted as a measured failure'
foreach ($k in $unreadable.Keys) {
    $html = Get-mdiSensorHealthHtml -Server @(New-Srv $unreadable[$k])
    $c = Get-Cell -Html $html -Index 2
    Assert-That "an unread sensor state ($k) is not red" ($c.Class -ne 'red') "class=$($c.Class)"
    Assert-That "an unread sensor state ($k) is muted-cell" ($c.Class -eq 'muted-cell') "class=$($c.Class)"
    Assert-That "an unread sensor state ($k) reads 'Not tested'" ($c.Text -eq 'Not tested') "text=$($c.Text)"
    # No rendered object may ever be shown to the operator as a service state.
    Assert-That "an unread sensor state ($k) never prints a .NET type name" `
    (-not ($html -match 'System\.Collections\.|System\.Object\[')) 'a rendered object is in the page'
}

''
'[the defect] the UPDATER column carries the same rule'
foreach ($k in $unreadable.Keys) {
    $c = Get-Cell -Html (Get-mdiSensorHealthHtml -Server @(New-Srv 'Running' $unreadable[$k])) -Index 4
    Assert-That "an unread updater state ($k) is muted-cell and not red" `
    ($c.Class -eq 'muted-cell') "class=$($c.Class)"
    Assert-That "an unread updater state ($k) reads 'Not tested'" ($c.Text -eq 'Not tested') "text=$($c.Text)"
}
# ...and the sensor column beside it is untouched when only the updater is unreadable.
$mixed = Get-Cell -Html (Get-mdiSensorHealthHtml -Server @(New-Srv 'Running' @{})) -Index 2
Assert-That 'an unread UPDATER does not disturb a readable SENSOR cell' ($mixed.Class -eq 'green') "class=$($mixed.Class)"

''
'[the contradiction] the row must not assert a failure its own tri-state says was never measured'
$naRow = Get-Cell -Html (Get-mdiSensorHealthHtml -Server @(New-Srv '' 'Running' $true 'N/A')) -Index 2
Assert-That 'SensorHealth N/A with an unread service is not painted red' ($naRow.Class -ne 'red') "class=$($naRow.Class)"

''
'[the half-installed branch] it carries its own copy of the expression'
# Installed reads FALSE and SensorHealth is FALSE - the half-installed sensor row, which renders the
# updater cell through the same rule.
$half = Get-Cell -Html (Get-mdiSensorHealthHtml -Server @(New-Srv 'Stopped' @{} $false $false)) -Index 4
Assert-That 'the half-installed row does not paint an unread updater red' ($half.Class -ne 'red') "class=$($half.Class)"
Assert-That 'the half-installed row reads Not tested for an unread updater' ($half.Text -eq 'Not tested') "text=$($half.Text)"

''
'[the helpers] class and text must agree, and agree with the sibling'
foreach ($k in $unreadable.Keys) {
    $cls = Get-mdiServiceStateClass -State $unreadable[$k]
    $txt = Get-mdiServiceStateText -State $unreadable[$k]
    Assert-That "helper class and text agree for ($k)" (($cls -eq 'muted-cell') -and ($txt -eq 'Not tested')) "class=$cls text=$txt"
}
Assert-That 'the helper agrees with Get-mdiStartModeClass that a blank value is not a failure' `
((Get-mdiServiceStateClass -State '') -ne 'red' -and (Get-mdiStartModeClass -StartMode '') -ne 'red') ''
Assert-That 'the helper agrees with Get-mdiStartModeClass that n/a is not a failure' `
((Get-mdiServiceStateClass -State 'N/A') -ne 'red' -and (Get-mdiStartModeClass -StartMode 'n/a') -ne 'red') ''
Assert-That 'the helper still calls a real Running state green' ((Get-mdiServiceStateClass -State 'Running') -eq 'green') ''
Assert-That 'the helper still calls a real Stopped state red' ((Get-mdiServiceStateClass -State 'Stopped') -eq 'red') ''

''
"pass=$script:pass  fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
