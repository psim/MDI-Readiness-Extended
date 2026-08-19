<#
    A v3.x prerequisite that was NEVER RUN must not be painted as a measured failure because its row
    arrived as a dictionary.

    THE DEFECT THIS PINS. Get-mdiSensorV3Html classifies each prerequisite cell, and the arm that
    separates "did not run" from "ran and failed" asked the question through a presence test:

        } elseif ($check.PSObject.Properties['Measured'] -and $check.Measured -ne $true) {
              '<td class="muted-cell">Not tested</td>'

    PSObject.Properties over an IDictionary enumerates the DICTIONARY'S OWN .NET MEMBERS - Count,
    Keys, Values, SyncRoot, IsReadOnly, IsFixedSize, IsSynchronized - and never its entries. On a
    dictionary-shaped row the flag therefore cannot be found, the arm never fires, and the cell falls
    through to the arms below, which read the STATUS of a check nobody took.

    The rows are documented, in this same function, as arriving across a JSON boundary: "Checks reach
    here from $srv.Details.SensorV3ReadyDetails.Checks, read back across the same base64/JSON boundary
    that already delivers 'Required.' and the number 636 on this field". Another tool's JSON handling,
    an -AsJson round trip and a hand-edited report all hand that row back as a hashtable.

    Measured on the shipped function, one prerequisite with Measured = $false and nothing differing
    but the row's shape:

        Status   PSCustomObject         Hashtable / OrderedDictionary / Generic.Dictionary
        $false   muted "Not tested"     RED "Fail"
        'N/A'    muted "Not tested"     grey "N/A"

    Red reads as "measured and failed". This file already names that the most expensive wrong answer
    it can give - it says so on the ports matrix, for exactly this reason - because it sends an
    operator to fix a prerequisite on a server where the check never ran, which for the v3.x checks
    normally means the sensor API could not be reached at all. Every UNREADABLE Measured that the
    object column correctly holds back - $null, '', 'Unknown', 'False', 0 - was painted red too once
    the row was dictionary-shaped: a value nobody could read came back looking like a measurement.

    A cross-forest estate is where the shape stops being hypothetical. -MultiForest reaches a second
    forest, and a cross-forest report is the one most likely to be assembled from another tool's JSON.

    THE FIX. The row is normalised through ConvertTo-mdiRecordObject before it is classified, which is
    the normaliser this script already applies to the port records, the server rows, the forest
    discovery record and the domain check results for the identical reason.

    Pinned here:

    1. Measured = $false is honoured on every IDictionary shape: the cell is "Not tested", whatever
       the status of a check that never ran happens to say.
    2. An UNREADABLE Measured - $null, '', 'Unknown', 'False', 0 - is held back on every shape exactly
       as it already was on an object. This is the false-red direction, so it is pinned hardest.
    3. A check that DID run keeps its verdict on every shape - a failure stays red, a pass stays green
       - so the fix cannot have bought the false red off with a false green.
    4. ABSENCE of Measured behaves exactly as it did before the flag existed, on every shape.
    5. The requirement label and the detail tooltip still read from the row on every shape.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiSensorV3Html') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

$shapes = @('PSCustomObject', 'Hashtable', 'OrderedDictionary', 'Generic.Dictionary')
$checkName = 'Defender for Endpoint onboarding'
$detail = 'Not tested - the sensor API could not be reached'

function New-CheckRow {
    param([string] $Shape, [object] $Status, [object] $Measured, [switch] $OmitMeasured)
    $f = [ordered]@{
        Name        = $checkName
        Requirement = 'Required'
        Status      = $Status
        Detail      = $detail
    }
    if (-not $OmitMeasured) { $f['Measured'] = $Measured }
    switch ($Shape) {
        'PSCustomObject' { return [PSCustomObject] $f }
        'Hashtable' { $h = @{}; foreach ($k in $f.Keys) { $h[$k] = $f[$k] }; return $h }
        'OrderedDictionary' { return $f }
        'Generic.Dictionary' {
            $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            foreach ($k in $f.Keys) { $d[[string] $k] = $f[$k] }
            return $d
        }
    }
    throw "unknown shape $Shape"
}

# A cross-forest sensor candidate, which is the estate that makes the row shape ordinary.
function Get-Row {
    param($CheckRow)
    $srv = [PSCustomObject]@{
        FQDN    = 'dcfab01.fabrikam.local'
        Details = [PSCustomObject]@{
            SensorV3ReadyDetails = [PSCustomObject]@{
                SensorState       = 'Running'
                MigrationEligible = $true
                Blockers          = @()
                Checks            = @($CheckRow)
            }
        }
    }
    $html = Get-mdiSensorV3Html -Server @($srv)
    @($html -split "`r?`n" | Where-Object { $_ -match [regex]::Escape($checkName) })[0]
}

function Get-Cell {
    param($CheckRow)
    $line = Get-Row -CheckRow $CheckRow
    if (-not $line) { return 'NO ROW' }
    $m = [regex]::Match($line, '<td class="(?<c>[^"]+)"[^>]*>(?<t>[^<]*)</td>\s*</tr>')
    if (-not $m.Success) { $m = [regex]::Match($line, '<td class="(?<c>[^"]+)"[^>]*>(?<t>[^<]*)</td>') }
    if ($m.Success) { return ('{0}/{1}' -f $m.Groups['c'].Value, $m.Groups['t'].Value) }
    return $line
}

''
'--- 1  a check that NEVER RAN is "Not tested", not a measured failure ---'
foreach ($shape in $shapes) {
    foreach ($status in @(@{ L = '$false'; V = $false }, @{ L = "'N/A'"; V = 'N/A' }, @{ L = '$null'; V = $null }, @{ L = "'False'"; V = 'False' })) {
        $cell = Get-Cell (New-CheckRow -Shape $shape -Status $status.V -Measured $false)
        Assert-That "$shape : Measured=`$false, Status=$($status.L) is Not tested" `
        ($cell -eq 'muted-cell/Not tested') "got $cell"
    }
}

''
'--- 2  an UNREADABLE Measured is held back on every shape, as it already was on an object ---'
foreach ($shape in $shapes) {
    foreach ($v in @(
            @{ L = '$null'; V = $null }, @{ L = "''"; V = '' }, @{ L = "'Unknown'"; V = 'Unknown' },
            @{ L = "'False'"; V = 'False' }, @{ L = '0'; V = 0 }
        )) {
        $cell = Get-Cell (New-CheckRow -Shape $shape -Status $false -Measured $v.V)
        Assert-That "$shape : Measured=$($v.L) is not a measured failure" `
        ($cell -eq 'muted-cell/Not tested') "got $cell"
    }
}

''
'--- 3  a check that DID run keeps its verdict on every shape ---'
foreach ($shape in $shapes) {
    $failCell = Get-Cell (New-CheckRow -Shape $shape -Status $false -Measured $true)
    Assert-That "$shape : a measured failure is still red" ($failCell -eq 'red/Fail') "got $failCell"
    $passCell = Get-Cell (New-CheckRow -Shape $shape -Status $true -Measured $true)
    Assert-That "$shape : a measured pass is still green" ($passCell -eq 'green/Pass') "got $passCell"
    $naCell = Get-Cell (New-CheckRow -Shape $shape -Status 'N/A' -Measured $true)
    Assert-That "$shape : a measured N/A is still an informational N/A" ($naCell -eq 'grey/N/A') "got $naCell"
    $trueCell = Get-Cell (New-CheckRow -Shape $shape -Status $false -Measured 'True')
    Assert-That "$shape : the string form Measured='True' is still a measured failure" ($trueCell -eq 'red/Fail') "got $trueCell"
}

''
'--- 4  ABSENCE of Measured behaves as it did before the flag existed ---'
foreach ($shape in $shapes) {
    $cell = Get-Cell (New-CheckRow -Shape $shape -Status $false -OmitMeasured)
    Assert-That "$shape : no Measured property at all is still a failure" ($cell -eq 'red/Fail') "got $cell"
    $cellWhenPassing = Get-Cell (New-CheckRow -Shape $shape -Status $true -OmitMeasured)
    Assert-That "$shape : no Measured property at all still passes when it passed" ($cellWhenPassing -eq 'green/Pass') "got $cellWhenPassing"
}

''
'--- 5  the row still carries its requirement label and its detail on every shape ---'
foreach ($shape in $shapes) {
    $line = Get-Row -CheckRow (New-CheckRow -Shape $shape -Status $false -Measured $false)
    Assert-That "$shape : the requirement label is on the row" ([bool] ($line -match 'Required')) "got $line"
    Assert-That "$shape : the detail reaches the tooltip" ([bool] ($line -match 'sensor API could not be reached')) "got $line"
}

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
