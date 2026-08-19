<#
    A capacity figure that was never read must not come back as a number, and must not destroy the
    capacity tab.

    THE DEFECT THIS PINS. The capacity tab rendered every figure through a hard numeric cast:

        [long] $c.BusyPacketsPerSec, [long] $c.AveragePacketsPerSec,
        [double] $c.RequiredCpu, [double] $c.TotalRamGb, [int] $c.PhysicalCores, ...

    guarded by one test, `if ($null -eq $c.BusyPacketsPerSec)`. $null is not the only shape an unread
    figure takes. Measured on the shipped Get-mdiCapacityHtml with one otherwise complete capacity
    block, BusyPacketsPerSec replaced one shape at a time:

        value        result
        4200         busy cell '4200'                                         (correct)
        $null        the 'n/a' row                                            (correct)
        ''           busy cell '0'          verdict 'Yes'   <- never measured
        $true        busy cell '1'          verdict 'Yes'   <- never measured
        'N/A'        THREW  Cannot convert value "N/A" to type "System.Int64"
        'unknown'    THREW  Cannot convert value "unknown" to type "System.Int64"
        '   '        THREW  Cannot convert value "   " to type "System.Int64"

    Both outcomes are the ones this tool must never produce. '' and $true print a hard packet rate
    under a green "Yes - sensor supported" verdict for a server whose traffic was never read - a
    measurement nobody took, which is the family every defect in this project has belonged to. The
    three that throw destroy the ENTIRE capacity tab, and with it the report, because one field on
    one server of an estate could not be read.

    A SECOND, SEPARATE HALF: the headline that governs how every figure in the table must be read was
    decided by `FullBusyWindow -is [bool]`, while the row rendered from the same field forty lines
    below coerced. The two therefore disagreed. Measured on the shipped function:

        FullBusyWindow   headline                        the row itself
        $false           "Estimate only"                 "Yes (estimate) / 900 s, partial"
        'False'          "could not be sampled"          "Yes (estimate) / 900 s, partial"
        'True'           "could not be sampled"          "Yes / 900 s"

    So a server that WAS sampled, whose own row shows a full set of measurements, was announced as
    one whose capacity could not be read - and the "Estimate only, this is not a formal sizing"
    caveat, which is the thing that stops a short sample being read as a sizing decision, was
    replaced by a claim that there were no figures at all.

    A cross-forest estate is where these shapes stop being hypothetical: -MultiForest assembles a
    second forest's results, and such a report is the one most likely to be merged between tools,
    round-tripped or hand-edited - the arrival vector ConvertTo-mdiBoolean and ConvertTo-mdiRecordObject
    already exist for.

    THE FIX. ConvertTo-mdiMeasuredNumber is the numeric twin of the existing ConvertTo-mdiBoolean: it
    returns a real number, or $null for anything that means "nothing was measured" - '', whitespace,
    'N/A', any unparseable text, a collection, and a BOOLEAN (because [long] $true is 1, which would
    turn a flag into a packet rate). Every figure in the row is read through it; an unreadable
    headline measurement falls to the existing 'n/a' row, and an unreadable secondary figure prints
    'n/a' instead of a zero nobody measured. The sampled/partial/notSampled split and the row now
    both read FullBusyWindow through ConvertTo-mdiBoolean, so the headline and the row cannot
    contradict each other. The hyper-threading footnote reads it the same way, because every
    non-empty string is truthy and 'False' was printing "Hyper-threading is enabled".

    Pinned here, driving the shipped Get-mdiCapacityHtml and reading the generated HTML back:

    1. No unreadable shape of BusyPacketsPerSec throws, on any row shape.
    2. No unreadable shape of BusyPacketsPerSec produces a numeric busy cell - it produces the 'n/a'
       row instead.
    3. An unreadable secondary figure prints 'n/a', never 0.
    4. The headline caveat and the row agree about FullBusyWindow, for real booleans and for the
       string forms.
    5. HyperThreaded = 'False' does not print the "Hyper-threading is enabled" footnote.
    6. A fully measured server is completely unchanged: same verdict, same figures, same headline.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiCapacityHtml') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# A capacity block in the shape Get-mdiCapacityPlanning emits for a server it DID size.
$measuredBlock = [ordered]@{
    Status = 'Yes'; Detail = 'Sized from a full busy window'
    BusyPacketsPerSec = 4200; AveragePacketsPerSec = 3100; PeakPacketsPerSec = 5000
    Band = '1k-10k'; RequiredCpu = 2; RequiredRamGb = 6
    PhysicalCores = 4; TotalRamGb = 16; HyperThreaded = $false
    AvgCpuPercent = 22; MaxCpuPercent = 41; MinAvailableRamGb = 7.5
    SampleSeconds = 900; FullBusyWindow = $true
}

function New-Capacity {
    param([hashtable] $Override = @{}, [string] $Shape = 'PSCustomObject')
    $o = [ordered]@{}
    # Assigned through an explicit branch, NOT `$o[$k] = if (...) { } else { }`. The output of an if
    # STATEMENT goes through the pipeline, which unrolls a single-element array to its element - so a
    # deliberately collection-shaped test value silently arrived at the product as a plain number and
    # the case tested nothing. Measured while writing this test.
    foreach ($k in $measuredBlock.Keys) {
        if ($Override.ContainsKey($k)) { $o[$k] = $Override[$k] } else { $o[$k] = $measuredBlock[$k] }
    }
    switch ($Shape) {
        'Hashtable' { $h = @{}; foreach ($k in $o.Keys) { $h[$k] = $o[$k] }; $h }
        'OrderedDictionary' { $o }
        default { [PSCustomObject] $o }
    }
}

function New-Server {
    param([string] $Fqdn, [object] $Capacity, [string] $Shape = 'PSCustomObject')
    $details = [ordered]@{ CapacityDetails = $Capacity }
    $d = switch ($Shape) {
        'Hashtable' { $h = @{}; foreach ($k in $details.Keys) { $h[$k] = $details[$k] }; $h }
        'OrderedDictionary' { $details }
        default { [PSCustomObject] $details }
    }
    $row = [ordered]@{ FQDN = $Fqdn; Domain = ($Fqdn -replace '^[^.]+\.', ''); Details = $d }
    switch ($Shape) {
        'Hashtable' { $h = @{}; foreach ($k in $row.Keys) { $h[$k] = $row[$k] }; $h }
        'OrderedDictionary' { $row }
        default { [PSCustomObject] $row }
    }
}

function Get-CapacityRow {
    param([string] $Html, [string] $Fqdn)
    foreach ($m in [regex]::Matches($Html, '<tr>.*?</tr>', 'Singleline')) {
        if ($m.Value -match [regex]::Escape($Fqdn)) { return $m.Value }
    }
    $null
}
function Get-Cells {
    param([string] $Row)
    if ($null -eq $Row) { return @() }
    @([regex]::Matches($Row, '<td[^>]*>(.*?)</td>') | ForEach-Object { $_.Groups[1].Value })
}
# The 'n/a' row is the one with the colspan - that is what "this server was not sized" looks like.
function Test-IsNotSizedRow {
    param([string] $Row)
    $null -ne $Row -and $Row -match 'colspan="9"'
}

$fqdn = 'dcfab01.fabrikam.local'
$unreadable = @(
    @{ Tag = "'' (empty)"; Value = '' }
    @{ Tag = "'   ' (whitespace)"; Value = '   ' }
    @{ Tag = "'N/A'"; Value = 'N/A' }
    @{ Tag = "'unknown'"; Value = 'unknown' }
    @{ Tag = '$true'; Value = $true }
    @{ Tag = '$false'; Value = $false }
    @{ Tag = '@() (empty collection)'; Value = @() }
    @{ Tag = '@(4200) (a collection)'; Value = @(4200) }
)

'1/2. an unreadable headline measurement never throws and never becomes a number'
foreach ($shape in @('PSCustomObject', 'Hashtable', 'OrderedDictionary')) {
    foreach ($u in $unreadable) {
        $srv = New-Server -Fqdn $fqdn -Capacity (New-Capacity -Override @{ BusyPacketsPerSec = $u.Value } -Shape $shape) -Shape $shape
        $threw = ''
        $row = $null
        try { $row = Get-CapacityRow -Html (Get-mdiCapacityHtml -Server @($srv)) -Fqdn $fqdn }
        catch { $threw = '-> THREW: ' + $_.Exception.Message }
        Assert-That "BusyPacketsPerSec $($u.Tag) on a $shape row does not throw" ($threw -eq '') $threw
        if ($threw -eq '') {
            Assert-That "BusyPacketsPerSec $($u.Tag) on a $shape row renders as not-sized" (Test-IsNotSizedRow -Row $row) "-> row was '$row'"
        }
    }
}
# $null is the shape that always worked, and must keep working.
$srv = New-Server -Fqdn $fqdn -Capacity (New-Capacity -Override @{ BusyPacketsPerSec = $null })
Assert-That 'BusyPacketsPerSec $null still renders as not-sized' (Test-IsNotSizedRow -Row (Get-CapacityRow -Html (Get-mdiCapacityHtml -Server @($srv)) -Fqdn $fqdn))

''
'3. an unreadable SECONDARY figure prints n/a, never a zero nobody measured'
foreach ($field in @('AveragePacketsPerSec', 'PeakPacketsPerSec', 'RequiredCpu', 'RequiredRamGb', 'PhysicalCores', 'TotalRamGb', 'SampleSeconds')) {
    foreach ($u in @(@{ Tag = "'N/A'"; Value = 'N/A' }, @{ Tag = "''"; Value = '' }, @{ Tag = '$true'; Value = $true })) {
        $srv = New-Server -Fqdn $fqdn -Capacity (New-Capacity -Override @{ $field = $u.Value })
        $threw = ''
        $cells = @()
        try { $cells = Get-Cells -Row (Get-CapacityRow -Html (Get-mdiCapacityHtml -Server @($srv)) -Fqdn $fqdn) }
        catch { $threw = '-> THREW: ' + $_.Exception.Message }
        Assert-That "$field $($u.Tag) does not throw" ($threw -eq '') $threw
        if ($threw -eq '' -and $cells.Count -gt 3) {
            # The row still renders (BusyPacketsPerSec is readable), and no cell may read a bare '0'
            # that was never measured. A genuine 0 elsewhere in the row would come from a real value.
            $zeroCells = @($cells | Where-Object { $_ -eq '0' -or $_ -eq '0.00' -or $_ -eq '0 core(s)' })
            Assert-That "$field $($u.Tag) does not print a fabricated zero" (@($zeroCells).Count -eq 0) "-> cells: $($cells -join ' | ')"
        }
    }
}

''
'4. the headline caveat and the row agree about FullBusyWindow'
function Get-Headline {
    param([string] $Html)
    if ($Html -match 'Estimate only') { 'estimate-only' }
    elseif ($Html -match 'could not be sampled') { 'could-not-be-sampled' }
    elseif ($Html -match 'Sampled over a full busy window') { 'full-busy-window' }
    else { '<none>' }
}
foreach ($f in @(
        @{ Tag = '$false'; Value = $false; Headline = 'estimate-only'; RowPartial = $true }
        @{ Tag = '$true'; Value = $true; Headline = 'full-busy-window'; RowPartial = $false }
        @{ Tag = "'False' (JSON string)"; Value = 'False'; Headline = 'estimate-only'; RowPartial = $true }
        @{ Tag = "'True' (JSON string)"; Value = 'True'; Headline = 'full-busy-window'; RowPartial = $false }
        @{ Tag = '$null'; Value = $null; Headline = 'could-not-be-sampled'; RowPartial = $false }
        @{ Tag = "'' (empty)"; Value = ''; Headline = 'could-not-be-sampled'; RowPartial = $false }
        @{ Tag = "'N/A'"; Value = 'N/A'; Headline = 'could-not-be-sampled'; RowPartial = $false }
        @{ Tag = '0 (the number)'; Value = 0; Headline = 'could-not-be-sampled'; RowPartial = $false }
    )) {
    $srv = New-Server -Fqdn $fqdn -Capacity (New-Capacity -Override @{ FullBusyWindow = $f.Value })
    $html = Get-mdiCapacityHtml -Server @($srv)
    $headline = Get-Headline -Html $html
    $row = Get-CapacityRow -Html $html -Fqdn $fqdn
    Assert-That "FullBusyWindow $($f.Tag): headline is $($f.Headline)" ($headline -eq $f.Headline) "-> got '$headline'"
    $rowSaysPartial = ($null -ne $row -and $row -match 'partial')
    Assert-That "FullBusyWindow $($f.Tag): the row agrees (partial=$($f.RowPartial))" ($rowSaysPartial -eq $f.RowPartial) "-> row partial=$rowSaysPartial"
    # A row announced as a partial sample must never also be painted plain green.
    if ($rowSaysPartial) {
        Assert-That "FullBusyWindow $($f.Tag): a partial sample is not plain green" ($row -notmatch '<td class="green">') "-> row was '$row'"
    }
}

''
'5. the hyper-threading footnote is not printed for a string that says False'
foreach ($h in @(@{ Tag = "'False'"; Value = 'False'; Expect = $false }, @{ Tag = "'N/A'"; Value = 'N/A'; Expect = $false },
        @{ Tag = '$false'; Value = $false; Expect = $false }, @{ Tag = '$true'; Value = $true; Expect = $true },
        @{ Tag = "'True'"; Value = 'True'; Expect = $true })) {
    $srv = New-Server -Fqdn $fqdn -Capacity (New-Capacity -Override @{ HyperThreaded = $h.Value })
    $html = Get-mdiCapacityHtml -Server @($srv)
    $printed = $html -match 'Hyper-threading is enabled'
    Assert-That "HyperThreaded $($h.Tag): footnote printed = $($h.Expect)" ($printed -eq $h.Expect) "-> got $printed"
}

''
'6. a fully measured server is unchanged'
$srv = New-Server -Fqdn $fqdn -Capacity (New-Capacity)
$html = Get-mdiCapacityHtml -Server @($srv)
$cells = Get-Cells -Row (Get-CapacityRow -Html $html -Fqdn $fqdn)
Assert-That 'the measured row is not the not-sized row' (-not (Test-IsNotSizedRow -Row (Get-CapacityRow -Html $html -Fqdn $fqdn)))
Assert-That 'the verdict is still Yes' ($cells.Count -gt 1 -and $cells[1] -eq 'Yes') "-> got '$(if ($cells.Count -gt 1) { $cells[1] })'"
Assert-That 'the sample still reads 900 s' ($cells.Count -gt 2 -and $cells[2] -eq '900 s') "-> got '$(if ($cells.Count -gt 2) { $cells[2] })'"
Assert-That 'the busy rate still reads 4200' ($cells.Count -gt 3 -and $cells[3] -eq '4200') "-> got '$(if ($cells.Count -gt 3) { $cells[3] })'"
Assert-That 'the average still reads 3100' ($cells.Count -gt 4 -and $cells[4] -eq '3100') "-> got '$(if ($cells.Count -gt 4) { $cells[4] })'"
Assert-That 'the peak still reads 5000' ($cells.Count -gt 5 -and $cells[5] -match '^5000') "-> got '$(if ($cells.Count -gt 5) { $cells[5] })'"
Assert-That 'the core count still reads 4' (@($cells | Where-Object { $_ -match '^4 core\(s\)' }).Count -gt 0) "-> cells: $($cells -join ' | ')"
Assert-That 'the headline is still the full busy window' ((Get-Headline -Html $html) -eq 'full-busy-window')
# The spike ratio still fires on a genuinely spiky measured server.
$spiky = New-Server -Fqdn $fqdn -Capacity (New-Capacity -Override @{ AveragePacketsPerSec = 100; PeakPacketsPerSec = 9000 })
$spikyRow = Get-CapacityRow -Html (Get-mdiCapacityHtml -Server @($spiky)) -Fqdn $fqdn
Assert-That 'the spike ratio is still surfaced on a measured spiky server' ($spikyRow -match 'x avg') "-> row was '$spikyRow'"
# A server that was never sized at all still renders beside a sampled one.
$notSized = [PSCustomObject]@{ Status = 'Missing traffic data'; Detail = 'Unable to read the network performance counters over WMI' }
$estateHtml = Get-mdiCapacityHtml -Server @((New-Server -Fqdn 'dc01.mdilab.local' -Capacity (New-Capacity)), (New-Server -Fqdn $fqdn -Capacity $notSized))
Assert-That 'a never-sized cross-forest DC still gets its own not-sized row' (Test-IsNotSizedRow -Row (Get-CapacityRow -Html $estateHtml -Fqdn $fqdn))
Assert-That 'the sampled DC beside it keeps its figures' ((Get-Cells -Row (Get-CapacityRow -Html $estateHtml -Fqdn 'dc01.mdilab.local')) -contains '4200')
Assert-That 'the estate is announced as partly unsampled' ((Get-Headline -Html $estateHtml) -eq 'could-not-be-sampled')

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
