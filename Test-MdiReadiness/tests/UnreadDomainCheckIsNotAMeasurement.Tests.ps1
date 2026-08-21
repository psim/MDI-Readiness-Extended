<#
    A DOMAIN CHECK THE SCANNER COULD NOT READ WAS SCORED AS A MEASUREMENT, AND NAMED AS A PASS.

    "Measured" is the companion flag that says whether the scanner managed to read a domain-level
    check at all. It is read in two places that matter, and both used a bare cast:

        Get-mdiDomainCheckDefinition, $resolveMeasured (15519, 15526)
            if ($null -ne $Companion) { return [bool] $Companion }
            ... if Measured present on the result { return [bool] $Result.Measured }

        Set-MdiReadinessReport, the domain auditing cell (19792)
            $measured = if ($null -eq $MeasuredFlag) { $true } else { [bool] $MeasuredFlag }
            if ($measured) { 'Not applicable' } else { 'Not tested' }

    [bool] 'False' is TRUE. ConvertTo-mdiBoolean's own header names this exact trap: "a value that has
    been through a JSON round trip in another tool, a hand-edited report, or an older version of this
    script can carry the STRING 'False' ... Parsed explicitly rather than cast: [bool]'False' is $true,
    which is exactly the trap."

    The cast runs BEFORE the consumer's comparison, so in Get-mdiDomainCheckState the branch

        elseif ($check.Measured -eq $false) { $null }        <- the UNREAD state

    can never fire for a round-tripped flag. Measured on the shipped functions, one domain, object
    auditing, nothing differing but the spelling of ObjectAuditingMeasured:

        flag value                 check state      score          verdict    table cell
        $true                      measured         3/3 unread 0   READY      Not applicable
        $false                     UNREAD           2/2 unread 1   NOT READY  Not tested
        'False' (JSON round trip)  MEASURED         3/3 unread 0   READY      NOT APPLICABLE

    So the identical fact, spelled two ways, removes the unread check from the score, FLIPS THE VERDICT
    FROM NOT READY TO READY, and makes the table assert that the role is absent from the domain - a
    definite claim about a check nobody could read. The comment above Get-mdiDomainCheckDefinition
    records the same harm from the previous time it happened: "scored as PASSED, the unread count
    dropped from 1 to 0, the issue disappeared, the verdict flipped from NOT READY to READY".

    WHY THE FIX IS `(ConvertTo-mdiBoolean $x) -eq $true` AND NOT A BARE ConvertTo-mdiBoolean SWAP.
    Measured, under 5.1, with the comparison the consumer actually makes:

        value      [bool]  ConvertTo-mdiBoolean   UNREAD before   UNREAD after a naive swap
        $false     False   False                  yes             yes
        'False'    True    False                  NO  <- the bug  yes
        ''         False   null                   yes             NO  <- would break a correct row
        0          False   null                   yes             NO  <- would break a correct row

    A naive swap fixes 'False' and silently turns the empty string and zero from UNREAD into measured.
    The strict form keeps them unread, because $null -eq $true is false.

    A DELIBERATE BEHAVIOUR CHANGE IS PINNED HERE TOO, rather than smuggled: 1, 'Unknown' and a
    hashtable previously counted as MEASURED (because [bool] of each is true) and now count as UNREAD,
    since ConvertTo-mdiBoolean recognises none of them. That is the conservative direction and the one
    this codebase argues for everywhere else - a value nobody could read is "not looked at", never a
    measurement.
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

# isObjectAuditingOk is deliberately NOT $false. Get-mdiDomainCheckState tests
# `[string] $check.Value -eq 'False'` FIRST, and that branch would fire before the Measured branch
# could, making every spelling read identically and the test measure nothing.
function New-Report {
    param($MeasuredFlag, [string] $Status = 'True', [switch] $OmitFlag)
    $domain = [PSCustomObject]@{
        Domain         = 'fabrikam.local'
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $Status }
    }
    if (-not $OmitFlag) {
        $domain | Add-Member -NotePropertyName ObjectAuditingMeasured -NotePropertyValue $MeasuredFlag -Force
    }
    [PSCustomObject]@{
        Domain = 'fabrikam.local'
        Domains = @('fabrikam.local')
        DomainsInScope = @('fabrikam.local')
        DomainAuditing = @($domain)
        DomainControllers = @(
            [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; Unreachable = $false
                isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
        )
        CAServers = @(); EntraConnectServers = @()
    }
}

function Measure-Score {
    param($Report)
    $state = @(Get-mdiDomainCheckState -ReportData $Report | Where-Object { $_.Name -eq 'Object auditing' })
    [PSCustomObject]@{
        Unread = ($state.Count -gt 0 -and $null -eq $state[0].Value)
        Ready  = [bool] (Test-mdiReadinessResult -ReportData $Report)
    }
}

# The rendered cell, read out of the real HTML rather than inferred from the expression.
function Measure-Cell {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $outDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-measured-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    try {
        Set-MdiReadinessReport -Domain 'fabrikam.local' -Path $outDir -ReportData $Report -Statistics $stats -SkipTrend | Out-Null
        $f = @(Get-ChildItem $outDir -Filter '*.html' -ErrorAction SilentlyContinue) | Select-Object -First 1
        $html = if ($f) { [IO.File]::ReadAllText($f.FullName) } else { '' }
        if ($html -match 'Not tested') { 'Not tested' }
        elseif ($html -match 'Not applicable') { 'Not applicable' }
        else { 'neither' }
    } finally { if (Test-Path $outDir) { Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue } }
}

Write-Host 'A check nobody could read is not a measurement, however the flag is spelled' -ForegroundColor Cyan

''
'--- THE DEFECT: a round-tripped flag must behave exactly like the boolean it came from ---'
foreach ($case in @(
        @{ L = 'a real $false'; V = $false }
        @{ L = "the string 'False' from a JSON round trip"; V = 'False' }
    )) {
    $m = Measure-Score (New-Report -MeasuredFlag $case.V)
    Assert-That ('{0}: the check is UNREAD' -f $case.L) $m.Unread
    Assert-That ('{0}: the run is NOT READY' -f $case.L) (-not $m.Ready)
    $cell = Measure-Cell (New-Report -MeasuredFlag $case.V -Status 'N/A')
    Assert-That ('{0}: the table says "Not tested"' -f $case.L) ($cell -eq 'Not tested') "(cell '$cell')"
}

''
'--- CONTROLS: a check that really was measured must be unaffected ---'
foreach ($case in @(
        @{ L = 'a real $true'; V = $true }
        @{ L = "the string 'True' from a JSON round trip"; V = 'True' }
    )) {
    $m = Measure-Score (New-Report -MeasuredFlag $case.V)
    Assert-That ('{0}: the check is measured' -f $case.L) (-not $m.Unread)
    Assert-That ('{0}: the run is READY' -f $case.L) $m.Ready
    $cell = Measure-Cell (New-Report -MeasuredFlag $case.V -Status 'N/A')
    Assert-That ('{0}: the table says "Not applicable"' -f $case.L) ($cell -eq 'Not applicable') "(cell '$cell')"
}

$m = Measure-Score (New-Report -OmitFlag)
Assert-That 'an ABSENT flag still counts as measured (older reports)' (-not $m.Unread)
$cell = Measure-Cell (New-Report -OmitFlag -Status 'N/A')
Assert-That '  ...and still renders "Not applicable"' ($cell -eq 'Not applicable') "(cell '$cell')"

''
'--- WHAT A NAIVE ConvertTo-mdiBoolean SWAP WOULD BREAK. These were correct before and must stay so ---'
foreach ($case in @(
        @{ L = 'an empty string'; V = '' }
        @{ L = 'a zero'; V = 0 }
    )) {
    $m = Measure-Score (New-Report -MeasuredFlag $case.V)
    Assert-That ('{0}: still UNREAD' -f $case.L) $m.Unread
    $cell = Measure-Cell (New-Report -MeasuredFlag $case.V -Status 'N/A')
    Assert-That ('{0}: still "Not tested"' -f $case.L) ($cell -eq 'Not tested') "(cell '$cell')"
}

''
'--- THE DELIBERATE CHANGE: unreadable values become UNREAD rather than measured ---'
foreach ($case in @(
        @{ L = 'a bare 1'; V = 1 }
        @{ L = "the string 'Unknown'"; V = 'Unknown' }
        @{ L = 'a hashtable'; V = @{ a = 1 } }
    )) {
    $m = Measure-Score (New-Report -MeasuredFlag $case.V)
    Assert-That ('{0}: UNREAD, because nobody could read it' -f $case.L) $m.Unread
}

''
"RESULT pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
