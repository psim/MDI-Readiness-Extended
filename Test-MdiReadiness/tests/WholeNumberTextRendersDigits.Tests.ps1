$ErrorActionPreference = 'Stop'
$script:p = 0; $script:f = 0
function Check {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") { $script:p++; '  PASS {0,-62} => {1}' -f $Name, $Actual }
    else { $script:f++; '  FAIL {0,-62} => got [{1}] want [{2}]' -f $Name, $Actual, $Expected }
}

$scriptPath = (Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1')
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$t = Get-Content $scriptPath -Raw
$t = $t -replace '(?m)^#Requires.*$', ''
$t = $t -replace '\[CmdletBinding\([^)]*\)\]', ''
$i = $t.IndexOf('#region Main'); if ($i -gt 0) { $t = $t.Substring(0, $i) }
Invoke-Expression $t

Write-Host ''
Write-Host '=== Counts render as DIGITS, never in scientific notation ===' -ForegroundColor Cyan
# Get-mdiWholeNumberText exists so a corrupted history entry cannot take the chart down with an
# [int] overflow. A [string] cast of the resulting double flips to "1E+15" from 1e15 up, which
# replaces the unreadable-but-honest count with something no reader can act on.
Check 'small count'                 '7'                       (Get-mdiWholeNumberText -Value 7)
Check 'zero'                        '0'                       (Get-mdiWholeNumberText -Value 0)
Check 'string count from JSON'      '42'                      (Get-mdiWholeNumberText -Value '42')
Check 'fractional is floored'       '3'                       (Get-mdiWholeNumberText -Value 3.99)
Check 'three billion'               '3000000000'              (Get-mdiWholeNumberText -Value 3000000000)
Check 'one thousand million million' '1000000000000000'       (Get-mdiWholeNumberText -Value '1000000000000000')
Check 'ten to the twenty'           '100000000000000000000'   (Get-mdiWholeNumberText -Value '1e20')
Check 'unparseable counts as zero'  '0'                       (Get-mdiWholeNumberText -Value 'n/a')
Check 'null counts as zero'         '0'                       (Get-mdiWholeNumberText -Value $null)
Check 'negative is clamped to zero' '0'                       (Get-mdiWholeNumberText -Value -5)

foreach ($v in @('1e15', '1e16', '1234567890123456', '9.9e19')) {
    Check ('no exponent marker for {0}' -f $v) $true ((Get-mdiWholeNumberText -Value $v) -notmatch '[eE][+-]')
}
foreach ($v in @('1e15', '1234567890123456', 12345.6)) {
    Check ('no group separator for {0}' -f $v) $true ((Get-mdiWholeNumberText -Value $v) -notmatch '[,.]')
}

Write-Host ''
Write-Host '=== The rendered trend tooltip carries digits, not an exponent ===' -ForegroundColor Cyan
$history = @(
    [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 3; ChecksTotal = 4; ChecksUnread = 1 }
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 3; ChecksTotal = 4; ChecksUnread = '1000000000000000000' }
)
$svg = New-mdiTrendChart -History $history
Check 'the chart rendered at all'                 $true ($svg -match '<circle')
Check 'no exponent leaked into the chart markup'  $true ($svg -notmatch '\dE\+\d')
Check 'the huge unread count is written in full'  $true ($svg -match '1000000000000000000')

Write-Host ''
"TOTAL PASS=$script:p FAIL=$script:f"
if ($script:f -gt 0) { exit 1 }
