<#
    Runs every *.Tests.ps1 in this folder and totals the results.

    The test files were written at different times and print their summary in three different
    formats. A runner that knows only one of them silently reports "no result" for the others,
    which reads exactly like a crashed test file - so a real failure in those files could sit
    unnoticed behind what looks like a harness quirk. All three are matched here, and any file
    that still yields no total is reported as a FAILURE rather than a note, because a test file
    that cannot be scored is not a test file that passed.
#>
[CmdletBinding()]
param(
    [string] $Path = $PSScriptRoot,
    [switch] $ShowPassing
)

$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
# The TOTAL prefix is optional: two files print a bare "PASS=n FAIL=n" and were scored as unparseable,
# which the runner then counted as a FAILURE each. That made a fully green suite exit non-zero and
# report "2 failed" with no failing assertion anywhere - a false red, which is the one thing a harness
# must never produce, because it trains everyone to ignore the exit code. "PASS=" with the equals sign
# cannot collide with the per-assertion "  PASS  name" lines, so dropping the prefix is unambiguous.
$patterns = @(
    '(\d+)\s+passed\s*/\s*(\d+)\s+failed'
    '(?:TOTAL\s+)?PASS=(\d+)\s+FAIL=(\d+)'
    '(\d+)\s+passed,\s*(\d+)\s+failed'
)

$totalPass = 0
$totalFail = 0
$problems = @()
$files = Get-ChildItem -Path $Path -Filter '*.Tests.ps1' | Sort-Object Name

foreach ($file in $files) {
    $output = & $ps -NoProfile -ExecutionPolicy Bypass -File $file.FullName 2>&1
    $text = $output | Out-String

    $match = $null
    foreach ($pattern in $patterns) {
        $found = [regex]::Matches($text, $pattern)
        if ($found.Count -gt 0) { $match = $found[$found.Count - 1]; break }
    }

    if (-not $match) {
        $problems += ('{0}: NO PARSEABLE TOTAL (exit {1})' -f $file.Name, $LASTEXITCODE)
        $totalFail++
        continue
    }

    $pass = [int] $match.Groups[1].Value
    $fail = [int] $match.Groups[2].Value
    $totalPass += $pass
    $totalFail += $fail

    if ($fail -gt 0) {
        $problems += ('{0}: {1} FAILED' -f $file.Name, $fail)
        $output | Select-String -Pattern 'FAIL' | Select-Object -First 10 |
            ForEach-Object { $problems += '    ' + $_.Line.Trim() }
    }
    elseif ($ShowPassing) {
        Write-Host ('  {0,-46} {1,4} passed' -f $file.Name, $pass) -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host ('TOTAL: {0} passed / {1} failed across {2} files' -f $totalPass, $totalFail, $files.Count) -ForegroundColor $(if ($totalFail) { 'Red' } else { 'Green' })
if ($problems) { Write-Host ''; $problems | ForEach-Object { Write-Host $_ -ForegroundColor Red } }

exit $(if ($totalFail) { 1 } else { 0 })
