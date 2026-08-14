<#
    Behavioural regression tests for baseline history ordering.

    The trend is the whole reason the baseline feature exists, and both defects here made the delta
    pill point the WRONG WAY - a green "improving" badge on an estate that had fallen. A percentage
    with an arrow on it is the number that gets reported upward, so a reversed arrow is worse than no
    arrow at all.

      * Pruning kept the LAST N ENTRIES OF THE FILE. On a history whose order is not time order - a
        hand merge, a restored backup, two collectors writing the same share, a clock correction -
        that discarded the chronologically newest run and kept older, poorer ones.

      * Plotting sorted by timestamp only when EVERY entry parsed, and gave up otherwise. ONE junk
        entry with no timestamp therefore reordered every real run beside it.

    Every assertion renders the actual pill and reads its direction. None of them inspects the source.
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

Write-Host 'BaselineHistoryOrdering.Tests.ps1' -ForegroundColor Cyan

# The delta refuses to compare two runs that measured different things, so every synthetic run below
# carries the same fingerprint - the check set, the server set and the script version. Without it the
# pill correctly reads "not comparable" and would say nothing at all about ordering, which is what
# these tests are actually about.
$script:checkNames = @('NtlmAuditing', 'AdvancedAuditing')
$script:serverNames = @('dc1.contoso.com')
$script:scriptVersion = [string] $settings.ScriptVersion

function New-Run {
    param([string] $Stamp, [int] $Passed, [int] $Total = 10)    [PSCustomObject]@{
        Timestamp = $Stamp; ScriptVersion = $script:scriptVersion
        ChecksPassed = $Passed; ChecksTotal = $Total; ChecksUnread = 0
        CheckNames = $script:checkNames; ServerNames = $script:serverNames
    }
}
function New-JunkRun {
    param([int] $Passed = 1)
    # Carries the numbers the point filter reads and the same fingerprint, but NO timestamp - which is
    # exactly what a bad hand merge from a sibling domain's history produces.
    [PSCustomObject]@{
        ChecksPassed = $Passed; ChecksTotal = 10; ChecksUnread = 0
        CheckNames = $script:checkNames; ServerNames = $script:serverNames; ScriptVersion = $script:scriptVersion
    }
}
function Get-PillText {
    param($History)
    $html = New-mdiTrendChart -History @($History)
    $plain = ($html -replace '<[^>]+>', ' ') -replace '\s+', ' '
    [PSCustomObject]@{ Html = $html; Text = $plain; Down = ($html -match '&darr;'); Up = ($html -match '&uarr;') }
}

# ---------------------------------------------------------------------------------------------
# The ordering primitive.
# ---------------------------------------------------------------------------------------------
$outOfOrder = @(
    (New-Run '2026-08-10T00:00:00' 10)
    (New-Run '2026-08-01T00:00:00' 1)
    (New-Run '2026-08-02T00:00:00' 2)
)
$sorted = @(Get-mdiChronologicalRun -Run $outOfOrder)
Assert-True 'runs come back oldest first regardless of file order' `
    (($sorted | ForEach-Object { $_.Timestamp }) -join ',' -eq '2026-08-01T00:00:00,2026-08-02T00:00:00,2026-08-10T00:00:00') `
    (($sorted | ForEach-Object { $_.Timestamp }) -join ',')

$withJunk = @(
    (New-Run '2026-08-01T00:00:00' 9)
    (New-JunkRun)
    (New-Run '2026-08-08T00:00:00' 5)
)
$cleaned = @(Get-mdiChronologicalRun -Run $withJunk)
Assert-True 'an entry with no parseable timestamp is dropped, not positioned by guesswork' `
    ($cleaned.Count -eq 2) ("kept {0}" -f $cleaned.Count)
Assert-True 'and the real runs keep their chronological order around it' `
    (($cleaned | ForEach-Object { $_.Timestamp }) -join ',' -eq '2026-08-01T00:00:00,2026-08-08T00:00:00')

# A file that predates the timestamp format has no ordering to recover, so append order stands.
$legacy = @(
    ([PSCustomObject]@{ ChecksPassed = 3; ChecksTotal = 10; ChecksUnread = 0 })
    ([PSCustomObject]@{ ChecksPassed = 7; ChecksTotal = 10; ChecksUnread = 0 })
)
Assert-True 'a history with no timestamps at all is left in its original order' `
    ((@(Get-mdiChronologicalRun -Run $legacy) | ForEach-Object { $_.ChecksPassed }) -join ',' -eq '3,7')
Assert-True 'an empty history yields nothing and does not throw' (@(Get-mdiChronologicalRun -Run @()).Count -eq 0)
Assert-True 'a null history yields nothing and does not throw' (@(Get-mdiChronologicalRun -Run $null).Count -eq 0)

# ---------------------------------------------------------------------------------------------
# The rendered pill: a genuine FALL must render as a fall, whatever the file order.
# ---------------------------------------------------------------------------------------------
$fell = @((New-Run '2026-08-01T00:00:00' 9), (New-Run '2026-08-08T00:00:00' 5))
$clean = Get-PillText -History $fell
Assert-True 'control: a genuine fall renders as a fall' ($clean.Down -and -not $clean.Up) $clean.Text

foreach ($placement in @(
        @{ Label = 'appended last'; History = @($fell + (New-JunkRun)) }
        @{ Label = 'in the middle'; History = @($fell[0], (New-JunkRun), $fell[1]) }
        @{ Label = 'first'; History = @((New-JunkRun)) + $fell }
    )) {
    $p = Get-PillText -History $placement.History
    Assert-True ("a junk entry {0} does not reverse the trend arrow" -f $placement.Label) `
        ($p.Down -and -not $p.Up) $p.Text
}

# Out-of-order REAL runs must also render by time, not by file position.
$outOfOrderFall = @((New-Run '2026-08-08T00:00:00' 5), (New-Run '2026-08-01T00:00:00' 9))
$reordered = Get-PillText -History $outOfOrderFall
Assert-True 'an out-of-order file still renders the arrow by time, not by position' `
    ($reordered.Down -and -not $reordered.Up) $reordered.Text

# And a genuine RISE must still render as a rise - the fix must not simply force one direction.
$rose = @((New-Run '2026-08-01T00:00:00' 5), (New-Run '2026-08-08T00:00:00' 9))
$risen = Get-PillText -History $rose
Assert-True 'control: a genuine rise still renders as a rise' ($risen.Up -and -not $risen.Down) $risen.Text

# ---------------------------------------------------------------------------------------------
# Pruning must keep the newest runs BY TIME, not the last lines of the file.
# ---------------------------------------------------------------------------------------------
$tempRoot = Join-Path $env:TEMP ('mdi-hist-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
[void] (New-Item -ItemType Directory -Force -Path $tempRoot)
try {
    $file = Join-Path $tempRoot 'mdi-baseline-contoso.com.json'
    [IO.File]::WriteAllText($file, (@(
                (New-Run '2026-08-10T00:00:00' 10)
                (New-Run '2026-08-01T00:00:00' 1)
                (New-Run '2026-08-02T00:00:00' 2)
            ) | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding $true))

    # CheckTotals and ServerScores are what the new entry's fingerprint is built from, so they have to
    # match the seeded runs or the pill correctly refuses to compare and says nothing about ordering.
    $stats = [PSCustomObject]@{
        ChecksPassed = 5; ChecksTotal = 10; ChecksUnread = 0; TotalServers = 1
        CheckTotals = ([ordered]@{ 'NtlmAuditing' = @{ Pass = 1; Total = 1; Unread = 0 }; 'AdvancedAuditing' = @{ Pass = 0; Total = 1; Unread = 0 } })
        Servers = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com' })
        ServerScores = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Passed = 5; Total = 10; Unread = 0 })
    }
    $result = Get-mdiBaselineHistory -BaselinePath $tempRoot -Domain 'contoso.com' -Statistics $stats -KeepRuns 2

    $kept = @($result.History | ForEach-Object { [string] $_.Timestamp })
    Assert-True 'pruning keeps the chronologically newest run, not the last line of the file' `
        ($kept -contains '2026-08-10T00:00:00') ($kept -join ' | ')
    Assert-True 'and drops the genuinely oldest ones' `
        (-not ($kept -contains '2026-08-01T00:00:00') -and -not ($kept -contains '2026-08-02T00:00:00')) ($kept -join ' | ')
    Assert-True 'the pruned history honours -KeepRuns' (@($result.History).Count -eq 2) ("kept {0}" -f @($result.History).Count)

    $pruned = Get-PillText -History $result.History
    Assert-True 'and the pill rendered from the pruned history shows the real direction' `
        ($pruned.Down -and -not $pruned.Up) $pruned.Text

    # What was written to disk must match what was returned, or the next run reads a different history.
    # Assigned BEFORE being wrapped. ConvertFrom-Json emits a JSON array as a single pipeline object in
    # Windows PowerShell, so @(... | ConvertFrom-Json) nests the whole history into one element - the
    # exact trap the reader in the script documents at its own parse site.
    $parsedDisk = [IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    $onDisk = @($parsedDisk)
    $diskStamps = @($onDisk | ForEach-Object { [string] $_.Timestamp })
    Assert-True 'the file on disk matches the pruned history in memory' `
        (($diskStamps.Count -eq $kept.Count) -and (@($diskStamps | Where-Object { $kept -notcontains $_ }).Count -eq 0)) `
        ("disk=[{0}] memory=[{1}]" -f ($diskStamps -join ','), ($kept -join ','))
} finally {
    Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
