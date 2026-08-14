# A baseline history entry with no usable timestamp was silently DELETED from the operator's file.
#
#  w54-F1  Get-mdiChronologicalRun EXCLUDES a run whose Timestamp cannot be parsed. That is correct
#          for a time axis - a run with no position in time must never become the "previous run" a
#          delta is measured against - and catastrophic for a file, because Get-mdiBaselineHistory
#          wrote the ordered result straight back to disk. Runs the ordering function only meant to
#          leave off the chart were erased from the operator's history for good.
#
#          Measured: a three-run legacy history with no Timestamp on any entry came back holding a
#          single entry after the next scan, with ZERO warnings, and the report then said "At least
#          two runs are needed to draw a trend" about the baseline it had just destroyed. The same
#          happened to a single hand-merged entry sitting among timestamped ones - a hand merge, a
#          restored backup, or two hosts writing the same share, all scenarios the ordering
#          function's own documentation names.
#
#          The function's documented legacy safety net ("if NOTHING in the file carries a parseable
#          timestamp the file predates this format and is returned unchanged") could never fire from
#          the persisting caller, because the CURRENT entry is appended before the call and always
#          carries a timestamp - so the "nothing is dated" condition was unreachable there.
#
#          The fix separates the two concerns: what the trend may PLOT, and what the file KEEPS.
#          Undated runs are preserved and the operator is warned, rather than being deleted in
#          silence.
#
# These tests are BEHAVIOURAL: they write a real history file, call the real Get-mdiBaselineHistory,
# and read the file back off disk.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
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

$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

$work = Join-Path $env:TEMP ('baseline-{0}' -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null

function Read-History {
    param([string] $Domain)
    $file = Join-Path $work ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName $Domain))
    if (-not (Test-Path $file)) { return @() }
    # Assigned BEFORE being wrapped: ConvertFrom-Json emits a JSON array as one pipeline object in
    # Windows PowerShell, so @(... | ConvertFrom-Json) would nest the whole history in one element.
    $parsed = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
    @($parsed)
}
function Write-History {
    param([string] $Domain, $Runs)
    $file = Join-Path $work ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName $Domain))
    [IO.File]::WriteAllText($file, ($Runs | ConvertTo-Json -Depth 4), [Text.Encoding]::UTF8)
}
$stats = [PSCustomObject]@{
    ChecksPassed = 3; ChecksTotal = 10; ChecksUnread = 0
    TotalServers = 2; ReachableList = @('dc1.contoso.com'); UnreachableList = @()
}

try {
    '[baseline] a wholly undated legacy history survives the next run'
    Write-History 'legacy.test' @(
        [PSCustomObject]@{ ChecksPassed = 1; ChecksTotal = 10; Servers = @('dc1') }
        [PSCustomObject]@{ ChecksPassed = 2; ChecksTotal = 10; Servers = @('dc1') }
        [PSCustomObject]@{ ChecksPassed = 5; ChecksTotal = 10; Servers = @('dc1') }
    )
    $script:warnings.Clear()
    $r = Get-mdiBaselineHistory -BaselinePath $work -Domain 'legacy.test' -Statistics $stats
    $after = Read-History 'legacy.test'
    Assert-That 'no run is deleted from the file' ($after.Count -eq 4) "(expected 4, got $($after.Count))"
    $kept = @($after | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Timestamp) })
    Assert-That 'all three legacy runs are still there' ($kept.Count -eq 3) "(got $($kept.Count))"
    # The scores prove it is the same three runs, not three blanks.
    $scores = @($kept | ForEach-Object { [int] $_.ChecksPassed }) | Sort-Object
    Assert-That '  ...with their scores intact' (($scores -join ',') -eq '1,2,5') "(got '$($scores -join ',')')"
    Assert-That 'the new run was appended' (@($after | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.Timestamp) }).Count -eq 1)

    '[baseline] the operator is TOLD, rather than losing history in silence'
    Assert-That 'a warning is raised' ($script:warnings.Count -ge 1) "(got $($script:warnings.Count))"
    $w = ($script:warnings -join ' ')
    Assert-That '  ...naming how many runs are affected' ($w -match '3 run\(s\)') "(got '$w')"
    Assert-That '  ...saying they are kept' ($w -match '(?i)kept') "(got '$w')"
    Assert-That '  ...and that they are not trended' ($w -match '(?i)trend') "(got '$w')"

    '[baseline] an undated run never enters the trend'
    # The whole reason ordering excludes them: an undated run must not become the previous run a
    # delta is measured against. Preserving the file must not undo that.
    $plotted = @($r.History)
    $undatedPlotted = @($plotted | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Timestamp) })
    Assert-That 'the trend plots no undated run' ($undatedPlotted.Count -eq 0) "(got $($undatedPlotted.Count))"

    '[baseline] one hand-merged entry among timestamped ones is kept too'
    Write-History 'mixed.test' @(
        [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 1; ChecksTotal = 10; Servers = @('dc1') }
        [PSCustomObject]@{ ChecksPassed = 2; ChecksTotal = 10; Servers = @('dc1') }
        [PSCustomObject]@{ Timestamp = '2026-08-05T09:00:00'; ChecksPassed = 5; ChecksTotal = 10; Servers = @('dc1') }
    )
    $script:warnings.Clear()
    $r2 = Get-mdiBaselineHistory -BaselinePath $work -Domain 'mixed.test' -Statistics $stats
    $after2 = Read-History 'mixed.test'
    Assert-That 'the hand-merged entry is not deleted' ($after2.Count -eq 4) "(expected 4, got $($after2.Count))"
    $orphan = @($after2 | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Timestamp) })
    Assert-That '  ...and keeps its score' ($orphan.Count -eq 1 -and [int] $orphan[0].ChecksPassed -eq 2) "(got $($orphan.Count) entr(ies))"
    Assert-That 'a warning is raised for it too' ($script:warnings.Count -ge 1) "(got $($script:warnings.Count))"
    # The dated runs must still be in time order for the trend.
    $dated = @($r2.History | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.Timestamp) })
    $stampOrder = @($dated | ForEach-Object { [string] $_.Timestamp })
    $sorted = @($stampOrder | Sort-Object)
    Assert-That 'the trend is still in time order' (($stampOrder -join '|') -eq ($sorted -join '|')) "(got '$($stampOrder -join '|')')"

    '[baseline] an ordinary all-dated history is completely unaffected'
    # The common case must not have gained a warning or an extra entry.
    Write-History 'normal.test' @(
        [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 1; ChecksTotal = 10; Servers = @('dc1') }
        [PSCustomObject]@{ Timestamp = '2026-08-05T09:00:00'; ChecksPassed = 5; ChecksTotal = 10; Servers = @('dc1') }
    )
    $script:warnings.Clear()
    $r3 = Get-mdiBaselineHistory -BaselinePath $work -Domain 'normal.test' -Statistics $stats
    $after3 = Read-History 'normal.test'
    Assert-That 'the file holds the two runs plus the new one' ($after3.Count -eq 3) "(got $($after3.Count))"
    Assert-That 'no warning is raised' ($script:warnings.Count -eq 0) "(got '$($script:warnings -join ' ')')"
    Assert-That 'the trend plots all three' (@($r3.History).Count -eq 3) "(got $(@($r3.History).Count))"

    '[baseline] the file stays bounded'
    # A history that keeps undated runs must still not grow without end.
    $many = @(for ($n = 1; $n -le 8; $n++) { [PSCustomObject]@{ ChecksPassed = $n; ChecksTotal = 10; Servers = @('dc1') } })
    Write-History 'bounded.test' $many
    $script:warnings.Clear()
    $null = Get-mdiBaselineHistory -BaselinePath $work -Domain 'bounded.test' -Statistics $stats -KeepRuns 5
    $after4 = Read-History 'bounded.test'
    Assert-That 'the retention cap is applied to the whole file' ($after4.Count -le 5) "(got $($after4.Count))"
    Assert-That '  ...and the newest run is still there' (@($after4 | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.Timestamp) }).Count -eq 1) "(got $($after4.Count))"
} finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
