<#
    Get-mdiBaselineHistory decides which previous runs carry no usable timestamp, so it can keep them
    in the file while leaving them out of the trend. It made that decision with its OWN inline
    TryParseExact against the 's' round-trip format - a second, narrower copy of the parser that
    Get-mdiRunTimestamp had already been widened to replace, precisely because a real history file
    carries stamps written by an older build, edited by hand, merged from another host, or round
    tripped through a JSON serialiser that emits a UTC offset or a Z suffix.

    So the two disagreed. For a stamp like 2026-08-01T09:00:00+02:00:
      - Get-mdiChronologicalRun (which uses Get-mdiRunTimestamp) parsed it and PLOTTED it
      - the inline test did not parse it and classified it as UNDATED

    The persisted file is the concatenation of the undated runs and the trended runs, so such an entry
    was written TWICE. Every subsequent run doubled it again - a three-run history went 3, 5, 9, 17 -
    the run-count pill inflated to match, and the operator was warned that runs carried "no usable
    timestamp" at the very moment those runs were being drawn on the chart.

    These tests pin the behaviour, not the parser: a stamp that the TREND can order must never be
    counted as undated, in any of the forms a real file carries, and a genuinely undated entry must
    still be preserved and still be reported.
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

$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('mdi-basestamp-' + [Guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Force -Path $root)

$stats = [PSCustomObject]@{ ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0; ServersReady = 1; ServersTotal = 1 }

# Runs one append against a baseline seeded with the two stamps given, and reports what ended up
# on disk versus what the trend received.
#
# -BaselinePath is the CONTAINING DIRECTORY; the file name is derived from -Domain via
# ConvertTo-mdiSafeFileName. Passing the file path itself makes the function build
# <file>\<file>.lock, which cannot be created, and every case fails on a lock error instead of on
# the behaviour under test.
function Get-BaselineFile {
    param([string] $Tag)
    Join-Path $root ('mdi-baseline-' + (ConvertTo-mdiSafeFileName -Name "$Tag.test") + '.json')
}
function Read-Baseline {
    param([string] $Path)
    # Assigned before it is returned, and returned WITHOUT the comma operator. ConvertFrom-Json emits
    # a JSON array as one pipeline object in 5.1, and ", @($parsed)" then makes an array whose single
    # element IS the array - the same comma-operator trap Merge-mdiServerByFqdn documents. Each
    # caller wraps in @() itself.
    $parsed = ConvertFrom-Json ([IO.File]::ReadAllText($Path))
    @($parsed)
}
function Invoke-Append {
    param([string] $Tag, [string] $First, [string] $Second)
    $file = Get-BaselineFile -Tag $Tag
    $seed = @(
        [PSCustomObject]@{ Timestamp = $First; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0; ServersReady = 1; ServersTotal = 1 },
        [PSCustomObject]@{ Timestamp = $Second; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0; ServersReady = 1; ServersTotal = 1 }
    )
    [IO.File]::WriteAllText($file, ($seed | ConvertTo-Json -Depth 4))
    $script:warnings.Clear()
    $result = Get-mdiBaselineHistory -BaselinePath $root -Domain "$Tag.test" -Statistics $stats
    # Assigned BEFORE it is wrapped. In Windows PowerShell 5.1 ConvertFrom-Json emits a JSON array as
    # a SINGLE pipeline object, so @(... | ConvertFrom-Json) yields one element that IS the array:
    # .Count reads 1 while member enumeration still returns every Timestamp, which looks exactly like
    # the defect under test. The project's own lint rule names this trap.
    $onDisk = @(Read-Baseline -Path $file)
    [PSCustomObject]@{
        DiskCount   = $onDisk.Count
        DiskStamps  = @($onDisk | ForEach-Object { [string] $_.Timestamp })
        TrendCount  = @($result.History).Count
        Warnings    = @($script:warnings)
        FirstOnDisk = @($onDisk | Where-Object { [string] $_.Timestamp -eq $First }).Count
    }
}

try {
    Write-Host 'The parser that ORDERS the trend is the one that decides "undated"' -ForegroundColor Cyan
    # Every one of these is a stamp Get-mdiRunTimestamp can place on the time axis.
    foreach ($case in @(
            @{ Tag = 'offset'; A = '2026-08-01T09:00:00+02:00'; B = '2026-08-08T09:00:00+02:00'; What = 'a UTC offset' },
            @{ Tag = 'zulu'; A = '2026-08-01T07:00:00Z'; B = '2026-08-08T07:00:00Z'; What = 'a Z suffix' },
            @{ Tag = 'canonical'; A = '2026-08-01T09:00:00'; B = '2026-08-08T09:00:00'; What = 'the canonical s format' }
        )) {
        $stamp = Get-mdiRunTimestamp -Value $case.A
        Assert-That "$($case.What): the shared parser reads it" ($null -ne $stamp) "got null for '$($case.A)'"

        $r = Invoke-Append -Tag $case.Tag -First $case.A -Second $case.B
        Assert-That "  ...the run is appended, not duplicated" ($r.DiskCount -eq 3) "disk holds $($r.DiskCount) entries: $($r.DiskStamps -join ' | ')"
        Assert-That "  ...the seeded entry is stored exactly once" ($r.FirstOnDisk -eq 1) "found $($r.FirstOnDisk) copies of '$($case.A)'"
        Assert-That "  ...all three runs reach the trend" ($r.TrendCount -eq 3) "got $($r.TrendCount)"
        Assert-That "  ...and no run is reported as undated" ($r.Warnings.Count -eq 0) "got: $($r.Warnings -join ' ;; ')"
    }

    Write-Host 'Repeated appends do not grow the file (the doubling this defect caused)' -ForegroundColor Cyan
    $file = Get-BaselineFile -Tag 'repeat'
    $seed = @(
        [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00+02:00'; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0; ServersReady = 1; ServersTotal = 1 },
        [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00+02:00'; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0; ServersReady = 1; ServersTotal = 1 }
    )
    [IO.File]::WriteAllText($file, ($seed | ConvertTo-Json -Depth 4))
    $counts = @(for ($i = 1; $i -le 4; $i++) {
            $script:warnings.Clear()
            [void] (Get-mdiBaselineHistory -BaselinePath $root -Domain 'repeat.test' -Statistics $stats)
            @(Read-Baseline -Path $file).Count
        })
    # Four appends onto two seeded runs: at most 2 + 4 = 6, and each step may add at most one.
    Assert-That 'the file grows by at most one entry per run' `
    (($counts[0] -le 3) -and ($counts[1] -le 4) -and ($counts[2] -le 5) -and ($counts[3] -le 6)) `
    "growth was: $($counts -join ' -> ')"
    Assert-That '  ...and never doubles' (($counts[3] - $counts[0]) -le 3) "growth was: $($counts -join ' -> ')"
    $finalStamps = @(Read-Baseline -Path $file | ForEach-Object { [string] $_.Timestamp })
    # Only the SEEDED stamps are checked for duplication. The four appends above run inside the same
    # second, and the 's' format this script writes has second precision, so the newly written runs
    # legitimately share a stamp - that is an artifact of running four appends in a test, not the
    # defect. The defect duplicated the runs that were ALREADY in the file.
    $seededDupes = @($finalStamps | Where-Object { $_ -in @('2026-08-01T09:00:00+02:00', '2026-08-08T09:00:00+02:00') } |
            Group-Object | Where-Object { $_.Count -gt 1 })
    Assert-That '  ...and no pre-existing run is duplicated' ($seededDupes.Count -eq 0) `
    "duplicated: $(@($seededDupes | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ')"
    Assert-That '  ...and both pre-existing runs survive exactly once' `
    (@($finalStamps | Where-Object { $_ -eq '2026-08-01T09:00:00+02:00' }).Count -eq 1 -and
        @($finalStamps | Where-Object { $_ -eq '2026-08-08T09:00:00+02:00' }).Count -eq 1) `
    "stamps: $($finalStamps -join ' | ')"

    Write-Host 'CONTROL - a genuinely undated run is still kept and still reported' -ForegroundColor Cyan
    $r = Invoke-Append -Tag 'undated' -First 'not-a-timestamp' -Second '2026-08-08T09:00:00'
    Assert-That 'the unparseable run is preserved in the file' ($r.FirstOnDisk -eq 1) "found $($r.FirstOnDisk) copies"
    Assert-That '  ...but kept out of the trend' ($r.TrendCount -eq 2) "got $($r.TrendCount)"
    Assert-That '  ...and the operator is warned exactly once' ($r.Warnings.Count -eq 1) "got: $($r.Warnings -join ' ;; ')"
    Assert-That '  ...with a message naming one run' ($r.Warnings.Count -eq 1 -and $r.Warnings[0] -like '*1 run(s)*') "got: $($r.Warnings -join ' ;; ')"

    Write-Host 'CONTROL - an empty stamp is undated too, and a stamp is never invented for it' -ForegroundColor Cyan
    Assert-That 'an empty string has no instant' ($null -eq (Get-mdiRunTimestamp -Value ''))
    Assert-That 'a null has no instant' ($null -eq (Get-mdiRunTimestamp -Value $null))
    Assert-That 'whitespace has no instant' ($null -eq (Get-mdiRunTimestamp -Value '   '))
    $r = Invoke-Append -Tag 'empty' -First '' -Second '2026-08-08T09:00:00'
    Assert-That 'an empty-stamped run is reported as undated' ($r.Warnings.Count -eq 1) "got: $($r.Warnings -join ' ;; ')"

    Write-Host 'CONTROL - mixed stamp formats in one file order by the instant they happened' -ForegroundColor Cyan
    # 07:00Z is 09:00+02:00, i.e. the SAME instant, and both precede the third run.
    $file = Get-BaselineFile -Tag 'mixed'
    $seed = @(
        [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00+02:00'; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0; ServersReady = 1; ServersTotal = 1 },
        [PSCustomObject]@{ Timestamp = '2026-08-01T07:00:00Z'; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0; ServersReady = 1; ServersTotal = 1 }
    )
    [IO.File]::WriteAllText($file, ($seed | ConvertTo-Json -Depth 4))
    $script:warnings.Clear()
    $mixed = Get-mdiBaselineHistory -BaselinePath $root -Domain 'mixed.test' -Statistics $stats
    $order = @($mixed.History | ForEach-Object { [string] $_.Timestamp })
    Assert-That 'the earlier instant is plotted first regardless of its format' `
    ($order[0] -eq '2026-08-01T07:00:00Z') "order was: $($order -join ' | ')"
    Assert-That '  ...and no run is called undated' ($script:warnings.Count -eq 0) "got: $($script:warnings -join ' ;; ')"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
