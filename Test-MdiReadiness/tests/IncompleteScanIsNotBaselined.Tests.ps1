<#
    A scan that stopped part way must not be written into the PERMANENT baseline history.

    The script already refuses to let a partial run be read as a result: it warns "the scan did not
    complete ... Re-run it rather than reading the result" and exits 255. Get-mdiBaselineHistory
    nevertheless appended that same run to the baseline JSON unconditionally, and unlike the console
    warning the baseline is permanent and is the surface that gets reported upward.

    The damage is not confined to the partial run's own dot on the chart. A scan stops part way
    precisely because a domain controller was unreachable, so the entry it leaves behind carries a
    SHORTER server set and a smaller check total than the estate really has. The next HEALTHY run is
    then compared against that stunted entry, Test-mdiTrendPointsComparable correctly refuses the
    pair, and the healthy run is denied its delta pill - the operator is blinded at the exact moment
    the estate recovered and the improvement was worth showing.

    Measured on the shipped function before the fix, three runs (healthy, partial, healthy) against
    one baseline path:

        runs persisted : 3
        run 3 vs run 2 : IsComparable=False  "a different number of checks was covered"

    - the operator's second good scan silently lost its comparison because a failed scan sat between
    them.

    Asserted on the REAL file the REAL function writes to a REAL temp directory, so the JSON on disk
    is genuine. A test that inspected only the returned object would keep passing while the defect
    returned, because the defect is specifically about what is PERSISTED.

    The controls carry equal weight and are the reason this cannot be "fixed" by writing less:
      - a COMPLETE run must still be appended, or the trend would never populate at all;
      - the partial run must still get the full history back for its OWN report, rather than the
        single-entry fallback, so nothing is hidden from the person looking at that run;
      - a partial FIRST run must not leave a bogus file behind;
      - the refusal must be ANNOUNCED, because an operator who is not told would read the unchanged
        run count as the trend update having succeeded.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = (Resolve-Path -LiteralPath $target).ProviderPath

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The canonical functions, lifted verbatim from the shipped file rather than re-implemented.
$raw = [IO.File]::ReadAllText($target)
$i = $raw.IndexOf('#region Main')
if ($i -lt 0) { throw 'no #region Main in the canonical script' }
$pre = $raw.Substring(0, $i)
$pre = $pre -replace '(?m)^\s*#Requires.*$', ''
$pre = $pre -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
Invoke-Expression $pre

if (-not (Get-Command Get-mdiBaselineHistory -ErrorAction SilentlyContinue)) {
    throw 'Get-mdiBaselineHistory was not defined by the canonical script'
}

$settings = [PSCustomObject]@{ ScriptVersion = '9.9.9' }

$root = Join-Path ([IO.Path]::GetTempPath()) ('mdi-incomplete-baseline-{0}' -f ([guid]::NewGuid().ToString('N')))
[void] (New-Item -ItemType Directory -Path $root -Force)

function New-Stats {
    param([int] $Servers, [int] $Partial, [int] $Passed, [int] $Total)
    $names = @(1..$Servers | ForEach-Object { [PSCustomObject]@{ FQDN = ('srv{0}.contoso.com' -f $_) } })
    [PSCustomObject]@{
        CheckTotals      = @{ 'Check1' = 1; 'Check2' = 1 }
        Servers          = $names
        ChecksPassed     = $Passed
        ChecksTotal      = $Total
        ChecksUnread     = 0
        TotalServers     = $Servers
        ServerScores     = @(1..$Servers | ForEach-Object { 1 })
        PartialScanCount = $Partial
        PortsOpen        = 0; PortsTotal = 0
        NnrResolvable    = 0; NnrTargetCount = 0
        V3Ready          = 0; V3Evaluated = 0; V3Unevaluated = 0
    }
}

$healthyA = New-Stats -Servers 2 -Partial 0 -Passed 10 -Total 20
$partial  = New-Stats -Servers 1 -Partial 1 -Passed 5  -Total 10
$healthyB = New-Stats -Servers 2 -Partial 0 -Passed 18 -Total 20

$dom = 'contoso.com'
$file = $null

# --- Run 1: healthy. The control that proves the function still records ordinary runs. ---
$r1 = Get-mdiBaselineHistory -BaselinePath $root -Domain $dom -Forest $dom -Statistics $healthyA
$file = $r1.Path
$parsed1 = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
$onDisk1 = @($parsed1)
Assert-That 'A complete run IS persisted to the baseline file' ($onDisk1.Count -eq 1) ("count=$($onDisk1.Count)")

$before = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8)

# --- Run 2: partial. Must not reach the file, and must say so. ---
$wv = $null
$r2 = Get-mdiBaselineHistory -BaselinePath $root -Domain $dom -Forest $dom -Statistics $partial -WarningVariable wv
$after = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8)
# Assigned BEFORE being wrapped. ConvertFrom-Json emits a JSON array as a single pipeline object in
# Windows PowerShell, so @(... | ConvertFrom-Json) nests the whole history into a ONE-element array
# and every count assertion below would read 1 no matter what the file holds - this test passed
# against the unfixed script that way. The canonical reader documents the same trap at the point it
# parses this file.
$parsed2 = $after | ConvertFrom-Json
$onDisk2 = @($parsed2)

$untouched = [bool] ($after -ceq $before)
$announced = [bool] (@($wv) | Where-Object { "$_" -match 'not a measurement|NOT added to the baseline' })

Assert-That 'An incomplete run is NOT persisted to the baseline file' ($onDisk2.Count -eq 1) ("count=$($onDisk2.Count)")
Assert-That 'An incomplete run leaves the existing history byte-for-byte untouched' $untouched ("beforeLen=$($before.Length) afterLen=$($after.Length)")
Assert-That 'The refusal to record an incomplete run is announced' $announced ("warnings=$(@($wv) -join ' | ')")

# The returned History drives the CHART. Refusing to write the partial run to the permanent file and
# then handing it to the renderer anyway would move the false confidence rather than remove it: the
# report drew a dot for the partial run and printed a confident delta pill about it.
$returned2 = @($r2.History)
$returnedTotals = @($returned2 | ForEach-Object { [int] $_.ChecksTotal })
Assert-That 'The incomplete run is NOT in the History handed to the renderer' (-not ($returnedTotals -contains 10)) `
    ("returnedTotals=$($returnedTotals -join ',')")
Assert-That 'The incomplete run is still returned as Current for its own report' ($null -ne $r2.Current -and $r2.Current.ChecksTotal -eq 10)

# ...and it must not silently drop a run the file still holds. History and the file have to agree
# about the estate's own past, or the report and the baseline tell different stories.
# $onDisk2 is used rather than re-parsing: assigning before wrapping is the only way to get a real
# count out of ConvertFrom-Json here, and re-parsing inline reintroduced the flattening trap - under
# a mutation that restored the defect the cast threw and killed the whole file instead of failing
# one assertion, which read as "no verdict" rather than "mutant killed".
$fileTotals = @($onDisk2 | ForEach-Object { [int] $_.ChecksTotal })
Assert-That 'The returned History matches what the file actually holds' (
    ($returnedTotals -join ',') -eq ($fileTotals -join ',')) `
    ("returned=$($returnedTotals -join ',') file=$($fileTotals -join ',')")

# --- Run 3: healthy again. The payoff - the delta survives an intervening failed scan. ---
$r3 = Get-mdiBaselineHistory -BaselinePath $root -Domain $dom -Forest $dom -Statistics $healthyB
$parsed3 = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
$onDisk3 = @($parsed3)
Assert-That 'The next healthy run IS persisted' ($onDisk3.Count -eq 2) ("count=$($onDisk3.Count)")

$cmp = Test-mdiTrendPointsComparable -Previous $onDisk3[-2] -Current $onDisk3[-1]
Assert-That 'A healthy run is comparable with the previous healthy run across an intervening partial scan' ($cmp.IsComparable) ("reason=$($cmp.Reason)")

# --- Control: a partial FIRST run must not create a bogus baseline file. ---
$root2 = Join-Path ([IO.Path]::GetTempPath()) ('mdi-incomplete-baseline-{0}' -f ([guid]::NewGuid().ToString('N')))
[void] (New-Item -ItemType Directory -Path $root2 -Force)
$r4 = Get-mdiBaselineHistory -BaselinePath $root2 -Domain $dom -Forest $dom -Statistics $partial
Assert-That 'A partial first run does not create a baseline file' (-not (Test-Path -LiteralPath $r4.Path))

# --- Control: the guard keys on PartialScanCount, not on a smaller estate. ---
# A genuinely smaller COMPLETE estate (a decommissioned DC) must still be recorded, or this fix
# would quietly stop trending every estate that shrank.
$root3 = Join-Path ([IO.Path]::GetTempPath()) ('mdi-incomplete-baseline-{0}' -f ([guid]::NewGuid().ToString('N')))
[void] (New-Item -ItemType Directory -Path $root3 -Force)
$smallComplete = New-Stats -Servers 1 -Partial 0 -Passed 5 -Total 10
$r5 = Get-mdiBaselineHistory -BaselinePath $root3 -Domain $dom -Forest $dom -Statistics $smallComplete
$parsed5 = [IO.File]::ReadAllText($r5.Path, [Text.Encoding]::UTF8) | ConvertFrom-Json
$onDisk5 = @($parsed5)
Assert-That 'A complete run over a SMALLER estate is still recorded' ($onDisk5.Count -eq 1) ("count=$($onDisk5.Count)")

foreach ($d in @($root, $root2, $root3)) {
    try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

""
"  $($script:pass) passed, $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
