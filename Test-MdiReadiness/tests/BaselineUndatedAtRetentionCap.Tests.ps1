# [w84] The retention cap must not delete the undated runs the warning promises are KEPT.
#
# w54-F1 established the contract: an entry with no usable timestamp is left OUT OF THE TREND but
# KEPT IN THE FILE, and the operator is told. Get-mdiBaselineHistory says so in as many words:
# "...so they are kept in the file but left out of the trend."
#
# The persist path then applied the retention cap TWICE - once to the dated history, and again to
# the concatenation after the undated runs had been PREPENDED. Select-Object -Last drops from the
# HEAD, which is exactly where the undated runs now sat, and the dated history had already claimed
# the whole cap on the first pass. So on any MATURE history - one whose dated runs have reached the
# cap, which is simply what a file looks like after a couple of months of scans - every undated run
# was destroyed on every run while the warning said it was being kept.
#
# Measured before the fix, 2 undated + 5 dated at KeepRuns 5: warning raised saying they are kept,
# 0 retained. The same file with room to spare kept both, which is why the existing all-undated
# bounded test never saw it.
#
# These tests are BEHAVIOURAL: they write a real history file, call the real Get-mdiBaselineHistory,
# and read the file back off disk. Probe: MDI-AB\live\w84-undated-at-cap.ps1

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

$work = Join-Path $env:TEMP ('baselinecap-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null

$stats = [PSCustomObject]@{
    ChecksPassed = 3; ChecksTotal = 10; ChecksUnread = 0
    TotalServers = 2; ReachableList = @('dc1.contoso.com'); UnreachableList = @()
}
function Read-History {
    param([string] $Domain)
    $file = Join-Path $work ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName $Domain))
    if (-not (Test-Path $file)) { return @() }
    $parsed = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
    @($parsed)
}
function Write-History {
    param([string] $Domain, $Runs)
    $file = Join-Path $work ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName $Domain))
    [IO.File]::WriteAllText($file, ($Runs | ConvertTo-Json -Depth 4), [Text.Encoding]::UTF8)
}
function New-Mixed {
    param([int] $Undated, [int] $Dated)
    $runs = @()
    for ($n = 1; $n -le $Undated; $n++) {
        $runs += [PSCustomObject]@{ ChecksPassed = (100 + $n); ChecksTotal = 10; Servers = @('dc1') }
    }
    for ($n = 1; $n -le $Dated; $n++) {
        $runs += [PSCustomObject]@{
            Timestamp = ([datetime]'2026-08-01T09:00:00').AddDays($n).ToString('s')
            ChecksPassed = $n; ChecksTotal = 10; Servers = @('dc1')
        }
    }
    $runs
}
# Wrapped in @() at every CALL SITE, not only inside these helpers: PowerShell unwraps a
# single-element array on the way out of a function, so an unwrapped (Get-Dated ...).Count is $null
# - not 1 - when exactly one run matches, and '$null -ge 1' is false. That produced a FAIL against a
# correct fix.
function Get-Undated { param($History) @($History | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Timestamp) }) }
function Get-Dated { param($History) @($History | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.Timestamp) }) }

try {
    '[w84] a MATURE history at the cap still keeps its undated runs'
    Write-History 'mature.test' (New-Mixed -Undated 2 -Dated 5)
    $script:warnings.Clear()
    $null = Get-mdiBaselineHistory -BaselinePath $work -Domain 'mature.test' -Statistics $stats -KeepRuns 5
    $after = Read-History 'mature.test'
    $u = @(Get-Undated $after)
    Assert-That 'both undated runs survive the cap' ($u.Count -eq 2) "(got $($u.Count))"
    $scores = @($u | ForEach-Object { [int] $_.ChecksPassed }) | Sort-Object
    Assert-That '  ...with their scores intact' (($scores -join ',') -eq '101,102') "(got '$($scores -join ',')')"
    Assert-That 'the file is still bounded by the cap' ($after.Count -le 5) "(got $($after.Count))"
    Assert-That 'the newest run is still there' (@(Get-Dated $after).Count -ge 1) "(dated: $(@(Get-Dated $after).Count))"

    '[w84] and the warning it prints is TRUE'
    # A warning that lies is worse than no warning: it is the thing that stops the operator looking.
    $w = ($script:warnings -join ' ')
    Assert-That 'a warning is raised' ($script:warnings.Count -ge 1) "(got $($script:warnings.Count))"
    Assert-That '  ...and it says they are kept, which they now are' ($w -match '(?i)kept') "(got '$w')"
    Assert-That '  ...and does not claim any were dropped' (-not ($w -match '(?i)dropped')) "(got '$w')"

    '[w84] the cap is still enforced when the undated runs alone would burst it'
    # The file must never grow without end, so untrendable entries cannot claim the whole cap.
    Write-History 'burst.test' (New-Mixed -Undated 9 -Dated 2)
    $script:warnings.Clear()
    $null = Get-mdiBaselineHistory -BaselinePath $work -Domain 'burst.test' -Statistics $stats -KeepRuns 5
    $afterB = Read-History 'burst.test'
    Assert-That 'the file is bounded by the cap' ($afterB.Count -le 5) "(got $($afterB.Count))"
    Assert-That 'the CURRENT run always survives' (@(Get-Dated $afterB).Count -ge 1) "(dated: $(@(Get-Dated $afterB).Count))"
    Assert-That 'some undated runs are still kept' (@(Get-Undated $afterB).Count -ge 1) "(undated: $(@(Get-Undated $afterB).Count))"

    '[w84] when the cap DOES force an undated run out, the warning says so'
    $wB = ($script:warnings -join ' ')
    Assert-That 'a warning is raised' ($script:warnings.Count -ge 1) "(got $($script:warnings.Count))"
    Assert-That '  ...disclosing that runs were dropped' ($wB -match '(?i)dropped') "(got '$wB')"
    Assert-That '  ...and NOT claiming they were all kept' (-not ($wB -match '(?i)they are kept in the file')) "(got '$wB')"
    Assert-That '  ...naming the retention limit' ($wB -match '5') "(got '$wB')"

    '[w84] CONTROL - with room to spare nothing is dropped at all'
    Write-History 'roomy.test' (New-Mixed -Undated 2 -Dated 5)
    $script:warnings.Clear()
    $null = Get-mdiBaselineHistory -BaselinePath $work -Domain 'roomy.test' -Statistics $stats -KeepRuns 20
    $afterR = Read-History 'roomy.test'
    Assert-That 'every run is still in the file' ($afterR.Count -eq 8) "(got $($afterR.Count))"
    Assert-That '  ...including both undated ones' (@(Get-Undated $afterR).Count -eq 2) "(got $(@(Get-Undated $afterR).Count))"
    Assert-That '  ...and the warning does not mention dropping' (-not (($script:warnings -join ' ') -match '(?i)dropped')) `
        "(got '$($script:warnings -join ' ')')"

    '[w84] CONTROL - an undated run still never enters the trend'
    # Preserving the file must not undo the reason ordering excluded them in the first place.
    Write-History 'trend.test' (New-Mixed -Undated 2 -Dated 5)
    $script:warnings.Clear()
    $r = Get-mdiBaselineHistory -BaselinePath $work -Domain 'trend.test' -Statistics $stats -KeepRuns 5
    $plottedUndated = @($r.History | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Timestamp) })
    Assert-That 'no undated run is plotted' ($plottedUndated.Count -eq 0) "(got $($plottedUndated.Count))"
    Assert-That 'the trend still has dated runs to plot' (@($r.History).Count -ge 1) "(got $(@($r.History).Count))"

    '[w84] CONTROL - a history with no undated runs is unaffected'
    Write-History 'clean.test' (New-Mixed -Undated 0 -Dated 5)
    $script:warnings.Clear()
    $null = Get-mdiBaselineHistory -BaselinePath $work -Domain 'clean.test' -Statistics $stats -KeepRuns 5
    $afterC = Read-History 'clean.test'
    Assert-That 'the file is capped as before' ($afterC.Count -eq 5) "(got $($afterC.Count))"
    Assert-That 'no warning is raised' ($script:warnings.Count -eq 0) "(got '$($script:warnings -join ' ')')"
} finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
