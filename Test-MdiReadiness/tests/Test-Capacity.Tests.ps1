<#
    Verifies the parallel traffic sampler: that it really runs concurrently, that the results are
    keyed per server, and that a failing server does not take the others down with it.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))

$sampleScriptAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$script:mdiTrafficSampleScript' }, $true)[0]
. ([scriptblock]::Create($sampleScriptAssignment.Extent.Text))

$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))

# EVERY script-scoped constant is loaded. These live at file scope rather than inside a function, so
# dot-sourcing the function bodies alone leaves them null - and a null regex in "-notmatch" matches
# everything, which silently inverted a filter and failed a suite for a reason unrelated to the script.
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

Write-Host "`n[1] Sampler script block is self-contained" -ForegroundColor Yellow
$paramNames = @($script:mdiTrafficSampleScript.Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert-That 'takes every setting as an argument' (
    ($paramNames -contains 'PerfClass') -and ($paramNames -contains 'CpuPerfClass') -and
    ($paramNames -contains 'MemoryPerfClass') -and ($paramNames -contains 'ExcludeAdapterName')
) "(params: $($paramNames -join ', '))"
# A runspace has no access to the script scope, so any reference to $settings would fail there
Assert-That 'does not reference $settings' ($script:mdiTrafficSampleScript.ToString() -notmatch '\$settings')

Write-Host "`n[2] Parallel execution" -ForegroundColor Yellow
# Unreachable RFC 5737 addresses: WMI fails fast and every runspace still returns
$targets = @('192.0.2.11', '192.0.2.12', '192.0.2.13', '192.0.2.14')
$sw = [Diagnostics.Stopwatch]::StartNew()
$result = Get-mdiTrafficSampleSet -ComputerName $targets -DurationSeconds 5 -IntervalSeconds 1
$sw.Stop()
Assert-That 'returns one entry per server' (@($result.Keys).Count -eq $targets.Count) "(got $(@($result.Keys).Count))"
Assert-That 'an unreachable server yields $null rather than throwing' (@($targets | Where-Object { $null -eq $result[$_] }).Count -eq $targets.Count)

Write-Host "`n[3] Concurrency is real" -ForegroundColor Yellow
# Each runspace sleeps; run sequentially this would take 4 x 3s, in parallel about 3s
$pool = [runspacefactory]::CreateRunspacePool(1, 4)
$pool.Open()
$shells = @(1..4 | ForEach-Object {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void] $ps.AddScript({ Start-Sleep -Seconds 3; [datetime]::Now })
        [PSCustomObject]@{ Shell = $ps; Handle = $ps.BeginInvoke() }
    })
$sw2 = [Diagnostics.Stopwatch]::StartNew()
$times = @($shells | ForEach-Object { $t = $_.Shell.EndInvoke($_.Handle); $_.Shell.Dispose(); $t })
$sw2.Stop()
$pool.Close(); $pool.Dispose()
Assert-That 'four 3s runspaces finish in well under 12s' ($sw2.Elapsed.TotalSeconds -lt 8) ("(took {0:N1}s)" -f $sw2.Elapsed.TotalSeconds)
$spread = ([datetime[]]$times | Measure-Object -Maximum).Maximum - ([datetime[]]$times | Measure-Object -Minimum).Minimum
Assert-That 'they overlap in time' ($spread.TotalSeconds -lt 2) ("(spread {0:N2}s)" -f $spread.TotalSeconds)

Write-Host "`n[4] Throttle" -ForegroundColor Yellow
$r2 = Get-mdiTrafficSampleSet -ComputerName @('192.0.2.21', '192.0.2.22') -DurationSeconds 4 -IntervalSeconds 1 -MaxParallel 1
Assert-That 'honours MaxParallel and still returns every server' (@($r2.Keys).Count -eq 2)
$r3 = Get-mdiTrafficSampleSet -ComputerName @() -DurationSeconds 4 -IntervalSeconds 1
Assert-That 'an empty target list returns an empty map' (@($r3.Keys).Count -eq 0)

Write-Host "`n[5] Capacity accepts a pre-collected sample" -ForegroundColor Yellow
$capacityParams = @((Get-Command Get-mdiCapacityPlanning).Parameters.Keys)
Assert-That 'exposes -TrafficSample' ($capacityParams -contains 'TrafficSample')
# $sample and $Sample are the same variable in PowerShell, so the local must not shadow the parameter
$body = (Get-Command Get-mdiCapacityPlanning).Definition
Assert-That 'does not assign to a local that collides with the parameter' ($body -notmatch '\$sample\s*=\s*Get-mdiTrafficSample')

Write-Host "`n[6] Busy window maths is unchanged" -ForegroundColor Yellow
$now = [datetime]::Now
$short = @(0..10 | ForEach-Object { [PSCustomObject]@{ Timestamp = $now.AddSeconds($_ * 5); PacketsPerSec = 100; CpuPercent = 1; AvailableMb = 100 } })
$b = Get-mdiBusyPacketsPerSecond -Sample $short -WindowMinutes 15
Assert-That 'a short sample is averaged and flagged' (($b.BusyPacketsPerSec -eq 100) -and (-not $b.FullWindow))
$long = @(0..400 | ForEach-Object { [PSCustomObject]@{ Timestamp = $now.AddSeconds($_ * 5); PacketsPerSec = $(if ($_ -ge 100 -and $_ -lt 300) { 900 } else { 10 }); CpuPercent = 1; AvailableMb = 100 } })
$b2 = Get-mdiBusyPacketsPerSecond -Sample $long -WindowMinutes 15
Assert-That 'a long sample uses the busiest window, not the average' (($b2.BusyPacketsPerSec -gt $b2.AveragePacketsPerSec) -and $b2.FullWindow) `
    "(busy=$($b2.BusyPacketsPerSec) avg=$($b2.AveragePacketsPerSec))"

Write-Host ("`n================ {0} passed / {1} failed ================" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
