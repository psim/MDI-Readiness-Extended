# Three defects in what a run CLAIMS versus what it examined.
#
#  cli-1  A run with -SkipNetworkPorts -SkipCA -SkipEntraConnect examined a fraction of the
#         prerequisites and still printed an unqualified "READY / All prerequisites met" and exited 0.
#         The skipped areas were correctly removed from the denominator and the detail tabs said
#         "skipped" - but the two headline surfaces a human and a compliance job actually read turned
#         a partial assessment into an unqualified success. The report carried no record of the skips
#         at all, so the verdict could not have qualified itself even if it had wanted to.
#  cc-1   Two scans of the same estate writing to the same -Path aborted each other: Out-File holds
#         FileShare.None, so the loser took a terminating IOException. Measured at 7 of 75 writes
#         across three processes - and a collision on the LAST write left the trend having already
#         gained a point for a run the operator was told had failed.
#  cc-2   A BOM-less baseline history read by Get-Content is decoded as ANSI, so a non-ASCII server
#         name was corrupted and WRITTEN BACK; the trend then reported that the set of servers had
#         changed on an estate that had not changed.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$healthy = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
    OSVersion = $true; NPCAP = $true; PowerScheme = $true
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
}
function New-ScopedReport {
    param($Skipped)
    $r = [PSCustomObject]@{ DomainControllers = @($healthy); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @()
    }
    if ($null -ne $Skipped) { $r | Add-Member -NotePropertyName SkippedAreas -NotePropertyValue @($Skipped) -Force }
    $r
}

'[scope] a run says what it did not examine'
$fullScan = New-ScopedReport -Skipped @()
Assert-That 'a full scan adds no qualifier' ([string]::IsNullOrEmpty((Get-mdiVerdictQualifier -ReportData $fullScan)))
Assert-That '  ...and is still READY' ((Test-mdiReadinessResult -ReportData $fullScan) -eq $true)

$partialScan = New-ScopedReport -Skipped @('Network ports', 'Certification authority servers', 'Entra Connect servers')
$qualifier = Get-mdiVerdictQualifier -ReportData $partialScan
Assert-That 'a partial scan names every skipped area' (
    $qualifier -match 'Network ports' -and $qualifier -match 'Certification authority servers' -and $qualifier -match 'Entra Connect servers') "(got '$qualifier')"
# A skip is a legitimate choice, not a failure: the verdict must not flip, only qualify itself.
Assert-That 'a skip does not turn into a failure' ((Test-mdiReadinessResult -ReportData $partialScan) -eq $true)

# Behavioural: the qualifier must reach BOTH verdicts. Asserting on the source text pinned it to the
# READY branch only, so widening it to "Action required" - the verdict an operator reads while
# deciding what to act on, and the one that most needs to say the scan was partial - broke a test
# whose actual subject had not changed.
$verdictBody = (Get-Command Set-MdiReadinessReport).Definition
Assert-That 'the HTML headline appends the qualifier' ($verdictBody -match 'Get-mdiVerdictQualifier -ReportData')
Assert-That '  ...on the ready verdict' ($verdictBody -match 'All prerequisites met')
Assert-That '  ...and on the action-required verdict too' ($verdictBody -match "Action required'[^\r\n]*\}\s*\)?\s*\+")
$mainRegion = (Get-Content -LiteralPath $target -Raw)
$mainRegion = $mainRegion.Substring($mainRegion.IndexOf('#region Main'))
Assert-That 'the console READY line appends it too' ($mainRegion -match 'Get-mdiVerdictQualifier -ReportData \$report\b')
# A typo'd variable would silently pass $null and the qualifier would vanish without any error.
Assert-That '  ...using a variable that exists in that scope' ($mainRegion -notmatch 'Get-mdiVerdictQualifier -ReportData \$reportData')
Assert-That 'the report records the skipped areas' ($mainRegion -match 'SkippedAreas\s*=')

'[scope] older reports and hostile input'
Assert-That 'a report without SkippedAreas produces no qualifier' (
    [string]::IsNullOrEmpty((Get-mdiVerdictQualifier -ReportData ([PSCustomObject]@{ DomainControllers = @($healthy) }))))
Assert-That 'a null report is handled' ([string]::IsNullOrEmpty((Get-mdiVerdictQualifier -ReportData $null)))
Assert-That 'blank entries do not produce a stray qualifier' (
    [string]::IsNullOrEmpty((Get-mdiVerdictQualifier -ReportData (New-ScopedReport -Skipped @('', ' ', $null)))))

'[concurrency] a locked report file is waited for, not fatal'
$ccDir = Join-Path $env:TEMP ('cc-{0}' -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $ccDir | Out-Null

# Is the file exclusively held right now? Used to synchronise with the holder instead of guessing.
function Test-HeldByAnother {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $probe = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $probe.Close()
        return $false
    }
    catch [System.IO.IOException] { return $true }
}

try {
    $file = Join-Path $ccDir 'report.json'
    # Held long enough that the writer has to retry at least once after the lock is confirmed.
    $holder = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList '-NoProfile', '-Command', "`$s=[System.IO.File]::Open('$file',[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None); Start-Sleep -Seconds 4; `$s.Close()" `
        -PassThru -WindowStyle Hidden

    # WAIT FOR THE LOCK, do not assume it. This used to sleep a fixed 500 ms, but starting
    # powershell.exe on a loaded machine takes about a second, so the writer won the race, wrote its
    # 11 bytes, and the holder's FileMode::Create then TRUNCATED the file to zero and held it. The
    # test read back an empty file and blamed Write-mdiReportFile for a lock it had never met -
    # measured: the writer returned in 0.0s having thrown nothing, which is impossible against a real
    # lock. Synchronising on the observable lock tests the retry path instead of the scheduler.
    $lockWait = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-HeldByAnother -Path $file) -and $lockWait.Elapsed.TotalSeconds -lt 20) {
        Start-Sleep -Milliseconds 20
    }
    $lockWait.Stop()
    $lockHeld = Test-HeldByAnother -Path $file
    # If the holder never took the lock there is nothing to retry against, and passing the assertions
    # below would be vacuous - the exact failure mode this file exists to prevent elsewhere.
    Assert-That 'the holder actually acquired the lock' $lockHeld "(after $([math]::Round($lockWait.Elapsed.TotalSeconds,2))s)"

    $threw = $false
    $waited = [Diagnostics.Stopwatch]::StartNew()
    try { Write-mdiReportFile -Content '{"ok":true}' -FilePath $file } catch { $threw = $true }
    $waited.Stop()
    try { $holder | Wait-Process -Timeout 30 } catch { }
    Assert-That 'a file held by another process is waited for' (-not $threw)
    # Read defensively: an empty file returns $null from -Raw, and calling .Trim() on it threw, which
    # aborted the whole file and reported "NO PARSEABLE TOTAL" rather than one failed assertion.
    $landed = if (Test-Path -LiteralPath $file) { [string] (Get-Content -LiteralPath $file -Raw) } else { '' }
    Assert-That '  ...and the content lands' ($landed.Trim() -eq '{"ok":true}') "(got '$($landed.Trim())')"
    Assert-That '  ...after actually waiting for the release' ($lockHeld -and $waited.Elapsed.TotalSeconds -gt 0.5) `
        "($([math]::Round($waited.Elapsed.TotalSeconds,2))s)"

    # A genuinely impossible path must still fail loudly - a run that writes nothing must not claim success.
    # It must also fail FAST and say what actually happened. DirectoryNotFoundException,
    # FileNotFoundException and PathTooLongException all derive from IOException, so a catch on the
    # base type retried a permanently broken path for the whole timeout and then reported it as
    # "still locked by another process", sending the operator to hunt a second process that does not
    # exist instead of looking at their own -Path.
    $impossible = Join-Path $ccDir 'no-such-folder\x.json'
    $failedLoudly = $false
    $failMessage = ''
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { Write-mdiReportFile -Content 'x' -FilePath $impossible -TimeoutSeconds 6 } catch { $failedLoudly = $true; $failMessage = $_.Exception.Message }
    $sw.Stop()
    Assert-That 'an unwritable path still raises' $failedLoudly
    Assert-That '  ...without burning the retry timeout' ($sw.Elapsed.TotalSeconds -lt 3) "($([int]$sw.Elapsed.TotalSeconds)s)"
    Assert-That '  ...and does not blame a phantom lock' ($failMessage -notmatch 'locked by another process')
    Assert-That '  ...but names the real cause' ($failMessage -match 'find|path|directory') "($failMessage)"

    # Behavioural, not textual: the writer is what every artefact goes through, so assert what the
    # writer DOES. A source-text search for "| Out-File" passed just as happily when a writer used
    # Set-Content or WriteAllText with the wrong encoding, which is the failure it existed to catch.
    $utf8File = Join-Path $ccDir 'enc.json'
    Write-mdiReportFile -Content ('{"n":"dc-m' + [char]0xFC + 'nchen"}') -FilePath $utf8File
    $bytes = [System.IO.File]::ReadAllBytes($utf8File)
    Assert-That 'report files are written UTF-8 with a BOM' (
        $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Assert-That '  ...so a non-ASCII name survives Get-Content' (
        (Get-Content -LiteralPath $utf8File -Raw) -match ('dc-m' + [char]0xFC + 'nchen'))
} finally {
    Remove-Item $ccDir -Recurse -Force -ErrorAction SilentlyContinue
}

'[encoding] the baseline history survives a BOM-less file'
$blDir = Join-Path $env:TEMP ('bl-{0}' -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $blDir | Out-Null
try {
    $umlautName = 'dc-m' + [char]0xFC + 'nchen.contoso.com'
    $srv = [PSCustomObject]@{ FQDN = $umlautName; Unreachable = $false; PartialFailure = $false
        OSVersion = $true; NPCAP = $true; Details = [PSCustomObject]@{}
    }
    $stats = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
            DomainControllers = @($srv); CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com')
        })
    $first = Get-mdiBaselineHistory -BaselinePath $blDir -Domain 'contoso.com' -Statistics $stats 3>$null
    Assert-That 'the name is recorded intact' ((@($first.Current.ServerNames) -join ',') -eq $umlautName)

    # Rewrite the history WITHOUT a BOM, exactly as PowerShell 7, VS Code or jq would.
    $json = [System.IO.File]::ReadAllText($first.Path, [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText($first.Path, $json, (New-Object System.Text.UTF8Encoding $false))
    Start-Sleep -Milliseconds 1100
    $second = Get-mdiBaselineHistory -BaselinePath $blDir -Domain 'contoso.com' -Statistics $stats 3>$null
    $readBack = @(@($second.History)[0].ServerNames) -join ','
    Assert-That 'a BOM-less history still reads the name correctly' ($readBack -eq $umlautName) "(got '$readBack')"
} finally {
    Remove-Item $blDir -Recurse -Force -ErrorAction SilentlyContinue
}


'[AsJson] the machine-readable mode keeps human text off stdout'
# Write-Host writes to the information stream, which powershell.exe folds into stdout - so the banner,
# the verdict and the report paths landed immediately before the JSON document and the obvious caller
# (Test-MdiReadiness.ps1 -AsJson | ConvertFrom-Json) could not parse it.
$jsonWork = Join-Path $env:TEMP ('aj-{0}' -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $jsonWork | Out-Null
try {
    $probe = Join-Path $jsonWork 'probe.ps1'
    Set-Content -LiteralPath $probe -Value @"
param([switch] `$AsJson)
function Write-mdiConsole {$((Get-Command Write-mdiConsole).Definition)}
Write-mdiConsole -AsJson:`$AsJson '  READY  3/3 checks passed.' -ForegroundColor Green
if (`$AsJson) { '{"verdict":"ready"}' }
"@ -Encoding UTF8
    $shell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    foreach ($jsonMode in @($false, $true)) {
        $so = Join-Path $jsonWork 'o.txt'; $se = Join-Path $jsonWork 'e.txt'
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $probe))
        if ($jsonMode) { $a += '-AsJson' }
        Start-Process -FilePath $shell -ArgumentList $a -Wait -NoNewWindow -RedirectStandardOutput $so -RedirectStandardError $se | Out-Null
        $stdout = [string] (Get-Content -LiteralPath $so -Raw)
        $stderr = [string] (Get-Content -LiteralPath $se -Raw)
        if ($jsonMode) {
            $parses = $false
            try { $null = $stdout | ConvertFrom-Json; $parses = $true } catch { }
            Assert-That '-AsJson stdout parses as JSON' $parses "(stdout '$($stdout.Trim())')"
            Assert-That '  ...and the banner goes to stderr' ($stderr -match 'checks passed')
            Assert-That '  ...leaving no human text on stdout' ($stdout -notmatch 'checks passed')
        } else {
            Assert-That 'a normal run still prints the banner for a human' ($stdout -match 'checks passed')
        }
    }
} finally {
    Remove-Item $jsonWork -Recurse -Force -ErrorAction SilentlyContinue
}
Assert-That 'the main region no longer calls Write-Host directly' (
    ($mainRegion -replace '(?m)^\s*#.*$', '') -notmatch 'Write-Host ')

'[docs] the -FailOnIssues help matches what the code returns'
$helpText = Get-Content -LiteralPath $target -Raw
Assert-That 'the help says ISSUES, not failed checks' (
    $helpText -match '(?s)\.PARAMETER FailOnIssues.{0,400}number of ISSUES')
Assert-That 'and states the full exit-code contract' (
    $helpText -match '(?s)\.PARAMETER FailOnIssues.{0,900}255\s+the scan did not run')

# Capacity planning is OPT-IN (-CapacityPlanning), so it must not be listed as "not examined" on an
# ordinary run - a qualifier that appears every time is one operators learn to ignore.
$mainForSkips = $mainRegion
Assert-That 'the skip list only names areas explicitly turned off' (
    $mainForSkips -notmatch "if \(-not \`$CapacityPlanning\) \{ 'Capacity planning' \}")
Assert-That '  ...and still records every -Skip switch' (
    $mainForSkips -match "SkipNetworkPorts\) \{ 'Network ports' \}" -and
    $mainForSkips -match "SkipCA\) \{ 'Certification authority servers' \}" -and
    $mainForSkips -match "SkipEntraConnect\) \{ 'Entra Connect servers' \}" -and
    $mainForSkips -match "SkipSensorV3Readiness\) \{ 'Sensor v3.x readiness' \}")
# A missed -AsJson at any one call site silently reintroduces the JSON-parsing bug.
$consoleCalls = [regex]::Matches($mainRegion, 'Write-mdiConsole')
$consoleWithSwitch = [regex]::Matches($mainRegion, 'Write-mdiConsole -AsJson:\$AsJson')
Assert-That 'every console call propagates -AsJson' (
    $consoleCalls.Count -eq $consoleWithSwitch.Count -and $consoleCalls.Count -ge 15) "($($consoleWithSwitch.Count) of $($consoleCalls.Count))"

'[stdout purity] a warning must never corrupt the JSON channel'
# Write-Warning emits a WarningRecord, and powershell.exe -File folds the warning stream into STDOUT
# - measured, not assumed. So under -AsJson a single warning breaks the documented caller,
# Test-MdiReadiness.ps1 -AsJson | ConvertFrom-Json, with "Unexpected character encountered while
# parsing value: W". Warning is the ordinary state on a large estate, so this broke automation on
# most real scans.
$rawTarget = Get-Content -LiteralPath $target -Raw
Assert-That 'a warning writer exists that respects JSON mode' ($rawTarget -match 'function Write-mdiWarning')
# Counted from the PARSED script, not from raw text: the writer's own docstring explains the trap and
# quotes "Write-Warning" twice in prose, which a text search cannot tell from a call.
$rawAst = [System.Management.Automation.Language.Parser]::ParseInput($rawTarget, [ref]$null, [ref]$null)
$bareWarnCalls = @($rawAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Write-Warning'
        }, $true))
Assert-That 'no bare Write-Warning call survives outside that writer' ($bareWarnCalls.Count -eq 1) `
    "(found $($bareWarnCalls.Count) call(s), expected 1 - the fallback inside Write-mdiWarning)"
Assert-That '  ...and the one that remains is inside Write-mdiWarning' (
    $bareWarnCalls.Count -eq 1 -and
    ($rawTarget.Substring(0, $bareWarnCalls[0].Extent.StartOffset).LastIndexOf('function Write-mdiWarning') -gt
     $rawTarget.Substring(0, $bareWarnCalls[0].Extent.StartOffset).LastIndexOf('function Write-mdiConsole')))
Assert-That 'JSON mode is set at the top of Main, before anything can warn' (
    $rawTarget -match '(?s)#region Main.{0,400}\$script:mdiJsonMode = \[bool\] \$AsJson')

# Behavioural: run a child process and see which stream each warning actually lands on.
$warnProbeText = @'
$src = "__SRC__"
$t = [IO.File]::ReadAllText($src)
$b = $t -replace '(?m)^\s*#Requires.*$','' -replace '(?m)^\s*\[CmdletBinding\(.*$',''
$i = $b.IndexOf('#region Main'); if ($i -gt 0) { $b = $b.Substring(0,$i) }
Invoke-Expression $b
$script:mdiJsonMode = $false
Write-mdiWarning 'plain-mode-warning'
$script:mdiJsonMode = $true
Write-mdiWarning 'json-mode-warning'
Write-Output '{"payload":true}'
'@
$warnProbeText = $warnProbeText.Replace('__SRC__', $target)
$stamp = [guid]::NewGuid().ToString('N').Substring(0, 8)
$probeFile = Join-Path $env:TEMP "mdi-warn-$stamp.ps1"
$probeOut = Join-Path $env:TEMP "mdi-warn-$stamp.out"
$probeErr = Join-Path $env:TEMP "mdi-warn-$stamp.err"
[IO.File]::WriteAllText($probeFile, $warnProbeText)
# The probe deliberately writes to stderr, and PowerShell surfaces a native command's stderr as an
# error record - which under this file's $ErrorActionPreference = 'Stop' terminated the test run
# before it could print its own summary. The preference is relaxed just around the call.
$previousEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $probeFile 1> $probeOut 2> $probeErr
} finally {
    $ErrorActionPreference = $previousEap
}
$probeStdout = [IO.File]::ReadAllText($probeOut)
$probeStderr = [IO.File]::ReadAllText($probeErr)
Remove-Item $probeFile, $probeOut, $probeErr -Force -ErrorAction SilentlyContinue

Assert-That 'a JSON-mode warning does NOT reach stdout' ($probeStdout -notmatch 'json-mode-warning')
Assert-That '  ...it reaches stderr instead' ($probeStderr -match 'json-mode-warning')
Assert-That '  ...leaving the payload line intact on stdout' ($probeStdout -match '\{"payload":true\}')
# Outside JSON mode the ordinary warning stream is unchanged, so interactive users lose nothing.
Assert-That 'a plain-mode warning still uses the warning stream' ($probeStdout -match 'plain-mode-warning')

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
