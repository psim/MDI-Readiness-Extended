<#
    THE PORT-PROBE COMMAND LINE HAD TO ACTUALLY RUN, NOT JUST FIT.

    Get-mdiPortProbeCommandLine builds the command line that Win32_Process.Create runs on every
    scanned server. It used -EncodedCommand, which costs 2.67 characters of command line for every
    character of stub - UTF-16 doubles it, then base64 adds a third - and that multiplier applied to
    the ENTIRE compressed payload rather than to a small wrapper.

    Measured on a 25-domain-controller, 10-target plan: an 11,392 character payload became a 31,106
    character command line, past the 31,000 budget the payload tests defend and only 894 characters
    short of the hard 32,000 throw. It got there while the shipped probe code was SHRINKING - the
    compressed function text was 578 characters smaller than a week earlier - so no amount of trimming
    helpers would have held the line. The multiplier was the defect.

    Passing the same payload as an ordinary -Command argument costs one character per character. The
    payload is base64, so its alphabet is A-Z a-z 0-9 + / = and nothing in it can close the quoting
    or be read as an operator; Win32_Process.Create calls CreateProcess directly, so there is no
    shell to satisfy either.

    Fitting is not the point though - RUNNING is. A command line can be short and still be malformed,
    so this file EXECUTES the generated command line the way CreateProcess does (the executable plus
    its literal argument string, UseShellExecute off) and asserts the probe wrote parseable results.
    A test that only measured the length would pass on a command line no machine could run.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

$outputFile = Join-Path ([IO.Path]::GetTempPath()) ('mdi-cmdline-{0}.json' -f [guid]::NewGuid().ToString('N'))
# Loopback, a short timeout and no NNR targets: the probe finishes in seconds and needs no lab.
$plan = New-mdiPortProbePlan -Domain 'contoso.com' -TimeoutMs 300 `
    -DomainController @([PSCustomObject]@{ Name = '127.0.0.1'; IP = '127.0.0.1' }) -NnrTarget @()
$commandLine = Get-mdiPortProbeCommandLine -Plan $plan -OutputFile $outputFile

Write-Host 'The generated command line must be well formed for CreateProcess' -ForegroundColor Cyan
Assert-That 'it is a single line' ($commandLine -notmatch "`n" -and $commandLine -notmatch "`r") (
    'the command line spans more than one line, which ends the command rather than continuing it')
Assert-That 'it invokes powershell.exe non-interactively' (
    $commandLine -match '^powershell\.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass ') (
    $commandLine.Substring(0, [Math]::Min(90, $commandLine.Length)))
# The quoting only holds because the payload's alphabet cannot close it. Stated as an assertion so a
# future change that puts operator text into this command line fails here rather than in production.
$quoted = [regex]::Match($commandLine, '-Command "(.+)"$').Groups[1].Value
Assert-That 'the quoted argument was recovered whole' ($quoted.Length -gt 100) "($($quoted.Length) chars)"
Assert-That 'the quoted argument contains no double quote of its own' (
    $quoted -notmatch '"') 'a double quote inside the argument would end it early'
$payload = [regex]::Match($quoted, "FromBase64String\('([^']+)'\)").Groups[1].Value
Assert-That 'the embedded payload is pure base64' (
    $payload.Length -gt 100 -and $payload -match '^[A-Za-z0-9+/=]+$') (
    "($($payload.Length) chars)")

Write-Host ''
Write-Host 'And it must actually run and produce probe results' -ForegroundColor Cyan
$exe = ($commandLine -split ' ', 2)[0]
$arguments = ($commandLine -split ' ', 2)[1]
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.Arguments = $arguments
$psi.UseShellExecute = $false      # CreateProcess, no shell - the same as Win32_Process.Create
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$process = [System.Diagnostics.Process]::Start($psi)
$stdout = $process.StandardOutput.ReadToEnd()
$stderr = $process.StandardError.ReadToEnd()
$exited = $process.WaitForExit(180000)

try {
    Assert-That 'the process finished' $exited 'it was still running after 180s'
    Assert-That 'it exited cleanly' ($process.ExitCode -eq 0) (
        "exit=$($process.ExitCode) stderr=$($stderr.Trim())")
    Assert-That 'it wrote nothing to stderr' ([string]::IsNullOrWhiteSpace($stderr)) $stderr.Trim()
    Assert-That 'the output file was created' (Test-Path $outputFile) $outputFile

    $records = @()
    if (Test-Path $outputFile) {
        $json = [IO.File]::ReadAllText($outputFile)
        $parsed = $null
        try { $parsed = $json | ConvertFrom-Json } catch { }
        $records = @($parsed)
        Assert-That 'the results parse as JSON' ($null -ne $parsed) (
            "($($json.Length) bytes) " + $json.Substring(0, [Math]::Min(120, $json.Length)))
    }
    Assert-That 'the probe returned at least one record' ($records.Count -gt 0) "($($records.Count) records)"
    Assert-That 'the records carry the shape the caller reads' (
        $records.Count -gt 0 -and
        ($records[0].PSObject.Properties.Name -contains 'Id') -and
        ($records[0].PSObject.Properties.Name -contains 'Protocol') -and
        ($records[0].PSObject.Properties.Name -contains 'Port')) (
        "first record: $($records[0] | ConvertTo-Json -Compress -Depth 2)")

    Write-Host ''
    Write-Host 'The budget it exists to protect' -ForegroundColor Cyan
    # A one-DC plan is the smallest thing anyone runs. If even that is close to the ceiling there is
    # no headroom for the estates that are not small, which is exactly how this was reached before.
    Assert-That 'a single-DC plan leaves most of the ceiling unused' (
        $commandLine.Length -lt 16000) "($($commandLine.Length) chars of the 32000 limit)"
} finally {
    if (Test-Path $outputFile) { Remove-Item $outputFile -Force -ErrorAction SilentlyContinue }
    if ($process) { $process.Dispose() }
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
