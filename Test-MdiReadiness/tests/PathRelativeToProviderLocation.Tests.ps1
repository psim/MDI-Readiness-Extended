<#
    A report written to a relative path landed in the wrong directory, and then killed the run.

    Write-mdiReportFile finishes with [IO.File]::WriteAllText, a .NET API. .NET resolves a relative
    path against [Environment]::CurrentDirectory - the directory the PROCESS started in. PowerShell's
    Set-Location moves its own location and deliberately leaves [Environment]::CurrentDirectory alone,
    so the two disagree from the first "cd" onwards. -Path defaults to '.', which makes the most
    ordinary invocation of the whole script the one that triggers it:

        cd C:\Reports
        .\Test-MdiReadiness.ps1

    wrote mdi-<domain>.json and .html into the shell's start directory - C:\Windows\System32 for a
    scheduled task - and left C:\Reports empty.

    Misfiling was not the end of it. Every caller hands the SAME relative string to Resolve-Path
    afterwards to tell the operator where the artefact went (canonical lines 5303, 12655, 13149).
    Resolve-Path goes through the PowerShell provider, looks in the location where nothing was
    created, and throws a terminating "Cannot find path" - so the scan aborted after every expensive
    collection step had already completed, having silently deposited a stray report elsewhere.

    These assertions are BEHAVIOURAL: each one runs the real Write-mdiReportFile with the two
    locations genuinely diverged and then looks at where the bytes actually are on disk. Asserting on
    the source text would pass against any reimplementation that reintroduced the split.
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
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$sandbox = Join-Path ([IO.Path]::GetTempPath()) ('mdi-relpath-' + [Guid]::NewGuid().ToString('N'))
$userCwd = Join-Path $sandbox 'operator-location'
$procCwd = Join-Path $sandbox 'process-start-dir'
$oldLoc = (Get-Location).Path
$oldEnv = [Environment]::CurrentDirectory

try {
    [void][IO.Directory]::CreateDirectory($userCwd)
    [void][IO.Directory]::CreateDirectory($procCwd)

    # Exactly the state a real shell is in after a single "cd": the provider location has moved, the
    # process current directory has not. Setting them by hand is what a Set-Location would produce.
    Set-Location -LiteralPath $userCwd
    [Environment]::CurrentDirectory = $procCwd

    Assert-That 'the two locations really are diverged for this test' ((Get-Location).Path -ne [Environment]::CurrentDirectory) 'the fixture itself is broken'

    Write-Host 'A relative report path follows the PowerShell location, not the process one' -ForegroundColor Cyan

    # './name' is what canonical line 12638 produces from the default -Path '.' on line 309.
    $relative = Join-Path -Path '.' -ChildPath 'mdi-contoso.json'
    Write-mdiReportFile -Content '{"report":"json"}' -FilePath $relative

    $inUser = Join-Path $userCwd 'mdi-contoso.json'
    $inProc = Join-Path $procCwd 'mdi-contoso.json'
    Assert-That 'the report is written where the operator is standing' (Test-Path -LiteralPath $inUser -PathType Leaf) 'nothing was created in the PowerShell location'
    Assert-That '  ...and NOT in the process start directory' (-not (Test-Path -LiteralPath $inProc -PathType Leaf)) "a stray copy was deposited in $procCwd"

    # The content has to survive the rooting, not just the location.
    if (Test-Path -LiteralPath $inUser -PathType Leaf) {
        Assert-That '  ...with the content intact' ((Get-Content -LiteralPath $inUser -Raw).Trim() -eq '{"report":"json"}') 'content was altered'
    } else {
        Assert-That '  ...with the content intact' $false 'file absent'
    }

    Write-Host 'The path the caller reports back is the path that was written' -ForegroundColor Cyan
    # This is the line that used to throw and abort the whole scan (canonical 12655 / 13149 / 5303).
    $resolved = $null
    $threw = $false
    try { $resolved = (Resolve-Path -Path $relative -ErrorAction Stop).Path } catch { $threw = $true }
    Assert-That 'Resolve-Path on the same relative string does not throw' (-not $threw) 'the run would abort here after all collection work'
    Assert-That '  ...and points at the file that actually exists' ($resolved -eq $inUser) "resolved to '$resolved', expected '$inUser'"

    Write-Host 'Every report artefact behaves the same way' -ForegroundColor Cyan
    # The HTML report (13142-13145) and the generated remediation .ps1 go through this same writer, so
    # a fix applied to only one caller would leave the others misfiling.
    foreach ($name in 'mdi-contoso.html', 'mdi-contoso-remediation.ps1', 'mdi-baseline-history.json') {
        $rel = Join-Path -Path '.' -ChildPath $name
        Write-mdiReportFile -Content "artefact $name" -FilePath $rel
        $landed = Test-Path -LiteralPath (Join-Path $userCwd $name) -PathType Leaf
        $strayed = Test-Path -LiteralPath (Join-Path $procCwd $name) -PathType Leaf
        Assert-That "'$name' lands in the PowerShell location" $landed 'not created where the operator is'
        Assert-That "  ...and leaves nothing behind in the process directory" (-not $strayed) 'stray copy created'
    }

    Write-Host 'A bare filename with no ./ prefix is rooted too' -ForegroundColor Cyan
    # -Path 'reports' or a bare name reaches WriteAllText without a leading './', and .NET treats that
    # as relative just the same.
    Write-mdiReportFile -Content 'bare' -FilePath 'mdi-bare.json'
    Assert-That 'a bare relative filename lands in the PowerShell location' (Test-Path -LiteralPath (Join-Path $userCwd 'mdi-bare.json') -PathType Leaf) 'not created where the operator is'
    Assert-That '  ...and not in the process start directory' (-not (Test-Path -LiteralPath (Join-Path $procCwd 'mdi-bare.json') -PathType Leaf)) 'stray copy created'

    Write-Host 'A nested relative path keeps its subfolder' -ForegroundColor Cyan
    # -Path '.\out' is an ordinary thing to pass; rooting must not flatten it.
    [void][IO.Directory]::CreateDirectory((Join-Path $userCwd 'out'))
    $nested = Join-Path -Path '.\out' -ChildPath 'mdi-nested.json'
    Write-mdiReportFile -Content 'nested' -FilePath $nested
    Assert-That 'a nested relative path resolves under the PowerShell location' (Test-Path -LiteralPath (Join-Path $userCwd 'out\mdi-nested.json') -PathType Leaf) 'subfolder was lost or misrooted'

    Write-Host 'An absolute path is left exactly as it was' -ForegroundColor Cyan
    # Rooting must be a no-op for the already-rooted case, which is how every documented example runs.
    $absolute = Join-Path $procCwd 'mdi-absolute.json'
    Write-mdiReportFile -Content 'absolute' -FilePath $absolute
    Assert-That 'an absolute path still writes exactly where it says' (Test-Path -LiteralPath $absolute -PathType Leaf) 'absolute path was rewritten'
    Assert-That '  ...and is not redirected into the PowerShell location' (-not (Test-Path -LiteralPath (Join-Path $userCwd 'mdi-absolute.json') -PathType Leaf)) 'absolute path was redirected'

    Write-Host 'A UNC path is left exactly as it was' -ForegroundColor Cyan
    # \\server\share is rooted, so it must skip rooting entirely rather than being glued onto the
    # local location. Asserted through the failure it produces: an unreachable UNC host must surface
    # as a write error naming the UNC path, never as a quiet local write.
    $unc = '\\mdi-no-such-host-w74\share\mdi-unc.json'
    $uncErr = $null
    try { Write-mdiReportFile -Content 'unc' -FilePath $unc -TimeoutSeconds 1 } catch { $uncErr = $_ }
    Assert-That 'an unreachable UNC path fails rather than writing locally' ($null -ne $uncErr) 'the write silently succeeded somewhere'
    Assert-That '  ...and no local file was created for it' (-not (Test-Path -LiteralPath (Join-Path $userCwd 'mdi-unc.json') -PathType Leaf)) 'UNC path was rooted into the local location'

    Write-Host 'Rooting happens before the retry loop, not inside it' -ForegroundColor Cyan
    # A relative path under a folder that does not exist must fail FAST as a missing directory. If the
    # rooting were done per-attempt, or if the path were left relative, this spent the whole timeout
    # spinning on a contention retry it could never win and then blamed a phantom second process.
    $missingRel = Join-Path -Path '.\no-such-folder-w74' -ChildPath 'mdi-x.json'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $missErr = $null
    try { Write-mdiReportFile -Content 'x' -FilePath $missingRel -TimeoutSeconds 20 } catch { $missErr = $_ }
    $sw.Stop()
    Assert-That 'a missing directory fails instead of writing' ($null -ne $missErr) 'the write unexpectedly succeeded'
    Assert-That '  ...and fails fast rather than burning the retry timeout' ($sw.Elapsed.TotalSeconds -lt 10) "took $([math]::Round($sw.Elapsed.TotalSeconds,1))s"
    Assert-That '  ...naming the resolved directory, not a phantom lock' ($missErr -and $missErr.Exception.Message -notmatch 'locked by another process') "message was '$($missErr.Exception.Message)'"

    Write-Host 'The rooted path is what error messages report' -ForegroundColor Cyan
    # An operator chasing a failed write needs the absolute path; echoing back './mdi-x.json' sends
    # them looking in the wrong directory - the exact confusion this defect caused.
    Assert-That 'a write failure reports an absolute path' ($missErr -and $missErr.Exception.Message -match '[A-Za-z]:\\') "message was '$($missErr.Exception.Message)'"
    Assert-That '  ...that sits under the PowerShell location' ($missErr -and $missErr.Exception.Message -match [regex]::Escape($userCwd)) "message was '$($missErr.Exception.Message)'"
} finally {
    Set-Location -LiteralPath $oldLoc
    [Environment]::CurrentDirectory = $oldEnv
    if (Test-Path -LiteralPath $sandbox) { Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
