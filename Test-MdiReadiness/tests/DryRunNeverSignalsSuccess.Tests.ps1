<#
    A dry run must never signal success, because no scan ran.

    -WhatIf performs no scan. Combined with -FailOnIssues or -AsJson it nevertheless exited 0, and both
    those switches exist precisely so a machine can read the exit code instead of the screen. A build
    step therefore recorded a clean scan with no issues, and a caller expecting -AsJson parsed a
    document that was never produced, from a run that never examined anything. Exit 0 from a scan that
    did not happen is indistinguishable from exit 0 from a scan that happened and found nothing.

    Pinned here: a bare -WhatIf still exits 0 and says no scan was performed; -WhatIf with -FailOnIssues
    or -AsJson exits the did-not-run sentinel instead, no JSON document is produced, and the sentinel
    cannot be mistaken for an issue count; both switches together still exit 255 with a message naming
    each of them and telling the operator how to get a real verdict; the dry-run warning and the
    exit-code announcement go to stderr so stdout stays machine-readable; and no output folder is
    created. The -FailOnIssues-only message is unchanged.
#>

# A run that performed no scan must never hand a MACHINE a success signal.
#
#  w163-F3  -WhatIf suppresses the whole scan. The script already knew that exiting 0 in that state
#           is the worst outcome available and says so at the call site:
#
#               "-WhatIf suppresses the entire scan, and the script then simply ran off the end and
#                exited 0. With -FailOnIssues that is the worst outcome available: a pipeline that
#                reads the exit code as 'readiness verified, nothing to fix' was handed a clean pass
#                by a run that looked at nothing at all."
#
#           The 255 sentinel was raised for -FailOnIssues only. -AsJson - the OTHER machine
#           interface, documented as "for use in a pipeline or a scheduled compliance job" - was
#           missed. Measured on the shipped script:
#
#               powershell -File Test-MdiReadiness.ps1 -Domain contoso.com -WhatIf -AsJson
#               STDOUT : What if: Performing the operation "Create MDI related configuration
#                        reports" on target "contoso.com".
#               ConvertFrom-Json -> Invalid JSON primitive: What.
#               EXIT   : 0
#
#           So the documented caller got a hard parse failure while the exit code said success. A
#           stale -WhatIf left in a saved command line - the exact scenario the branch was written
#           for - hands a JSON compliance job a clean pass over a run that looked at nothing.
#
# These tests are BEHAVIOURAL. They start the SHIPPED script as a real process and read the real
# process exit code and the real stdout/stderr split. Nothing is grepped.
#
# The ActiveDirectory module gate sits before -WhatIf is honoured, so the test stages a stub
# ActiveDirectory module on PSModulePath. -WhatIf then stops the run at ShouldProcess: no directory
# is contacted, no report is written and no output folder is created.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$work = Join-Path $env:TEMP ('mdi-dryrun-{0}' -f [guid]::NewGuid().ToString('N'))
$stubRoot = Join-Path $work 'modules'
$stubAd = Join-Path $stubRoot 'ActiveDirectory'
[void] (New-Item -ItemType Directory -Path $stubAd -Force)
[IO.File]::WriteAllText((Join-Path $stubAd 'ActiveDirectory.psm1'), "function Get-MdiTestStub { 'stub' }`r`nExport-ModuleMember -Function Get-MdiTestStub`r`n")
[IO.File]::WriteAllText((Join-Path $stubAd 'ActiveDirectory.psd1'), @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'b1b2c3d4-0000-4a1f-9c2d-00000000d1f0'
    Author = 'Test-MdiReadiness tests'
    RootModule = 'ActiveDirectory.psm1'
    FunctionsToExport = @('Get-MdiTestStub')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
"@)

$savedModulePath = $env:PSModulePath
$env:PSModulePath = $stubRoot + ';' + $savedModulePath

function Invoke-Script {
    <#
        Runs the shipped script as a real process. stdout and stderr are captured SEPARATELY,
        because which stream a line lands on is half of what is being asserted. stderr is drained
        asynchronously so a full pipe on one stream cannot deadlock the read of the other.
    #>
    param([string[]] $Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ps51
    $psi.Arguments = ((@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $target) + $Arguments) |
            ForEach-Object { if ($_ -match '[\s"]') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    [PSCustomObject]@{ ExitCode = $p.ExitCode; StdOut = $out; StdErr = $errTask.Result }
}

function Test-IsJsonReport {
    param([string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    try { $null = $Text | ConvertFrom-Json; $true } catch { $false }
}

function Get-Flat {
    <#
        The warning stream HARD-WRAPS at the console width of the redirected host, so a sentence the
        operator reads as one line arrives split across two. Match against a whitespace-flattened
        copy or the assertion is really asserting the buffer width.
    #>
    param([string] $Text)
    ($Text -replace '\s+', ' ').Trim()
}

try {
    '[w163] a dry run with no machine interface keeps the interactive convention'
    $plain = Invoke-Script @('-Domain', 'contoso.com', '-WhatIf')
    "    exit=$($plain.ExitCode)  stdout=$($plain.StdOut.Length)B  stderr=$($plain.StdErr.Length)B"
    Assert-That 'a bare -WhatIf still exits 0' ($plain.ExitCode -eq 0) "(exit $($plain.ExitCode))"
    Assert-That '  ...and says no scan was performed' (
        (Get-Flat ($plain.StdOut + $plain.StdErr)) -match 'No scan was performed because -WhatIf was specified')

    # -PassThru is not a machine GATE: a caller reading the object gets $null, which is falsy, so the
    # common `if (-not (& script -PassThru))` form already fails safe. It must not start exiting 255.
    $passThru = Invoke-Script @('-Domain', 'contoso.com', '-WhatIf', '-PassThru')
    "    exit=$($passThru.ExitCode)"
    Assert-That 'CONTROL: -WhatIf -PassThru still exits 0' ($passThru.ExitCode -eq 0) "(exit $($passThru.ExitCode))"

    '[w163] a dry run never reports success to a machine interface'
    $foi = Invoke-Script @('-Domain', 'contoso.com', '-WhatIf', '-FailOnIssues')
    "    -FailOnIssues exit=$($foi.ExitCode)"
    Assert-That '-WhatIf -FailOnIssues exits with the did-not-run sentinel' ($foi.ExitCode -eq 255) "(exit $($foi.ExitCode))"

    # The defect. -AsJson asks for a document this run cannot produce.
    $json = Invoke-Script @('-Domain', 'contoso.com', '-WhatIf', '-AsJson')
    "    -AsJson exit=$($json.ExitCode)  stdout=<<<$($json.StdOut.Trim())>>>"
    Assert-That '-WhatIf -AsJson exits with the did-not-run sentinel' ($json.ExitCode -eq 255) "(exit $($json.ExitCode))"
    Assert-That '  ...because no JSON document was produced' (
        -not (Test-IsJsonReport $json.StdOut)) "(stdout '$($json.StdOut.Trim())')"
    Assert-That '  ...and it never exits 0 over a missing document' ($json.ExitCode -ne 0) "(exit $($json.ExitCode))"
    Assert-That '  ...and the sentinel is not mistakable for an issue count' (
        $json.ExitCode -eq 255 -or $json.ExitCode -eq 0) "(exit $($json.ExitCode))"

    '[w163] the warning names the interface that could not be served'
    $both = Invoke-Script @('-Domain', 'contoso.com', '-WhatIf', '-AsJson', '-FailOnIssues')
    $bothText = Get-Flat ($both.StdOut + $both.StdErr)
    "    both exit=$($both.ExitCode)"
    Assert-That 'both switches together still exit 255' ($both.ExitCode -eq 255) "(exit $($both.ExitCode))"
    Assert-That '  ...and the message names -FailOnIssues' ($bothText -match '\-FailOnIssues')
    Assert-That '  ...and names -AsJson' ($bothText -match '\-AsJson')
    Assert-That '  ...and tells the operator how to get a verdict' ($bothText -match 'Remove -WhatIf')
    # The -FailOnIssues-only wording must be unchanged for the case that already worked.
    Assert-That 'the -FailOnIssues-only message is unchanged' (
        (Get-Flat ($foi.StdOut + $foi.StdErr)) -match
        'Exiting with code 255: -FailOnIssues cannot report on a run that did not happen\. Remove -WhatIf to produce a verdict\.') `
        "(got '$(Get-Flat ($foi.StdOut + $foi.StdErr))')"

    '[w163] under -AsJson the dry-run diagnostics stay off stdout'
    # stdout is reserved for the document. The host's own "What if:" line is PowerShell's, not the
    # script's, but nothing the SCRIPT writes may join it there.
    Assert-That 'the script''s own dry-run warning is on stderr, not stdout' (
        (Get-Flat $json.StdErr) -match 'No scan was performed because -WhatIf was specified' -and
        $json.StdOut -notmatch 'No scan was performed') "(stdout '$($json.StdOut.Trim())')"
    Assert-That '  ...as is the exit-code announcement' (
        (Get-Flat $json.StdErr) -match 'Exiting with code 255' -and $json.StdOut -notmatch 'Exiting with code 255')

    '[w163] a dry run writes nothing at all'
    $outDir = Join-Path $work 'reports'
    $withPath = Invoke-Script @('-Path', $outDir, '-Domain', 'contoso.com', '-WhatIf', '-FailOnIssues')
    "    exit=$($withPath.ExitCode)  folder created=$(Test-Path -LiteralPath $outDir)"
    Assert-That 'the output folder is not created by a dry run' (-not (Test-Path -LiteralPath $outDir))
    Assert-That '  ...and the run still reports the sentinel' ($withPath.ExitCode -eq 255) "(exit $($withPath.ExitCode))"
} finally {
    $env:PSModulePath = $savedModulePath
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
