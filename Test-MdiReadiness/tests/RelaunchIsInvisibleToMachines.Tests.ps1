<#
    The re-launch into Windows PowerShell must be invisible to anything reading the output.

    On PowerShell 7 the script re-launches itself under 5.1. That re-launch announced itself on STDOUT,
    so the banner landed in front of the document -AsJson callers parse, silently corrupting output that
    is contractually machine-readable. The two hosts also had to agree on everything else a caller can
    observe - one -WhatIf must give one exit code, not a different one per host - and the internal
    parameter file used to carry arguments across the boundary must never appear in a preview or be left
    on disk.

    Pinned here: the dry run previews the scan itself and never the internal parameter file, reaches the
    branch that says no scan was performed, and creates no output folder; one -WhatIf gives ONE exit
    code on both supported hosts, and that code is 0; the child sees the values the caller typed and
    never reports a bind failure on an empty -Path; stdout carries no re-launch banner and the
    re-launch adds no stdout bytes at all, the banner having gone to stderr; the notice is still shown
    without -AsJson; and no parameter file is left behind, not even by a dry run. Controls run the same
    command line natively on 5.1 and require identical behaviour.
#>

# The Windows PowerShell 5.1 re-launch must be INVISIBLE on the interfaces a machine reads.
#
# The script re-launches itself under powershell.exe when started on PowerShell 7. Two things that
# hand-off did to callers were measured on the shipped script:
#
#  w163-F1  The "re-launching" banner was Write-Host, which lands on STDOUT. stdout is reserved for
#           the JSON document under -AsJson - that is the entire reason Write-mdiConsole exists -
#           and the banner is written before that helper is defined, so it made its own choice and
#           made it wrongly. Measured:
#
#               pwsh -File Test-MdiReadiness.ps1 -Domain contoso.com -AsJson ...
#               STDOUT len : 99
#               STDOUT     : PowerShell 7.6.5 detected. Re-launching under Windows PowerShell 5.1,...
#               ConvertFrom-Json -> Invalid JSON primitive: PowerShell.
#
#           The same command line under powershell.exe left stdout empty, which is what identified
#           this one line as the polluter. The documented caller `... -AsJson | ConvertFrom-Json`
#           therefore failed for every shop standardised on PowerShell 7 - exactly the audience the
#           re-launch was written for.
#
#  w163-F2  Export-Clixml SUPPORTS ShouldProcess, so the parameter file the re-launcher stages for
#           the child inherited the CALLER's -WhatIf and was never written. Import-Clixml then
#           failed, $p stayed $null, and `& script @p` splatted a $null. Measured:
#
#               pwsh -File Test-MdiReadiness.ps1 -Path <folder> -Domain contoso.com -WhatIf
#               -> What if: Performing the operation "Export-Clixml" on target "...mdi-relaunch.xml"
#               -> Test-MdiReadiness did not complete: Cannot bind argument to parameter 'Path'
#                  because it is an empty string.
#               -> exit 255
#
#           while the IDENTICAL command line on powershell.exe previewed the scan and exited 0. One
#           -WhatIf, two different exit codes on the two supported hosts; the operator was shown a
#           preview of an internal temp file instead of the scan; and every parameter typed on the
#           command line was lost. Splatting $null passing ONE POSITIONAL $null into a -Path that
#           rejects empty strings is the only reason a parameterless scan did not run against
#           production instead.
#
# These tests are BEHAVIOURAL. They start the SHIPPED script as a real process on BOTH hosts and
# compare the real exit codes and the real stdout/stderr split. Nothing is grepped.
#
# The ActiveDirectory module gate sits ahead of everything under test, so a stub ActiveDirectory
# module is staged on PSModulePath. Every case here stops at -WhatIf or at parameter validation, so
# no directory is contacted, no report is written and no output folder is created.

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
$pwsh = $null
foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'PowerShell\7\pwsh.exe'))) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) { $pwsh = $candidate; break }
}
if (-not $pwsh) {
    $found = Get-Command pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $pwsh = $found.Source }
}

$work = Join-Path $env:TEMP ('mdi-relaunch-test-{0}' -f [guid]::NewGuid().ToString('N'))
$stubRoot = Join-Path $work 'modules'
$stubAd = Join-Path $stubRoot 'ActiveDirectory'
[void] (New-Item -ItemType Directory -Path $stubAd -Force)
[IO.File]::WriteAllText((Join-Path $stubAd 'ActiveDirectory.psm1'), "function Get-MdiTestStub { 'stub' }`r`nExport-ModuleMember -Function Get-MdiTestStub`r`n")
[IO.File]::WriteAllText((Join-Path $stubAd 'ActiveDirectory.psd1'), @"
@{
    ModuleVersion = '1.0.0'
    GUID = 'b1b2c3d4-0000-4a1f-9c2d-00000000d1f1'
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

function Invoke-Host {
    <#
        Runs the shipped script as a real process on the requested host. stdout and stderr are
        captured SEPARATELY because which stream a line lands on is half of what is asserted here.
        stderr is drained asynchronously so a full pipe on one stream cannot deadlock the other.
    #>
    param([string] $Exe, [string[]] $Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
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

function Get-Flat {
    # The warning and error streams HARD-WRAP at the console width of the redirected host, so a
    # sentence the operator reads as one line arrives split across two.
    param([string] $Text)
    ($Text -replace '\s+', ' ').Trim()
}

$tempDir = [IO.Path]::GetTempPath()
$leftoverBefore = @(Get-ChildItem -LiteralPath $tempDir -Filter 'mdi-relaunch-*.xml' -File -ErrorAction SilentlyContinue).Count

try {
    if (-not $pwsh) {
        '[w163] PowerShell 7 is not installed on this host - the cross-host cases cannot run.'
        '       The re-launch branch only executes when $PSVersionTable.PSEdition -eq ''Core'', so'
        '       there is nothing to drive. Install PowerShell 7 to exercise them.'
        Assert-That 'a host to re-launch FROM is available' $false '(pwsh.exe not found)'
    } else {
        "[w163] host under test: $pwsh"

        '[w163] -WhatIf previews the SCAN, not the re-launcher''s own bookkeeping'
        $outDir7 = Join-Path $work 'reports7'
        $whatIf7 = Invoke-Host $pwsh @('-Path', $outDir7, '-Domain', 'contoso.com', '-WhatIf')
        $whatIf7Text = Get-Flat ($whatIf7.StdOut + $whatIf7.StdErr)
        "    pwsh  exit=$($whatIf7.ExitCode)"
        "    pwsh  out=<<<$whatIf7Text>>>"
        Assert-That 'the dry run previews the scan itself' (
            $whatIf7Text -match 'Performing the operation "Create MDI related configuration reports"') "(got '$whatIf7Text')"
        Assert-That '  ...and never previews the internal parameter file' (
            $whatIf7Text -notmatch 'Export-Clixml' -and $whatIf7Text -notmatch 'mdi-relaunch-') "(got '$whatIf7Text')"
        Assert-That '  ...and reaches the branch that says no scan was performed' (
            $whatIf7Text -match 'No scan was performed because -WhatIf was specified') "(got '$whatIf7Text')"
        Assert-That '  ...and creates no output folder' (-not (Test-Path -LiteralPath $outDir7))

        $outDir51 = Join-Path $work 'reports51'
        $whatIf51 = Invoke-Host $ps51 @('-Path', $outDir51, '-Domain', 'contoso.com', '-WhatIf')
        "    51    exit=$($whatIf51.ExitCode)"
        Assert-That 'CONTROL: the same command line on 5.1 behaves the same' (
            (Get-Flat ($whatIf51.StdOut + $whatIf51.StdErr)) -match 'Performing the operation "Create MDI related configuration reports"')
        Assert-That 'one -WhatIf gives ONE exit code on both supported hosts' (
            $whatIf7.ExitCode -eq $whatIf51.ExitCode) "(pwsh $($whatIf7.ExitCode) vs 5.1 $($whatIf51.ExitCode))"
        Assert-That '  ...and that code is 0' ($whatIf7.ExitCode -eq 0) "(exit $($whatIf7.ExitCode))"

        '[w163] the caller''s parameters survive the hand-off'
        # A contradictory pair the script rejects by name. If the child ran parameterless, or with a
        # splatted $null, this message could not appear - so seeing it proves BOTH values arrived.
        $pair7 = Invoke-Host $pwsh @('-Domain', 'contoso.com', '-CAServer', 'ca1.contoso.com', '-SkipCA', '-WhatIf')
        $pair7Text = Get-Flat ($pair7.StdOut + $pair7.StdErr)
        "    pwsh  exit=$($pair7.ExitCode)"
        Assert-That 'the child sees the values the caller typed' (
            $pair7Text -match 'Use either -CAServer or -SkipCA, not both') "(got '$pair7Text')"
        Assert-That '  ...and never reports a bind failure on an empty -Path' (
            $pair7Text -notmatch "parameter 'Path' because it is an empty string") "(got '$pair7Text')"
        $pair51 = Invoke-Host $ps51 @('-Domain', 'contoso.com', '-CAServer', 'ca1.contoso.com', '-SkipCA', '-WhatIf')
        "    51    exit=$($pair51.ExitCode)"
        Assert-That 'CONTROL: both hosts reject the pair identically' (
            $pair7.ExitCode -eq $pair51.ExitCode) "(pwsh $($pair7.ExitCode) vs 5.1 $($pair51.ExitCode))"

        '[w163] under -AsJson the re-launch writes nothing to stdout'
        # This run fails before any document exists, so stdout must be EMPTY. Anything on it is
        # something the re-launcher put there, and it is enough to break ConvertFrom-Json.
        $json7 = Invoke-Host $pwsh @('-Domain', 'contoso.com', '-CAServer', 'ca1.contoso.com', '-SkipCA', '-AsJson')
        "    pwsh  exit=$($json7.ExitCode)  stdout=$($json7.StdOut.Length)B  stderr=$($json7.StdErr.Length)B"
        "    pwsh  stdout=<<<$($json7.StdOut.Trim())>>>"
        Assert-That 'stdout carries no re-launch banner' (
            [string]::IsNullOrWhiteSpace($json7.StdOut)) "(stdout '$($json7.StdOut.Trim())')"
        Assert-That '  ...the banner went to stderr instead' (
            (Get-Flat $json7.StdErr) -match 'Re-launching under Windows PowerShell 5\.1') "(stderr '$(Get-Flat $json7.StdErr)')"
        $json51 = Invoke-Host $ps51 @('-Domain', 'contoso.com', '-CAServer', 'ca1.contoso.com', '-SkipCA', '-AsJson')
        "    51    exit=$($json51.ExitCode)  stdout=$($json51.StdOut.Length)B"
        Assert-That 'CONTROL: 5.1 leaves stdout empty for the same run' (
            [string]::IsNullOrWhiteSpace($json51.StdOut)) "(stdout '$($json51.StdOut.Trim())')"
        Assert-That 'the re-launch adds no stdout bytes at all' (
            $json7.StdOut.Length -eq $json51.StdOut.Length) "(pwsh $($json7.StdOut.Length)B vs 5.1 $($json51.StdOut.Length)B)"

        '[w163] a human still sees the banner when stdout is not spoken for'
        $plain7 = Invoke-Host $pwsh @('-Domain', 'contoso.com', '-CAServer', 'ca1.contoso.com', '-SkipCA')
        Assert-That 'without -AsJson the notice is still shown' (
            (Get-Flat ($plain7.StdOut + $plain7.StdErr)) -match 'Re-launching under Windows PowerShell 5\.1')

        '[w163] the staged parameter file is always cleaned up'
        $leftoverAfter = @(Get-ChildItem -LiteralPath $tempDir -Filter 'mdi-relaunch-*.xml' -File -ErrorAction SilentlyContinue).Count
        "    mdi-relaunch-*.xml in TEMP: before=$leftoverBefore after=$leftoverAfter"
        Assert-That 'no parameter file is left behind, not even by a dry run' (
            $leftoverAfter -le $leftoverBefore) "(before=$leftoverBefore after=$leftoverAfter)"
    }
} finally {
    $env:PSModulePath = $savedModulePath
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
