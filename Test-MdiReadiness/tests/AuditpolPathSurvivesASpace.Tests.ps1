<#
    A SPACE IN THE SYSTEM TEMP PATH SILENTLY DELETED EVERY ADVANCED AUDIT MEASUREMENT.

    Get-mdiAdvancedAuditing runs `auditpol /backup` on each server and reads the CSV back. The
    command was built with the path unquoted:

        cmd.exe /c auditpol.exe /backup /file:C:\ProgramData\Company Temp\mdi-....csv

    so a TEMP directory containing a space split into two arguments and auditpol rejected the whole
    command. Measured against the REAL auditpol.exe:

        CONTROL-no-space        exit=1314   (ERROR_PRIVILEGE_NOT_HELD - it reached the privilege check)
        SHIPPED-unquoted-space  exit=87     (ERROR_INVALID_PARAMETER - it never parsed the command)
        QUOTED-space            exit=1314   (reaches the privilege check again)

    The quoted and no-space forms behave identically; only the unquoted space differs. That is what
    proves the quoting is the whole defect rather than something about the path.

    The consequence is silent and total. auditpol writes no CSV, so the function returns 'N/A' and the
    run loses EVERY advanced audit policy measurement on every domain controller, CA server and Entra
    Connect server - reported as "not read" rather than as a defect, on an estate whose audit policy
    may be perfectly configured. Advanced audit policy is what decides whether MDI sees the events it
    exists to detect, so an unmeasured result there is expensive.

    Get-mdiRemoteTempFolder takes the machine-wide TEMP value from Win32_Environment and accepts any
    rooted path. A space is legal in a Windows directory name and is rejected nowhere upstream, so an
    administrator or a build image that sets TEMP to such a directory reaches this on every server.

    These assertions read the command the shipped function actually builds, and then prove the two
    forms are not equivalent by running the REAL auditpol.exe.
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
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# Only the two transport boundaries are replaced: where the temp folder comes from, and the remote
# execution itself. Everything between them is the shipped code.
$script:tempFolder = 'C:\Windows\Temp'
$script:capturedCommand = $null
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value {
    param($ComputerName)
    $script:tempFolder
}
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
    $script:capturedCommand = $CommandLine
    $null
}

function Get-BuiltCommand {
    param([string] $TempFolder)
    $script:tempFolder = $TempFolder
    $script:capturedCommand = $null
    [void] (Get-mdiAdvancedAuditing -ComputerName 'dc01.contoso.com' `
            -ExpectedAuditing @('Subcategory GUID,Setting Value', '{0cce9236-69ae-11d9-bed3-505054503030},3') 3>$null)
    if ($null -eq $script:capturedCommand) { throw 'the shipped function issued no remote command - the probe measured nothing' }
    $script:capturedCommand
}

Write-Host 'The path given to auditpol must survive a space' -ForegroundColor Cyan
$spaceCommand = Get-BuiltCommand -TempFolder 'C:\ProgramData\Company Temp'
$plainCommand = Get-BuiltCommand -TempFolder 'C:\Windows\Temp'

$spacePath = [regex]::Match($spaceCommand, '/file:"?(.+?)"?$').Groups[1].Value
Assert-That 'the space-containing path reaches the command whole' (
    $spacePath -like 'C:\ProgramData\Company Temp\mdi-*.csv') "path=$spacePath"
Assert-That 'and it is quoted, so it is one argument' (
    $spaceCommand -match '/file:"[^"]+"$') "command=$spaceCommand"
Assert-That 'a path with no space is built the same way' (
    $plainCommand -match '/file:"[^"]+"$') "command=$plainCommand"

Write-Host ''
Write-Host 'Proved against the real auditpol.exe, because a quoting claim is not worth reasoning about' -ForegroundColor Cyan
$auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
if (-not (Test-Path $auditpol)) {
    Write-Host '  SKIP  auditpol.exe is not present on this machine' -ForegroundColor Yellow
} else {
    $workDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi audit {0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void] (New-Item -ItemType Directory -Path $workDir -Force)
    try {
        $file = Join-Path $workDir 'mdi-backup.csv'
        function Invoke-Native {
            param([string] $Arguments)
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $auditpol
            $psi.Arguments = $Arguments
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($psi)
            [void] $process.StandardOutput.ReadToEnd()
            [void] $process.StandardError.ReadToEnd()
            [void] $process.WaitForExit(60000)
            $code = $process.ExitCode
            $process.Dispose()
            $code
        }

        # 87 is ERROR_INVALID_PARAMETER: auditpol never parsed the command. Any other code means it
        # parsed the argument and got as far as doing something with it, which is the whole question.
        $unquoted = Invoke-Native -Arguments ('/backup /file:{0}' -f $file)
        $quoted = Invoke-Native -Arguments ('/backup /file:"{0}"' -f $file)

        Assert-That 'the unquoted form of a space path is rejected as malformed' (
            $unquoted -eq 87) "exit=$unquoted (87 = ERROR_INVALID_PARAMETER)"
        Assert-That 'the quoted form is NOT rejected as malformed' (
            $quoted -ne 87) "exit=$quoted"
        Assert-That 'so quoting is the only material difference' (
            $unquoted -ne $quoted) "unquoted=$unquoted quoted=$quoted"

        # And the shipped function must build the form that works.
        $builtWithSpace = Get-BuiltCommand -TempFolder $workDir
        $builtArguments = [regex]::Match($builtWithSpace, 'auditpol\.exe (.+)$').Groups[1].Value
        $builtExit = Invoke-Native -Arguments $builtArguments
        Assert-That 'the command the shipped function builds is not rejected as malformed' (
            $builtExit -ne 87) "exit=$builtExit arguments=$builtArguments"
    } finally {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
