# A failing dsacls.exe was reported as "Remediation complete."
#
#  w53-F2  The generated remediation script's Deleted Objects section is the only part that runs a
#          native tool LOCALLY, outside Invoke-MdiRemote, and it was the only one with no
#          $LASTEXITCODE inspection:
#
#              try {
#                  dsacls.exe $container /takeownership
#                  dsacls.exe $container /G "${dsaAccount}:LCRP"
#              } catch { ... }
#
#          dsacls.exe reports failure through its EXIT CODE, not by throwing - "Access is denied",
#          "The object does not exist", an unresolvable DSA name are all exit codes - so the catch
#          could never fire for the failure that actually happens. Measured with a real console
#          executable exiting 5: the transcript was BYTE-IDENTICAL to the one from an executable
#          exiting 0, both ending "Remediation complete. Re-run Test-MdiReadiness.ps1 to verify."
#          The operator is told the Directory Service Account now has read access to the Deleted
#          Objects container when it does not, and the next scan's finding looks like a new
#          regression rather than a fix that never applied.
#
#          The script already knows this: the comment on Invoke-MdiRemote names dsacls.exe as
#          exactly this kind of command and is the reason that wrapper checks $LASTEXITCODE. The
#          local call was simply missed.
#
# These tests are BEHAVIOURAL. They GENERATE the remediation script with the real generator, extract
# the emitted section, and EXECUTE it against a fake dsacls.exe built by the test - a real console
# executable that touches no directory and only returns an exit code. No remediation is applied.

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

Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

$work = Join-Path $env:TEMP ('dsacls-{0}' -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null

try {
    # A report whose only finding is the Deleted Objects permission, measured and found wrong.
    $report = [PSCustomObject]@{
        DomainAuditing = @(
            [PSCustomObject]@{
                Domain                 = 'contoso.com'
                DeletedObjects         = [PSCustomObject]@{
                    isDeletedObjectsPermissionOk = $false
                    details = [PSCustomObject]@{
                        Container = 'CN=Deleted Objects,DC=contoso,DC=com'
                        Detail    = 'no trustee holds both List Contents and Read Property'
                    }
                }
                DeletedObjectsMeasured = $true
            }
        )
        DomainControllers   = @()
        CAServers           = @()
        EntraConnectServers = @()
    }

    $genPath = Join-Path $work 'remediate.ps1'
    New-mdiRemediationScript -ReportData $report -FilePath $genPath | Out-Null
    Assert-That 'the remediation script was generated' (Test-Path $genPath)
    $generated = if (Test-Path $genPath) { [IO.File]::ReadAllText($genPath) } else { '' }

    '[dsacls] the generated script is valid PowerShell'
    $parseErrors = $null
    [void] [System.Management.Automation.Language.Parser]::ParseInput($generated, [ref] $null, [ref] $parseErrors)
    Assert-That 'the generated script parses' (@($parseErrors).Count -eq 0) "(got $(@($parseErrors).Count) parse error(s))"

    '[dsacls] every native call has its exit code checked'
    # Behavioural gate below; this pins WHICH call was left unchecked when it regresses.
    $dsaclsCalls = @([regex]::Matches($generated, 'dsacls\.exe'))
    Assert-That 'the section calls dsacls.exe' ($dsaclsCalls.Count -ge 2) "(got $($dsaclsCalls.Count))"
    $exitChecks = @([regex]::Matches($generated, '\$LASTEXITCODE -ne 0'))
    Assert-That 'each dsacls call is followed by an exit-code check' ($exitChecks.Count -ge $dsaclsCalls.Count) "(calls=$($dsaclsCalls.Count) checks=$($exitChecks.Count))"

    '[dsacls] a failing dsacls is reported as a failure, not as success'
    # Build two real console executables named dsacls.exe: one exits 5, one exits 0. They touch no
    # directory whatsoever - they print their argument count and return.
    foreach ($pair in @(@{ Dir = 'bin-fail'; Code = 5 }, @{ Dir = 'bin-ok'; Code = 0 })) {
        $dir = Join-Path $work $pair.Dir
        New-Item -ItemType Directory -Path $dir | Out-Null
        $src = @"
using System;
public class P {
  public static int Main(string[] a) {
    Console.WriteLine("fake dsacls invoked with " + a.Length + " arg(s)");
    return $($pair.Code);
  }
}
"@
        Add-Type -TypeDefinition $src -OutputAssembly (Join-Path $dir 'dsacls.exe') -OutputType ConsoleApplication
    }

    # Extract the emitted dsacls region and run it UNMODIFIED. Nothing is stripped: a fake $PSCmdlet
    # satisfies ShouldProcess and $DirectoryServiceAccount supplies the account, which is exactly the
    # contract the generated script offers so it can run without a console. Running the real emitted
    # text is the whole point - a rewritten copy would test the test.
    $startIdx = $generated.IndexOf('#region Deleted Objects container permissions')
    $endIdx = if ($startIdx -ge 0) { $generated.IndexOf('#endregion', $startIdx) } else { -1 }
    $block = if ($startIdx -ge 0 -and $endIdx -gt $startIdx) { $generated.Substring($startIdx, $endIdx - $startIdx) } else { '' }
    Assert-That 'the Deleted Objects section was emitted' ($block -match 'dsacls\.exe')

    $harness = @"
`$script:mdiFailed = New-Object System.Collections.ArrayList
`$DirectoryServiceAccount = 'CONTOSO\mdisvc'
`$PSCmdlet = New-Object psobject
`$PSCmdlet | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value { param(`$a, `$b) `$true }
$block
if (`$script:mdiFailed.Count -gt 0) {
    Write-Warning ('Remediation finished with failures on {0} target(s).' -f `$script:mdiFailed.Count)
} else {
    Write-Host 'Remediation complete. Re-run Test-MdiReadiness.ps1 to verify.'
}
"@
    $harnessPath = Join-Path $work 'section.ps1'
    [IO.File]::WriteAllText($harnessPath, $harness)
    $probeErrors = $null
    [void] [System.Management.Automation.Language.Parser]::ParseInput($harness, [ref] $null, [ref] $probeErrors)
    Assert-That 'the emitted section is runnable as generated' (@($probeErrors).Count -eq 0) "(got $(@($probeErrors).Count) parse error(s))"

    $transcript = @{}
    foreach ($pair in @(@{ Label = 'fail'; Dir = 'bin-fail' }, @{ Label = 'ok'; Dir = 'bin-ok' })) {
        $binDir = Join-Path $work $pair.Dir
        $out = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
            -Command "`$env:Path = '$binDir' + ';' + `$env:Path; & '$harnessPath'" 2>&1
        $transcript[$pair.Label] = (@($out) | ForEach-Object { [string] $_ }) -join "`n"
    }

    Assert-That 'a failing dsacls does NOT report success' ($transcript['fail'] -notmatch 'Remediation complete') "(got: $($transcript['fail']))"
    Assert-That 'a failing dsacls reports the failure' ($transcript['fail'] -match 'failures on') "(got: $($transcript['fail']))"
    Assert-That 'the failing and succeeding runs differ' ($transcript['fail'] -ne $transcript['ok']) '(transcripts identical)'
    # And the success path must still say so, or the fix would have turned every run into a failure.
    Assert-That 'a succeeding dsacls still reports success' ($transcript['ok'] -match 'Remediation complete') "(got: $($transcript['ok']))"
    Assert-That '  ...and reports no failure' ($transcript['ok'] -notmatch 'failures on') "(got: $($transcript['ok']))"

    '[dsacls] a failure on the FIRST call is not masked by a second that succeeds'
    # /takeownership can fail while /G succeeds. Checking only the last exit code would call that run
    # a success, which is why both calls are checked.
    $mixedDir = Join-Path $work 'bin-mixed'
    New-Item -ItemType Directory -Path $mixedDir | Out-Null
    $mixedSrc = @'
using System;
using System.IO;
public class P {
  public static int Main(string[] a) {
    string marker = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "called.txt");
    bool first = !File.Exists(marker);
    File.AppendAllText(marker, "x");
    Console.WriteLine("fake dsacls call " + (first ? "1" : "2"));
    return first ? 5 : 0;
  }
}
'@
    Add-Type -TypeDefinition $mixedSrc -OutputAssembly (Join-Path $mixedDir 'dsacls.exe') -OutputType ConsoleApplication
    $mixedOut = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
        -Command "`$env:Path = '$mixedDir' + ';' + `$env:Path; & '$harnessPath'" 2>&1
    $mixedText = (@($mixedOut) | ForEach-Object { [string] $_ }) -join "`n"
    Assert-That 'a first-call failure is still a failure' ($mixedText -notmatch 'Remediation complete') "(got: $mixedText)"
} finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
