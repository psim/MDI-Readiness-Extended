<#
    The generated remediation script must not claim work it did not do.

    This file is the highest-consequence output of the tool: the HTML report tells an administrator to
    run Fix-MdiReadiness-<domain>.ps1 as Domain Admin against production domain controllers. Three
    ways it could report success without having succeeded:

      - the WinRM branch never inspected the exit code, and WinRM is the DEFAULT transport, so eight
        failing auditpol.exe calls ended "Remediation complete";
      - the -WhatIf banner existed on only one of the two closing arms, so as soon as any finding was
        un-scriptable - one unreachable domain controller is enough - a rehearsal and a real run
        produced byte-identical transcripts;
      - a status file that could not be read back only warned, and the run still reported complete.

    All three are the same mistake in different clothes: treating "I could not tell" as "it worked".
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

$script:pass = 0; $script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$tmp = Join-Path $env:TEMP ('mdi-remed-tests-{0}' -f ([guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    function New-TestReport {
        param([switch] $Unscriptable, [switch] $OnlyScriptable)
        # REAL property names, as the scan writes them: AdvancedAuditing, PowerSettings, and so on.
        # An earlier version of this file invented 'Advanced auditing' and 'Power scheme', which are
        # the FRIENDLY names. Running ConvertTo-mdiFriendlyName over an already-friendly name is a
        # no-op, so the issue text kept the lower-case 'a' while the generator's cover key produced
        # 'Advanced Auditing' - and the covered set is a HashSet[string], which compares ORDINALLY.
        # PowerShell's -eq would have called those two strings equal; the HashSet does not. The test
        # therefore saw every scripted fix listed as still needing manual attention and reported a
        # defect that does not exist on any real report.
        $dc = [PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
            AdvancedAuditing = $false
            Details = [PSCustomObject]@{ AdvancedAuditingDetails = [PSCustomObject]@{ Missing = @('Kerberos Service Ticket Operations') } }
        }
        if (-not $OnlyScriptable) {
            $dc | Add-Member -NotePropertyName 'PowerSettings' -NotePropertyValue $false -Force
        }
        $dcs = @($dc)
        if ($Unscriptable) {
            $dcs += [PSCustomObject]@{ FQDN = 'dc2.contoso.com'; Domain = 'contoso.com'
                Unreachable = $true; PartialFailure = $false; Details = [PSCustomObject]@{} }
        }
        [PSCustomObject]@{ DomainControllers = $dcs; CAServers = @(); EntraConnectServers = @()
            DomainsInScope = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com' }
    }
    function New-Generated {
        param([switch] $Unscriptable, [switch] $OnlyScriptable)
        $f = Join-Path $tmp ('Fix-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
        New-mdiRemediationScript -ReportData (New-TestReport -Unscriptable:$Unscriptable -OnlyScriptable:$OnlyScriptable) -FilePath $f 3>$null | Out-Null
        $f
    }
    # Every remote call neutralised, so only the reporting logic runs.
    function Invoke-Generated {
        param([string] $Path, [switch] $WhatIf)
        $runner = Join-Path $tmp ('run-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
        $s = [IO.File]::ReadAllText($Path) -replace '(?m)^function Invoke-MdiRemote\b', 'function Invoke-MdiRemoteOriginal'
        [IO.File]::WriteAllText($runner, $s + "`r`nfunction Invoke-MdiRemote { param(`$ComputerName,`$ScriptBlock,`$ArgumentList,`$Transport,`$TimeoutSeconds) }`r`n")
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runner)
        if ($WhatIf) { $a += '-WhatIf' }
        (& $ps @a 2>&1 | Out-String)
    }

    Write-Host 'A rehearsal must not read like the real thing' -ForegroundColor Cyan
    # The transcript of a maintenance-window preview is what the next person reads, not the
    # "What if:" lines scrolled past above it.
    foreach ($case in @(@{ N = 'with un-scriptable findings'; U = $true }, @{ N = 'with none'; U = $false })) {
        $g = New-Generated -Unscriptable:$case.U
        $dry = Invoke-Generated -Path $g -WhatIf
        $real = Invoke-Generated -Path $g
        Assert-That ("a dry run differs from a real run {0}" -f $case.N) ($dry.Trim() -ne $real.Trim())
        Assert-That "  and the dry run says nothing was changed ($($case.N))" ($dry -match 'WhatIf: nothing was changed')
        Assert-That "  while the real run does not ($($case.N))" ($real -notmatch 'WhatIf: nothing was changed')
    }
    # The un-scriptable findings must still be surfaced under -WhatIf: a rehearsal that hides them
    # sends the operator into the maintenance window unaware of the manual work.
    $gU = New-Generated -Unscriptable
    $dryU = Invoke-Generated -Path $gU -WhatIf
    Assert-That 'a dry run still reports findings needing manual attention' ($dryU -match 'manual attention')

    Write-Host 'A failed command over WinRM is a failure' -ForegroundColor Cyan
    # WinRM is the DEFAULT transport. auditpol.exe, dsacls.exe and reg.exe all report failure through
    # an exit code rather than an exception, so a branch that ignores $LASTEXITCODE reports success
    # over every one of them.
    $gen = [IO.File]::ReadAllText((New-Generated))
    $invoke = [regex]::Match($gen, 'function Invoke-MdiRemote[\s\S]{0,8000}').Value
    $winrmBranch = [regex]::Match($invoke, 'if \(\$script:mdiTransport\[\$ComputerName\]\)[\s\S]{0,1500}').Value
    Assert-That 'the WinRM branch was located in the generated script' ($winrmBranch.Length -gt 0)
    Assert-That 'the WinRM branch inspects the exit code' ($winrmBranch -match 'LASTEXITCODE')
    Assert-That '  and throws on a non-zero code' ($winrmBranch -match 'exited with code')
    Assert-That '  after resetting it, so a stale value is not inherited' ($winrmBranch -match '\$global:LASTEXITCODE = 0')
    Assert-That '  and the remote call is terminating' ($winrmBranch -match 'Invoke-Command[^\r\n]*-ErrorAction Stop')
    # The WMI branch has always checked; both transports must agree about what failure means.
    $wmiBranch = [regex]::Match($invoke, '(Win32_Process|Invoke-WmiMethod)[\s\S]{0,2000}').Value
    Assert-That 'the WMI branch still inspects the exit code' ($invoke -match 'LASTEXITCODE -ne 0')

    Write-Host 'An unverifiable result is neither pass nor fail' -ForegroundColor Cyan
    # The command was started but its status file could not be read back. Claiming success is
    # unfounded; so is claiming failure. It gets its own state, as everywhere else in this tool.
    Assert-That 'the generated script tracks unconfirmed servers separately' ($gen -match '\$script:mdiUnconfirmed')
    Assert-That '  and records the host rather than only warning' ($gen -match '\$script:mdiUnconfirmed\.Add\(\$ComputerName\)')
    Assert-That '  and an unconfirmed host is not also counted as failed' ($gen -match 'notin \$mdiFailedHosts')

    # Behaviour, driven through the emitted summary itself. A report with ONLY scriptable findings,
    # so the summary reaches the plain closing arm and "complete" is genuinely available to it.
    $genU = [IO.File]::ReadAllText((New-Generated -OnlyScriptable))
    $marker = '$mdiFailedHosts = @($script:mdiFailed | Select-Object -Unique)'
    $at = $genU.IndexOf($marker)
    Assert-That 'the summary block was located' ($at -gt 0)
    if ($at -gt 0) {
        $prelude = "`$script:mdiFailed = New-Object System.Collections.ArrayList`r`n`$script:mdiUnconfirmed = New-Object System.Collections.ArrayList`r`n"
        # One unconfirmed host, nothing failed.
        $sp = Join-Path $tmp 'sum-unconf.ps1'
        [IO.File]::WriteAllText($sp, $prelude + "[void] `$script:mdiUnconfirmed.Add('dc9.contoso.com')`r`n" + $genU.Substring($at))
        $out = (& $ps -NoProfile -ExecutionPolicy Bypass -File $sp 2>&1 | Out-String)
        Assert-That 'an unverified server is named in the summary' ($out -match 'could not be verified on 1 server')
        Assert-That '  and it is named explicitly' ($out -match 'dc9\.contoso\.com')
        Assert-That '  and "Remediation complete" is withheld' ($out -notmatch 'Remediation complete')

        # Nothing unconfirmed and nothing failed: the clean run must still be able to say complete,
        # or the guard has simply replaced a false green with a false amber.
        $sp2 = Join-Path $tmp 'sum-clean.ps1'
        [IO.File]::WriteAllText($sp2, $prelude + $genU.Substring($at))
        $out2 = (& $ps -NoProfile -ExecutionPolicy Bypass -File $sp2 2>&1 | Out-String)
        Assert-That 'a clean run still reports complete' ($out2 -match 'Remediation complete') "(got: $($out2.Trim()))"
        Assert-That '  and mentions no unverified server' ($out2 -notmatch 'could not be verified')

        # A host that both failed and could not be confirmed is reported once, as a failure.
        $sp3 = Join-Path $tmp 'sum-both.ps1'
        [IO.File]::WriteAllText($sp3, $prelude + "[void] `$script:mdiFailed.Add('dc9.contoso.com')`r`n[void] `$script:mdiUnconfirmed.Add('dc9.contoso.com')`r`n" + $genU.Substring($at))
        $out3 = (& $ps -NoProfile -ExecutionPolicy Bypass -File $sp3 2>&1 | Out-String)
        Assert-That 'a host that failed is not also listed as unverified' ($out3 -notmatch 'could not be verified')
        Assert-That '  and is reported as a failure' ($out3 -match 'finished with failures on 1 server')
    }

    Write-Host 'A scripted fix is not also listed as manual work' -ForegroundColor Cyan
    # The generator marks findings it handles in a HashSet[string] keyed on "<friendly name> check
    # failed", and Get-mdiIssueList builds that same string independently. HashSet[string] compares
    # ORDINALLY - unlike PowerShell's -eq - so a single character of casing drift between the two
    # would make every scripted fix ALSO appear under "still need manual attention", telling the
    # operator to go and do by hand what the script had just done, and making the "Remediation
    # complete" banner unreachable. Nothing warns; the two strings simply stop matching.
    $stats = Get-mdiReportStatistics -ReportData (New-TestReport -OnlyScriptable)
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData (New-TestReport -OnlyScriptable))
    foreach ($prop in 'AdvancedAuditing', 'NtlmAuditing', 'PowerSettings', 'SensorHealth', 'TimeSync') {
        $coverKey = (ConvertTo-mdiFriendlyName $prop) + ' check failed'
        Assert-That "the cover key for $prop is stable under an ordinal comparison" (
            [string]::Equals($coverKey, ((ConvertTo-mdiFriendlyName $prop) + ' check failed'), [StringComparison]::Ordinal))
    }
    $auditIssue = @($issues | Where-Object { $_.Issue -like '*Auditing*' } | ForEach-Object { $_.Issue })[0]
    Assert-That 'the issue list wording matches the cover key EXACTLY, not merely case-insensitively' (
        [string]::Equals($auditIssue, ((ConvertTo-mdiFriendlyName 'AdvancedAuditing') + ' check failed'), [StringComparison]::Ordinal)) `
        "(issue='$auditIssue' cover='$((ConvertTo-mdiFriendlyName 'AdvancedAuditing')) check failed')"
    # And end to end: a report whose every finding IS scriptable must produce no outstanding list.
    $gScriptable = [IO.File]::ReadAllText((New-Generated -OnlyScriptable))
    Assert-That 'a fully scriptable report lists nothing as needing manual attention' (
        $gScriptable -notmatch 'still need manual attention')
    Assert-That '  so the completion banner is reachable' ($gScriptable -match 'Remediation complete')

    Write-Host 'The generated script remains valid' -ForegroundColor Cyan
    $g = New-Generated -Unscriptable
    $pe = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($g, [ref]$null, [ref]$pe)
    Assert-That 'the generated script parses' ($null -eq $pe -or $pe.Count -eq 0) `
        "($(if ($pe) { $pe[0].Message } else { '' }))"
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($g, [ref]$null, [ref]$null)
    $defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
    $called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -like '*mdi*' } | Select-Object -Unique)
    Assert-That 'it is self-contained (every mdi function it calls, it defines)' (
        @($called | Where-Object { $_ -notin $defined }).Count -eq 0) `
        "(missing: $(@($called | Where-Object { $_ -notin $defined }) -join ', '))"
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
