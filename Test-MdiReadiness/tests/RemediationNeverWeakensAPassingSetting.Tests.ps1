# [w104] The generated remediation must never WEAKEN a setting that already passes.
#
# The NTLM auditing section writes three registry values. The finding that triggers it is per-SERVER
# (NtlmAuditing goes false if ANY of the three is wrong), but the values are independent - so the
# generator rewrote all three, using the FIRST branch of each expected alternation.
#
# RestrictSendingNTLMTraffic accepts '1|2':
#     1 = Audit all outgoing NTLM
#     2 = Deny all outgoing NTLM   <- the hardened setting
# Both PASS the shipped check. A domain controller already at 2, whose only real problem was a
# missing AuditNTLMInDomain, was emitted a script that wrote RestrictSendingNTLMTraffic = 1.
#
# An administrator running the remediation that an MDI READINESS tool generated would have relaxed
# their NTLM policy from "deny" to "audit only" - a security regression, to fix an unrelated value,
# with no warning in the script and nothing in the report to say it had happened. Reproduced on the
# shipped generator and confirmed against the AST of the emitted script.
#
# The emitted script now reads the current value on the target and only writes when it does not
# already satisfy the expected set. The guard has to live in the EMITTED script rather than in the
# generator because one script block is emitted for ALL affected servers and their current values
# differ.
#
# NOTE this file never EXECUTES a generated remediation script - it contains commands that modify
# audit policy and directory permissions. It parses it, and it evaluates the emitted guard's own
# regular expression against candidate current-values.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$dir = Join-Path $env:TEMP ('w104test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$emitted = $null
try {
    $srv = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false
        NtlmAuditing = $false
        Details = [PSCustomObject]@{ }
    }
    $report = [PSCustomObject]@{
        DomainsInScope = @('contoso.com')
        DomainControllers = @($srv)
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $fp = Join-Path $dir 'remediate.ps1'
    New-mdiRemediationScript -ReportData $report -FilePath $fp | Out-Null
    $emitted = [IO.File]::ReadAllText($fp)
} finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}

'[w104] the generated script is well formed'
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($emitted, [ref] $null, [ref] $parseErrors)
Assert-That 'the emitted remediation parses cleanly' (@($parseErrors).Count -eq 0) `
    "($(@($parseErrors).Count) parse error(s))"
Assert-That 'and it contains the NTLM section' ($emitted -match 'RestrictSendingNTLMTraffic') '(section absent)'

'[w104] every NTLM write is guarded by a check of the current value'
$lines = $emitted -split "`r?`n"
$writeIdx = @(0..($lines.Count - 1) | Where-Object { $lines[$_] -match 'New-ItemProperty' -and $lines[$_] -match 'NTLM|AuditNTLMInDomain' })
Assert-That 'the section emits its registry writes' ($writeIdx.Count -ge 1) "($($writeIdx.Count) write(s) found)"
foreach ($idx in $writeIdx) {
    $name = if ($lines[$idx] -match "-Name '([^']+)'") { $Matches[1] } else { '?' }
    $preceding = $lines[([Math]::Max(0, $idx - 4))..($idx - 1)] -join ' '
    Assert-That "  $name is written only after its current value is read" `
        ($preceding -match 'Get-ItemProperty' -and $preceding -match 'notmatch') `
        "(preceding lines: $preceding)"
}

'[w104] the guard leaves a hardened value alone and still repairs a broken one'
# The emitted regular expression is extracted from the script and evaluated exactly as the emitted
# script would evaluate it. Nothing is executed.
$restrictIdx = @($writeIdx | Where-Object { $lines[$_] -match 'RestrictSendingNTLMTraffic' })
Assert-That 'the RestrictSendingNTLMTraffic write was located' ($restrictIdx.Count -eq 1) "($($restrictIdx.Count))"
if ($restrictIdx.Count -eq 1) {
    $guardLine = @($lines[([Math]::Max(0, $restrictIdx[0] - 4))..($restrictIdx[0] - 1)] | Where-Object { $_ -match 'notmatch' })[0]
    $rx = if ($guardLine -match "notmatch\s+'([^']+)'") { $Matches[1] } else { $null }
    Assert-That 'the guard carries a right-anchored alternation' `
        ($null -ne $rx -and $rx -match '^\^\(\?:.*\)\$$') "(guard '$guardLine')"

    if ($null -ne $rx) {
        # 2 = Deny all. This is the case that matters: it PASSES, and must never be overwritten.
        Assert-That '  a hardened value of 2 is NOT overwritten' (-not ('2' -notmatch $rx)) "(regex '$rx')"
        Assert-That '  a passing value of 1 is not needlessly rewritten' (-not ('1' -notmatch $rx)) "(regex '$rx')"
        # ...and the repair path must survive.
        Assert-That '  an absent value IS still written' ('' -notmatch $rx) "(regex '$rx')"
        Assert-That '  a wrong value of 0 IS still written' ('0' -notmatch $rx) "(regex '$rx')"
        Assert-That '  an unreadable value IS still written' ('not-a-number' -notmatch $rx) "(regex '$rx')"

        # The written value must still be one the check accepts, or the repair would not repair.
        $written = if ($lines[$restrictIdx[0]] -match '-Value (\d+)') { $Matches[1] } else { '' }
        Assert-That '  the value it writes is itself acceptable to the check' ($written -match $rx) `
            "(writes '$written', accepts '$rx')"
    }
}

'[w104] control: a server whose NTLM auditing passes gets no NTLM section at all'
$dir2 = Join-Path $env:TEMP ('w104test2-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir2 -Force | Out-Null
try {
    $good = [PSCustomObject]@{
        FQDN = 'dc2.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false
        NtlmAuditing = $true
        Details = [PSCustomObject]@{ }
    }
    $report2 = [PSCustomObject]@{
        DomainsInScope = @('contoso.com'); DomainControllers = @($good)
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $fp2 = Join-Path $dir2 'remediate.ps1'
    New-mdiRemediationScript -ReportData $report2 -FilePath $fp2 | Out-Null
    $clean = [IO.File]::ReadAllText($fp2)
    Assert-That 'a passing server produces no NTLM registry write' `
        ($clean -notmatch 'RestrictSendingNTLMTraffic') '(the section was emitted for a passing server)'
} finally {
    Remove-Item -LiteralPath $dir2 -Recurse -Force -ErrorAction SilentlyContinue
}

''
"RemediationNeverWeakensAPassingSetting: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
