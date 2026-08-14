# [w83] Every native command in a generated remediation batch must be exit-code checked.
#
# Invoke-MdiRemote's emitted wrapper inspects $LASTEXITCODE ONCE, after the whole scriptblock has
# run, so in a BATCH only the FINAL command's code is ever seen. Two sections emitted batches and
# relied on a promise the wrapper cannot keep:
#
#   * advanced audit policy - one auditpol.exe /set per subcategory. Measured: 7 of 8 calls failing
#     and the 8th succeeding produced exit code 0, no failing server, "Remediation complete."
#   * time synchronisation  - w32tm /resync /force followed by a READ-ONLY w32tm /query /status.
#     The remediating command was never last, so it was never checked: a resync that failed was
#     masked unconditionally, which is the one fault MDI raises the clock-skew alert for.
#
# Both now check each call inside the scriptblock, as the Deleted Objects (dsacls) section already
# did. This test drives the REAL generator and then EXECUTES the script it produced against stubbed
# native commands, so it fails if the check is removed OR if the batch ordering is changed back.
#
# Probes: MDI-AB\live\w83-timesync-e2e.ps1, MDI-AB\live\w83-lastexit-e2e.ps1

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

function New-RemSrv {
    param([bool] $AuditOk = $true, [bool] $TimeOk = $true)
    [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        AdvancedAuditing = $AuditOk
        TimeSync = $TimeOk
        NtlmAuditing = $true; PowerSettings = $true; RequiredPorts = $true
        Details = [PSCustomObject]@{
            AdvancedAuditingDetails = [PSCustomObject]@{ Detail = 'Advanced audit policy is not configured' }
            TimeSyncDetails = [PSCustomObject]@{ Detail = 'The clock is 11 minutes from this computer' }
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() }
        }
    }
}

function New-Generated {
    param([bool] $AuditOk = $true, [bool] $TimeOk = $true)
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com')
        DomainControllers = @(New-RemSrv -AuditOk $AuditOk -TimeOk $TimeOk)
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); SkippedAreas = @()
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
    }
    $dir = Join-Path $env:TEMP ('mdirem-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $dir -Force)
    $file = Join-Path $dir 'Fix-MdiReadiness-contoso.com.ps1'
    New-mdiRemediationScript -ReportData $report -FilePath $file 3>$null 4>$null 6>$null | Out-Null
    [PSCustomObject]@{ Dir = $dir; File = $file; Text = [IO.File]::ReadAllText($file) }
}

# Executes the generated script with the native commands stubbed. Invoke-Command is replaced (a
# built-in, not one of the script's own functions) so the emitted $mdiRemoteWrapper runs locally and
# its $LASTEXITCODE logic is exercised for real rather than simulated.
function Invoke-Generated {
    param([string] $GeneratedPath, [int] $AuditExit, [int] $ResyncExit)
    $stub = @"
function Invoke-Command {
    param(`$ComputerName, `$ScriptBlock, `$ArgumentList, `$ErrorAction, `$Credential, `$Authentication)
    if (`$ArgumentList) { & `$ScriptBlock @ArgumentList } else { & `$ScriptBlock }
}
function auditpol.exe { Write-Output 'auditpol stub'; `$global:LASTEXITCODE = $AuditExit }
function w32tm.exe {
    if (`$args -contains '/resync') { Write-Output 'resync stub'; `$global:LASTEXITCODE = $ResyncExit }
    else { Write-Output 'query stub'; `$global:LASTEXITCODE = 0 }
}
function dsacls.exe { Write-Output 'dsacls stub'; `$global:LASTEXITCODE = 0 }
"@
    $body = [IO.File]::ReadAllText($GeneratedPath)
    # Inserted after the param block, before the first region, so the script's own header is intact.
    $at = $body.IndexOf('#region')
    if ($at -lt 0) { $at = 0 }
    $patched = $body.Substring(0, $at) + $stub + [Environment]::NewLine + $body.Substring($at)
    $run = Join-Path (Split-Path $GeneratedPath -Parent) 'run.ps1'
    [IO.File]::WriteAllText($run, $patched, (New-Object Text.UTF8Encoding($true)))
    $out = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $run 2>&1 | Out-String
    $out
}

'[w83] the generated audit-policy batch checks EVERY call, not merely the last'
$gen = New-Generated -AuditOk $false -TimeOk $true
try {
    $setCalls = @([regex]::Matches($gen.Text, "auditpol\.exe /set /subcategory:'[^']+' /success:enable /failure:enable")).Count
    $setChecks = @([regex]::Matches($gen.Text, "throw \(""auditpol\.exe /set /subcategory:'[^']+' exited with code "" \+ \`$LASTEXITCODE\)")).Count
    Assert-That 'the audit policy section emits more than one native call' ($setCalls -gt 1) "(calls: $setCalls)"
    Assert-That 'every auditpol /set call has its own exit-code check' ($setChecks -eq $setCalls) "(calls $setCalls, checks $setChecks)"

    '[w83] a FAILING auditpol call is reported, not swallowed'
    $failOut = Invoke-Generated -GeneratedPath $gen.File -AuditExit 1 -ResyncExit 0
    Assert-That 'the failing subcategory is named' ($failOut -match "auditpol\.exe /set /subcategory:'\{[0-9A-Fa-f\-]+\}' exited with code 1") `
        "(transcript: $(($failOut -split "`r?`n" | Where-Object { $_ -match 'exited with code' } | Select-Object -First 1)))"
    Assert-That 'the server is reported as failed' ($failOut -match 'Remediation finished with failures') '(no failure banner)'
    Assert-That 'it does NOT claim "Remediation complete"' (-not ($failOut -match 'Remediation complete\.')) '(it still claimed success)'

    '[w83] CONTROL - a SUCCEEDING auditpol run still reports success'
    # Without this, throwing unconditionally would satisfy everything above.
    $okOut = Invoke-Generated -GeneratedPath $gen.File -AuditExit 0 -ResyncExit 0
    Assert-That 'a clean run still says "Remediation complete"' ($okOut -match 'Remediation complete\.') '(clean run did not report success)'
    Assert-That 'a clean run reports no failed server' (-not ($okOut -match 'Remediation finished with failures')) '(clean run reported a failure)'
} finally { Remove-Item $gen.Dir -Recurse -Force -ErrorAction SilentlyContinue }

'[w83] the time-sync batch checks the /resync call, which is never last'
$genT = New-Generated -AuditOk $true -TimeOk $false
try {
    Assert-That 'the resync call is emitted' ($genT.Text -match 'w32tm\.exe /resync /force') '(no resync call)'
    Assert-That 'the resync call has an exit-code check' `
        ($genT.Text -match 'throw \("w32tm\.exe /resync /force exited with code " \+ \$LASTEXITCODE\)') '(no check on the resync)'
    # The ordering is the whole defect: the read-only query must not be what gets checked.
    $resyncAt = $genT.Text.IndexOf('w32tm.exe /resync /force')
    $checkAt = $genT.Text.IndexOf('w32tm.exe /resync /force exited with code')
    $queryAt = $genT.Text.IndexOf('w32tm.exe /query /status')
    Assert-That 'the check sits between the resync and the read-only query' `
        ($resyncAt -gt 0 -and $checkAt -gt $resyncAt -and $queryAt -gt $checkAt) "(resync $resyncAt, check $checkAt, query $queryAt)"
    Assert-That 'the diagnostic query is still emitted' ($queryAt -gt 0) '(the query was dropped)'

    '[w83] a FAILING resync is reported, not masked by the query that follows it'
    $failT = Invoke-Generated -GeneratedPath $genT.File -AuditExit 0 -ResyncExit 1
    Assert-That 'the failed resync is named' ($failT -match 'w32tm\.exe /resync /force exited with code 1') `
        "(transcript: $(($failT -split "`r?`n" | Where-Object { $_ -match 'exited with code' } | Select-Object -First 1)))"
    Assert-That 'the server is reported as failed' ($failT -match 'Remediation finished with failures') '(no failure banner)'
    Assert-That 'it does NOT claim "Remediation complete"' (-not ($failT -match 'Remediation complete\.')) '(it still claimed success)'

    '[w83] CONTROL - a SUCCEEDING resync still reports success'
    $okT = Invoke-Generated -GeneratedPath $genT.File -AuditExit 0 -ResyncExit 0
    Assert-That 'a clean resync still says "Remediation complete"' ($okT -match 'Remediation complete\.') '(clean run did not report success)'
    Assert-That 'a clean resync reports no failed server' (-not ($okT -match 'Remediation finished with failures')) '(clean run reported a failure)'
    Assert-That 'the query still ran after a successful resync' ($okT -match 'query stub') '(the diagnostic query did not run)'
} finally { Remove-Item $genT.Dir -Recurse -Force -ErrorAction SilentlyContinue }

'[w83] the wrapper no longer claims a guarantee it cannot keep'
# The comment on Invoke-MdiRemote asserted "EVERY native call is checked, not merely the last".
# It inspects $LASTEXITCODE once, after the batch, so that was false and was read as a guarantee by
# the two sections above. A false claim in a comment is how both defects survived review.
Assert-That 'the false "EVERY native call is checked" claim is gone' `
    (-not ($full -match 'And EVERY native call is checked, not merely the')) '(the claim is still there)'

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
