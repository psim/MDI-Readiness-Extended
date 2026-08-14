<#
    Verifies the split between "never answered" and "answered, then failed part way through".

    Both leave a Comment on the server object, and the report used to treat any Comment as proof the
    server was unreachable. That was wrong in the direction that costs the operator work: a server
    that WAS reached and produced ten real results, then hit one error, had every one of those
    results written off. It was dropped from the remediation script, its row was badged "not
    reachable", and its checks were excluded from the score - so genuine, measured, actionable
    findings silently disappeared from the report.

    Two explicit boolean flags now carry the distinction. Because they are booleans living on the
    same object as the boolean checks, they also have to be kept out of every count, or each server
    would gain two free "passed checks" it never earned.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))

# The helpers read two script-scoped lists that live outside any function, so they are pulled from
# the source in the same way the settings block is.
# EVERY script-scoped constant is loaded, not a hand-maintained list. The list went stale the moment a
# new constant was added: $script:mdiPortNotTestedPattern was null in the harness, and "-notmatch $null"
# treats the pattern as an empty string, which matches everything - so a filter meant to exclude
# untested probes silently excluded ALL of them.
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

$source = Get-Content $scriptPath -Raw

# A server that answered everything.
$healthy = [PSCustomObject]@{
    FQDN = 'dc-good.contoso.com'; IP = '10.0.0.1'; OS = 'Windows Server 2022'
    NtlmAuditing = $true; PowerScheme = $true; SensorVersion = 'N/A'
    PartialFailure = $false; Unreachable = $false; Comment = $null
}
# A server that answered, produced real results, then hit an error.
$partial = [PSCustomObject]@{
    FQDN = 'dc-partial.contoso.com'; IP = '10.0.0.2'; OS = 'Windows Server 2019'
    NtlmAuditing = $true; PowerScheme = $false; SensorVersion = 'N/A'
    PartialFailure = $true; Unreachable = $false
    Comment = 'Testing stopped early: The RPC server is unavailable'
}
# A server that never answered at all.
$dead = [PSCustomObject]@{
    FQDN = 'dc-dead.contoso.com'; IP = '10.0.0.3'; OS = 'N/A'
    PartialFailure = $false; Unreachable = $true
    Comment = 'Server is not available: ICMP, TCP 135 and WMI all failed'
}

Write-Host "`n[1] Status flags are not counted as readiness checks" -ForegroundColor Yellow
# Both flags are booleans sitting alongside the boolean checks. Counted naively, every server would
# report two extra checks, and a healthy server would report two extra passes it never earned.
$healthyChecks = @(Get-mdiCheckProperty -Server $healthy)
Assert-That 'a healthy server exposes only its real checks' (
    $healthyChecks.Count -eq 2) "(got $($healthyChecks.Count): $($healthyChecks.Name -join ', '))"
Assert-That 'PartialFailure is excluded' ('PartialFailure' -notin $healthyChecks.Name)
Assert-That 'Unreachable is excluded'    ('Unreachable'    -notin $healthyChecks.Name)
Assert-That 'the descriptive SensorVersion is excluded' ('SensorVersion' -notin $healthyChecks.Name)

$deadChecks = @(Get-mdiCheckProperty -Server $dead)
Assert-That 'an unreachable server contributes no checks at all' (
    $deadChecks.Count -eq 0) "(got $($deadChecks.Count))"

Write-Host "`n[2] A partial failure keeps the results it measured" -ForegroundColor Yellow
# This is the whole point. Ten measured results plus one error is still ten measured results.
$partialChecks = @(Get-mdiCheckProperty -Server $partial)
Assert-That 'both measured checks survive the partial failure' (
    $partialChecks.Count -eq 2) "(got $($partialChecks.Count))"
Assert-That 'the failing check is still reported as failing' (
    ($partialChecks | Where-Object { $_.Name -eq 'PowerScheme' }).Value -eq $false)

Write-Host "`n[3] Unread checks are counted, descriptive N/A is not" -ForegroundColor Yellow
# 'N/A' on SensorVersion means "no sensor installed" - an answer. 'N/A' on a check means the read
# failed. Conflating them made a healthy forest impossible to report as ready.
Assert-That 'SensorVersion N/A is not an unread check' (
    (Get-mdiUnreadCheckCount -Server $healthy) -eq 0) "(got $(Get-mdiUnreadCheckCount -Server $healthy))"

$unread = [PSCustomObject]@{
    FQDN = 'dc-unread.contoso.com'; SensorVersion = 'N/A'; MachineType = 'N/A'
    NtlmAuditing = 'N/A'; PowerScheme = 'N/A'
    PartialFailure = $false; Unreachable = $false
}
Assert-That 'two unread checks are counted, the two descriptive fields are not' (
    (Get-mdiUnreadCheckCount -Server $unread) -eq 2) "(got $(Get-mdiUnreadCheckCount -Server $unread))"

Write-Host "`n[4] Reachability is decided by the flag, never by the Comment" -ForegroundColor Yellow
# A Comment is present in both cases, so any code that branches on it gets the partial case wrong.
$stats = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
        DomainControllers   = @($healthy, $partial, $dead)
        CAServers           = @()
        EntraConnectServers = @()
    })
Assert-That 'the partial server counts as reached'   ($stats.ReachableServers -eq 2) "(got $($stats.ReachableServers))"
Assert-That 'only the dead server counts as unreachable' ($stats.UnreachableCount -eq 1) "(got $($stats.UnreachableCount))"
Assert-That 'the partial server is in the reachable list' (
    'dc-partial.contoso.com' -in @($stats.ReachableList.FQDN))
Assert-That 'the dead server is not in the reachable list' (
    'dc-dead.contoso.com' -notin @($stats.ReachableList.FQDN))

# Four measured checks across two servers, three of them passing.
Assert-That 'the score counts the partial server''s checks' ($stats.ChecksTotal -eq 4) "(got $($stats.ChecksTotal))"
Assert-That 'the score does not inflate with status flags' ($stats.ChecksPassed -eq 3) "(got $($stats.ChecksPassed))"

Write-Host "`n[5] No code path still treats a Comment as proof of unreachability" -ForegroundColor Yellow
# The regression this suite exists to prevent. Every one of these shapes was a live bug.
$commentAsReachability = [regex]::Matches($source, '-not\s+\$_\.Comment|\$_\.Comment\s*\}|Where-Object\s*\{\s*\$_\.Comment\s*\}')
Assert-That 'no Where-Object filters on Comment' (
    $commentAsReachability.Count -eq 0) "(found $($commentAsReachability.Count))"
$commentEmptiness = [regex]::Matches($source, 'IsNullOrWhiteSpace\(\[string\]\s*\$srv\.Comment\)')
Assert-That 'no row is badged unreachable from Comment emptiness' (
    $commentEmptiness.Count -eq 0) "(found $($commentEmptiness.Count))"

Write-Host "`n[6] Both flags are actually set by every server loop" -ForegroundColor Yellow
# Reading a flag that is never written is worse than not having it: $null is falsy, so every
# unreachable server would silently read as reachable and pass.
foreach ($v in 'dc', 'ca', 'ec') {
    Assert-That "`$$v sets PartialFailure on a mid-scan error" (
        $source -match ([regex]::Escape('$' + $v + "['PartialFailure'] = `$true")))
    Assert-That "`$$v sets Unreachable when the server never answered" (
        $source -match ([regex]::Escape('$' + $v + "['Unreachable'] = `$true")))
    Assert-That "`$$v defaults both flags so they always exist" (
        ($source -match ([regex]::Escape("if (-not `$$v.Contains('PartialFailure'))"))) -and
        ($source -match ([regex]::Escape("if (-not `$$v.Contains('Unreachable'))"))))
}

Write-Host "`n[7] The remediation script keeps partially-failed servers" -ForegroundColor Yellow
# Dropping them hid fixes the operator genuinely needed, which is the opposite of the tool's job.
$remediationAst = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'New-mdiRemediationScript' }, $true)[0]
$remediationText = $remediationAst.Extent.Text
# Asserted BEHAVIOURALLY. This used to match the source text "-not $_.Unreachable", so it broke when
# the flag started going through Test-mdiServerIsUnreachable - a change that only made the filter
# stricter (the raw form treated the string 'False' as unreachable). A test that fails when the code
# improves is testing the wrong thing; what matters is which servers reach the generated script.
$filterReport = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @(
        [PSCustomObject]@{ FQDN = 'dc-partial.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
            PartialFailure = $true; OperatingSystem = 'Windows Server 2022'; NtlmAuditing = $false
            Details = [ordered]@{} }
        [PSCustomObject]@{ FQDN = 'dc-down.contoso.com'; Domain = 'contoso.com'; Unreachable = $true
            PartialFailure = $false; OperatingSystem = 'Windows Server 2022'; NtlmAuditing = $false
            Details = [ordered]@{} }
    )
    CAServers = @(); EntraConnectServers = @()
}
$filterPath = Join-Path $env:TEMP ('mdi-partial-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
[void] (New-mdiRemediationScript -ReportData $filterReport -FilePath $filterPath)
$filterText = if (Test-Path $filterPath) { [IO.File]::ReadAllText($filterPath) } else { '' }
Remove-Item $filterPath -Force -ErrorAction SilentlyContinue
Assert-That 'a partially-failed server still reaches the remediation script' ($filterText -match 'dc-partial\.contoso\.com')
# The unreachable server must not be RECONFIGURED - it is absent from every scripted section that
# changes a server. It may still be named in the manual-attention advisory, and should be: the
# operator needs to know it was missed. So the assertion is on the scripted regions, not on the whole
# file, which is the distinction the old source-text match could not make.
$scriptedRegions = ([regex]::Matches($filterText, '(?s)#region (?!Findings that need manual attention).*?#endregion') |
        ForEach-Object { $_.Value }) -join "`n"
Assert-That 'an unreachable server is never reconfigured by the generated script' `
    ($scriptedRegions -notmatch 'dc-down\.contoso\.com') `
    (([regex]::Matches($filterText, '#region (.+)') | ForEach-Object { $_.Groups[1].Value }) -join ' | ')
Assert-That 'and the partially-failed server IS reconfigured' ($scriptedRegions -match 'dc-partial\.contoso\.com')
Assert-That 'the server filter does not use Comment'      ($remediationText -notmatch '-not \$_\.Comment')

Write-Host "`n[8] The verdict still fails on an unreachable server" -ForegroundColor Yellow
# Relaxing the partial case must not accidentally relax the unreachable one.
$verdictPartialOnly = Test-mdiReadinessResult -ReportData ([PSCustomObject]@{
        DomainControllers      = @($healthy)
        CAServers              = @(); EntraConnectServers = @()
        DomainAdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DomainObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $true }
        DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    })
Assert-That 'an all-passing forest is ready' ($verdictPartialOnly -eq $true)

$verdictWithDead = Test-mdiReadinessResult -ReportData ([PSCustomObject]@{
        DomainControllers      = @($healthy, $dead)
        CAServers              = @(); EntraConnectServers = @()
        DomainAdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DomainObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $true }
        DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    })
Assert-That 'one unreachable server fails the whole run' ($verdictWithDead -eq $false)

# A server that answered but whose every read failed has no checks at all. It must not pass for the
# same reason an empty scan must not pass: nothing measured is not the same as nothing wrong.
$blind = [PSCustomObject]@{
    FQDN = 'dc-blind.contoso.com'; SensorVersion = 'N/A'
    PartialFailure = $true; Unreachable = $false; Comment = 'Testing stopped early: Access is denied'
}
$verdictBlind = Test-mdiReadinessResult -ReportData ([PSCustomObject]@{
        DomainControllers      = @($healthy, $blind)
        CAServers              = @(); EntraConnectServers = @()
        DomainAdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DomainObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $true }
        DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    })
Assert-That 'a server that measured nothing fails the run' ($verdictBlind -eq $false)

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
