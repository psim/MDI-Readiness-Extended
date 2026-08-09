<#
    Verifies that a server holding several roles is counted ONCE, without losing any role's results.

    Running AD CS and Entra Connect on a domain controller is ordinary in a small environment. The
    three discovery passes each found that host and scanned it independently, so one machine appeared
    three times: "3 servers scanned" for one box, every shared check counted three times in the score,
    each of its findings listed three times, and a generated remediation script that set the power
    scheme and restarted the sensor three times on the same server.

    The rows are MERGED rather than de-duplicated, because dropping the later copies would discard the
    checks that exist only for a role - CA auditing, the root certificates. The merge must therefore
    satisfy two opposing requirements at once: one row out, and no result lost.

    It must also be non-destructive. PSObject.Copy() is a SHALLOW copy, so a careless merge would add
    the CA's details to the domain controller object that the per-role HTML table still renders and
    that is written into the JSON.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))
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

# One physical server discovered three times, once per role. The shared checks agree; each role also
# contributes a check the others do not have.
function New-Trio {
    @(
        [PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com'
            PowerSettings = $true; TimeSync = $true; AdvancedAuditing = $false
            PartialFailure = $false; Unreachable = $false
            Details = [ordered]@{ TimeSyncDetails = [PSCustomObject]@{ Detail = 'clock ok' } }
        }
        [PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com'
            PowerSettings = $true; TimeSync = $true; CAAuditing = $false; RootCertificates = $true
            PartialFailure = $false; Unreachable = $false
            Details = [ordered]@{ CAAuditingDetails = [PSCustomObject]@{ Detail = 'ca audit missing' } }
        }
        [PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com'
            PowerSettings = $true; TimeSync = $true; AdvancedAuditingEntraConnect = $true
            PartialFailure = $false; Unreachable = $false
            Details = [ordered]@{ EntraDetails = [PSCustomObject]@{ Detail = 'entra ok' } }
        }
    )
}

Write-Host "`n[1] One physical server becomes one row" -ForegroundColor Yellow
$trio = New-Trio
$merged = Merge-mdiServerByFqdn -Server $trio
Assert-That 'three role rows merge into one' (@($merged).Count -eq 1) "(got $(@($merged).Count))"
Assert-That 'the merged row keeps the name' ([string] @($merged)[0].FQDN -eq 'dc1.contoso.com')

Write-Host "`n[2] No role's checks are lost" -ForegroundColor Yellow
# De-duplicating by keeping the first row would silently drop CA auditing and the Entra Connect
# audit policy - checks that exist on no other role.
$names = @(Get-mdiCheckProperty -Server @($merged)[0] | Select-Object -ExpandProperty Name)
foreach ($expected in 'PowerSettings', 'TimeSync', 'AdvancedAuditing', 'CAAuditing', 'RootCertificates', 'AdvancedAuditingEntraConnect') {
    Assert-That "$expected survives the merge" ($expected -in $names)
}
Assert-That 'each check appears exactly once' (
    @($names).Count -eq @($names | Select-Object -Unique).Count) "(got $($names -join ', '))"
Assert-That 'a failing role-specific check is still failing' (@($merged)[0].CAAuditing -eq $false)

Write-Host "`n[3] Details from every role are carried" -ForegroundColor Yellow
$d = @($merged)[0].Details
foreach ($expected in 'TimeSyncDetails', 'CAAuditingDetails', 'EntraDetails') {
    Assert-That "$expected is present" (Test-mdiDetailEntry -Details $d -Name $expected)
}

Write-Host "`n[4] The merge does not mutate the originals" -ForegroundColor Yellow
# PSObject.Copy() is shallow. Sharing the Details object would add the CA's details to the domain
# controller row that the per-role HTML table still renders and that goes into the JSON.
Assert-That 'the DC row did not gain the CA details' (
    -not (Test-mdiDetailEntry -Details $trio[0].Details -Name 'CAAuditingDetails'))
Assert-That 'the DC row did not gain a CA check' (
    $null -eq $trio[0].PSObject.Properties['CAAuditing'])
Assert-That 'the CA row did not gain the DC details' (
    -not (Test-mdiDetailEntry -Details $trio[1].Details -Name 'TimeSyncDetails'))

Write-Host "`n[5] The score counts the server once" -ForegroundColor Yellow
$report = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($trio[0]); CAServers = @($trio[1]); EntraConnectServers = @($trio[2])
    DomainAuditing = @()
    DomainAdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DomainObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
    DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    DomainDeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
}
$stats = Get-mdiReportStatistics -ReportData $report
Assert-That 'one server is reported, not three' ($stats.TotalServers -eq 1) "(got $($stats.TotalServers))"
# Six distinct checks: PowerSettings, TimeSync, AdvancedAuditing, CAAuditing, RootCertificates,
# AdvancedAuditingEntraConnect. Counted per role it was ten.
Assert-That 'each check counted once' ($stats.ChecksTotal -eq 6) "(got $($stats.ChecksTotal))"
Assert-That 'passes counted once' ($stats.ChecksPassed -eq 4) "(got $($stats.ChecksPassed))"

Write-Host "`n[6] Findings are not listed three times" -ForegroundColor Yellow
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
$forHost = @($issues | Where-Object { [string] $_.Server -eq 'dc1.contoso.com' })
Assert-That 'two failing checks produce two findings' ($forHost.Count -eq 2) "(got $($forHost.Count): $($forHost.Issue -join ' | '))"
Assert-That 'no finding is duplicated' (
    @($forHost | Select-Object -ExpandProperty Issue -Unique).Count -eq $forHost.Count)

Write-Host "`n[7] The remediation script acts once per server" -ForegroundColor Yellow
$fixFile = Join-Path $env:TEMP ('mdi-merge-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 6))
try {
    $fix = New-mdiRemediationScript -ReportData $report -FilePath $fixFile
    $text = Get-Content $fix.Path -Raw
    $mentions = ([regex]::Matches($text, [regex]::Escape("'dc1.contoso.com'"))).Count
    # One mention per section that needs fixing, not three per section.
    Assert-That 'the server is not listed three times per section' ($mentions -le $fix.SectionCount) `
        "($mentions mention(s) across $($fix.SectionCount) section(s))"
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($fix.Path, [ref]$null, [ref]$parseErrors)
    Assert-That 'the generated script is valid PowerShell' (@($parseErrors).Count -eq 0)
} finally {
    Remove-Item $fixFile -Force -ErrorAction SilentlyContinue
}

Write-Host "`n[8] Distinct servers are never merged" -ForegroundColor Yellow
# The other direction: merging two different machines would hide one of them entirely.
$distinct = Merge-mdiServerByFqdn -Server @(
    [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; PowerSettings = $true; PartialFailure = $false; Unreachable = $false }
    [PSCustomObject]@{ FQDN = 'dc2.contoso.com'; PowerSettings = $false; PartialFailure = $false; Unreachable = $false }
)
Assert-That 'two servers stay two servers' (@($distinct).Count -eq 2) "(got $(@($distinct).Count))"
# Case-insensitively, because AD is.
$cased = Merge-mdiServerByFqdn -Server @(
    [PSCustomObject]@{ FQDN = 'DC1.contoso.com'; PowerSettings = $true; PartialFailure = $false; Unreachable = $false }
    [PSCustomObject]@{ FQDN = 'dc1.CONTOSO.com'; TimeSync = $true; PartialFailure = $false; Unreachable = $false }
)
Assert-That 'the same name in different case is one server' (@($cased).Count -eq 1) "(got $(@($cased).Count))"

Write-Host "`n[9] Degenerate input" -ForegroundColor Yellow
Assert-That 'an empty list merges to nothing' (@(Merge-mdiServerByFqdn -Server @()).Count -eq 0)
$single = Merge-mdiServerByFqdn -Server @([PSCustomObject]@{ FQDN = 'only.contoso.com'; PowerSettings = $true })
Assert-That 'a single server survives' (@($single).Count -eq 1) "(got $(@($single).Count))"
# A server with no name cannot be keyed, and dropping it would hide it entirely.
$nameless = Merge-mdiServerByFqdn -Server @(
    [PSCustomObject]@{ FQDN = $null; PowerSettings = $false }
    [PSCustomObject]@{ FQDN = ''; PowerSettings = $false }
)
Assert-That 'nameless servers are kept, not merged together' (@($nameless).Count -eq 2) "(got $(@($nameless).Count))"

Write-Host "`n[10] Reachability and partial failure merge in the safe direction" -ForegroundColor Yellow
# Reached by any role means the machine was reachable; failed part way in any role means part of it
# was never measured. Both must survive the merge or the verdict changes.
$mixed = Merge-mdiServerByFqdn -Server @(
    [PSCustomObject]@{ FQDN = 'x.contoso.com'; Unreachable = $true; PartialFailure = $false; Comment = 'not available' }
    [PSCustomObject]@{ FQDN = 'x.contoso.com'; Unreachable = $false; PartialFailure = $true; PowerSettings = $true; Comment = 'stopped early' }
)
Assert-That 'reached by one role counts as reached' (@($mixed)[0].Unreachable -eq $false)
Assert-That 'a partial failure in one role survives' (@($mixed)[0].PartialFailure -eq $true)

# One physical host discovered twice - as a domain controller and as a certificate authority. One
# copy measured the required ports as healthy, the other measured the SAME probe as blocked. First-
# key-wins would let whichever role was merged first decide the outcome, dropping the blocked port and
# reporting the host ready. The merge must be pessimistic: the failure survives regardless of order.
function New-DualRoleHost {
    param([bool] $DcHealthy)
    $dcSuccess = $DcHealthy; $caSuccess = -not $DcHealthy
    $mkRec = {
        param($ok)
        [PSCustomObject]@{ Id = 'p1'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389; Scope = 'DomainController'
            Group = 'LDAP'; Requirement = 'Required'; Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'
            Applicable = $true; Success = $ok
            Detail = if ($ok) { 'ok' } else { 'Blocked - no response within 5000 ms, retried and still silent' } }
    }
    $dcFailed = if ($dcSuccess) { @() } else { @('TCP/389 to dc1.contoso.com: Blocked - no response within 5000 ms, retried and still silent') }
    $caFailed = if ($caSuccess) { @() } else { @('TCP/389 to dc1.contoso.com: Blocked - no response within 5000 ms, retried and still silent') }
    $dc = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com'
        RequiredPorts = $dcSuccess; PartialFailure = $false; Unreachable = $false
        Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ ProbedFrom = 'sensor'
                FailedRequired = $dcFailed; NnrFailedTargets = @(); Results = @((& $mkRec $dcSuccess)) } } }
    $ca = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com'
        RequiredPorts = $caSuccess; PartialFailure = $false; Unreachable = $false
        Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ ProbedFrom = 'sensor'
                FailedRequired = $caFailed; NnrFailedTargets = @(); Results = @((& $mkRec $caSuccess)) } } }
    @($dc, $ca)
}

Write-Host "`n[11] A failure under any role survives the merge" -ForegroundColor Yellow
$pair = New-DualRoleHost -DcHealthy $true
$mergedPair = @(Merge-mdiServerByFqdn -Server $pair)
Assert-That 'two roles of one host merge into one row' ($mergedPair.Count -eq 1) "(got $($mergedPair.Count))"
Assert-That 'RequiredPorts fails when either role measured it blocked' ($mergedPair[0].RequiredPorts -eq $false) `
    "(got $($mergedPair[0].RequiredPorts))"
$mergedFailed = @($mergedPair[0].Details.RequiredPortsDetails.FailedRequired | Where-Object { $_ })
Assert-That 'the blocked-port evidence is carried into the merged details' ($mergedFailed.Count -ge 1) "(got $($mergedFailed.Count))"

Write-Host "`n[12] The merge is order-independent" -ForegroundColor Yellow
$fwd = @(Merge-mdiServerByFqdn -Server (New-DualRoleHost -DcHealthy $true))
$rev = @(Merge-mdiServerByFqdn -Server (@(New-DualRoleHost -DcHealthy $true)[1, 0]))
Assert-That 'RequiredPorts is the same whichever role is merged first' ($fwd[0].RequiredPorts -eq $rev[0].RequiredPorts)
Assert-That 'the failure survives in both orders' (($fwd[0].RequiredPorts -eq $false) -and ($rev[0].RequiredPorts -eq $false))
$fwdRecs = @($fwd[0].Details.RequiredPortsDetails.Results)
$revRecs = @($rev[0].Details.RequiredPortsDetails.Results)
Assert-That 'the surviving record set is order-independent' ($fwdRecs.Count -eq $revRecs.Count) "(fwd $($fwdRecs.Count) / rev $($revRecs.Count))"

Write-Host "`n[13] Duplicate probe records de-duplicate with the failure winning" -ForegroundColor Yellow
# The same probe measured from both roles must not be double-counted; when the two records for that
# probe disagree, the failing one wins.
$dupPass = [PSCustomObject]@{ Id = 'p1'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389; Scope = 'DomainController'
    Group = 'LDAP'; Requirement = 'Required'; Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'; Applicable = $true; Success = $true; Detail = 'ok' }
$dupFail = [PSCustomObject]@{ Id = 'p1'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389; Scope = 'DomainController'
    Group = 'LDAP'; Requirement = 'Required'; Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'; Applicable = $true; Success = $false; Detail = 'Blocked - silent' }
$dupA = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; RequiredPorts = $true; PartialFailure = $false; Unreachable = $false
    Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ ProbedFrom = 'sensor'; FailedRequired = @(); NnrFailedTargets = @(); Results = @($dupPass) } } }
$dupB = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; RequiredPorts = $false; PartialFailure = $false; Unreachable = $false
    Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ ProbedFrom = 'sensor'; FailedRequired = @('TCP/389 to dc1.contoso.com: Blocked - silent'); NnrFailedTargets = @(); Results = @($dupFail) } } }
$dupMergedFwd = @(Merge-mdiServerByFqdn -Server @($dupA, $dupB))[0].Details.RequiredPortsDetails.Results
$dupMergedRev = @(Merge-mdiServerByFqdn -Server @($dupB, $dupA))[0].Details.RequiredPortsDetails.Results
Assert-That 'the shared probe appears exactly once' (@($dupMergedFwd).Count -eq 1) "(got $(@($dupMergedFwd).Count))"
Assert-That 'the failing record wins the de-duplication' (@($dupMergedFwd)[0].Success -eq $false)
Assert-That 'de-duplication is order-independent' ((@($dupMergedRev).Count -eq 1) -and (@($dupMergedRev)[0].Success -eq $false))

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
