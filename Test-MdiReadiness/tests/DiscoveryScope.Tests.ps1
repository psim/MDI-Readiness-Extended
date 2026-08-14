<#
    Discovery decides WHAT GETS SCANNED, so a defect here silently shrinks the estate and every later
    stage then reports confidently about servers it never looked at. Two defects, both of that shape:

      - a domain controller record whose HostName is blank counted towards "ADWS worked", so the LDAP
        fallback was never tried and the row was then discarded downstream for having no name. With
        four records of which two were blank, two domain controllers were scanned and nothing warned.
        With all of them blank, the domain reported ZERO servers, LDAP was never called, and nothing
        anywhere said discovery had failed - a domain that HAS domain controllers looked exactly like
        a domain that has none.

      - the scope list was de-duplicated with Select-Object -Unique, which is ORDINAL, while every
        comparison against it used -notin, which is not. So "contoso.com" and "CONTOSO.COM" survived
        as two domains, as did "contoso.com." which DNS considers the same name - and the spelling no
        server matched was charged as an unexamined domain, losing readiness over a domain that had
        just been scanned under its other spelling.
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
$script:warnings = New-Object System.Collections.ArrayList
function Write-mdiWarning { param($Message) [void]$script:warnings.Add([string]$Message) }

$script:pass = 0; $script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'A domain controller without a DNS name is still a domain controller' -ForegroundColor Cyan
$script:adwsRows = @()
Set-Item -Path function:script:Get-ADDomainController -Value {
    param($Server, $Filter, $ErrorAction)
    if ($script:adwsRows -is [scriptblock]) { return & $script:adwsRows }
    $script:adwsRows
}
$script:ldapCalled = $false
Set-Item -Path function:script:Get-mdiDomainControllerFromLdap -Value {
    param($Domain)
    $script:ldapCalled = $true
    @([PSCustomObject]@{ Name = 'ldap-dc.contoso.com'; IP = '10.9.9.9' })
}
function Resolve-Test($rows) {
    $script:adwsRows = $rows
    $script:ldapCalled = $false
    $script:warnings.Clear()
    Resolve-mdiDomainController -Domain 'contoso.com'
}

# The ordinary case must be unaffected.
$good = Resolve-Test @([PSCustomObject]@{ HostName = 'dc1.contoso.com'; Name = 'DC1'; IPv4Address = '10.0.0.1' })
Assert-That 'a normal ADWS result is used as-is' ($good.Method -eq 'ADWS' -and $good.Servers.Count -eq 1)
Assert-That '  and the LDAP fallback is not called' (-not $script:ldapCalled)

# A record carrying only the short name is RECOVERED rather than discarded.
$mixed = Resolve-Test @(
    [PSCustomObject]@{ HostName = 'dc1.contoso.com'; Name = 'DC1'; IPv4Address = '10.0.0.1' }
    [PSCustomObject]@{ HostName = $null; Name = 'DC2'; IPv4Address = '10.0.0.2' }
    [PSCustomObject]@{ HostName = ''; Name = 'DC3'; IPv4Address = '10.0.0.3' }
)
Assert-That 'a record with only a short name is still scanned' ($mixed.Servers.Count -eq 3) `
    "(got $($mixed.Servers.Count) of 3)"
Assert-That '  and the short name is qualified with the domain' (
    @($mixed.Servers | Where-Object { $_.Name -eq 'DC2.contoso.com' }).Count -eq 1) `
    "(names: $(($mixed.Servers | ForEach-Object { $_.Name }) -join ', '))"
Assert-That '  and its address is preserved' (
    @($mixed.Servers | Where-Object { $_.Name -eq 'DC2.contoso.com' -and $_.IP -eq '10.0.0.2' }).Count -eq 1)

# A record with NO usable identifier at all is dropped, but never silently.
$unusable = Resolve-Test @(
    [PSCustomObject]@{ HostName = 'dc1.contoso.com'; Name = 'DC1'; IPv4Address = '10.0.0.1' }
    [PSCustomObject]@{ HostName = $null; Name = $null; IPv4Address = '10.0.0.9' }
)
Assert-That 'a record with neither name is dropped' ($unusable.Servers.Count -eq 1)
Assert-That '  and the operator is told' (@($script:warnings | Where-Object { $_ -match 'neither a DNS host name nor a name' }).Count -eq 1) `
    "(warnings: $($script:warnings -join ' | '))"

# THE defect: every record blank. Rows came back, so the old code called it a success and never fell
# back - the domain reported zero servers and nothing warned.
$allBlank = Resolve-Test @(
    [PSCustomObject]@{ HostName = $null; Name = $null; IPv4Address = '10.0.0.1' }
    [PSCustomObject]@{ HostName = ''; Name = ''; IPv4Address = '10.0.0.2' }
)
Assert-That 'when no record yields a name, the LDAP fallback IS tried' $script:ldapCalled
Assert-That '  and the domain is not reported as empty' ($allBlank.Servers.Count -gt 0) `
    "(got $($allBlank.Servers.Count))"
Assert-That '  via the LDAP method' ($allBlank.Method -eq 'LDAP') "(method=$($allBlank.Method))"

# A genuinely empty domain still falls through to LDAP and then reports nothing, as before.
$script:ldapCalled = $false
Set-Item -Path function:script:Get-mdiDomainControllerFromLdap -Value { param($Domain) $script:ldapCalled = $true; @() }
$empty = Resolve-Test @()
Assert-That 'a genuinely empty result still falls back to LDAP' $script:ldapCalled
Assert-That '  and then reports no servers with a reason' ($empty.Servers.Count -eq 0 -and $empty.Method -eq 'None')
Assert-That '  and the reason distinguishes empty from unusable' ($empty.Error -match 'returned no domain controllers')

$script:adwsRows = @([PSCustomObject]@{ HostName = $null; Name = $null; IPv4Address = '1.1.1.1' })
$script:ldapCalled = $false
$noneUsable = Resolve-mdiDomainController -Domain 'contoso.com'
Assert-That 'an all-unusable result reports a DIFFERENT reason from an empty one' (
    $noneUsable.Error -match 'none carried a usable host name') "(error='$($noneUsable.Error)')"

Write-Host 'One domain spelled two ways is one domain' -ForegroundColor Cyan
# Get-mdiUnexaminedDomain is the single definition, shared by the statistics, the issue list and the
# verdict. It must agree with itself about casing and trailing dots.
function New-Srv($domain) {
    [PSCustomObject]@{ FQDN = "dc.$domain"; Domain = $domain; Unreachable = $false
        PartialFailure = $false; PowerSettings = $true }
}
Assert-That 'a domain scanned under a different CASE is not reported unexamined' (
    @(Get-mdiUnexaminedDomain -ScopedDomain @('CONTOSO.COM') -Server @((New-Srv 'contoso.com'))).Count -eq 0)
Assert-That 'a trailing dot in scope does not create a phantom domain' (
    @(Get-mdiUnexaminedDomain -ScopedDomain @('contoso.com.') -Server @((New-Srv 'contoso.com'))).Count -eq 0)
Assert-That 'a trailing dot on the SERVER side matches too' (
    @(Get-mdiUnexaminedDomain -ScopedDomain @('contoso.com') -Server @((New-Srv 'contoso.com.'))).Count -eq 0)
Assert-That 'surrounding whitespace does not create a phantom domain' (
    @(Get-mdiUnexaminedDomain -ScopedDomain @(' contoso.com ') -Server @((New-Srv 'contoso.com'))).Count -eq 0)

# The false-red guard's opposite: a genuinely unexamined domain must STILL be reported.
$missing = @(Get-mdiUnexaminedDomain -ScopedDomain @('contoso.com', 'fabrikam.com') -Server @((New-Srv 'contoso.com')))
Assert-That 'a genuinely unexamined domain is still reported' ($missing.Count -eq 1) "(got $($missing.Count))"
Assert-That '  and named in the spelling the operator used' ($missing[0] -eq 'fabrikam.com')

# Two spellings of one MISSING domain are one finding, not two.
Assert-That 'two spellings of one missing domain give one finding' (
    @(Get-mdiUnexaminedDomain -ScopedDomain @('fabrikam.com', 'FABRIKAM.COM') -Server @((New-Srv 'contoso.com'))).Count -eq 1)

# A scan that enumerated nothing anywhere is a different, more serious failure, reported elsewhere.
Assert-That 'a scan with no servers at all reports no per-domain findings' (
    @(Get-mdiUnexaminedDomain -ScopedDomain @('a.com', 'b.com') -Server @()).Count -eq 0)
Assert-That 'servers carrying no Domain do not silently pass every domain' (
    @(Get-mdiUnexaminedDomain -ScopedDomain @('a.com') -Server @([PSCustomObject]@{ FQDN = 'x'; Unreachable = $false })).Count -eq 0)

Write-Host 'The three views of "unexamined" agree' -ForegroundColor Cyan
# The statistics, the issue list and the verdict each used to write this comparison out by hand.
$rep = [PSCustomObject]@{
    DomainControllers = @((New-Srv 'contoso.com')); CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('CONTOSO.COM.', 'fabrikam.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
}
$stats = Get-mdiReportStatistics -ReportData $rep
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $rep)
$discovery = @($issues | Where-Object { $_.Area -eq 'Discovery' })
Assert-That 'the statistics charge exactly one unexamined domain' ($stats.ChecksUnread -eq 1) "(unread=$($stats.ChecksUnread))"
Assert-That 'the issue list raises exactly one discovery finding' ($discovery.Count -eq 1) `
    "(got $($discovery.Count): $(($discovery | ForEach-Object { $_.Server }) -join ', '))"
Assert-That '  naming the genuinely missing domain' ($discovery.Count -eq 1 -and $discovery[0].Server -eq 'fabrikam.com')
$script:warnings.Clear()
$verdict = Test-mdiReadinessResult -ReportData $rep
Assert-That 'the verdict refuses READY' ($verdict.Ready -ne $true)
Assert-That '  and warns about the same single domain' (
    @($script:warnings | Where-Object { $_ -match 'not examined' -and $_ -match 'fabrikam' -and $_ -notmatch 'CONTOSO' }).Count -eq 1) `
    "(warnings: $($script:warnings -join ' | '))"

# And the matching false-red guard: a fully examined forest, spelled inconsistently, stays clean.
$clean = [PSCustomObject]@{
    DomainControllers = @((New-Srv 'contoso.com'), (New-Srv 'fabrikam.com'))
    CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('CONTOSO.COM', 'fabrikam.com.'); Domain = 'contoso.com'; Forest = 'contoso.com'
}
$cleanStats = Get-mdiReportStatistics -ReportData $clean
Assert-That 'a fully examined forest charges no unread check despite mixed spelling' ($cleanStats.ChecksUnread -eq 0) `
    "(unread=$($cleanStats.ChecksUnread))"
Assert-That '  and raises no discovery finding' (
    @(Get-mdiIssueList -Statistics $cleanStats -ReportData $clean | Where-Object { $_.Area -eq 'Discovery' }).Count -eq 0)

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
