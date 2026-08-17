<#
    THE DEFECT THIS TEST PINS

    When remote WMI cannot run on a server, Get-mdiRequiredPorts falls back to probing that server
    INBOUND from the computer running the script. In that direction the DomainController-scoped
    probes - LDAP 389 TCP and UDP, Global Catalog 3268, and LDAPS 636 and LDAPS to GC 3269 - are
    only meaningful against a server that is itself a domain controller, so the fallback narrows
    them away for anything else. That rule is right.

    How it decided the question was not. It read

        $Plan.DomainControllers

    which is not the domain controller population. It is the LDAP probe SAMPLE, chosen by
    Resolve-mdiLdapTarget and capped by -MaxLdapTargetsPerDomain, WHICH DEFAULTS TO 2. On any
    domain holding more than two controllers a real domain controller is routinely missing from
    that list, and the fallback then concluded it was not a domain controller at all. The extended
    lab holds five in mdilab.local plus dcfab01 in fabrikam.local, so this is what an ordinary
    default run does - and the fallback is itself the ordinary path across a forest trust, where
    remote WMI usually cannot run.

    Measured on the shipped functions with that estate, -MultiForest, the default cap of 2, both
    servers probed inbound from the same computer with every socket answering open:

        dc01.mdilab.local (in the sample)   5 DomainController probes, 5 MEASURED
        dc03.mdilab.local (not sampled)     5 DomainController probes, 0 measured

    Identical estate, identical reachability, and the only difference between the two servers is
    which of them the sampler happened to pick. Each of dc03's five probes was recorded with the
    reason "this probe measures the DomainController scope, which cannot be established by probing
    the server inbound from this computer". That reason is false: the scope was established for
    dc01 from the same computer in the same run. A measurement that WAS available came back as one
    that could not be taken, on every domain controller past the second in its domain - and under
    -MultiForest two of the five it discards have just been promoted to Required.

    The fix lets the caller state what it knows. Get-mdiDomainControllerReadiness is iterating the
    domain controllers; it does not have to guess. The sample-based inference is kept for callers
    that say nothing, so a server outside the domain controller pass which does appear in the
    plan's target list is unaffected - and a certification authority, which the CA pass does not
    declare, must still lose the DomainController probes rather than gain five false failures.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$script:target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $script:target)) {
    $script:target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
}
if (-not (Test-Path $script:target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $What, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:pass++
        Write-Host ("  PASS  {0}" -f $What) -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host ("  FAIL  {0} {1}" -f $What, $Detail) -ForegroundColor Red
    }
}

$text = Get-Content -LiteralPath $script:target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

# Remote WMI cannot run - the documented trigger for the reverse-direction fallback, and the
# ordinary case across a forest trust.
function Invoke-mdiRemoteCommand { param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds) $null }
function Get-mdiRemoteTempFolder { param($ComputerName) 'C:\Windows\Temp' }
function New-mdiRemoteScriptFile { param($ComputerName, $ScriptText, $Folder) $null }

# The friendliest possible network: every socket answers open, instantly and without traffic. Any
# probe reported below as not measured is therefore the code's own doing, not the network's.
function Test-mdiTcpPort { param($ComputerName, $Port, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'open' } }
function Test-mdiUdpPort { param($ComputerName, $Port, $TimeoutMs, $Payload, $ExpectedTransactionId, $ResponseValidator) [PSCustomObject]@{ Success = $true; Detail = 'open' } }
function Test-mdiNnrNetBios { param($ComputerName, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'open' } }
function Test-mdiReverseDns { param($IPAddress, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'resolved' } }
function Test-mdiCloudConnectivity { param($Url, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'reachable' } }
function Test-mdiLocalTcpListener { param($Port) @(1) }
function Get-mdiComputerAddress {
    param($ComputerName, $KnownAddress)
    switch -Regex ($ComputerName) {
        '^dc01\.' { @('10.10.1.10') }
        '^dc03\.' { @('10.10.1.12') }
        '^dcfab01\.' { @('10.10.1.50') }
        default { @('10.10.1.99') }
    }
}

Write-Host 'A domain controller keeps its DomainController-scoped probes whether or not the LDAP sampler picked it'

# Five controllers in mdilab.local plus one across the fabrikam.local trust, which is the estate
# the extended lab has.
$inventory = @(
    [PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc02.mdilab.local'; IP = '10.10.1.11'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc03.mdilab.local'; IP = '10.10.1.12'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc04.mdilab.local'; IP = '10.10.1.13'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc05.mdilab.local'; IP = '10.10.1.14'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50'; Domain = 'fabrikam.local' }
)

# Built exactly as Main builds it, at the shipped default cap.
$ldapTargets = @(Resolve-mdiLdapTarget -DomainControllers $inventory -MaxPerDomain 2)
$nnrTargets = @(Resolve-mdiNnrTarget -DomainControllers $inventory -MaxTargets 5)
$plan = New-mdiPortProbePlan -Domain 'mdilab.local' -DomainController $ldapTargets `
    -NnrTarget $nnrTargets -TimeoutMs 100 -MultiForest

# The premise the whole test rests on: the sample really does leave real controllers out.
$sampledNames = @($ldapTargets | ForEach-Object { [string] $_.Name })
Assert-True 'the default LDAP sample does not contain every domain controller' `
    ($sampledNames -notcontains 'dc03.mdilab.local') `
    ("sampled: [{0}]" -f ($sampledNames -join ','))

function Get-DcScopeStat {
    param([string] $ComputerName, [switch] $AsDomainController)
    $result = Get-mdiRequiredPorts -ComputerName $ComputerName -Plan $plan -IsDomainController:$AsDomainController
    $rows = @($result.details.Results | Where-Object { $_.Scope -eq 'DomainController' })
    [PSCustomObject]@{
        Rows      = $rows.Count
        Mandatory = @($rows | Where-Object { Test-mdiRequirementIsMandatory -Requirement $_.Requirement }).Count
        Measured  = @($rows | Where-Object { Test-mdiProbeWasMeasured -Record $_ }).Count
        Failed    = @($rows | Where-Object { $_.Success -eq $false }).Count
    }
}

$sampled = Get-DcScopeStat -ComputerName 'dc01.mdilab.local' -AsDomainController
$declared = Get-DcScopeStat -ComputerName 'dc03.mdilab.local' -AsDomainController
$undeclared = Get-DcScopeStat -ComputerName 'dc03.mdilab.local'
$authority = Get-DcScopeStat -ComputerName 'ca01.mdilab.local'

# -MultiForest promotes LDAPS 636 and LDAPS-GC 3269 to Required, so all five are mandatory.
Assert-True 'the multi-forest plan carries five mandatory DomainController probes' `
    ($sampled.Mandatory -eq 5) ("mandatory: {0}" -f $sampled.Mandatory)

Assert-True 'a SAMPLED domain controller measures its DomainController probes inbound' `
    ($sampled.Measured -eq 5) ("measured: {0} of {1}" -f $sampled.Measured, $sampled.Rows)

# The defect itself: this was 0 of 5 before the fix, on a server the network could answer for.
Assert-True 'an UNSAMPLED domain controller measures them too when the caller declares it' `
    ($declared.Measured -eq 5) ("measured: {0} of {1}" -f $declared.Measured, $declared.Rows)

Assert-True 'sampling changes nothing about what a declared domain controller measures' `
    ($declared.Measured -eq $sampled.Measured) `
    ("sampled {0}, unsampled {1}" -f $sampled.Measured, $declared.Measured)

Assert-True 'no declared domain controller probe is recorded as a measured failure' `
    ($declared.Failed -eq 0) ("failed: {0}" -f $declared.Failed)

# The narrowing must survive for everything it was written for. A certification authority is not a
# domain controller, the CA pass does not declare one, and probing LDAP against it would invent
# five blocked required ports.
Assert-True 'a server the caller does not declare keeps the old sample-based inference' `
    ($undeclared.Measured -eq 0) ("measured: {0}" -f $undeclared.Measured)

Assert-True 'a certification authority still loses the DomainController probes' `
    ($authority.Measured -eq 0) ("measured: {0}" -f $authority.Measured)

Assert-True 'a certification authority gains no measured DomainController failure' `
    ($authority.Failed -eq 0) ("failed: {0}" -f $authority.Failed)

# Narrowed-away probes must still be REMEMBERED, or the required denominator quietly shrinks.
Assert-True 'the narrowed-away probes are still emitted as unmeasured records' `
    ($authority.Rows -eq 5 -and $undeclared.Rows -eq 5) `
    ("ca rows {0}, undeclared rows {1}" -f $authority.Rows, $undeclared.Rows)

# The declaration must not be able to leak between servers through the shared plan object.
$secondPass = Get-DcScopeStat -ComputerName 'ca01.mdilab.local'
Assert-True 'a declaration for one server does not leak into the next through the shared plan' `
    ($secondPass.Measured -eq 0) ("measured: {0}" -f $secondPass.Measured)

# Unreadable shapes: the switch must survive a caller that passes nothing readable, and the
# inference behind it must survive a target list carrying junk.
$brokenPlan = $plan.PSObject.Copy()
$brokenPlan.DomainControllers = @(
    $null
    [PSCustomObject]@{ Name = $null; IP = $null }
    [PSCustomObject]@{ Name = ''; IP = '' }
    [PSCustomObject]@{ Name = 'dc09.mdilab.local'; IP = 'not-an-address' }
)
$threw = $false
try {
    $r = Get-mdiRequiredPorts -ComputerName 'dc03.mdilab.local' -Plan $brokenPlan -IsDomainController
    $brokenRows = @($r.details.Results | Where-Object { $_.Scope -eq 'DomainController' })
} catch { $threw = $true }
Assert-True 'an unreadable target list does not throw when the caller declares the server' (-not $threw)
Assert-True 'a declared domain controller is measured even from an unreadable target list' `
    ((-not $threw) -and @($brokenRows | Where-Object { Test-mdiProbeWasMeasured -Record $_ }).Count -eq 5) `
    'the declaration did not survive an unreadable plan'

Write-Host ''
Write-Host ("pass={0}  fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
