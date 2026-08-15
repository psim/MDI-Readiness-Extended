<#
    A lookup that FAILED is not a computer that is ABSENT.

    Get-mdiEntraConnectReadiness resolves each sync account's parsed server name with Get-ADComputer.
    The catch around that call caught EVERYTHING and reported all of it as "does not resolve" - a
    positive claim about the directory that the directory never made.

    The script's own comment beside that code states the rule it then broke:

        "Absence of evidence and evidence of absence, kept apart."

      * the directory positively answered NO SUCH OBJECT  ->  evidence of absence. Usually a stale
        sync account for a decommissioned host. NOT charged; charging it would fabricate a
        permanently unclearable failure.

      * the lookup THREW for any other reason - access denied, server down, RPC or referral failure
        -> absence of evidence. The directory never answered, so the server is unmeasured and IS
        charged, exactly like the sibling unparsable-description path.

    Measured on the shipped producer before the fix, with AADC01 resolving and the AADC02 lookup
    throwing UnauthorizedAccessException:

        rows=1  placeholders=0  checks=17/17  unread=0  score=100%  issues=0  READY=True

    and its report JSON was BYTE-IDENTICAL to a genuine one-server deployment. An Entra Connect
    staging pair whose second server cannot be read for permission reasons was silently reduced to a
    single-server estate and certified at 100%.

    This file pins the classification. It must be decided on a POSITIVE not-found signal, never on
    "not access denied", so that an unrecognised failure defaults to being charged.
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$parsable = 'Account created by Microsoft Entra Connect with installation identifier 8f2 running on {0} configured to synchronize to tenant contoso.onmicrosoft.com'

$script:syncAccounts = @()
$script:warnings = New-Object System.Collections.ArrayList
# How the AADC02 lookup fails: 'ok', 'denied', 'down', or 'absent'.
$script:aadc02Mode = 'ok'

Set-Item -Path function:script:Get-ADUser -Value {
    param($LDAPFilter, $Properties, $Server, $ErrorAction)
    $script:syncAccounts
}
Set-Item -Path function:script:Get-ADComputer -Value {
    param($Identity, $Server, $Properties, $ErrorAction)
    $id = [string] $Identity
    if ($id -eq 'AADC02') {
        switch ($script:aadc02Mode) {
            # The real directory raises UnauthorizedAccessException here; the object may well exist.
            'denied' { throw [UnauthorizedAccessException]::new('Access is denied while reading the computer object') }
            # A server-down / RPC failure. Also says nothing about whether the object exists.
            'down' { throw [Runtime.InteropServices.COMException]::new('The RPC server is unavailable') }
            # The directory positively answered: no such object.
            'absent' { throw [InvalidOperationException]::new('Cannot find an object with identity: AADC02') }
        }
    }
    if ($id -in @('AADC01', 'AADC02')) {
        return [PSCustomObject]@{ distinguishedName = ('CN={0},CN=Computers,DC=contoso,DC=com' -f $id) }
    }
    throw [InvalidOperationException]::new(('Cannot find an object with identity: {0}' -f $id))
}
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName) [PSCustomObject]@{ Reachable = $false; Method = 'stubbed' }
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value { param($ComputerName, $KnownAddress) @('10.0.0.5') }

function New-SyncAccount {
    param([string] $Sam, [string] $Description)
    [PSCustomObject]@{ sAMAccountName = $Sam; description = $Description }
}

function New-PassingDc {
    $o = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
        Comment = $null; Details = [ordered]@{}
    }
    foreach ($n in 'NtlmAuditing', 'AdvancedAuditing', 'PowerSettings', 'TimeSync', 'SensorHealth', 'RootCertificates', 'CapacitySufficient') {
        $o | Add-Member -NotePropertyName $n -NotePropertyValue $true -Force
    }
    $o
}

function Get-Facts {
    param([object[]] $Accounts, [string] $Mode = 'ok')
    $script:syncAccounts = @($Accounts)
    $script:aadc02Mode = $Mode
    $script:warnings = New-Object System.Collections.ArrayList
    $ecs = @(Get-mdiEntraConnectReadiness -Domain 'contoso.com' 3>$null 4>$null)
    $report = [PSCustomObject]@{
        DomainControllers   = @(New-PassingDc)
        CAServers           = @()
        EntraConnectServers = @($ecs)
        DomainsInScope      = @('contoso.com')
        ForestDiscovery     = [PSCustomObject]@{ Complete = $true }
    }
    $st = Get-mdiReportStatistics -ReportData $report
    [PSCustomObject]@{
        Rows         = $ecs
        Placeholders = @($ecs | Where-Object { Test-mdiServerIsPlaceholder -Server $_ })
        Unread       = [int] $st.ChecksUnread
        Denominator  = [int] (Get-mdiCoverageDenominator -Measured $st.ChecksTotal -Unread $st.ChecksUnread)
        Percent      = [int] [math]::Floor((Get-mdiCoveragePercent -Passed $st.ChecksPassed -Measured $st.ChecksTotal -Unread $st.ChecksUnread))
        Verdict      = (Test-mdiReadinessResult -ReportData $report 3>$null)
        Issues       = @(Get-mdiIssueList -Statistics $st -ReportData $report)
        Warnings     = @($script:warnings)
    }
}

Write-Host 'An Entra Connect lookup that failed is not a computer that is absent' -ForegroundColor Cyan

$pair = @(
    (New-SyncAccount 'AAD_1a2b3c' ($parsable -f 'AADC01')),
    (New-SyncAccount 'AAD_4d5e6f' ($parsable -f 'AADC02'))
)
$single = @( (New-SyncAccount 'AAD_1a2b3c' ($parsable -f 'AADC01')) )

$bothResolve = Get-Facts $pair   'ok'
$oneResolves = Get-Facts $single 'ok'
$denied      = Get-Facts $pair   'denied'
$down        = Get-Facts $pair   'down'
$absent      = Get-Facts $pair   'absent'

# --- The defect: access denied was banked as "the server is gone" ------------------------------------
Assert-That 'an access-denied lookup emits a placeholder row' (
    $denied.Placeholders.Count -eq 1
) ("got $($denied.Placeholders.Count)")
Assert-That 'an access-denied lookup is charged as unread' (
    $denied.Unread -gt $oneResolves.Unread
) ("denied unread=$($denied.Unread) single unread=$($oneResolves.Unread)")
Assert-That 'an access-denied lookup does not raise the score' (
    $denied.Percent -le $bothResolve.Percent
) ("both=$($bothResolve.Percent)% denied=$($denied.Percent)%")
Assert-That 'an access-denied estate is NOT identical to a genuine single-server estate' (
    $denied.Denominator -ne $oneResolves.Denominator -or $denied.Percent -ne $oneResolves.Percent
) ("denied=$($denied.Percent)%/den$($denied.Denominator) single=$($oneResolves.Percent)%/den$($oneResolves.Denominator)")
Assert-That 'an access-denied lookup refuses READY' (-not $denied.Verdict) "verdict=$($denied.Verdict)"
Assert-That 'an access-denied lookup raises a finding' ($denied.Issues.Count -ge 1) ("got $($denied.Issues.Count)")
Assert-That 'the operator is NOT told the server does not resolve' (
    @($denied.Warnings | Where-Object { $_ -like '*does not resolve*' }).Count -eq 0
) ("got '$($denied.Warnings -join ' | ')'")

# An unrecognised transport failure must default to the SAFE side, not to "absent".
Assert-That 'an RPC failure is charged like access denied' (
    $down.Placeholders.Count -eq 1 -and $down.Unread -eq $denied.Unread -and $down.Percent -eq $denied.Percent
) ("placeholders=$($down.Placeholders.Count) unread=$($down.Unread) vs denied unread=$($denied.Unread)")

# --- The distinction that must NOT be collapsed the other way ---------------------------------------
# A positive "no such object" is evidence of absence and stays a warning only. A careless fix that
# charges every exception would fabricate a permanent failure out of a decommissioned host.
Assert-That 'a positively ABSENT computer emits no placeholder' (
    $absent.Placeholders.Count -eq 0
) ("got $($absent.Placeholders.Count)")
Assert-That 'a positively ABSENT computer is not charged' (
    $absent.Unread -eq $oneResolves.Unread -and $absent.Percent -eq $oneResolves.Percent
) ("absent=$($absent.Percent)%/unread$($absent.Unread) single=$($oneResolves.Percent)%/unread$($oneResolves.Unread)")
Assert-That 'a positively ABSENT computer does not change the verdict' (
    $absent.Verdict -eq $oneResolves.Verdict
) ("absent=$($absent.Verdict) single=$($oneResolves.Verdict)")
Assert-That 'a positively ABSENT computer still warns that it was not verified' (
    @($absent.Warnings | Where-Object { $_ -like '*does not resolve*' }).Count -eq 1
) ("got '$($absent.Warnings -join ' | ')'")

# --- Guards that must not weaken --------------------------------------------------------------------
Assert-That 'a fully resolved pair emits no placeholders' ($bothResolve.Placeholders.Count -eq 0) (
    "got $($bothResolve.Placeholders.Count)")
Assert-That 'a fully resolved pair reports both servers' (@($bothResolve.Rows).Count -eq 2) (
    "got $(@($bothResolve.Rows).Count)")
Assert-That 'a genuine single-server estate emits no placeholders' ($oneResolves.Placeholders.Count -eq 0) (
    "got $($oneResolves.Placeholders.Count)")
Assert-That 'a genuine single-server estate reports exactly one server' (@($oneResolves.Rows).Count -eq 1) (
    "got $(@($oneResolves.Rows).Count)")
# A domain with no Entra Connect at all stays completely silent and READY.
$none = Get-Facts @() 'ok'
Assert-That 'a domain with no Entra Connect emits no rows' (@($none.Rows).Count -eq 0) ("got $(@($none.Rows).Count)")
Assert-That 'a domain with no Entra Connect is still READY' ($none.Verdict) "verdict=$($none.Verdict)"

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
