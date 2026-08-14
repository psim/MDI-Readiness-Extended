<#
    An Entra Connect server that could not be READ is not an Entra Connect server that is GONE.

    Get-mdiEntraConnectReadiness discovers sync servers by parsing the server name out of each
    directory-synchronisation account's description. Its not-measured marker was ALL-OR-NOTHING: it
    fired only when NO account yielded a resolvable server. So a staging pair where one account parses
    and the other does not lost the second server completely, and the score IMPROVED for the loss:

        two accounts, both resolve      ->  den 9, 7/9 = 77%   (the true two-server estate)
        two accounts, one unparsable    ->  den 8, 7/8 = 87%   <-- higher, for discovering less
        one account, resolves           ->  den 8, 7/8 = 87%   <-- and identical to the above

    The HTML and the JSON were byte-for-byte identical between "one Entra Connect server exists" and
    "two exist, one was never assessed".

    THE DISTINCTION THIS FILE EXISTS TO PIN — the two failure paths are NOT the same fact:

      * the description could not be PARSED (documented cause: a non-English directory, where the
        description reads "auf Computer AADC01 konfiguriert"). Nothing here says the server is gone;
        the account is present, the description is present, and only this parser failed. A server that
        exists and was not looked at is unmeasured, so it IS charged.

      * the description parsed but the computer it names is ABSENT from the directory. There the
        directory positively answered "no such computer" - usually a stale sync account for a
        decommissioned host. Charging it would fabricate a permanently unclearable failure, so it
        stays a warning only.

    Absence of evidence and evidence of absence, kept apart. A future simplification that collapses
    them in either direction is caught here.
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
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# The English description the parser is written for, and the German one it cannot read. Both are
# real shapes: the localised wording is recorded in the script's own comments.
$parsable = 'Account created by Microsoft Entra Connect with installation identifier 8f2 running on {0} configured to synchronize to tenant contoso.onmicrosoft.com'
$germanUnparsable = 'Konto erstellt von Microsoft Entra Connect mit der Installations-ID 8f2 zur Synchronisierung des Verzeichnisses'

$script:syncAccounts = @()
$script:knownComputers = @('AADC01', 'AADC02')

Set-Item -Path function:script:Get-ADUser -Value {
    param($LDAPFilter, $Properties, $Server, $ErrorAction)
    $script:syncAccounts
}
Set-Item -Path function:script:Get-ADComputer -Value {
    param($Identity, $Server, $Properties, $ErrorAction)
    if ($script:knownComputers -contains [string] $Identity) {
        return [PSCustomObject]@{ distinguishedName = ('CN={0},CN=Computers,DC=contoso,DC=com' -f $Identity) }
    }
    throw ('Cannot find an object with identity: {0}' -f $Identity)
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
    param([object[]] $Accounts)
    $script:syncAccounts = @($Accounts)
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
        Rows        = $ecs
        Stats       = $st
        Unread      = [int] $st.ChecksUnread
        Denominator = [int] (Get-mdiCoverageDenominator -Measured $st.ChecksTotal -Unread $st.ChecksUnread)
        Percent     = [int] [math]::Floor((Get-mdiCoveragePercent -Passed $st.ChecksPassed -Measured $st.ChecksTotal -Unread $st.ChecksUnread))
        Verdict     = (Test-mdiReadinessResult -ReportData $report 3>$null)
        Issues      = @(Get-mdiIssueList -Statistics $st -ReportData $report)
    }
}

Write-Host 'An Entra Connect server that could not be read is not one that is gone' -ForegroundColor Cyan

$bothResolve = Get-Facts @(
    (New-SyncAccount 'AAD_1a2b3c' ($parsable -f 'AADC01')),
    (New-SyncAccount 'AAD_4d5e6f' ($parsable -f 'AADC02'))
)
$oneResolves = Get-Facts @( (New-SyncAccount 'AAD_1a2b3c' ($parsable -f 'AADC01')) )
$partialLoss = Get-Facts @(
    (New-SyncAccount 'AAD_1a2b3c' ($parsable -f 'AADC01')),
    (New-SyncAccount 'AAD_4d5e6f' $germanUnparsable)
)

# --- The defect ------------------------------------------------------------------------------------
Assert-That 'losing a sync server does not raise the score' (
    $partialLoss.Percent -le $bothResolve.Percent
) ("both=$($bothResolve.Percent)% partial=$($partialLoss.Percent)%")
Assert-That 'a partial loss scores the same as the whole pair being unread' (
    $partialLoss.Percent -eq $bothResolve.Percent -and $partialLoss.Denominator -eq $bothResolve.Denominator
) ("both=$($bothResolve.Percent)%/den$($bothResolve.Denominator) partial=$($partialLoss.Percent)%/den$($partialLoss.Denominator)")
Assert-That 'a partial loss is NOT identical to a genuine single-server estate' (
    $partialLoss.Denominator -ne $oneResolves.Denominator -or $partialLoss.Percent -ne $oneResolves.Percent
) ("partial=$($partialLoss.Percent)%/den$($partialLoss.Denominator) single=$($oneResolves.Percent)%/den$($oneResolves.Denominator)")
Assert-That 'the unread server is charged' ($partialLoss.Unread -eq $bothResolve.Unread) (
    "both unread=$($bothResolve.Unread) partial unread=$($partialLoss.Unread)")

# The row exists, names the account, and is a placeholder rather than a counted machine.
$lostRow = @($partialLoss.Rows | Where-Object { Test-mdiServerIsPlaceholder -Server $_ })
Assert-That 'a row is emitted for the sync account that could not be read' ($lostRow.Count -eq 1) ("got $($lostRow.Count)")
Assert-That 'the row names the offending sync account' (
    $lostRow.Count -eq 1 -and [string] $lostRow[0].FQDN -like '*AAD_4d5e6f*'
) ("got '$(if ($lostRow.Count) { [string] $lostRow[0].FQDN })'")
Assert-That 'the row explains the locale cause and the workaround' (
    $lostRow.Count -eq 1 -and
    [string] $lostRow[0].Comment -like '*not in English*' -and
    [string] $lostRow[0].Comment -like '*-EntraConnectServer*'
) ("got '$(if ($lostRow.Count) { [string] $lostRow[0].Comment })'")
Assert-That 'the run is not READY while a sync server is unverified' (-not $partialLoss.Verdict) "verdict=$($partialLoss.Verdict)"

# --- The distinction that must NOT be collapsed ----------------------------------------------------
# The description parsed, but the computer it names is absent from the directory. The directory gave a
# positive answer, so this stays a warning: charging it would invent a permanent failure out of a
# stale sync account for a decommissioned host.
$staleAccount = Get-Facts @(
    (New-SyncAccount 'AAD_1a2b3c' ($parsable -f 'AADC01')),
    (New-SyncAccount 'AAD_9z8y7x' ($parsable -f 'AADC-GONE'))
)
Assert-That 'a sync account naming an ABSENT computer is not charged' (
    $staleAccount.Denominator -eq $oneResolves.Denominator -and $staleAccount.Percent -eq $oneResolves.Percent
) ("stale=$($staleAccount.Percent)%/den$($staleAccount.Denominator) single=$($oneResolves.Percent)%/den$($oneResolves.Denominator)")
Assert-That 'a sync account naming an ABSENT computer emits no placeholder row' (
    @($staleAccount.Rows | Where-Object { Test-mdiServerIsPlaceholder -Server $_ }).Count -eq 0
) 'a placeholder was invented for a decommissioned host'

# --- Guards that must not weaken -------------------------------------------------------------------
# A domain with no Entra Connect at all stays completely silent.
$none = Get-Facts @()
Assert-That 'a domain with no Entra Connect emits no rows' (@($none.Rows).Count -eq 0) ("got $(@($none.Rows).Count)")
Assert-That 'a domain with no Entra Connect still scores 100%' ($none.Percent -eq 100) ("got $($none.Percent)%")
Assert-That 'a domain with no Entra Connect is still READY' ($none.Verdict) "verdict=$($none.Verdict)"
Assert-That 'a domain with no Entra Connect raises no findings' (@($none.Issues).Count -eq 0) ("got $(@($none.Issues).Count)")

# The pre-existing TOTAL-loss path is unchanged: one account, unparsable, still yields exactly one
# placeholder - not two, which is what a careless per-account fix would produce.
$totalLoss = Get-Facts @( (New-SyncAccount 'AAD_4d5e6f' $germanUnparsable) )
$totalRows = @($totalLoss.Rows | Where-Object { Test-mdiServerIsPlaceholder -Server $_ })
Assert-That 'total loss still emits exactly one placeholder, not one per path' ($totalRows.Count -eq 1) ("got $($totalRows.Count)")
# The SHAPE is pinned, not the exact string. The guard above - one placeholder per LOST ACCOUNT,
# never one per code path - is the substantive one and is unchanged. This one used to require the
# unnamed 'Entra Connect (not identified) - contoso.com', which silently also pinned the defect
# beside it: a TOTAL loss emitted one row for the whole domain while a PARTIAL loss emitted one per
# lost account, so losing MORE of the estate scored HIGHER (3-of-3 scored 92% against 81% for
# 2-of-3). Now that a total loss is charged per account like a partial one, the row NAMES the
# account that was lost, which is what the operator needs in order to go and read it.
Assert-That 'total loss identifies the account it could not read' (
    $totalRows.Count -eq 1 -and [string] $totalRows[0].FQDN -like 'Entra Connect (not identified)*contoso.com' -and
    [string] $totalRows[0].FQDN -match 'AAD_4d5e6f'
) ("got '$(if ($totalRows.Count) { [string] $totalRows[0].FQDN })'")

# Every account resolving is unaffected.
Assert-That 'a fully discovered pair emits no placeholders' (
    @($bothResolve.Rows | Where-Object { Test-mdiServerIsPlaceholder -Server $_ }).Count -eq 0
) 'a placeholder appeared on a fully discovered estate'
Assert-That 'a fully discovered pair reports both servers' (@($bothResolve.Rows).Count -eq 2) ("got $(@($bothResolve.Rows).Count)")

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
