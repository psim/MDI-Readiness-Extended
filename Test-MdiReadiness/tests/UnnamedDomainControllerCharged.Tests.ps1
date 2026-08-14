<#
    A domain controller the directory could not NAME is still part of the estate.

    Resolve-mdiDomainController discards any record that carries neither a dNSHostName nor a Name, and
    said so only with a console warning. Nothing carried the loss into the report, so a PARTIAL loss
    was invisible - and worse than invisible, it flattered the result:

        4 DC records, 2 of them nameless   ->  2 servers, 4 of 6 checks, 66%
        a genuinely 2-DC domain            ->  2 servers, 4 of 6 checks, 66%   (identical)
        the same 4-DC estate, all named    ->  4 servers, 4 of 8 checks, 50%

    So discovering LESS of the estate raised the headline from 50% to 66%, and the two reports were
    programmatically indistinguishable. This is the campaign's defining defect class - a gap that
    leaves the numerator AND the denominator - on the object the script's own comments call the most
    damaging one to lose.

    The lost records are now carried as placeholder rows: charged as unread checks, visible in the
    report, and kept out of the server COUNT (there is no machine to count - only a record).

    Invariants pinned here, all behavioural:
      1. a partial loss is charged, so the score does NOT rise for losing domain controllers
      2. the partial-loss report is no longer identical to a genuinely smaller domain
      3. the loss is visible in the rendered report, not only on the console
      4. the placeholders are not counted as servers
      5. an explicitly supplied -DomainController list never invents placeholders
      6. a domain with no nameless records is completely unaffected
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

# The shape Get-ADDomainController returns. A record with neither HostName nor Name is the one that
# gets discarded; the script's own comment records it as measured in the field (a replication gap, an
# RODC whose dNSHostName has not populated, a partially-created object).
$script:dcRecords = @()
Set-Item -Path function:script:Get-ADDomainController -Value {
    param($Server, $Filter, $ErrorAction)
    $script:dcRecords
}
# LDAP is the fallback and must not rescue the test's ADWS shapes.
Set-Item -Path function:script:Get-mdiDomainControllerFromLdap -Value { param($Domain) @() }
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName) [PSCustomObject]@{ Reachable = $false; Method = 'stubbed' }
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value { param($ComputerName, $KnownAddress) @('10.0.0.1') }
Set-Item -Path function:script:Get-ADObject -Value {
    param($Identity, $Server, $Filter, $Properties, $ErrorAction, [switch] $IncludeDeletedObjects) $null
}

function New-DcRecord {
    param([string] $HostName, [string] $Name)
    [PSCustomObject]@{ HostName = $HostName; Name = $Name; IPv4Address = '10.0.0.1' }
}

function Get-Facts {
    param([object[]] $Records, [string[]] $Supplied)
    $script:dcRecords = @($Records)
    $dcs = if ($Supplied) {
        @(Get-mdiDomainControllerReadiness -Domain 'contoso.com' -DomainController $Supplied 3>$null 4>$null)
    } else {
        @(Get-mdiDomainControllerReadiness -Domain 'contoso.com' 3>$null 4>$null)
    }
    $report = [PSCustomObject]@{
        DomainControllers   = @($dcs)
        CAServers           = @()
        EntraConnectServers = @()
        DomainsInScope      = @('contoso.com')
        ForestDiscovery     = [PSCustomObject]@{ Complete = $true }
    }
    $st = Get-mdiReportStatistics -ReportData $report
    [PSCustomObject]@{
        Rows         = $dcs
        Stats        = $st
        TotalServers = [int] $st.TotalServers
        Unread       = [int] $st.ChecksUnread
        Denominator  = [int] (Get-mdiCoverageDenominator -Measured $st.ChecksTotal -Unread $st.ChecksUnread)
        Percent      = [int] [math]::Floor((Get-mdiCoveragePercent -Passed $st.ChecksPassed -Measured $st.ChecksTotal -Unread $st.ChecksUnread))
        Html         = (Get-mdiOverviewHtml -Statistics $st -ReportData $report | Out-String)
        Issues       = @(Get-mdiIssueList -Statistics $st -ReportData $report)
    }
}

Write-Host 'A domain controller that could not be named is still part of the estate' -ForegroundColor Cyan

$fourNamed = @(1..4 | ForEach-Object { New-DcRecord -HostName ('dc{0}.contoso.com' -f $_) -Name ('dc{0}' -f $_) })
$twoNamed = @(1..2 | ForEach-Object { New-DcRecord -HostName ('dc{0}.contoso.com' -f $_) -Name ('dc{0}' -f $_) })
$twoNamedTwoBlank = @($twoNamed) + @(1..2 | ForEach-Object { New-DcRecord -HostName '' -Name '' })

$whole = Get-Facts -Records $fourNamed        # the TRUE 4-DC estate
$partial = Get-Facts -Records $twoNamedTwoBlank # the same estate, 2 records unnameable
$small = Get-Facts -Records $twoNamed          # a genuinely 2-DC domain

# 1. The score must not IMPROVE for having discovered less of the estate.
Assert-That 'losing two domain controllers does not raise the score' (
    $partial.Percent -le $whole.Percent
) ("whole=$($whole.Percent)% partial=$($partial.Percent)%")
Assert-That 'a partial loss scores the same as the whole estate being unmeasured' (
    $partial.Percent -eq $whole.Percent -and $partial.Denominator -eq $whole.Denominator
) ("whole=$($whole.Percent)%/den$($whole.Denominator) partial=$($partial.Percent)%/den$($partial.Denominator)")
Assert-That 'the lost records are charged as unread checks' (
    $partial.Unread -eq $whole.Unread
) ("whole unread=$($whole.Unread) partial unread=$($partial.Unread)")

# 2. It must be distinguishable from a domain that really is smaller. This is the assertion that
#    fails the moment the loss stops being charged, because the two collapse onto each other.
Assert-That 'a partial loss is NOT identical to a genuinely smaller domain' (
    $partial.Denominator -ne $small.Denominator -or $partial.Percent -ne $small.Percent
) ("partial=$($partial.Percent)%/den$($partial.Denominator) small=$($small.Percent)%/den$($small.Denominator)")

# 3. Visible in the report, not only on the console.
Assert-That 'the rendered report mentions the unnamed domain controllers' (
    $partial.Html -match 'not named'
) 'the loss appears nowhere in the report'
$lostIssues = @($partial.Issues | Where-Object { [string] $_.Server -like '*not named*' })
Assert-That 'each lost record raises a finding' ($lostIssues.Count -eq 2) ("got $($lostIssues.Count)")
Assert-That 'the finding explains the cause and the workaround' (
    $lostIssues.Count -ge 1 -and
    [string] $lostIssues[0].Issue -like '*dNSHostName*' -and
    [string] $lostIssues[0].Issue -like '*-DomainController*'
) ("got '$(if ($lostIssues.Count) { [string] $lostIssues[0].Issue })'")

# 4. A record is not a machine: the server COUNT stays at what was actually found.
Assert-That 'placeholders are not counted as servers' ($partial.TotalServers -eq 2) ("got $($partial.TotalServers)")
$phScores = @($partial.Stats.ServerScores | Where-Object { $_.FQDN -like '*not named*' })
Assert-That 'each placeholder scores as Unmeasured' (
    $phScores.Count -eq 2 -and @($phScores | Where-Object { [string] $_.Kind -eq 'Unmeasured' }).Count -eq 2
) ("got $($phScores.Count) row(s)")

# 5. An explicitly supplied list is authoritative - nothing was enumerated, so nothing can be lost.
$supplied = Get-Facts -Records $twoNamedTwoBlank -Supplied @('dc1.contoso.com', 'dc2.contoso.com')
Assert-That 'a supplied -DomainController list invents no placeholders' (
    @($supplied.Rows | Where-Object { [string] $_.FQDN -like '*not named*' }).Count -eq 0
) 'placeholders were emitted for a supplied list'

# 6. The ordinary case is untouched.
Assert-That 'a domain with no unnamed records emits no placeholders' (
    @($small.Rows | Where-Object { [string] $_.FQDN -like '*not named*' }).Count -eq 0
) 'placeholders appeared on a clean domain'
Assert-That 'a clean domain still reports its own servers' ($small.TotalServers -eq 2) ("got $($small.TotalServers)")
Assert-That 'the whole estate still reports four servers' ($whole.TotalServers -eq 4) ("got $($whole.TotalServers)")

# 7. The count travels on the resolver result, which is where the report reads it from.
$script:dcRecords = @($twoNamedTwoBlank)
$resolved = Resolve-mdiDomainController -Domain 'contoso.com' 3>$null
Assert-That 'the resolver reports how many records it could not name' (
    [int] $resolved.Unnamed -eq 2
) ("got '$([string] $resolved.Unnamed)'")
$script:dcRecords = @($twoNamed)
$resolvedClean = Resolve-mdiDomainController -Domain 'contoso.com' 3>$null
Assert-That 'the resolver reports zero when every record is named' (
    [int] $resolvedClean.Unnamed -eq 0
) ("got '$([string] $resolvedClean.Unnamed)'")

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
