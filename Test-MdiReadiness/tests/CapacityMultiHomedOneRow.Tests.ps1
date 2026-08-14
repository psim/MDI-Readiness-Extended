# [w83] The Capacity Planning table must show ONE row per PHYSICAL domain controller.
#
# Get-mdiDomainControllerInventory emits ONE ENTRY PER ADDRESS - a multi-homed domain controller has
# to be probed on each NIC, because NNR resolves whatever source address the sensor observed - so
# $ReportData.DomainControllers legitimately holds the same physical server once per IP.
#
# Every table on the report page is fed $allServers, which Merge-mdiServerByFqdn has collapsed to one
# row per host. The Capacity Planning table was the ONLY section still handed the raw per-IP list, so
# a dual-homed domain controller rendered TWO IDENTICAL rows and the summary above the table counted
# it twice - "2 of 2 server(s) could not be sampled" for a single machine - disagreeing with the
# server count every other table on the same page derived from the same fact. Sizing is read off this
# table, so the duplicate also doubled the apparent number of sensors to budget for.
#
# Proven against the REAL renderer: Set-MdiReadinessReport is called and the HTML it writes to disk is
# read back. See MDI-AB\live\w83-capacity-multihomed.ps1 for the probe that found it.

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

function New-CapSrv {
    param(
        [string] $Fqdn,
        [string] $Ip,
        [bool] $MultiHomed = $false,
        [object] $FullBusyWindow = $null
    )
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; IP = $Ip; MultiHomed = $MultiHomed
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true; RequiredPorts = $true
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() }
            CapacityDetails      = [PSCustomObject]@{
                Status            = 'Unknown'
                Detail            = 'Unable to read the processor information over WMI'
                FullBusyWindow    = $FullBusyWindow
                SampleSeconds     = 0
                BusyPacketsPerSec = $null
            }
        }
    }
}
function New-Audit {
    param([string] $Domain)
    [PSCustomObject]@{
        Domain = $Domain
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; NotAsserted = $false }; DeletedObjectsMeasured = $true
    }
}

function Get-ReportHtml {
    param([object[]] $DomainControllers, [object[]] $CAServers = @(), [object[]] $EntraConnectServers = @())
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com')
        LdapPlanGapDomains = @()
        DomainControllers = $DomainControllers
        CAServers = $CAServers; EntraConnectServers = $EntraConnectServers
        DomainAuditing = @(New-Audit -Domain 'contoso.com')
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        SkippedAreas = @()
    }
    $outDir = Join-Path $env:TEMP ('mdicap-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $outDir -Force)
    try {
        Set-MdiReadinessReport -Domain 'contoso.com' -Path $outDir -ReportData $report -SkipTrend 3>$null 4>$null 6>$null | Out-Null
        $file = @(Get-ChildItem $outDir -Filter '*.html' -File)
        if ($file.Count -eq 0) { return $null }
        [IO.File]::ReadAllText($file[0].FullName)
    } finally { Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue }
}

# The capacity table is isolated by its own header, which no other table on the page carries, so the
# assertions below cannot be satisfied by rows belonging to the server or ports tables.
function Get-CapacitySection {
    param([string] $Html)
    $marker = '<th>Busy packets/sec</th>'
    $start = $Html.IndexOf($marker)
    if ($start -lt 0) { return '' }
    $end = $Html.IndexOf('</table>', $start)
    if ($end -lt 0) { return '' }
    $Html.Substring($start, $end - $start)
}
function Get-CapacityRowCount {
    param([string] $Html, [string] $Fqdn)
    @([regex]::Matches((Get-CapacitySection -Html $Html), '<td class="mono">' + [regex]::Escape($Fqdn) + '</td>')).Count
}
function Get-CapacityRowTotal {
    param([string] $Html)
    @([regex]::Matches((Get-CapacitySection -Html $Html), '<td class="mono">')).Count
}
function Get-NotSampledClaim {
    param([string] $Html)
    $m = [regex]::Match($Html, '<b>(\d+) of (\d+) server\(s\) could not be sampled\.</b>')
    if ($m.Success) { $m.Groups[1].Value + ' of ' + $m.Groups[2].Value } else { '' }
}

'[w83] a dual-homed domain controller is ONE server in the capacity table'
# The defect. Two inventory entries, one physical host.
$dual = @(
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.1' -MultiHomed $true),
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.2' -MultiHomed $true)
)
$html = Get-ReportHtml -DomainControllers $dual
Assert-That 'the renderer wrote an HTML report' ($null -ne $html -and $html.Length -gt 500) "(length $(if ($html) { $html.Length } else { 0 }))"
Assert-That 'the capacity table was rendered' ((Get-CapacitySection -Html $html).Length -gt 0)
Assert-That 'the dual-homed DC has exactly ONE capacity row' ((Get-CapacityRowCount -Html $html -Fqdn 'dc1.contoso.com') -eq 1) `
    "(rows: $(Get-CapacityRowCount -Html $html -Fqdn 'dc1.contoso.com'))"
Assert-That 'the capacity table holds exactly one row in total' ((Get-CapacityRowTotal -Html $html) -eq 1) `
    "(rows: $(Get-CapacityRowTotal -Html $html))"

'[w83] the summary counts PHYSICAL servers, not addresses'
# The denominator is the sentence an operator budgets sensors from.
Assert-That 'the not-sampled summary reads "1 of 1", not "2 of 2"' ((Get-NotSampledClaim -Html $html) -eq '1 of 1') `
    "(claim: '$(Get-NotSampledClaim -Html $html)')"

'[w83] a triple-homed domain controller is still ONE server'
$triple = @(
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.1' -MultiHomed $true),
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.2' -MultiHomed $true),
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.3' -MultiHomed $true)
)
$htmlTriple = Get-ReportHtml -DomainControllers $triple
Assert-That 'a triple-homed DC has exactly ONE capacity row' ((Get-CapacityRowCount -Html $htmlTriple -Fqdn 'dc1.contoso.com') -eq 1) `
    "(rows: $(Get-CapacityRowCount -Html $htmlTriple -Fqdn 'dc1.contoso.com'))"
Assert-That 'the triple-homed summary reads "1 of 1"' ((Get-NotSampledClaim -Html $htmlTriple) -eq '1 of 1') `
    "(claim: '$(Get-NotSampledClaim -Html $htmlTriple)')"

'[w83] the trailing-dot and casing spellings of one host are still one server'
# Merge-mdiServerByFqdn keys on a trimmed, lowercased, dot-stripped name. The capacity table must
# inherit that, or the same host discovered under two spellings splits back into two rows.
$spelling = @(
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.1' -MultiHomed $true),
    (New-CapSrv -Fqdn 'DC1.CONTOSO.COM.' -Ip '10.0.0.2' -MultiHomed $true)
)
$htmlSpelling = Get-ReportHtml -DomainControllers $spelling
Assert-That 'two spellings of one host produce one capacity row' ((Get-CapacityRowTotal -Html $htmlSpelling) -eq 1) `
    "(rows: $(Get-CapacityRowTotal -Html $htmlSpelling))"

'[w83] CONTROL - genuinely distinct domain controllers are NOT collapsed'
# Without this, deleting the table body altogether would satisfy everything above.
$distinct = @(
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.1'),
    (New-CapSrv -Fqdn 'dc2.contoso.com' -Ip '10.0.0.2')
)
$htmlDistinct = Get-ReportHtml -DomainControllers $distinct
Assert-That 'two distinct DCs still produce two capacity rows' ((Get-CapacityRowTotal -Html $htmlDistinct) -eq 2) `
    "(rows: $(Get-CapacityRowTotal -Html $htmlDistinct))"
Assert-That '  the first distinct DC is present' ((Get-CapacityRowCount -Html $htmlDistinct -Fqdn 'dc1.contoso.com') -eq 1)
Assert-That '  the second distinct DC is present' ((Get-CapacityRowCount -Html $htmlDistinct -Fqdn 'dc2.contoso.com') -eq 1)
Assert-That 'the distinct-DC summary reads "2 of 2"' ((Get-NotSampledClaim -Html $htmlDistinct) -eq '2 of 2') `
    "(claim: '$(Get-NotSampledClaim -Html $htmlDistinct)')"

'[w83] CONTROL - capacity is a DOMAIN CONTROLLER question'
# Guards the shape of the fix as well as its effect. Merging the whole $allServers list would also
# de-duplicate the addresses, so the assertions above would pass - but it would drag certification
# authority and Entra Connect hosts, which have no sensor to size, into a table that reports on
# domain controllers and whose summary sentence counts "server(s)" for sizing.
$ca = New-CapSrv -Fqdn 'ca1.contoso.com' -Ip '10.0.0.9'
$entra = New-CapSrv -Fqdn 'aadc1.contoso.com' -Ip '10.0.0.8'
$htmlRoles = Get-ReportHtml -DomainControllers $dual -CAServers @($ca) -EntraConnectServers @($entra)
Assert-That 'the dual-homed DC is still one row when other roles exist' ((Get-CapacityRowCount -Html $htmlRoles -Fqdn 'dc1.contoso.com') -eq 1) `
    "(rows: $(Get-CapacityRowCount -Html $htmlRoles -Fqdn 'dc1.contoso.com'))"
Assert-That 'a certification authority host is NOT in the capacity table' ((Get-CapacityRowCount -Html $htmlRoles -Fqdn 'ca1.contoso.com') -eq 0) `
    "(rows: $(Get-CapacityRowCount -Html $htmlRoles -Fqdn 'ca1.contoso.com'))"
Assert-That 'an Entra Connect host is NOT in the capacity table' ((Get-CapacityRowCount -Html $htmlRoles -Fqdn 'aadc1.contoso.com') -eq 0) `
    "(rows: $(Get-CapacityRowCount -Html $htmlRoles -Fqdn 'aadc1.contoso.com'))"
Assert-That 'the capacity table still holds exactly one row in total' ((Get-CapacityRowTotal -Html $htmlRoles) -eq 1) `
    "(rows: $(Get-CapacityRowTotal -Html $htmlRoles))"
Assert-That 'the summary still counts one domain controller' ((Get-NotSampledClaim -Html $htmlRoles) -eq '1 of 1') `
    "(claim: '$(Get-NotSampledClaim -Html $htmlRoles)')"

'[w83] CONTROL - a sampled dual-homed DC is also one row'
# The de-duplication must not depend on which capacity branch the row takes.
$dualSampled = @(
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.1' -MultiHomed $true -FullBusyWindow $true),
    (New-CapSrv -Fqdn 'dc1.contoso.com' -Ip '10.0.0.2' -MultiHomed $true -FullBusyWindow $true)
)
$htmlSampled = Get-ReportHtml -DomainControllers $dualSampled
Assert-That 'a sampled dual-homed DC has exactly one capacity row' ((Get-CapacityRowTotal -Html $htmlSampled) -eq 1) `
    "(rows: $(Get-CapacityRowTotal -Html $htmlSampled))"
Assert-That 'a fully sampled run raises no "could not be sampled" claim' ((Get-NotSampledClaim -Html $htmlSampled) -eq '') `
    "(claim: '$(Get-NotSampledClaim -Html $htmlSampled)')"

'[w83] CONTROL - capacity planning that was never run still says so'
# The un-run message must survive the merge, or the fix would hide the opt-in notice.
$noCap = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; IP = '10.0.0.1'; MultiHomed = $false
    Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
    NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true; RequiredPorts = $true
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
}
$htmlNoCap = Get-ReportHtml -DomainControllers @($noCap)
Assert-That 'a run without -CapacityPlanning still shows the opt-in notice' `
    ($htmlNoCap -match 'Capacity planning was not run') `
    '(the un-run notice is missing)'

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
