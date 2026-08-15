# The capacity check's evidence could contradict the check itself, on the same report.
#
# The merge finds the check a detail explains by stripping 'Details' from the detail's name:
# SensorHealthDetails explains SensorHealth. Twenty-eight of the twenty-nine detail producers in the
# script follow that convention exactly. One does not - the check is stored as 'CapacitySufficient'
# while its evidence is stored as 'CapacityDetails', so stripping yields 'Capacity', a property that
# does not exist on the server.
#
# Every caller therefore read $null, Get-mdiCheckDetailRank scored BOTH roles identically, and the
# rank comparison it feeds became inert for that one check. The tie-break fell through to an ordinal
# string comparison, which picks whichever explanation happens to sort first - and
# "The server has enough resources..." sorts before "Unable to read the processor information...".
#
# Measured on the shipped producers and the shipped merge, one host discovered twice (once with a
# trailing dot, which the merge correctly folds into one host) with one pass sized and one pass unable
# to read WMI:
#
#   merged check    CapacitySufficient = N/A
#   issues table    High - "Capacity Sufficient could not be read on this server, so its state is unknown"
#   capacity tab    "Yes (estimate)" - "The server has enough resources for a sensor v2.x at 1200 busy packets/sec"
#   disclosure      the "N of M server(s) could not be sampled" callout SILENTLY DISAPPEARED
#
# Both discovery orders. A reader who opens the Capacity tab is shown a sizing verdict for a machine
# nobody managed to measure, and the warning that would have told them so is gone.
#
# This is exactly the contradiction Get-mdiCheckDetailRank was written to remove - its own doc comment
# describes the identical failure for TimeSync - it simply never applied to this one check.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

'[detail naming] every detail resolves to a check the server actually carries'
# The convention is load-bearing: the merge uses it to decide which role's explanation wins. Assert it
# for every detail the script produces, so a future producer that breaks the convention is caught here
# rather than by a contradicting report.
$producedPairs = @(
    @{ Detail = 'ServerRequirementsDetails'; Check = 'ServerRequirements' }
    @{ Detail = 'PowerSettingsDetails'; Check = 'PowerSettings' }
    @{ Detail = 'AdvancedAuditingDetails'; Check = 'AdvancedAuditing' }
    @{ Detail = 'AdvancedAuditingCADetails'; Check = 'AdvancedAuditingCA' }
    @{ Detail = 'AdvancedAuditingEntraConnectDetails'; Check = 'AdvancedAuditingEntraConnect' }
    @{ Detail = 'NtlmAuditingDetails'; Check = 'NtlmAuditing' }
    @{ Detail = 'RootCertificatesDetails'; Check = 'RootCertificates' }
    @{ Detail = 'OSVersionDetails'; Check = 'OSVersion' }
    @{ Detail = 'RequiredPortsDetails'; Check = 'RequiredPorts' }
    @{ Detail = 'SensorHealthDetails'; Check = 'SensorHealth' }
    @{ Detail = 'TimeSyncDetails'; Check = 'TimeSync' }
    @{ Detail = 'SensorV3ReadyDetails'; Check = 'SensorV3Ready' }
    @{ Detail = 'CAAuditingDetails'; Check = 'CAAuditing' }
    # The one exception, and the reason the resolver exists.
    @{ Detail = 'CapacityDetails'; Check = 'CapacitySufficient' }
)
foreach ($pair in $producedPairs) {
    Assert-That ("{0} resolves to {1}" -f $pair.Detail, $pair.Check) (
        (Get-mdiDetailCheckName -DetailName $pair.Detail) -eq $pair.Check
    ) "(got '$(Get-mdiDetailCheckName -DetailName $pair.Detail)')"
}
# The resolved name must be a name the check enumerator recognises, or the rank is scored on $null.
foreach ($pair in $producedPairs) {
    $resolved = Get-mdiDetailCheckName -DetailName $pair.Detail
    Assert-That ("{0} resolves to a real check name" -f $pair.Detail) (
        $resolved -in $script:mdiCheckName
    ) "(resolved '$resolved' is not in the check-name list)"
}

''
'[detail rank] an unread role displaces a passing role for the CAPACITY check'
# The whole point of the rank: the merged VALUE is pessimistic, so the merged EXPLANATION must come
# from the role that drove it.
function New-CapacityRow {
    param($Fqdn, $Sized)
    $details = if ($Sized) {
        [PSCustomObject]@{ CapacityDetails = [PSCustomObject]@{
                FullBusyWindow = $true; SampleSeconds = 30; Band = 'Medium'
                SensorSupported = 'Yes (estimate)'; HyperThreaded = $false
                Detail = 'The server has enough resources for a sensor v2.x at 1200 busy packets/sec' } }
    } else {
        [PSCustomObject]@{ CapacityDetails = [PSCustomObject]@{
                FullBusyWindow = 'N/A'; SampleSeconds = 0; Band = $null
                SensorSupported = 'Missing core data'; HyperThreaded = $null
                Detail = 'Unable to read the processor information over WMI' } }
    }
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        CapacitySufficient = $(if ($Sized) { $true } else { 'N/A' })
        Details = $details
    }
}

function Merge-Pair {
    param($First, $Second)
    @(Merge-mdiServerByFqdn -Server @($First, $Second))[0]
}

# 'dc1.contoso.com' and 'dc1.contoso.com.' are the same host - the merge folds the trailing dot.
$sizedFirst = Merge-Pair (New-CapacityRow 'dc1.contoso.com' $true) (New-CapacityRow 'dc1.contoso.com.' $false)
$failedFirst = Merge-Pair (New-CapacityRow 'dc1.contoso.com' $false) (New-CapacityRow 'dc1.contoso.com.' $true)

foreach ($case in @(@{ Name = 'sized role first'; Row = $sizedFirst }, @{ Name = 'unread role first'; Row = $failedFirst })) {
    $row = $case.Row
    Assert-That ("{0}: the merged check is pessimistic (N/A)" -f $case.Name) (
        [string] $row.CapacitySufficient -eq 'N/A'
    ) "(got '$($row.CapacitySufficient)')"
    # THE DEFECT: the explanation must follow the value, not contradict it.
    Assert-That ("{0}: the detail follows the value, not the passing role" -f $case.Name) (
        [string] $row.Details.CapacityDetails.Detail -match 'Unable to read'
    ) "(got '$($row.Details.CapacityDetails.Detail)')"
    Assert-That ("{0}: the sizing verdict is not claimed for an unmeasured host" -f $case.Name) (
        [string] $row.Details.CapacityDetails.SensorSupported -ne 'Yes (estimate)'
    ) "(got '$($row.Details.CapacityDetails.SensorSupported)')"
    # FullBusyWindow drives the "could not be sampled" disclosure on the capacity tab: a [bool] means
    # sampled, anything else means not. The passing role's $true was hiding the whole callout.
    Assert-That ("{0}: the host is not counted as sampled" -f $case.Name) (
        $row.Details.CapacityDetails.FullBusyWindow -isnot [bool]
    ) "(FullBusyWindow = '$($row.Details.CapacityDetails.FullBusyWindow)')"
}

''
'[detail rank] the capacity tab discloses the unsampled host'
function Get-CapacityTab {
    param($Row)
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com'); DomainControllers = @($Row)
        CAServers = @(); EntraConnectServers = @(); DomainAuditing = @(); SkippedAreas = @()
    }
    (Get-mdiCapacityHtml -Server @($Row) 3>$null | Out-String)
}
foreach ($case in @(@{ Name = 'sized role first'; Row = $sizedFirst }, @{ Name = 'unread role first'; Row = $failedFirst })) {
    $tab = Get-CapacityTab $case.Row
    Assert-That ("{0}: the 'could not be sampled' disclosure is present" -f $case.Name) (
        $tab -match 'could not be sampled'
    ) '(disclosure absent)'
    Assert-That ("{0}: the tab does not claim a sizing verdict" -f $case.Name) (
        $tab -notmatch 'Yes \(estimate\)'
    ) '(tab still shows a sizing verdict)'
}

''
'[detail rank] the unmerged baselines are unchanged'
# The fix must not disturb a host that was only discovered once, in either state.
$onlySized = @(Merge-mdiServerByFqdn -Server @((New-CapacityRow 'dc1.contoso.com' $true)))[0]
Assert-That 'a sized host keeps its sizing verdict' ([string] $onlySized.Details.CapacityDetails.SensorSupported -eq 'Yes (estimate)') "(got '$($onlySized.Details.CapacityDetails.SensorSupported)')"
Assert-That '  ...and its check still passes' ([string] $onlySized.CapacitySufficient -eq 'True') "(got '$($onlySized.CapacitySufficient)')"
Assert-That '  ...and its tab carries no false disclosure' ((Get-CapacityTab $onlySized) -notmatch 'could not be sampled')

$onlyFailed = @(Merge-mdiServerByFqdn -Server @((New-CapacityRow 'dc1.contoso.com' $false)))[0]
Assert-That 'an unread host keeps its unread explanation' ([string] $onlyFailed.Details.CapacityDetails.Detail -match 'Unable to read') "(got '$($onlyFailed.Details.CapacityDetails.Detail)')"
Assert-That '  ...and its check is still N/A' ([string] $onlyFailed.CapacitySufficient -eq 'N/A') "(got '$($onlyFailed.CapacitySufficient)')"

''
'[detail rank] the other checks were never broken and still are not'
# TimeSync is the control the rank function documents. Same shape, same expectation.
function New-TimeRow {
    param($Fqdn, $Ok)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
        TimeSync = $(if ($Ok) { $true } else { 'N/A' })
        Details = [PSCustomObject]@{ TimeSyncDetails = [PSCustomObject]@{
                Detail = $(if ($Ok) { 'Clock is within 3 second(s) of this computer' } else { 'Unable to read the time service over WMI' }) } }
    }
}
$timeMerged = @(Merge-mdiServerByFqdn -Server @((New-TimeRow 'dc1.contoso.com' $true), (New-TimeRow 'dc1.contoso.com.' $false)))[0]
Assert-That 'TimeSync merges pessimistically' ([string] $timeMerged.TimeSync -eq 'N/A') "(got '$($timeMerged.TimeSync)')"
Assert-That 'TimeSync detail follows its value' ([string] $timeMerged.Details.TimeSyncDetails.Detail -match 'Unable to read') "(got '$($timeMerged.Details.TimeSyncDetails.Detail)')"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
