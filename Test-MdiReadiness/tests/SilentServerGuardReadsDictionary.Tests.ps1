<#
    The "nothing was measured" guard must work for the Details shape the producers actually store.

    Get-mdiIssueList raises a row for a server that was REACHED but produced no evidence at all -
    otherwise the report renders NOT READY, "Action required", exit 1, and an issue table with ZERO
    rows: the operator is told to act, told nothing failed, and given nothing to act on.

    The guard asked "is there any detail" with $srv.Details.PSObject.Properties. Every producer stores
    Details as [ordered]@{}, and PSObject.Properties on a dictionary enumerates the dictionary's .NET
    MEMBERS, never its entries. Measured on the shipped functions:

        [ordered]@{} EMPTY      -> 7 non-null "properties" (Count, IsReadOnly, Keys, Values,
                                   IsFixedSize, SyncRoot, IsSynchronized)
        [ordered]@{} populated  -> the same 7
        [PSCustomObject]@{}     -> 0

    So $hasAnyDetail was $true for every server the guard could ever be asked about, and the
    protection was DEAD for the entire estate. The identical fixture built as a [PSCustomObject]
    produced the row correctly, which is what made the two shapes disagree about the same server -
    they are interchangeable everywhere else in this file, which is what Get-mdiDetailEntry exists for.

    Asserted through the REAL Get-mdiIssueList, not by re-testing the expression.

    The controls carry equal weight: a server whose Details genuinely CONTAIN something must NOT gain a
    spurious "nothing was measured" row, or the fix would put a false High finding on every real
    server whose measurements live in detail records rather than boolean checks - which is exactly the
    case the guard's own comment says it must not break.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
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

$domainAuditing = [PSCustomObject]@{
    Domain                 = 'contoso.com'
    ObjectAuditing         = [PSCustomObject]@{ isObjectAuditingOk = $true }
    ExchangeAuditing       = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    AdfsAuditing           = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DeletedObjects         = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured = $true; ExchangeAuditingMeasured = $true
    AdfsAuditingMeasured   = $true; DeletedObjectsMeasured = $true
}

function New-Rep {
    param($DetailsObj, [hashtable] $Checks = @{})
    $srv = [PSCustomObject]@{
        FQDN        = 'dc1.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false; Comment = ''
        Details     = $DetailsObj
    }
    foreach ($k in $Checks.Keys) { Add-Member -InputObject $srv -MemberType NoteProperty -Name ([string] $k) -Value $Checks[$k] }
    [PSCustomObject]@{
        Domain              = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers   = @($srv); CAServers = @(); EntraConnectServers = @()
        DomainAuditing      = @($domainAuditing); ForestDiscovery = $null
        DomainSchemaVersion = [PSCustomObject]@{ details = 'x'; schemaVersion = 1 }
        LdapPlanGapDomains  = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
    }
}
function Get-SilentRowCount {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    @(@(Get-mdiIssueList -Statistics $stats -ReportData $Report) | Where-Object { $_.Issue -match 'returned no readiness checks' }).Count
}

'[the defect] the shape the producers actually store must be handled'
# Every producer builds Details as [ordered]@{} - Get-mdiDomainControllerReadiness, Get-mdiCAReadiness
# and Get-mdiEntraConnectReadiness all do, and Merge-mdiServerByFqdn preserves the type.
$dictEmpty = New-Rep ([ordered]@{})
Assert-That 'an empty ordered-dictionary Details raises the row' ((Get-SilentRowCount $dictEmpty) -eq 1) "(rows=$(Get-SilentRowCount $dictEmpty))"

'[shape agreement] the two Details shapes must not disagree about the same server'
$psEmpty = New-Rep ([PSCustomObject]@{})
Assert-That 'a PSCustomObject Details still raises the row' ((Get-SilentRowCount $psEmpty) -eq 1) "(rows=$(Get-SilentRowCount $psEmpty))"
Assert-That 'both shapes agree' ((Get-SilentRowCount $dictEmpty) -eq (Get-SilentRowCount $psEmpty)) "(dict=$(Get-SilentRowCount $dictEmpty) pso=$(Get-SilentRowCount $psEmpty))"

'[the mechanism] a dictionary must not be probed with PSObject.Properties'
# Pinned directly, because this is the trap the fix exists to remove and it is invisible in the output
# of any single case: an EMPTY dictionary reports exactly as many "properties" as a populated one.
$emptyDict = [ordered]@{}
$fullDict = [ordered]@{ TimeSyncDetails = 'x' }
$emptyMembers = @($emptyDict.PSObject.Properties | Where-Object { $null -ne $_.Value }).Count
$fullMembers = @($fullDict.PSObject.Properties | Where-Object { $null -ne $_.Value }).Count
Assert-That 'PSObject.Properties cannot tell an empty dictionary from a full one' ($emptyMembers -eq $fullMembers) "(empty=$emptyMembers full=$fullMembers)"
Assert-That 'the shared reader CAN tell them apart' (
    @(Get-mdiDetailEntry -Details $emptyDict).Count -eq 0 -and @(Get-mdiDetailEntry -Details $fullDict).Count -eq 1
) "(empty=$(@(Get-mdiDetailEntry -Details $emptyDict).Count) full=$(@(Get-mdiDetailEntry -Details $fullDict).Count))"

'[detail-only control] a server measured ONLY through detail records must NOT be called unmeasured'
# The guard's own comment requires this: port probe results and sensor v3 blockers are detail records,
# and a server can legitimately carry no boolean check properties while still having been measured.
$detailOnly = [ordered]@{}
$detailOnly.Add('RequiredPortsDetails', [PSCustomObject]@{ Results = @([PSCustomObject]@{ Port = 389; Success = $true }) })
Assert-That 'a detail-only server raises no "nothing was measured" row' ((Get-SilentRowCount (New-Rep $detailOnly)) -eq 0) "(rows=$(Get-SilentRowCount (New-Rep $detailOnly)))"

'[checked-server control] a server with real boolean checks must NOT gain a spurious row'
$checked = New-Rep ([ordered]@{}) @{ AdvancedAuditing = $true; NtlmAuditing = $true }
Assert-That 'a server with checks raises no "nothing was measured" row' ((Get-SilentRowCount $checked) -eq 0) "(rows=$(Get-SilentRowCount $checked))"

'[null control] a server carrying no Details object at all is still handled'
Assert-That 'a null Details raises the row rather than throwing' ((Get-SilentRowCount (New-Rep $null)) -eq 1) "(rows=$(Get-SilentRowCount (New-Rep $null)))"

'[no orphan verdict] a NOT-READY verdict must never render an empty issue table'
# The whole point of the guard, stated as the invariant an operator actually experiences.
foreach ($case in @(@{ N = 'ordered'; R = $dictEmpty }, @{ N = 'pscustomobject'; R = $psEmpty }, @{ N = 'null'; R = (New-Rep $null) })) {
    $stats = Get-mdiReportStatistics -ReportData $case.R
    $ready = Test-mdiReadinessResult -ReportData $case.R
    $count = @(Get-mdiIssueList -Statistics $stats -ReportData $case.R).Count
    Assert-That ("the $($case.N) case is not ready AND has something to act on") ((-not $ready) -and ($count -gt 0)) "(ready=$ready issues=$count)"
}

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
