# Two false greens, both of which made the report LOOK BETTER the more went wrong.
#
# 1. A scan that aborted part way keeps the checks that ran and never adds the rest, so the missed
#    ones are ABSENT rather than 'N/A'. Absent properties cannot be enumerated, so nothing counted as
#    unread and the report read "servers fully ready 2/2 - all checks passed" for a server whose scan
#    had died.
# 2. [PSCustomObject] only special-cases Hashtable and OrderedDictionary. Any other IDictionary cast
#    that way yields an object whose properties are Comparer/Count/Keys/Values, with every entry lost -
#    so a required port measured as refused arrived with no Requirement and was not counted as a
#    required failure.

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

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}
function New-Report {
    param($Servers)
    [PSCustomObject]@{ DomainControllers = @($Servers); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com')
    }
}
function Get-ReadyCount {
    param($Stats)
    @($Stats.ServerScores | Where-Object { $_.Total -gt 0 -and $_.Failed -eq 0 -and $_.Unread -eq 0 }).Count
}

'[aborted scan] a server whose scan died is not a server that passed'
$complete = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
    OSVersion = $true; NPCAP = $true; SensorVersion = $true; PowerScheme = $true
    Details = [PSCustomObject]@{}
}
# Mirrors the catch in Get-mdiDomainControllerReadiness: only the checks that ran are present.
$aborted = [PSCustomObject]@{ FQDN = 'dc2.contoso.com'; Unreachable = $false; PartialFailure = $true
    Comment = 'Testing stopped early: The RPC server is unavailable'
    OSVersion = $true; NPCAP = $true
    Details = [PSCustomObject]@{}
}
Assert-That 'the aborted scan reports at least one check unread' (
    (Get-mdiUnreadCheckCount -Server $aborted) -ge 1) "(got $(Get-mdiUnreadCheckCount -Server $aborted))"
Assert-That 'a completed scan still reports nothing unread' (
    (Get-mdiUnreadCheckCount -Server $complete) -eq 0) "(got $(Get-mdiUnreadCheckCount -Server $complete))"

$stats = Get-mdiReportStatistics -ReportData (New-Report @($complete, $aborted))
Assert-That 'only the completed server is counted fully ready' ((Get-ReadyCount $stats) -eq 1) "(got $(Get-ReadyCount $stats))"
Assert-That 'the report does not claim every check was read' ($stats.ChecksUnread -ge 1) "(got $($stats.ChecksUnread))"
Assert-That 'so it cannot claim all checks passed' ($stats.ChecksUnread -gt 0) "(unread $($stats.ChecksUnread))"
# The per-server score must carry the gap too, or a bar renders 2/2 = 100% for a server that died.
$abortedScore = @($stats.ServerScores | Where-Object { $_.FQDN -eq 'dc2.contoso.com' })[0]
Assert-That 'the aborted server score carries the unread gap' ($abortedScore.Unread -ge 1) "(got $($abortedScore.Unread))"
Assert-That 'and it is therefore excluded from the ready predicate' (
    -not ($abortedScore.Total -gt 0 -and $abortedScore.Failed -eq 0 -and $abortedScore.Unread -eq 0))

# An aborted scan that ALSO stored a genuine 'N/A' must not be double counted.
$abortedWithNa = [PSCustomObject]@{ FQDN = 'dc3.contoso.com'; Unreachable = $false; PartialFailure = $true
    OSVersion = $true; NPCAP = 'N/A'; Details = [PSCustomObject]@{}
}
Assert-That 'an aborted scan with a real N/A counts that one, not one extra' (
    (Get-mdiUnreadCheckCount -Server $abortedWithNa) -eq 1) "(got $(Get-mdiUnreadCheckCount -Server $abortedWithNa))"

'[dictionary shapes] every IDictionary keeps its entries'
$entries = [ordered]@{ Group = 'NNR'; Protocol = 'TCP'; Port = 3389; Target = 'wks1.contoso.com'
    TargetIP = '10.0.0.5'; Requirement = 'Required'; Success = $false
    Detail = 'Connection refused'; Applicable = $true
}
$shapes = @(
    @{ Name = 'Hashtable'; Make = { $d = @{}; foreach ($k in $entries.Keys) { $d[$k] = $entries[$k] }; $d } }
    @{ Name = 'OrderedDictionary'; Make = { $entries } }
    @{ Name = 'Generic.Dictionary'; Make = { $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'; foreach ($k in $entries.Keys) { $d[$k] = $entries[$k] }; $d } }
    @{ Name = 'SortedDictionary'; Make = { $d = New-Object 'System.Collections.Generic.SortedDictionary[string,object]'; foreach ($k in $entries.Keys) { $d[$k] = $entries[$k] }; $d } }
    @{ Name = 'ListDictionary'; Make = { $d = New-Object System.Collections.Specialized.ListDictionary; foreach ($k in $entries.Keys) { $d[$k] = $entries[$k] }; $d } }
    @{ Name = 'HybridDictionary'; Make = { $d = New-Object System.Collections.Specialized.HybridDictionary; foreach ($k in $entries.Keys) { $d[$k] = $entries[$k] }; $d } }
)
foreach ($shape in $shapes) {
    $dict = & $shape.Make
    $server = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; OSVersion = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
                FailedRequired = @(); NnrFailedTargets = @(); Results = @($dict)
            }
        }
    }
    $records = @(Get-mdiPortResultRecord -Server @($server))
    $required = @($records | Where-Object { [string] $_.Requirement -eq 'Required' })
    Assert-That "$($shape.Name): the record keeps its Requirement" ($required.Count -eq 1) "(got $($required.Count))"
    Assert-That "$($shape.Name): the record keeps its Detail" (
        [string] @($records)[0].Detail -eq 'Connection refused') "(got '$(@($records)[0].Detail)')"
    Assert-That "$($shape.Name): the measured failure is not read as success" (
        (ConvertTo-mdiBoolean @($records)[0].Success) -eq $false)
    Assert-That "$($shape.Name): no .NET plumbing leaked in as a property" (
        @($records)[0].PSObject.Properties.Name -notcontains 'IsReadOnly')
    # The whole point: the blocked required port must keep the server out of the ready count.
    $shapeStats = Get-mdiReportStatistics -ReportData (New-Report $server)
    Assert-That "$($shape.Name): the server is not counted ready" ((Get-ReadyCount $shapeStats) -eq 0)
}

'[ConvertTo-mdiRecordObject] leaves everything else alone'
Assert-That 'null stays null' ($null -eq (ConvertTo-mdiRecordObject -Value $null))
$obj = [PSCustomObject]@{ Requirement = 'Required'; Detail = 'x' }
Assert-That 'a PSCustomObject is returned unchanged' ([object]::ReferenceEquals($obj, (ConvertTo-mdiRecordObject -Value $obj)))
Assert-That 'a string is returned unchanged' ((ConvertTo-mdiRecordObject -Value 'abc') -eq 'abc')
$converted = ConvertTo-mdiRecordObject -Value (& $shapes[2].Make)
Assert-That 'a converted dictionary exposes its entries as properties' (
    ([string] $converted.Requirement -eq 'Required') -and ([string] $converted.Detail -eq 'Connection refused'))

'[dictionary shapes] an entry whose NAME collides with a member'
# PowerShell resolves a property name against a dictionary's ENTRIES first, so $dict.Keys on a record
# carrying an entry called 'Keys' returns that entry's value rather than the key collection. The
# conversion then produced one nonsense property and dropped Port, Requirement, Success and Detail -
# a required port measured as refused raised no issue at all.
$hostile = @{}
$hostile['Keys'] = 'this is an entry, not the key collection'
$hostile['Group'] = 'LDAP'; $hostile['Protocol'] = 'TCP'; $hostile['Port'] = 389
$hostile['Target'] = 'dc2.contoso.com'; $hostile['TargetIP'] = '10.0.0.2'
$hostile['Requirement'] = 'Required'; $hostile['Success'] = $false
$hostile['Detail'] = 'Connection refused'; $hostile['Applicable'] = $true
$converted = ConvertTo-mdiRecordObject -Value $hostile
Assert-That "an entry named 'Keys' does not destroy the record" (
    [string] $converted.Requirement -eq 'Required' -and [string] $converted.Port -eq '389'
) "(Requirement='$($converted.Requirement)' Port='$($converted.Port)')"
Assert-That "  ...and the colliding entry is preserved too" ([string] $converted.Keys -match 'not the key collection')

$hostileServer = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; OSVersion = $true
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
            FailedRequired = @(); NnrFailedTargets = @(); Results = @($hostile)
        }
    }
}
$hostileStats = Get-mdiReportStatistics -ReportData (New-Report $hostileServer)
Assert-That 'the refused required port still keeps the server out of ready' (
    (Get-ReadyCount $hostileStats) -eq 0)
Assert-That 'and it still raises an issue' (
    @(Get-mdiIssueList -Statistics $hostileStats -ReportData (New-Report $hostileServer)).Count -ge 1)

# Names that are reserved on PSObject make the cast throw, which would kill the whole report rather
# than lose one record. They are carried under a prefixed name instead of being dropped.
foreach ($reserved in 'PSObject', 'PSBase', 'PSTypeNames', 'PSAdapted', 'PSExtended') {
    $t = @{}
    $t[$reserved] = 'hostile'
    $t['Requirement'] = 'Required'; $t['Success'] = $false; $t['Port'] = 389
    $threw = $false
    $out = $null
    try { $out = ConvertTo-mdiRecordObject -Value $t } catch { $threw = $true }
    Assert-That "an entry named '$reserved' does not throw" (-not $threw)
    if (-not $threw) {
        Assert-That "  ...and the record survives it" ([string] $out.Requirement -eq 'Required')
        Assert-That "  ...and the colliding value is not lost" ([string] $out.('_' + $reserved) -eq 'hostile')
    }
}
foreach ($benign in 'Count', 'Length', 'Item', 'Values', 'SyncRoot', 'IsReadOnly') {
    $t = @{}
    $t[$benign] = 'x'
    $t['Requirement'] = 'Required'; $t['Success'] = $false
    $out = ConvertTo-mdiRecordObject -Value $t
    Assert-That "an entry named '$benign' keeps the record intact" ([string] $out.Requirement -eq 'Required')
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
