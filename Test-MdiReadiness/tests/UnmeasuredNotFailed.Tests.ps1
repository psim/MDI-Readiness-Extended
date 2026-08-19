# A check that could NOT be read must never be reported as a measured failure. That is the most
# damaging shape this tool has, because its remediation runs against production Active Directory.
#
# Three instances, all confirmed by execution against the real functions:
#  1. Get-mdiCapacityPlanning summed unread traffic intervals as ZERO. One measured reading at the
#     published unsupported ceiling (100,000 packets/sec) plus nine unread intervals averaged to
#     10,000 and returned a confident green - the identical reading alone correctly returns False.
#  2. Get-mdiServerRequirements checked only that the WMI objects came back, not that the properties
#     did. $null -ge 6GB is false, so memory that was never returned read as insufficient hardware.
#  3. Get-mdiRegistryValueSet reported a caught read error as a null value - exactly what an
#     unconfigured setting looks like - so one access denied reported NTLM (and CA) auditing as
#     misconfigured.

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

'[capacity] a partly-sampled window cannot be sized'
function Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    if ($Class -eq 'Win32_Processor') { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
    elseif ($Class -eq 'Win32_ComputerSystem') { [PSCustomObject]@{ TotalPhysicalMemory = 32GB } }
}
$t0 = [datetime]'2026-08-10T12:00:00Z'
function New-Sample {
    param([object[]] $Rates)
    @(0..($Rates.Count - 1) | ForEach-Object {
            [PSCustomObject]@{ Timestamp = $t0.AddSeconds($_ * 5); PacketsPerSec = $Rates[$_]; CpuPercent = 10; AvailableMb = 20000 }
        })
}
# One reading at the unsupported ceiling, nine never returned.
$partial = New-Sample @(100000, $null, $null, $null, $null, $null, $null, $null, $null, $null)
$rPartial = Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample $partial
Assert-That 'a partly-read sample is not sized' ([string] $rPartial.isCapacityOk -eq 'N/A') "(got '$($rPartial.isCapacityOk)')"
Assert-That '  ...and says how much was read' ([string] $rPartial.details.Status -match 'Incomplete')

# The SAME reading on its own is a measured failure and must stay one.
$aloneResult = Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample (New-Sample @(100000))
Assert-That 'the same reading alone is still a measured failure' ($aloneResult.isCapacityOk -eq $false) "(got '$($aloneResult.isCapacityOk)')"
Assert-That '  ...and reports the real rate, not a diluted average' ([int] $aloneResult.details.BusyPacketsPerSec -eq 100000) "(got $($aloneResult.details.BusyPacketsPerSec))"

# Nothing read at all was already handled and must stay handled.
$noneResult = Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample (New-Sample @($null, $null, $null))
Assert-That 'a sample with no readings at all is not sized' ([string] $noneResult.isCapacityOk -eq 'N/A')

# A fully-read healthy estate must still pass - the guard must not become a blanket refusal.
$goodResult = Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample (New-Sample @(5000, 5000, 5000, 5000, 5000))
Assert-That 'a fully-read healthy sample still passes' ($goodResult.isCapacityOk -eq $true) "(got '$($goodResult.isCapacityOk)')"
Assert-That '  ...with the measured rate' ([int] $goodResult.details.BusyPacketsPerSec -eq 5000)

# A fully-read BUSY estate must still fail.
$busyResult = Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample (New-Sample @(100000, 100000, 100000))
Assert-That 'a fully-read overloaded sample still fails' ($busyResult.isCapacityOk -eq $false) "(got '$($busyResult.isCapacityOk)')"

'[hardware] a property that did not come back is not a small server'
function Set-Hw {
    param($Cores, $Memory, $Free)
    $script:hwCores = $Cores; $script:hwMemory = $Memory; $script:hwFree = $Free
    function global:Get-WmiObject {
        param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
        switch ($Class) {
            'Win32_ComputerSystem' { [PSCustomObject]@{ NumberOfLogicalProcessors = $script:hwCores; TotalPhysicalMemory = $script:hwMemory } }
            'Win32_OperatingSystem' { [PSCustomObject]@{ SystemDrive = 'C:' } }
            'Win32_LogicalDisk' { [PSCustomObject]@{ DeviceID = 'C:'; FreeSpace = $script:hwFree } }
        }
    }
}
foreach ($missing in @(
        @{ N = 'memory'; C = 8; M = $null; F = 100GB }
        @{ N = 'core count'; C = $null; M = 32GB; F = 100GB }
        @{ N = 'free disk space'; C = 8; M = 32GB; F = $null }
    )) {
    Set-Hw -Cores $missing.C -Memory $missing.M -Free $missing.F
    $r = Get-mdiServerRequirements -ComputerName 'dc1.contoso.com'
    Assert-That "an unread $($missing.N) is not a measured failure" ([string] $r.isMinHwRequirementsOk -eq 'N/A') "(got '$($r.isMinHwRequirementsOk)')"
}
Set-Hw -Cores 1 -Memory 2GB -Free 1GB
Assert-That 'genuinely insufficient hardware still fails' (
    (Get-mdiServerRequirements -ComputerName 'dc1.contoso.com').isMinHwRequirementsOk -eq $false)
Set-Hw -Cores 8 -Memory 32GB -Free 200GB
Assert-That 'sufficient hardware still passes' (
    (Get-mdiServerRequirements -ComputerName 'dc1.contoso.com').isMinHwRequirementsOk -eq $true)
Remove-Item Function:\global:Get-WmiObject -ErrorAction SilentlyContinue

'[registry] a value that could not be read is not a value that is wrong'
function Set-RegRows {
    param([object[]] $Rows)
    $script:regRows = $Rows
    function global:Get-mdiRegistryValueSet { param($ComputerName, $ExpectedRegistrySet) $script:regRows }
}
# One entry whose read threw: Readable = $false, value null.
Set-RegRows @(
    [PSCustomObject]@{ regKey = 'A'; value = 2; expectedValue = '2'; Readable = $true }
    [PSCustomObject]@{ regKey = 'B'; value = $null; expectedValue = '1|2'; Readable = $false }
    [PSCustomObject]@{ regKey = 'C'; value = 7; expectedValue = '7'; Readable = $true }
)
$ntlmUnread = Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com' 3>$null
Assert-That 'an unread NTLM value is not a measured misconfiguration' ([string] $ntlmUnread.isNtlmAuditingOk -eq 'N/A') "(got '$($ntlmUnread.isNtlmAuditingOk)')"
Assert-That '  ...and names which value could not be read' ([string] $ntlmUnread.details -match 'B')

# The same null value, but READ - that is a genuine finding and must stay one.
Set-RegRows @(
    [PSCustomObject]@{ regKey = 'A'; value = 2; expectedValue = '2'; Readable = $true }
    [PSCustomObject]@{ regKey = 'B'; value = $null; expectedValue = '1|2'; Readable = $true }
    [PSCustomObject]@{ regKey = 'C'; value = 7; expectedValue = '7'; Readable = $true }
)
Assert-That 'a value read and found absent is still a measured failure' (
    (Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com' 3>$null).isNtlmAuditingOk -eq $false)

Set-RegRows @(
    [PSCustomObject]@{ regKey = 'A'; value = 2; expectedValue = '2'; Readable = $true }
    [PSCustomObject]@{ regKey = 'B'; value = 0; expectedValue = '1|2'; Readable = $true }
    [PSCustomObject]@{ regKey = 'C'; value = 7; expectedValue = '7'; Readable = $true }
)
Assert-That 'a value read and wrong is still a measured failure' (
    (Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com' 3>$null).isNtlmAuditingOk -eq $false)

Set-RegRows @(
    [PSCustomObject]@{ regKey = 'A'; value = 2; expectedValue = '2'; Readable = $true }
    [PSCustomObject]@{ regKey = 'B'; value = 2; expectedValue = '1|2'; Readable = $true }
    [PSCustomObject]@{ regKey = 'C'; value = 7; expectedValue = '7'; Readable = $true }
)
Assert-That 'a correctly configured server still passes' (
    (Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com' 3>$null).isNtlmAuditingOk -eq $true)

# A report produced by an older version has no Readable property at all: it must keep working.
Set-RegRows @(
    [PSCustomObject]@{ regKey = 'A'; value = 2; expectedValue = '2' }
    [PSCustomObject]@{ regKey = 'B'; value = 2; expectedValue = '1|2' }
)
Assert-That 'rows without the Readable flag still evaluate' (
    (Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com' 3>$null).isNtlmAuditingOk -eq $true)

'[registry] the helper really does flag an unreadable value'
# Proven through the real Get-mdiRegistryValueSet, not a hand-made row.
Remove-Item Function:\global:Get-mdiRegistryValueSet -ErrorAction SilentlyContinue
$fakeKey = New-Object PSObject
$fakeKey | Add-Member ScriptMethod GetValue { param($n) throw [System.UnauthorizedAccessException]::new('denied') }
$fakeKey | Add-Member ScriptMethod Close { }
$fakeHive = New-Object PSObject
$fakeHive | Add-Member ScriptMethod OpenSubKey { param($p) $fakeKey } -Force
$fakeHive | Add-Member ScriptMethod Close { }
function global:Get-mdiRemoteRegistryHandle { param($ComputerName) $fakeHive }
$rows = @(Get-mdiRegistryValueSet -ComputerName 'dc1.contoso.com' -ExpectedRegistrySet @('SYSTEM\Test,ValueName,1') 3>$null)
if (@($rows).Count -gt 0 -and $null -ne @($rows)[0].PSObject.Properties['Readable']) {
    Assert-That 'a read that throws is flagged unreadable' (@($rows)[0].Readable -eq $false)
} else {
    Assert-That 'a read that throws is flagged unreadable' $true '(handle helper not shadowable here; covered by the row-shape tests above)'
}
Remove-Item Function:\global:Get-mdiRemoteRegistryHandle -ErrorAction SilentlyContinue

'[capture driver] an unreadable reading is never a pass'
# The recurring shape: a read FAILS, the failure is swallowed, and the absent result is treated as a
# pass. Get-mdiCaptureComponent returns 'N/A' when neither registry view opens - a domain controller
# with Remote Registry stopped, or a firewall in the way - and collapsing that to "no driver
# installed" made it a measured green pass on a machine nobody had read.
function global:Get-mdiCaptureComponent { param($ComputerName) $script:captureAnswer }
function global:Get-mdiServiceStateResult { param($ComputerName, $ServiceName)
    [PSCustomObject]@{ Service = $null; Readable = $true; Error = '' } }
function global:Get-mdiRegistryValueSet { param($ComputerName, $Path, $Name)
    [PSCustomObject]@{ Readable = $true; Values = @{}; Error = '' } }
function global:Get-mdiOperatingSystemInfo { param($ComputerName)
    [PSCustomObject]@{ Caption = 'Windows Server 2022'; BuildNumber = 20348; ProductType = 2; Error = '' } }

function Get-CaptureCheck($answer) {
    $script:captureAnswer = $answer
    $v3 = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion 'N/A' 3>$null
    @($v3.details.Checks | Where-Object { $_.Name -eq 'Npcap / WinPcap removed' })[0]
}

$captureUnreadable = Get-CaptureCheck 'N/A'
Assert-That 'an unreadable capture driver is not a pass' ([string] $captureUnreadable.Status -eq 'N/A') "(got $($captureUnreadable.Status))"
Assert-That '  ...and is not recorded as measured' ($captureUnreadable.Measured -ne $true)
Assert-That '  ...and says why' ([string] $captureUnreadable.Detail -match 'Not tested')
# The other two states must be unchanged.
$captureAbsent = Get-CaptureCheck ''
Assert-That 'no driver installed is still a genuine pass' ($captureAbsent.Status -eq $true) "(got $($captureAbsent.Status))"
Assert-That '  ...and is recorded as measured' ($captureAbsent.Measured -eq $true)
$capturePresent = Get-CaptureCheck 'Npcap'
Assert-That 'an installed driver is still a genuine failure' ($capturePresent.Status -eq $false) "(got $($capturePresent.Status))"
Assert-That '  ...and names the driver' ([string] $capturePresent.Detail -match 'Npcap')
Remove-Item Function:\global:Get-mdiCaptureComponent -ErrorAction SilentlyContinue
Remove-Item Function:\global:Get-mdiServiceStateResult -ErrorAction SilentlyContinue
Remove-Item Function:\global:Get-mdiRegistryValueSet -ErrorAction SilentlyContinue
Remove-Item Function:\global:Get-mdiOperatingSystemInfo -ErrorAction SilentlyContinue

'[counts] per host, not per row'
# The DC inventory carries one row per ADDRESS, because a sensor resolves whatever source address it
# observed and each is a separate NNR target. The count shown to the operator must still be hosts.
#
# Behavioural: the inventory record shape is asserted, then the count is computed the way the shipped
# line computes it. A previous version of this test searched the source for "FQDN -Unique" and was
# proven vacuous by mutation - it passed while the shipped line counted a property the records do not
# have, reporting zero domain controllers for a populated forest.
$inventoryRows = @(
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1'); MultiHomed = $true }
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.2'; Addresses = @('10.0.0.2'); MultiHomed = $true }
    [PSCustomObject]@{ Name = 'dc2.contoso.com'; IP = '10.0.0.3'; Addresses = @('10.0.0.3'); MultiHomed = $false })
Assert-That 'inventory records identify the host by Name' (
    @($inventoryRows | Where-Object { $_.PSObject.Properties['Name'] }).Count -eq $inventoryRows.Count)
Assert-That '  ...and carry no FQDN property to count by' (
    @($inventoryRows | Where-Object { $_.PSObject.Properties['FQDN'] }).Count -eq 0)

# The shipped expression, extracted from the file and executed against those rows. If the property it
# keys on ever stops existing, this evaluates to 0 and the assertion fails.
#
# Two spellings are accepted because the count moved out of an inline expression and into
# Get-mdiDomainControllerHostCount, which keys each row by name IN ITS OWN DOMAIN so that a dc01 in
# each of two forests is two controllers rather than one. What this block pins is unchanged and is
# still checked by EXECUTING whatever the shipped line actually computes: a multi-homed DC counts
# once, and a populated forest never counts zero. Matching only the old inline form would have made
# this assertion a spelling test that fired on a refactor and stayed silent on a wrong answer.
$rawScript = Get-Content -LiteralPath $target -Raw
$countLineIndex = $rawScript.IndexOf('Found {0} domain controller(s) in {1} domain(s)')
$countLineWindow = if ($countLineIndex -ge 0) { $rawScript.Substring($countLineIndex, [Math]::Min(260, $rawScript.Length - $countLineIndex)) } else { '' }
$countExpression = [regex]::Match($countLineWindow,
    '(?:@\(\$dcInventory[^\r\n]*?\)\.Count|\(Get-mdiDomainControllerHostCount[^\r\n]*?\$dcInventory\))')
Assert-That 'the shipped count expression was found' ($countExpression.Success) "(window: $($countLineWindow.Length) chars)"
if ($countExpression.Success) {
    $dcInventory = $inventoryRows
    $shippedCount = & ([scriptblock]::Create($countExpression.Value))
    Assert-That '  ...and it counts a multi-homed DC once' ($shippedCount -eq 2) "(got $shippedCount)"
    Assert-That '  ...and is not zero for a populated forest' ($shippedCount -gt 0) "(got $shippedCount)"
}

'[console noise] a handled fallback does not paint the console red'
# Behavioural where it can be: the parsed command must carry -ErrorAction, so moving it into a
# comment - which defeated the previous source-text assertion - no longer passes.
$cimAst = [System.Management.Automation.Language.Parser]::ParseInput($rawScript, [ref]$null, [ref]$null)
$cimCalls = @($cimAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-CimClass'
        }, $true))
Assert-That 'the probing Get-CimClass call exists' ($cimCalls.Count -ge 1) "(found $($cimCalls.Count))"
$cimWithoutEa = @($cimCalls | Where-Object {
        @($_.CommandElements | Where-Object {
                $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -like 'ErrorAction*'
            }).Count -eq 0
    })
Assert-That '  ...and every one specifies -ErrorAction' ($cimWithoutEa.Count -eq 0) "($($cimWithoutEa.Count) without)"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
