# An unread performance counter was rendered as a measured zero.
#
#  w49-F3  The traffic sampler reads two supplementary counters alongside the packet rate: CPU
#          utilisation and available memory. It guarded only on whether WMI returned an INSTANCE:
#
#              if ($cpu)    { $cpuPercent  = [double] $cpu.PercentProcessorTime }
#              if ($memory) { $availableMb = [double] $memory.AvailableMBytes }
#
#          WMI can return an instance whose counter property is empty - a provider that partly
#          failed, a hardened server, a counter class present but not populated - and [double]
#          $null is 0, not "unknown". The aggregation in Get-mdiCapacityPlanning selects readings
#          with "$null -ne $_.CpuPercent", so that manufactured zero passed as a real sample and
#          the capacity table stated:
#
#              0% avg / 0% max        (CPU used)
#              0.00 GB min            (RAM free)
#
#          about a server where neither counter was ever read. The two failures point in opposite
#          directions, which is what makes this worse than a blank: 0% CPU reads as an idle server
#          with headroom to spare, and 0.00 GB free reads as a server that has exhausted its
#          memory. One invites a false green, the other a false red, and both describe a
#          measurement that does not exist.
#
#          Correct behaviour is the one the report already implements for a genuinely absent
#          counter: leave the value null so the cell renders 'n/a'.
#
# These tests are BEHAVIOURAL. They drive the real Get-mdiCapacityPlanning with sample rows and
# assert on what it returns and on what the report cell expression produces, so they fail if the
# manufactured zero comes back regardless of how the sampler is written.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

# Hardware inventory stub. Script scope so it shadows the cmdlet inside Get-mdiCapacityPlanning; a
# global function would not take effect there and every assertion below would test nothing.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_Processor'      { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
        'Win32_ComputerSystem' { [PSCustomObject]@{ TotalPhysicalMemory = 32GB } }
        default                { $null }
    }
}

$now = Get-Date
function New-Rows {
    param($Cpu, $Mem)
    @(
        [PSCustomObject]@{ Timestamp = $now.AddMinutes(-15); PacketsPerSec = 2500.0; CpuPercent = $Cpu; AvailableMb = $Mem }
        [PSCustomObject]@{ Timestamp = $now.AddMinutes(-10); PacketsPerSec = 2500.0; CpuPercent = $Cpu; AvailableMb = $Mem }
        [PSCustomObject]@{ Timestamp = $now.AddMinutes(-5);  PacketsPerSec = 2500.0; CpuPercent = $Cpu; AvailableMb = $Mem }
        [PSCustomObject]@{ Timestamp = $now;                 PacketsPerSec = 2500.0; CpuPercent = $Cpu; AvailableMb = $Mem }
    )
}
# The exact expressions the capacity table uses to render the two cells.
function Get-CpuCell { param($D) if ($null -ne $D.AvgCpuPercent) { '{0}% avg / {1}% max' -f [int] $D.AvgCpuPercent, [int] $D.MaxCpuPercent } else { 'n/a' } }
function Get-RamCell { param($D) if ($null -ne $D.MinAvailableRamGb) { '{0:N2} GB min' -f $D.MinAvailableRamGb } else { 'n/a' } }

'[counters] the sampler does not manufacture a zero from a null property'
# BEHAVIOURAL: drive the real sampler scriptblock with WMI returning counter INSTANCES whose values
# are null. Invoked with & so it runs in the script session state and sees the script-scoped stub -
# this is the same way Get-mdiTrafficSample calls it. A global stub would not be seen and every
# assertion here would silently test nothing.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch -Wildcard ($Class) {
        '*Network*'            { [PSCustomObject]@{ Name = 'Ethernet'; PacketsPersec = 1500 } }
        'CPUCLASS'             { [PSCustomObject]@{ Name = '_Total'; PercentProcessorTime = $null } }
        'MEMCLASS'             { [PSCustomObject]@{ AvailableMBytes = $null } }
        'Win32_Processor'      { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
        'Win32_ComputerSystem' { [PSCustomObject]@{ TotalPhysicalMemory = 32GB } }
        default                { $null }
    }
}
$live = & $script:mdiTrafficSampleScript 'dc-live.contoso.com' 1 0 'Win32_PerfFormattedData_Tcpip_NetworkInterface' 'CPUCLASS' 'MEMCLASS' 'isatap|Teredo|Loopback'
$liveRows = @($live | Where-Object { $_ })
Assert-That 'the sampler still returns a packet reading' ($liveRows.Count -gt 0 -and [double] $liveRows[0].PacketsPerSec -eq 1500) "(got $($liveRows.Count) row(s))"
Assert-That 'a null CPU counter is not recorded as 0' ($liveRows.Count -gt 0 -and $null -eq $liveRows[0].CpuPercent) "(got '$($liveRows[0].CpuPercent)')"
Assert-That 'a null memory counter is not recorded as 0' ($liveRows.Count -gt 0 -and $null -eq $liveRows[0].AvailableMb) "(got '$($liveRows[0].AvailableMb)')"

# Positive control on the same path: real counter values must still be recorded.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch -Wildcard ($Class) {
        '*Network*'            { [PSCustomObject]@{ Name = 'Ethernet'; PacketsPersec = 1500 } }
        'CPUCLASS'             { [PSCustomObject]@{ Name = '_Total'; PercentProcessorTime = 37 } }
        'MEMCLASS'             { [PSCustomObject]@{ AvailableMBytes = 2048 } }
        'Win32_Processor'      { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
        'Win32_ComputerSystem' { [PSCustomObject]@{ TotalPhysicalMemory = 32GB } }
        default                { $null }
    }
}
$live2 = @((& $script:mdiTrafficSampleScript 'dc-live2.contoso.com' 1 0 'Win32_PerfFormattedData_Tcpip_NetworkInterface' 'CPUCLASS' 'MEMCLASS' 'isatap|Teredo|Loopback') | Where-Object { $_ })
Assert-That 'a real CPU counter is recorded' ($live2.Count -gt 0 -and [double] $live2[0].CpuPercent -eq 37) "(got '$($live2[0].CpuPercent)')"
Assert-That 'a real memory counter is recorded' ($live2.Count -gt 0 -and [double] $live2[0].AvailableMb -eq 2048) "(got '$($live2[0].AvailableMb)')"

# Restore the hardware-only stub for the aggregation tests below.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_Processor'      { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
        'Win32_ComputerSystem' { [PSCustomObject]@{ TotalPhysicalMemory = 32GB } }
        default                { $null }
    }
}

# The source guard must test the property, not just the instance. Kept alongside the behavioural
# assertions above so a reader of a failure can see immediately which guard was weakened.
$sourceText = Get-Content -LiteralPath $target -Raw
Assert-That 'the sampler guards on the CPU property' ($sourceText -match '\$null -ne \$cpu\.PercentProcessorTime')
Assert-That 'the sampler guards on the memory property' ($sourceText -match '\$null -ne \$memory\.AvailableMBytes')

'[counters] an unread counter reaches the report as unknown, not as zero'
$unread = Get-mdiCapacityPlanning -ComputerName 'dc-unread.contoso.com' -TrafficSample (New-Rows -Cpu $null -Mem $null)
$du = $unread.details
Assert-That 'average CPU is unknown' ($null -eq $du.AvgCpuPercent) "(got '$($du.AvgCpuPercent)')"
Assert-That 'peak CPU is unknown' ($null -eq $du.MaxCpuPercent) "(got '$($du.MaxCpuPercent)')"
Assert-That 'minimum free memory is unknown' ($null -eq $du.MinAvailableRamGb) "(got '$($du.MinAvailableRamGb)')"
Assert-That 'the CPU cell reads n/a' ((Get-CpuCell $du) -eq 'n/a') "(got '$(Get-CpuCell $du)')"
Assert-That 'the memory cell reads n/a' ((Get-RamCell $du) -eq 'n/a') "(got '$(Get-RamCell $du)')"
# The whole point of the supplementary counters being supplementary: their absence must not stop
# the server being sized from the packet rate, which was measured.
Assert-That 'the server is still sized from the packet rate' ([string] $unread.isCapacityOk -ne 'N/A') "(got '$($unread.isCapacityOk)')"

'[counters] a genuine zero is still reported as a measurement'
# The opposite error would be just as wrong: a server that really is idle measured 0% and that is a
# reading. Suppressing it would hide a real observation behind 'n/a'.
$realZero = Get-mdiCapacityPlanning -ComputerName 'dc-idle.contoso.com' -TrafficSample (New-Rows -Cpu 0.0 -Mem 0.0)
$dz = $realZero.details
Assert-That 'a measured 0% CPU is kept' ($null -ne $dz.AvgCpuPercent -and [int] $dz.AvgCpuPercent -eq 0) "(got '$($dz.AvgCpuPercent)')"
Assert-That 'a measured 0 MB free is kept' ($null -ne $dz.MinAvailableRamGb -and [double] $dz.MinAvailableRamGb -eq 0) "(got '$($dz.MinAvailableRamGb)')"
Assert-That 'the CPU cell shows the measured zero' ((Get-CpuCell $dz) -eq '0% avg / 0% max') "(got '$(Get-CpuCell $dz)')"
Assert-That 'the memory cell shows the measured zero' ((Get-RamCell $dz) -eq '0.00 GB min') "(got '$(Get-RamCell $dz)')"

'[counters] ordinary readings are unaffected'
$normal = Get-mdiCapacityPlanning -ComputerName 'dc-normal.contoso.com' -TrafficSample (New-Rows -Cpu 40.0 -Mem 8192.0)
$dn = $normal.details
Assert-That 'a real CPU reading survives' ([int] $dn.AvgCpuPercent -eq 40) "(got '$($dn.AvgCpuPercent)')"
Assert-That 'a real memory reading survives and is converted to GB' ([double] $dn.MinAvailableRamGb -eq 8) "(got '$($dn.MinAvailableRamGb)')"
Assert-That 'the CPU cell reports it' ((Get-CpuCell $dn) -eq '40% avg / 40% max') "(got '$(Get-CpuCell $dn)')"

'[counters] a partly readable counter averages only what was read'
# Two intervals returned CPU, two did not. Averaging over all four would drag a measured 80% down to
# 40% by counting two intervals that were never observed as idle.
$mixed = @(
    [PSCustomObject]@{ Timestamp = $now.AddMinutes(-15); PacketsPerSec = 2500.0; CpuPercent = 80.0;  AvailableMb = 4096.0 }
    [PSCustomObject]@{ Timestamp = $now.AddMinutes(-10); PacketsPerSec = 2500.0; CpuPercent = $null; AvailableMb = $null }
    [PSCustomObject]@{ Timestamp = $now.AddMinutes(-5);  PacketsPerSec = 2500.0; CpuPercent = 80.0;  AvailableMb = 4096.0 }
    [PSCustomObject]@{ Timestamp = $now;                 PacketsPerSec = 2500.0; CpuPercent = $null; AvailableMb = $null }
)
$dm = (Get-mdiCapacityPlanning -ComputerName 'dc-mixed.contoso.com' -TrafficSample $mixed).details
Assert-That 'unread intervals are not averaged in as idle' ([int] $dm.AvgCpuPercent -eq 80) "(got '$($dm.AvgCpuPercent)')"
Assert-That 'the peak is the measured peak' ([int] $dm.MaxCpuPercent -eq 80) "(got '$($dm.MaxCpuPercent)')"
Assert-That 'minimum free memory uses only read intervals' ([double] $dm.MinAvailableRamGb -eq 4) "(got '$($dm.MinAvailableRamGb)')"

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
