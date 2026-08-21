# A PROCESSOR CORE COUNT THAT WAS NEVER READ WAS PRESENTED AS A MEASURED HARDWARE SHORTFALL
#
# Get-mdiCapacityPlanning gates every reading it takes except one. The processor COLLECTION is
# gated ("Missing core data" when WMI returns nothing), the RAM is gated ("Missing RAM data"), and
# the packet rate goes through Get-mdiPacketRateReading with separate answers for "nothing usable
# arrived" and "the window was only partly sampled". The physical CORE COUNT was the exception:
#
#     $physicalCores += [int] $cpu.NumberOfCores
#
# a bare cast, outside any try, whose result is compared against the published sizing table
# ($cpuOk = $physicalCores -ge $requiredCpu) and then printed to the operator as a hardware order
# ("N more physical core(s)").
#
# [int] $null and [int] '' are a clean ZERO, and zero physical cores is a plausible-looking number
# to everything downstream. Measured on the shipped function with a Win32_Processor instance whose
# NumberOfCores did not arrive - $null, '', or the property absent altogether, which is the shape a
# partial or property-filtered WMI read returns - against an ordinary 42,000 packets/sec sample:
#
#     isCapacityOk  = False    Status  = 'Yes, but additional resources required'
#     PhysicalCores = 0        Missing = '4 more physical core(s)'
#
# A server whose processors were never inspected was told, as a measured fact, to buy four cores.
# The identical cause on the very next reading of the same call - RAM that did not arrive -
# correctly returned 'N/A' / 'Missing RAM data'. One cause, two opposite verdicts.
#
# Two shapes were worse than wrong rather than merely wrong: 'four' and an Object[] both THREW
# inside the cast, and because the loop sits outside any try the exception escaped
# Get-mdiCapacityPlanning and destroyed the whole server's capacity section. $true became 1 core.
#
# What this test pins:
#   1. CONTROLS. A readable count still sizes: 8 cores passes, 2 cores still reports the REAL
#      shortfall, and a numeric string '8' is still a reading. Without these the guard could be
#      "fixed" by refusing everything, and the assertions below would be worthless.
#   2. Every unreadable shape yields isCapacityOk 'N/A' with Status 'Missing core data', and
#      NOTHING in Missing[] mentions cores. An unread value must never become a hardware order.
#   3. No unreadable shape throws out of the function.
#   4. The ASYMMETRY is gone: unreadable cores and unreadable RAM are both unsized.
#   5. PhysicalCores is not reported as 0 for an unread count - a zero in the JSON is a number a
#      consumer will act on just as readily as the text.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
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

# Script scope so the stub shadows the cmdlet INSIDE Get-mdiCapacityPlanning. A global function is
# not visible there, and every assertion below would then be measuring a live WMI call to a host
# that does not exist rather than the shape it means to test.
$script:CpuInstances = $null
$script:RamBytes = 32GB
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_Processor' { $script:CpuInstances }
        'Win32_ComputerSystem' {
            if ($null -eq $script:RamBytes) { throw 'RPC server is unavailable' }
            [PSCustomObject]@{ TotalPhysicalMemory = $script:RamBytes }
        }
        default { $null }
    }
}

# 42,000 packets/sec over a full window: a band that genuinely requires more than zero cores, so a
# manufactured zero has somewhere visible to go.
$now = Get-Date
$sample = @(0..30 | ForEach-Object {
        [PSCustomObject]@{
            Timestamp     = $now.AddMinutes(-30).AddSeconds($_ * 60)
            PacketsPerSec = 42000.0
            CpuPercent    = 22.0
            AvailableMb   = 9000.0
        }
    })

function New-Cpu {
    param($Cores, $Logical)
    $o = New-Object psobject
    $o | Add-Member -NotePropertyName NumberOfCores -NotePropertyValue $Cores
    $o | Add-Member -NotePropertyName NumberOfLogicalProcessors -NotePropertyValue $Logical
    $o
}

function Invoke-Sizing {
    param($Cpus, $Ram = 32GB)
    $script:CpuInstances = $Cpus
    $script:RamBytes = $Ram
    try {
        $r = Get-mdiCapacityPlanning -ComputerName 'dcfab01.fabrikam.local' -TrafficSample $sample 3>$null 4>$null
        [PSCustomObject]@{ Threw = $false; Result = $r; Error = $null }
    } catch {
        [PSCustomObject]@{ Threw = $true; Result = $null; Error = $_.Exception.Message }
    }
}

'[controls] a core count that WAS read still sizes the server'
$eight = Invoke-Sizing -Cpus @((New-Cpu 8 16))
Assert-That 'a readable 8-core server is sized and passes' `
    ((-not $eight.Threw) -and $eight.Result.isCapacityOk -eq $true -and $eight.Result.details.PhysicalCores -eq 8) `
    "got ok=$($eight.Result.isCapacityOk) cores=$($eight.Result.details.PhysicalCores) threw=$($eight.Threw) $($eight.Error)"

$two = Invoke-Sizing -Cpus @((New-Cpu 2 4))
Assert-That 'a readable 2-core server still reports the REAL shortfall' `
    ((-not $two.Threw) -and $two.Result.isCapacityOk -eq $false -and
        $two.Result.details.PhysicalCores -eq 2 -and (@($two.Result.details.Missing) -join ' ') -match 'physical core') `
    "got ok=$($two.Result.isCapacityOk) cores=$($two.Result.details.PhysicalCores) missing=$(@($two.Result.details.Missing) -join ' ;; ')"

$strEight = Invoke-Sizing -Cpus @((New-Cpu '8' '16'))
Assert-That "a numeric STRING '8' is still a reading, not a refusal" `
    ((-not $strEight.Threw) -and $strEight.Result.isCapacityOk -eq $true -and $strEight.Result.details.PhysicalCores -eq 8) `
    "got ok=$($strEight.Result.isCapacityOk) cores=$($strEight.Result.details.PhysicalCores)"

$multi = Invoke-Sizing -Cpus @((New-Cpu 4 8), (New-Cpu 4 8))
Assert-That 'two readable sockets still sum to 8 cores' `
    ((-not $multi.Threw) -and $multi.Result.details.PhysicalCores -eq 8 -and $multi.Result.details.LogicalCores -eq 16) `
    "got cores=$($multi.Result.details.PhysicalCores) logical=$($multi.Result.details.LogicalCores)"

Assert-That 'hyper-threading is still detected from a readable pair' `
    ($multi.Result.details.HyperThreaded -eq $true) "got $($multi.Result.details.HyperThreaded)"

''
'[the defect] an unread core count is not a measured shortfall'
$absent = New-Object psobject
$absent | Add-Member -NotePropertyName Manufacturer -NotePropertyValue 'GenuineIntel'

$unreadable = @(
    @{ Name = '$null';                Cpus = @((New-Cpu $null $null)) }
    @{ Name = "'' (empty string)";    Cpus = @((New-Cpu '' '')) }
    @{ Name = "'four' (non-numeric)"; Cpus = @((New-Cpu 'four' 'eight')) }
    @{ Name = '$true (wrong type)';   Cpus = @((New-Cpu $true $true)) }
    @{ Name = '@(4,4) (collection)';  Cpus = @((New-Cpu @(4, 4) @(4, 4))) }
    @{ Name = 'property absent';      Cpus = @($absent) }
    @{ Name = 'Int32 overflow';       Cpus = @((New-Cpu '99999999999999' '99999999999999')) }
)
foreach ($u in $unreadable) {
    $o = Invoke-Sizing -Cpus $u.Cpus
    Assert-That ("{0}: does not throw out of the function" -f $u.Name) (-not $o.Threw) "threw: $($o.Error)"
    if ($o.Threw) { continue }
    $d = $o.Result.details
    Assert-That ("{0}: is N/A, not a verdict" -f $u.Name) ($o.Result.isCapacityOk -eq 'N/A') `
        "got isCapacityOk=$($o.Result.isCapacityOk) status=$($d.Status)"
    Assert-That ("{0}: says the core data is missing" -f $u.Name) ($d.Status -eq 'Missing core data') `
        "got '$($d.Status)'"
    Assert-That ("{0}: orders no hardware" -f $u.Name) `
        (((@($d.Missing) -join ' ') -notmatch 'core') -and ($d.Detail -notmatch 'more physical core')) `
        "missing=[$(@($d.Missing) -join ' ;; ')] detail='$($d.Detail)'"
    Assert-That ("{0}: does not report 0 cores as a figure" -f $u.Name) ($d.PhysicalCores -ne 0) `
        "got PhysicalCores=$($d.PhysicalCores)"
}

''
'[symmetry] the two readings of the same call answer the same way'
$ramGone = Invoke-Sizing -Cpus @((New-Cpu 8 16)) -Ram $null
Assert-That 'unreadable RAM is still unsized (unchanged behaviour)' `
    ($ramGone.Result.isCapacityOk -eq 'N/A' -and $ramGone.Result.details.Status -eq 'Missing RAM data') `
    "got $($ramGone.Result.isCapacityOk) / $($ramGone.Result.details.Status)"

$coresGone = Invoke-Sizing -Cpus @((New-Cpu $null $null))
Assert-That 'unreadable cores are unsized in exactly the same way' `
    ($coresGone.Result.isCapacityOk -eq 'N/A') "got $($coresGone.Result.isCapacityOk)"

Assert-That 'an unreadable reading never outranks an unreadable reading' `
    ($ramGone.Result.isCapacityOk -eq $coresGone.Result.isCapacityOk) `
    "ram=$($ramGone.Result.isCapacityOk) cores=$($coresGone.Result.isCapacityOk)"

$noneAtAll = Invoke-Sizing -Cpus @()
Assert-That 'no processors at all is still its own answer' `
    ($noneAtAll.Result.isCapacityOk -eq 'N/A' -and $noneAtAll.Result.details.Detail -match 'processor information') `
    "got $($noneAtAll.Result.isCapacityOk) / $($noneAtAll.Result.details.Detail)"

''
'[partial] a socket that answered is not discarded by one that did not'
$mixed = Invoke-Sizing -Cpus @((New-Cpu 8 16), (New-Cpu $null $null))
Assert-That 'one readable socket beside one unreadable one is still sized' `
    (([string] $mixed.Result.isCapacityOk) -ne 'N/A' -and $mixed.Result.details.PhysicalCores -eq 8) `
    "got ok=$($mixed.Result.isCapacityOk) cores=$($mixed.Result.details.PhysicalCores)"

''
"pass=$script:pass  fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
