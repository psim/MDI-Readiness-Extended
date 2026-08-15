# The capacity shortfall told a German or Italian operator to add "2,25 GB more RAM" - and put that
# string into the machine-readable JSON.
#
# Get-mdiCapacityPlanning builds the shortfall list with the -f operator, which formats using the
# CURRENT THREAD CULTURE. The resulting strings are not cosmetic: they land in the Missing[] array and
# the Detail string of the JSON, in the SAME document where ConvertTo-Json writes the numeric fields
# invariantly. Measured under de-DE on the shipped function:
#
#     Missing[]  : 4 more physical core(s) ;; 2,25 GB more RAM      <- decimal comma
#     JSON       : "TotalRamGb": 9.25   "RequiredRamGb": 11.5       <- decimal point
#
# One document, two decimal conventions. A consumer matching '([\d.]+) GB' against the shortfall reads
# 2 instead of 2.25, and the number it acts on is the size of a RAM order. The HTML capacity tab
# carries the same string, so the human sees it too.
#
# This test asserts the shortfall text is IDENTICAL under en-US, de-DE and it-IT, which is the only
# property that matters: the report must not depend on the operator's locale. The core count is a
# whole number today and is asserted alongside the RAM figure so a future fractional value cannot
# reintroduce the split silently.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$source = [IO.File]::ReadAllText($target)
$source = $source -replace '(?m)^\s*#Requires.*$', ''
$source = $source -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$main = $source.IndexOf('#region Main')
if ($main -lt 1) { throw 'Could not isolate the canonical function definitions.' }
Invoke-Expression $source.Substring(0, $main)
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The OS boundary: only Get-WmiObject is stubbed. Get-WmiObject is a CMDLET, not one of the script's
# own functions, so a global function legitimately shadows it here.
$script:ramBytes = [long] (9.25 * 1GB)
$script:cores = 2
function global:Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_Processor' { return @([PSCustomObject]@{ NumberOfCores = $script:cores; NumberOfLogicalProcessors = ($script:cores * 2) }) }
        'Win32_ComputerSystem' { return [PSCustomObject]@{ TotalPhysicalMemory = $script:ramBytes } }
    }
    $null
}

# An estate sized so BOTH shortfalls fire and the RAM figure is fractional: 9.25 GB installed against
# the 50k-75k band's 11.5 GB requirement is a 2.25 GB shortfall, which is the only kind of value that
# can expose a decimal separator.
$t0 = [datetime]'2026-08-01T10:00:00'
$busySample = @(0..11 | ForEach-Object {
        [PSCustomObject]@{ Timestamp = $t0.AddSeconds($_ * 5); PacketsPerSec = 60000; CpuPercent = 12.5; AvailableMb = 3400 }
    })
$quietSample = @(0..11 | ForEach-Object {
        [PSCustomObject]@{ Timestamp = $t0.AddSeconds($_ * 5); PacketsPerSec = 500; CpuPercent = 5; AvailableMb = 40000 }
    })

function Get-Plan {
    param($Sample)
    (Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample $Sample 3>$null 4>$null).details
}

$cultures = @('en-US', 'de-DE', 'it-IT')
$results = @{}
$original = [System.Threading.Thread]::CurrentThread.CurrentCulture
try {
    foreach ($name in $cultures) {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($name)
        $plan = Get-Plan -Sample $busySample
        $results[$name] = [PSCustomObject]@{
            Missing = @($plan.Missing | ForEach-Object { [string] $_ })
            Detail  = [string] $plan.Detail
        }
    }
} finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $original
}

'[capacity culture] the shortfall list does not depend on the operator locale'
foreach ($name in $cultures) {
    "      $name  Missing = $($results[$name].Missing -join ' ;; ')"
}
foreach ($name in @('de-DE', 'it-IT')) {
    Assert-That ("{0}: the Missing[] list is identical to en-US" -f $name) (
        ($results[$name].Missing -join '|') -eq ($results['en-US'].Missing -join '|')) `
        "(en-US '$($results['en-US'].Missing -join '|')' vs $name '$($results[$name].Missing -join '|')')"
    Assert-That ("{0}: the Detail sentence is identical to en-US" -f $name) (
        $results[$name].Detail -eq $results['en-US'].Detail) `
        "(got '$($results[$name].Detail)')"
}

''
'[capacity culture] the RAM shortfall uses a decimal POINT and keeps its precision'
# THE DEFECT: under a comma culture this read "2,25 GB more RAM", so a consumer regexing the number
# out of it extracted 2.
foreach ($name in $cultures) {
    $ram = @($results[$name].Missing | Where-Object { $_ -match 'GB more RAM' })
    Assert-That ("{0}: a RAM shortfall line is present" -f $name) ($ram.Count -eq 1) "(got $($ram.Count))"
    Assert-That ("{0}: it contains no decimal comma" -f $name) ($ram[0] -notmatch ',') "(got '$($ram[0])')"
    Assert-That ("{0}: it reads exactly '2.25 GB more RAM'" -f $name) ($ram[0] -eq '2.25 GB more RAM') "(got '$($ram[0])')"
    # The property a consuming pipeline actually relies on.
    $parsed = [regex]::Match($ram[0], '([\d.]+) GB').Groups[1].Value
    Assert-That ("{0}: a consumer matching '([\d.]+) GB' recovers 2.25" -f $name) ($parsed -eq '2.25') "(recovered '$parsed')"
}

''
'[capacity culture] the core shortfall is formatted the same way'
foreach ($name in $cultures) {
    $cpu = @($results[$name].Missing | Where-Object { $_ -match 'physical core' })
    Assert-That ("{0}: a core shortfall line is present" -f $name) ($cpu.Count -eq 1) "(got $($cpu.Count))"
    Assert-That ("{0}: it reads exactly '4 more physical core(s)'" -f $name) (
        $cpu[0] -eq '4 more physical core(s)') "(got '$($cpu[0])')"
}

''
'[capacity culture] the Detail sentence carries the same numbers as the list'
# The sentence is assembled from the list, so a divergence means one of them was rebuilt separately.
foreach ($name in $cultures) {
    $d = $results[$name].Detail
    foreach ($item in $results[$name].Missing) {
        Assert-That ("{0}: the Detail sentence contains '{1}'" -f $name, $item) ($d.Contains($item)) "(detail '$d')"
    }
    Assert-That ("{0}: the Detail sentence has no decimal comma" -f $name) ($d -notmatch '\d,\d') "(detail '$d')"
}

''
'[capacity culture] a sized estate still reports no shortfall at all'
# The fix must not invent a shortfall on a machine that has enough.
$original2 = [System.Threading.Thread]::CurrentThread.CurrentCulture
try {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')
    $script:cores = 16
    $script:ramBytes = [long] (64 * 1GB)
    $big = Get-Plan -Sample $quietSample
} finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $original2
    $script:cores = 2
    $script:ramBytes = [long] (9.25 * 1GB)
}
Assert-That 'a well-sized server lists no missing resources' (@($big.Missing).Count -eq 0) `
    "(got: $(@($big.Missing) -join ' ;; '))"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
