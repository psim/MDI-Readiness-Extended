<#
    TWO MEASUREMENTS WERE ROUNDED OR DISCARDED BEFORE THE THING THAT READ THEM.

    1. RAM was rounded to two decimals and the SIZING THRESHOLD was then applied to the rounded value.

       A domain controller assigned 11,772 MiB holds 11.49609375 GiB. Rounded that is 11.50, which
       satisfies the 11.5 GiB requirement it is four mebibytes short of:

           REPORTED_TOTAL_RAM_GB=11.5  REQUIRED_RAM_GB=11.5  RAW_MEETS_REQUIREMENT=False
           CAPACITY=True  STATUS=Yes  MISSING=

       A false pass on a sizing requirement, and an ordinary one: a virtual machine is assigned memory
       in MiB, so landing inside the rounding window takes no unusual configuration. Rounding is for
       display; a threshold must see the measurement.

       The shortfall text had the same fault in mirror image - rounding the deficit to the nearest
       hundredth prints "0 GB more RAM" for a real four-mebibyte gap, and a shortfall stated as
       nothing reads as no shortfall.

    2. A power plan whose NAME contains parentheses made a perfectly readable line unreadable.

       The success line was matched with '\((?<name>[^)]*)\)\s*$', which requires the first closing
       parenthesis to end the line. `powercfg /changename` exists precisely so plans can be renamed,
       and a plan called "High performance (MDI hosts)" stopped matching:

           high-performance-ordinary-control            RESULT=True
           high-performance-renamed-with-parentheses    RESULT=N/A

       The GUID is byte-for-byte identical in both, and the GUID is the ONLY value the verdict uses.
       A renamed Balanced plan went from a measured False to 'N/A' the same way - which suppresses
       the finding AND the High-performance line in the generated remediation script, so the one
       server that needed the fix is the one that stops asking for it.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# ---------------------------------------------------------------------------------------------
# 1. The sizing threshold must see the measurement, not a rounded copy of it
# ---------------------------------------------------------------------------------------------
$script:ramBytes = [uint64] 0
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ([string] $Class) {
        'Win32_Processor' { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
        'Win32_ComputerSystem' { [PSCustomObject]@{ TotalPhysicalMemory = $script:ramBytes } }
        default { $null }
    }
}

# A steady 50,000 packets/sec sample lands in the band that requires 11.5 GB of RAM. Dense enough and
# long enough that the sample itself is never the reason a case fails.
$t0 = [datetime] '2026-08-20T12:00:00Z'
$sample = @(0..180 | ForEach-Object {
        [PSCustomObject]@{
            Timestamp     = $t0.AddSeconds($_ * 5)
            PacketsPerSec = [uint64] 50000
            CpuPercent    = [uint64] 10
            AvailableMb   = [uint64] 4096
        }
    })

function Invoke-Capacity {
    param([long] $RamMiB)
    $script:ramBytes = [uint64] ([long] $RamMiB * 1MB)
    Get-mdiCapacityPlanning -ComputerName 'dc01.contoso.com' -TrafficSample $sample 3>$null
}

Write-Host 'A sizing threshold must be applied to the measurement, not to its rounded display value' -ForegroundColor Cyan
# 11,772 MiB = 11.49609375 GiB: four mebibytes short of 11.5, and it rounds up onto the threshold.
$short = Invoke-Capacity -RamMiB 11772
if ([double] $short.details.RequiredRamGb -ne 11.5) {
    throw "the fixture did not land in the 11.5 GB band (required=$($short.details.RequiredRamGb)) - the assertions below would prove nothing"
}
Assert-That 'a server four mebibytes short does NOT meet the requirement' (
    $short.isCapacityOk -eq $false) "isCapacityOk=$($short.isCapacityOk) status=$($short.details.Status)"
Assert-That 'and the status says resources are required' (
    [string] $short.details.Status -match 'additional resources required') "status=$($short.details.Status)"
Assert-That 'the shortfall is listed rather than omitted' (
    @($short.details.Missing | Where-Object { $_ -match 'GB more RAM' }).Count -eq 1) (
    "missing=$(@($short.details.Missing) -join '; ')")
# A shortfall printed as "0 GB more RAM" reads as no shortfall at all.
Assert-That 'and it is not stated as zero' (
    @($short.details.Missing | Where-Object { $_ -match '^0 GB more RAM$' }).Count -eq 0) (
    "missing=$(@($short.details.Missing) -join '; ')")
Assert-That 'the DISPLAYED total is still the friendly rounded value' (
    [double] $short.details.TotalRamGb -eq 11.5) "totalRamGb=$($short.details.TotalRamGb)"

Write-Host ''
Write-Host 'CONTROLS - the healthy paths on both sides of the threshold' -ForegroundColor Cyan
$exact = Invoke-Capacity -RamMiB 11776      # exactly 11.5 GiB
Assert-That 'CONTROL: exactly the required RAM passes' (
    $exact.isCapacityOk -eq $true) "isCapacityOk=$($exact.isCapacityOk) status=$($exact.details.Status)"
Assert-That 'CONTROL: and nothing is listed as missing' (
    @($exact.details.Missing | Where-Object { $_ -match 'RAM' }).Count -eq 0) (
    "missing=$(@($exact.details.Missing) -join '; ')")

$ample = Invoke-Capacity -RamMiB 32768      # 32 GiB
Assert-That 'CONTROL: comfortably more than required passes' (
    $ample.isCapacityOk -eq $true) "isCapacityOk=$($ample.isCapacityOk)"

$clearlyShort = Invoke-Capacity -RamMiB 11770   # 11.494 GiB, below without rounding up
Assert-That 'CONTROL: clearly below still fails, and says by how much' (
    $clearlyShort.isCapacityOk -eq $false -and
    @($clearlyShort.details.Missing | Where-Object { $_ -match 'GB more RAM' }).Count -eq 1) (
    "isCapacityOk=$($clearlyShort.isCapacityOk) missing=$(@($clearlyShort.details.Missing) -join '; ')")

# ---------------------------------------------------------------------------------------------
# 2. A renamed power plan is still the same power plan
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'The power scheme verdict comes from the GUID, so a custom plan name cannot erase it' -ForegroundColor Cyan
$highPerformanceGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
$balancedGuid = '381b4222-f694-41f0-9685-ff5bb260df2e'

$script:powercfgOutput = ''
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
    $script:powercfgOutput
}

function Invoke-PowerScheme {
    param([string] $Output)
    $script:powercfgOutput = $Output
    Get-mdiPowerScheme -ComputerName 'dc01.contoso.com' 3>$null
}

# The control has to behave, or the renamed cases below prove nothing about the name.
$plainHigh = Invoke-PowerScheme -Output ('Power Scheme GUID: {0}  (High performance)' -f $highPerformanceGuid)
if ($plainHigh.isPowerSchemeOk -ne $true) {
    throw "the ordinary High performance control did not pass (got $($plainHigh.isPowerSchemeOk)) - the harness is not reaching the parser"
}

foreach ($case in @(
        @{ N = 'High performance (MDI hosts)'; G = $highPerformanceGuid; Expected = $true },
        @{ N = 'High performance (site A) (managed)'; G = $highPerformanceGuid; Expected = $true },
        @{ N = 'Balanced (server baseline)'; G = $balancedGuid; Expected = $false })) {
    $result = Invoke-PowerScheme -Output ('Power Scheme GUID: {0}  ({1})' -f $case.G, $case.N)
    Assert-That ("a plan named '$($case.N)' is still classified from its GUID") (
        $result.isPowerSchemeOk -eq $case.Expected) (
        "got=$($result.isPowerSchemeOk) expected=$($case.Expected) detail=$($result.details.Detail)")
    Assert-That '  ...and is not reported as unreadable' (
        [string] $result.details.Detail -notmatch 'Unable to read the active power scheme') (
        "detail=$($result.details.Detail)")
}

Write-Host ''
Write-Host 'CONTROLS - the parser must still refuse what it cannot read' -ForegroundColor Cyan
$plainBalanced = Invoke-PowerScheme -Output ('Power Scheme GUID: {0}  (Balanced)' -f $balancedGuid)
Assert-That 'CONTROL: an ordinary Balanced plan is still a measured failure' (
    $plainBalanced.isPowerSchemeOk -eq $false) "got=$($plainBalanced.isPowerSchemeOk)"
Assert-That 'CONTROL: an ordinary High performance plan still passes' (
    $plainHigh.isPowerSchemeOk -eq $true) "got=$($plainHigh.isPowerSchemeOk)"
# No parenthesised name at all is not a success line, and must stay unmeasured rather than being
# read as a pass by a now-greedier pattern.
$noName = Invoke-PowerScheme -Output ('Power Scheme GUID: {0}' -f $highPerformanceGuid)
Assert-That 'CONTROL: a line with no scheme name is still unreadable' (
    [string] $noName.isPowerSchemeOk -eq 'N/A') "got=$($noName.isPowerSchemeOk)"
$errorLine = Invoke-PowerScheme -Output ('The system cannot find the file specified: {0}' -f $highPerformanceGuid)
Assert-That 'CONTROL: a GUID inside an error message is not a verdict' (
    [string] $errorLine.isPowerSchemeOk -eq 'N/A') "got=$($errorLine.isPowerSchemeOk)"

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
