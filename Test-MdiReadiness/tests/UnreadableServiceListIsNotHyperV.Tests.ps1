# Get-mdiMachineType asserted 'Hyper-V' as a measured fact from a Win32_Service list it could not read.
#
# It was the LAST Win32_Service read in the file still using -ErrorAction SilentlyContinue. Every
# other one goes through Get-mdiServiceStateResult, which reads with ErrorAction 'Stop' and returns
# a Result carrying a Readable flag. That accessor exists because of exactly this pattern, and says
# so in its own documentation:
#
#     "Get-WmiObject with -ErrorAction SilentlyContinue returns $null both for a service that is not
#      installed and for a query that failed ... Callers testing "if ($service)" therefore asserted
#      facts they had never measured ... Both are false greens produced from a read that never
#      happened."
#
# and `if (Get-WmiObject @azgaParams) { 'Azure' } else { 'Hyper-V' }` was precisely that
# `if ($service)` test. On a server whose service list is Access-Denied, one report row therefore
# read: SensorHealth = Not tested, SensorVersion = Not tested, SensorV3Ready = Not tested, and -
# from the SAME denial, in the SAME row - MachineType = Hyper-V.
#
# Reachability, measured rather than assumed: the service read is issued only when Manufacturer is
# exactly 'Microsoft Corporation' AND Model is not exactly 'Virtual Machine' (and does not match
# VMware|VirtualBox). An ordinary Hyper-V or Azure VM reporting Model = 'Virtual Machine'
# short-circuits on the first switch arm and never reads a service at all - which is why that case
# is asserted below to keep issuing NO service query. The shapes that do reach it are
# Microsoft-manufactured hardware, any Microsoft-Corporation model string that is not literally
# 'Virtual Machine', and WMI answering with Manufacturer but without Model.
#
# These tests are BEHAVIOURAL. They drive the SHIPPED Get-mdiMachineType - and the SHIPPED
# Get-mdiServiceStateResult and Get-mdiSensorVersion for the cross-surface assertion - through one
# discriminating Win32_* stub, and assert the VERDICT. No assertion reads the source text.
#
# What must NOT regress, and is asserted below:
#   * a machine that genuinely IS Azure (list readable, agent present) still says 'Azure'
#   * a machine that genuinely IS Hyper-V (list readable, agent absent) still says 'Hyper-V' -
#     Readable=$true + Service=$null must not collapse into the unread branch
#   * Model = 'Virtual Machine' still short-circuits to 'Hyper-V' with NO service read at all
#   * VMware and OEM-physical paths still read no service and keep their answers

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw 'Test-MdiReadiness.ps1 was not found beside or above this test' }
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

# Script scope, not global: Get-mdiMachineType calls these from inside the script scope and would
# not see a global override, so every assertion would silently be testing the real cmdlets against
# a machine name that does not exist - which can pass for entirely the wrong reason.
$script:verbose = New-Object Collections.ArrayList
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) [void] $script:verbose.Add([string] $Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:model = 'Virtual Machine 2'
$script:manufacturer = 'Microsoft Corporation'
$script:svcMode = 'absent'   # absent | denied | present
$script:calls = New-Object Collections.ArrayList

# The stub DISCRIMINATES by class, by service NAME and by ErrorAction, and every call it answers is
# recorded and printed raw below. A stub that answers the same way for every service name would
# make 'Azure' unfalsifiable; one that ignored ErrorAction could not model the defect at all.
#
# 'denied' throws under Stop and hands back $null under SilentlyContinue. That is the real cmdlet's
# contract and it is the whole point: SilentlyContinue is what turned a denial into the same $null
# that "the agent is not installed" produces, and the else-arm then said Hyper-V.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_ComputerSystem' {
            [void] $script:calls.Add('Win32_ComputerSystem')
            return [PSCustomObject]@{ Model = $script:model; Manufacturer = $script:manufacturer }
        }
        'Win32_Service' {
            $name = ($Filter -replace "^Name\s*=\s*'", '') -replace "'$", ''
            [void] $script:calls.Add(('Win32_Service name={0} ea={1}' -f $name, $ErrorAction))
            if ($script:svcMode -eq 'denied') {
                if ($ErrorAction -eq 'Stop') { throw 'Access denied (Exception from HRESULT: 0x80070005)' }
                return $null
            }
            if ($script:svcMode -eq 'present' -and $name -eq 'WindowsAzureGuestAgent') {
                return [PSCustomObject]@{ Name = $name; State = 'Running'; StartMode = 'Auto'
                    PathName = 'C:\WindowsAzure\GuestAgent\WindowsAzureGuestAgent.exe' }
            }
            return $null
        }
        'Win32_ComputerSystemProduct' {
            # A readable, ordinary OEM UUID, so nothing here can be confused with the separate
            # "unreadable product query" defect - reaching this class at all would be a bug.
            [void] $script:calls.Add('Win32_ComputerSystemProduct')
            return [PSCustomObject]@{ UUID = '4C4C4544-0051-3010-8054-B7C04F565432' }
        }
        'CIM_DataFile' { [void] $script:calls.Add('CIM_DataFile'); return $null }
    }
    throw ('unexpected class in stub: {0}' -f $Class)
}

# Returns ONLY the verdict. The trace is printed separately by Show-Stub: emitting it from here
# would append it to the captured value, and every -eq below would then be comparing an array,
# which filters instead of returning a boolean and passes for the wrong reason.
$script:trace = ''
function Invoke-MachineType {
    param([string] $Model, [string] $Manufacturer, [string] $Svc)
    $script:model = $Model; $script:manufacturer = $Manufacturer; $script:svcMode = $Svc
    $script:calls.Clear(); $script:verbose.Clear()
    $r = Get-mdiMachineType -ComputerName 'dc1.contoso.test'
    $script:trace = '    STUB model=[{0}] mfr=[{1}] svc=[{2}] -> verdict=[{3}] calls=[{4}] verbose=[{5}]' -f
        $Model, $Manufacturer, $Svc, [string] $r, ($script:calls -join '; '), ($script:verbose -join ' / ')
    $r
}
function Show-Stub { $script:trace }
function Get-ServiceCall { @($script:calls | Where-Object { $_ -like 'Win32_Service*' }) }
function Test-Verbose { param([string] $Pattern) @($script:verbose | Where-Object { $_ -match $Pattern }).Count -gt 0 }

'[machine type] a service list that could not be read is not a reading of "no Azure agent"'
$denied = Invoke-MachineType -Model 'Virtual Machine 2' -Manufacturer 'Microsoft Corporation' -Svc 'denied'
Show-Stub
Assert-That 'an unreadable service list is N/A' ([string] $denied -eq 'N/A') "(got '$denied')"
Assert-That '  ...and is never called Hyper-V' ([string] $denied -ne 'Hyper-V') "(got '$denied')"
Assert-That '  ...nor Azure' ([string] $denied -ne 'Azure') "(got '$denied')"
Assert-That '  ...and tells the operator the platform was not read' (Test-Verbose 'Unable to read the virtualization platform')
Assert-That '  ...naming the service list as the reason' (Test-Verbose 'the service list could not be read')
Assert-That '  ...and carrying the underlying error' (Test-Verbose 'Access denied')
# The read now goes through the shipped Result-style accessor, which reads with ErrorAction 'Stop'.
# Asserted by observing the query the function actually issued, not by reading the source.
Assert-That 'the agent query is issued with ErrorAction Stop' ((Get-ServiceCall) -join ';' -like "*WindowsAzureGuestAgent ea=Stop*") "(calls: $((Get-ServiceCall) -join '; '))"
Assert-That '  ...and never with SilentlyContinue' (((Get-ServiceCall) -join ';') -notlike '*ea=SilentlyContinue*') "(calls: $((Get-ServiceCall) -join '; '))"

# Also measured for the two other shapes w170 found reach this branch.
$deniedSurface = Invoke-MachineType -Model 'Surface Pro 7' -Manufacturer 'Microsoft Corporation' -Svc 'denied'
Show-Stub
Assert-That 'Microsoft-manufactured hardware with a denied list is N/A' ([string] $deniedSurface -eq 'N/A') "(got '$deniedSurface')"
$deniedNoModel = Invoke-MachineType -Model '' -Manufacturer 'Microsoft Corporation' -Svc 'denied'
Show-Stub
Assert-That 'WMI answering without a Model, denied list, is N/A' ([string] $deniedNoModel -eq 'N/A') "(got '$deniedNoModel')"

'[machine type] both knowable answers are still given'
# The distinction that must NOT collapse: Readable=$true + Service=$null is a measured "no agent".
$azure = Invoke-MachineType -Model 'Virtual Machine 2' -Manufacturer 'Microsoft Corporation' -Svc 'present'
Show-Stub
Assert-That 'a genuine Azure VM still says Azure' ([string] $azure -eq 'Azure') "(got '$azure')"
Assert-That '  ...silently, with no failure reported' (-not (Test-Verbose '.'))
$hyperv = Invoke-MachineType -Model 'Virtual Machine 2' -Manufacturer 'Microsoft Corporation' -Svc 'absent'
Show-Stub
Assert-That 'a genuine Hyper-V VM still says Hyper-V' ([string] $hyperv -eq 'Hyper-V') "(got '$hyperv')"
Assert-That '  ...and is not blanked to N/A by the readable-but-absent case' ([string] $hyperv -ne 'N/A') "(got '$hyperv')"
Assert-That 'the measured and the unread answers are different values' ([string] $hyperv -ne [string] $denied) "(both '$hyperv')"

'[machine type] the branches that never read a service still do not read one'
# Moving the Azure probe earlier would make every ordinary Hyper-V DC's platform column depend on a
# service read it does not need today. Asserted on the calls the function actually issued.
$plainVm = Invoke-MachineType -Model 'Virtual Machine' -Manufacturer 'Microsoft Corporation' -Svc 'denied'
Show-Stub
Assert-That 'Model "Virtual Machine" still short-circuits to Hyper-V' ([string] $plainVm -eq 'Hyper-V') "(got '$plainVm')"
Assert-That '  ...issuing NO service query at all, even with a denied list' ((Get-ServiceCall).Count -eq 0) "(calls: $($script:calls -join '; '))"
$vmware = Invoke-MachineType -Model 'VMware Virtual Platform' -Manufacturer 'VMware, Inc.' -Svc 'denied'
Show-Stub
Assert-That 'a VMware VM still names its platform' ([string] $vmware -eq 'VMware Virtual Platform') "(got '$vmware')"
Assert-That '  ...issuing NO service query' ((Get-ServiceCall).Count -eq 0) "(calls: $($script:calls -join '; '))"
$oem = Invoke-MachineType -Model '20MAS08508' -Manufacturer 'LENOVO' -Svc 'denied'
Show-Stub
Assert-That 'an OEM physical machine still says Physical' ([string] $oem -eq 'Physical') "(got '$oem')"
Assert-That '  ...issuing NO service query' ((Get-ServiceCall).Count -eq 0) "(calls: $($script:calls -join '; '))"

'[cross-surface] one denial, one server, one answer'
# The visible symptom: from a single Access-Denied service list, five checks correctly said "Not
# tested" while the platform column asserted Hyper-V. Both surfaces are driven here from the SAME
# stub in the SAME state, using the shipped functions.
$script:model = 'Virtual Machine 2'; $script:manufacturer = 'Microsoft Corporation'; $script:svcMode = 'denied'
$script:calls.Clear(); $script:verbose.Clear()
$mt = Get-mdiMachineType -ComputerName 'dc1.contoso.test'
$sv = Get-mdiSensorVersion -ComputerName 'dc1.contoso.test'
$state = Get-mdiServiceStateResult -ComputerName 'dc1.contoso.test' -ServiceName 'WindowsAzureGuestAgent'
"    CROSS  MachineType=[$mt]  SensorVersion=[$sv]  ServiceStateResult.Readable=[$($state.Readable)] Error=[$($state.Error)]"
Assert-That 'the shipped accessor reports the list as unreadable' ($state.Readable -eq $false) "(got '$($state.Readable)')"
Assert-That 'the sensor version says N/A from that denial' ([string] $sv -eq 'N/A') "(got '$sv')"
Assert-That 'the platform column now says N/A from the same denial' ([string] $mt -eq 'N/A') "(got '$mt')"
Assert-That 'the two surfaces no longer contradict each other' ([string] $mt -eq [string] $sv) "(MachineType '$mt' vs SensorVersion '$sv')"

'[machine type] the unread marker is the one the server table already renders as Not tested'
Assert-That "the marker is literally 'N/A'" ([string] $denied -ceq 'N/A') "(got '$denied')"
Assert-That '  ...and not an empty value the table would render as blank' (-not [string]::IsNullOrWhiteSpace([string] $denied)) "(got '$denied')"

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
