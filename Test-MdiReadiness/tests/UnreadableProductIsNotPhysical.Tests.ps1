# Get-mdiMachineType reported a machine whose Win32_ComputerSystemProduct read FAILED as 'Physical'.
#
# The function already had the right rule for its OUTER query - Win32_ComputerSystem is read with
# ErrorAction 'Stop' and a null result is turned into a throw, under the comment
#
#     "Without this a failed query left $csi null and the switch fell through to 'Physical', so a
#      virtual machine that could not be queried was reported as bare metal."
#
# but the rule was applied one query too shallow. The INNER Win32_ComputerSystemProduct read still
# used -ErrorAction SilentlyContinue, which hands back $null for a query that FAILED and for a
# machine that simply carries no EC2 UUID alike. Those are not the same fact, and the else-arm
# turned both into the positive claim 'Physical'. One function, one fault, two treatments:
#
#     OUTER Win32_ComputerSystem fails          -> 'N/A' + a verbose line saying so
#     INNER Win32_ComputerSystemProduct fails    -> 'Physical', silently
#
# The population reaching that branch demonstrably contains virtual machines: the branch's own
# `if ($uuid -match '^EC2') { 'AWS' }` exists precisely because a machine arriving there may be an
# EC2 instance. So an unread UUID there is "a virtual machine that could not be queried, reported
# as bare metal" - exactly what the outer guard was written to stop.
#
# These tests are BEHAVIOURAL. They drive the SHIPPED Get-mdiMachineType through a discriminating
# Win32_* stub and assert the VERDICT it returns; no assertion reads the source text. The stub
# models the contract measured against the unstubbed cmdlet in w170 section 0: a provider fault
# THROWS under -ErrorAction Stop and yields $null under -ErrorAction SilentlyContinue. That is what
# makes the central case mutation-sensitive - reinstate SilentlyContinue and the stub hands back
# $null, the else-arm fires, and the verdict is 'Physical' again.
#
# What must NOT regress, and is asserted below:
#   * a genuinely physical machine (product read OK, UUID present, not EC2) still says 'Physical'
#   * a genuine AWS instance (UUID starts EC2) still says 'AWS'
#   * the outer guard keeps its own distinct "computer system inventory was not returned" wording
#   * Hyper-V / VMware never read Win32_ComputerSystemProduct at all

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

$script:csMode = 'oem'      # oem | vm | vmware | throw | null
$script:cspMode = 'oem'     # oem | ec2 | fault | absent | noUuid
$script:calls = New-Object Collections.ArrayList

# The stub DISCRIMINATES by class and by ErrorAction, and every call it answers is recorded and
# printed raw below. A stub that answers for every input has repeatedly produced false findings
# on this campaign by quietly satisfying a check it was never meant to reach.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_ComputerSystem' {
            [void] $script:calls.Add('Win32_ComputerSystem')
            if ($script:csMode -eq 'throw') { throw 'Access is denied. (Exception from HRESULT: 0x80070005)' }
            if ($script:csMode -eq 'null') { return $null }
            if ($script:csMode -eq 'vm') { return [PSCustomObject]@{ Model = 'Virtual Machine'; Manufacturer = 'Microsoft Corporation' } }
            if ($script:csMode -eq 'vmware') { return [PSCustomObject]@{ Model = 'VMware Virtual Platform'; Manufacturer = 'VMware, Inc.' } }
            return [PSCustomObject]@{ Model = 'PowerEdge R750'; Manufacturer = 'Dell Inc.' }
        }
        'Win32_ComputerSystemProduct' {
            [void] $script:calls.Add(('Win32_ComputerSystemProduct ea={0}' -f $ErrorAction))
            if ($script:cspMode -eq 'fault') {
                # The real contract, measured in w170 section 0 against the unstubbed cmdlet: a
                # provider fault throws under Stop and hands back $null under SilentlyContinue.
                if ($ErrorAction -eq 'Stop') { throw 'The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)' }
                return $null
            }
            if ($script:cspMode -eq 'absent') { return $null }
            if ($script:cspMode -eq 'noUuid') { return [PSCustomObject]@{ UUID = $null } }
            if ($script:cspMode -eq 'ec2') { return [PSCustomObject]@{ UUID = 'EC2ABCDE-1234-5678-9abc-def012345678' } }
            return [PSCustomObject]@{ UUID = '4C4C4544-0051-3010-8054-B7C04F565432' }
        }
        'Win32_Service' {
            [void] $script:calls.Add(('Win32_Service ea={0}' -f $ErrorAction))
            return $null
        }
    }
    throw ('unexpected class in stub: {0}' -f $Class)
}

# Returns ONLY the verdict. The raw stub trace goes to $script:trace and is printed by Show-Stub,
# because emitting it from here would append it to the captured value and every -eq below would
# then be comparing an array (which filters instead of returning a boolean, and passes wrongly).
$script:trace = ''
function Invoke-MachineType {
    param([string] $Cs, [string] $Csp)
    $script:csMode = $Cs; $script:cspMode = $Csp
    $script:calls.Clear(); $script:verbose.Clear()
    $r = Get-mdiMachineType -ComputerName 'dc1.contoso.test'
    $script:trace = '    STUB cs=[{0}] csp=[{1}] -> verdict=[{2}] calls=[{3}] verbose=[{4}]' -f
        $Cs, $Csp, [string] $r, ($script:calls -join '; '), ($script:verbose -join ' / ')
    $r
}
function Show-Stub { $script:trace }
function Test-Verbose {
    param([string] $Pattern)
    @($script:verbose | Where-Object { $_ -match $Pattern }).Count -gt 0
}
function Test-ProductQueryIssued {
    @($script:calls | Where-Object { $_ -like 'Win32_ComputerSystemProduct*' }).Count -gt 0
}

'[machine type] a Win32_ComputerSystemProduct read that FAILED is not a reading of "bare metal"'
# The central case. Under the fix the product query is issued with ErrorAction 'Stop', so the
# provider fault throws and the function's catch returns the unread marker. Reinstate
# SilentlyContinue and the stub returns $null instead, the else-arm fires, and this says 'Physical'.
$faulted = Invoke-MachineType -Cs 'oem' -Csp 'fault'
Show-Stub
Assert-That 'a faulted product read is N/A' ([string] $faulted -eq 'N/A') "(got '$faulted')"
Assert-That '  ...and is never called Physical' ([string] $faulted -ne 'Physical') "(got '$faulted')"
Assert-That '  ...and tells the operator the platform was not read' (Test-Verbose 'Unable to read the virtualization platform')
Assert-That '  ...naming the product inventory, not the outer one' (Test-Verbose 'computer system product inventory')

# A query that answered with no instance, and one that answered with an instance carrying no UUID,
# are both "the value was not obtained" - not "this machine has no EC2 UUID".
$absent = Invoke-MachineType -Cs 'oem' -Csp 'absent'
Show-Stub
Assert-That 'a product query that returned nothing is N/A' ([string] $absent -eq 'N/A') "(got '$absent')"
Assert-That '  ...and is never called Physical' ([string] $absent -ne 'Physical') "(got '$absent')"
$noUuid = Invoke-MachineType -Cs 'oem' -Csp 'noUuid'
Show-Stub
Assert-That 'a product answer carrying no UUID is N/A' ([string] $noUuid -eq 'N/A') "(got '$noUuid')"
Assert-That '  ...and is never called Physical' ([string] $noUuid -ne 'Physical') "(got '$noUuid')"
Assert-That '  ...and says so rather than staying silent' (Test-Verbose 'did not carry a UUID')

'[machine type] every knowable answer is still given'
# The regression that matters most: a physical DC is the majority of a real estate, and a fix that
# treated any non-EC2 UUID as unread would blank the platform column for every one of them.
$physical = Invoke-MachineType -Cs 'oem' -Csp 'oem'
Show-Stub
Assert-That 'a genuinely physical machine still says Physical' ([string] $physical -eq 'Physical') "(got '$physical')"
Assert-That '  ...and is not blanked to N/A' ([string] $physical -ne 'N/A') "(got '$physical')"
Assert-That '  ...silently, with no failure reported' (-not (Test-Verbose '.'))
$aws = Invoke-MachineType -Cs 'oem' -Csp 'ec2'
Show-Stub
Assert-That 'a genuine AWS instance still says AWS' ([string] $aws -eq 'AWS') "(got '$aws')"
Assert-That 'the read and the unread answers are different values' ([string] $physical -ne [string] $faulted) "(both '$physical')"

'[machine type] the outer guard is untouched and keeps its own message'
$outerThrow = Invoke-MachineType -Cs 'throw' -Csp 'oem'
Show-Stub
Assert-That 'an unreadable computer system is still N/A' ([string] $outerThrow -eq 'N/A') "(got '$outerThrow')"
Assert-That '  ...still reporting the underlying HRESULT' (Test-Verbose 'Access is denied')
$outerNull = Invoke-MachineType -Cs 'null' -Csp 'oem'
Show-Stub
Assert-That 'a null computer system is still N/A' ([string] $outerNull -eq 'N/A') "(got '$outerNull')"
Assert-That '  ...keeping the distinct "computer system inventory" wording' (Test-Verbose 'the computer system inventory was not returned')

'[machine type] the branches that never needed the product query still do not issue it'
$hyperv = Invoke-MachineType -Cs 'vm' -Csp 'fault'
Show-Stub
Assert-That 'a Hyper-V VM still says Hyper-V though the product provider is faulting' ([string] $hyperv -eq 'Hyper-V') "(got '$hyperv')"
Assert-That '  ...because it never reads Win32_ComputerSystemProduct' (-not (Test-ProductQueryIssued)) "(calls: $($script:calls -join '; '))"
$vmware = Invoke-MachineType -Cs 'vmware' -Csp 'fault'
Show-Stub
Assert-That 'a VMware VM still names its platform' ([string] $vmware -eq 'VMware Virtual Platform') "(got '$vmware')"
Assert-That '  ...because it never reads Win32_ComputerSystemProduct' (-not (Test-ProductQueryIssued)) "(calls: $($script:calls -join '; '))"

'[machine type] the unread marker is the one the server table already renders as Not tested'
# The renderer leaves 'N/A' alone in the descriptive-column rewrite and then blanket-maps it to
# "Not tested", so the exact marker string is pinned here: a fix that invented a new one would
# render as a raw value in the platform column instead.
Assert-That "the marker is literally 'N/A'" ([string] $faulted -ceq 'N/A') "(got '$faulted')"
Assert-That '  ...and not an empty value the table would render as blank' (-not [string]::IsNullOrWhiteSpace([string] $faulted)) "(got '$faulted')"

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
