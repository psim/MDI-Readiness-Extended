<#
    THE DEFECT THIS TEST PINS

    The remediation script generator wrote PowerShell CODE from values nobody had read, and did it
    silently. Two lists in New-mdiRemediationScript decided what was readable by looking at how a
    value RENDERS:

        $blockedTargets = @($blockedNnr | ForEach-Object { [string] $_.Target } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ...)
        $blockedNnrUnnameable = @($blockedNnr | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Target) }).Count

        $hostAddresses = @($sensorHost.Addresses | Where-Object { $_ })
        $hostAddresses = @($hostAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })

    IsNullOrWhiteSpace is a test of the rendering, and every non-string renders to something
    non-blank: a hashtable to 'System.Collections.Hashtable', a two-element list @('a','b') to the
    single string 'a b'. So both filters passed values nobody read, AND the unnameable counter beside
    the first one saw nothing to charge, so no warning was raised either. The blank case was guarded;
    the unreadable case walked straight through the same guard.

    Measured on the shipped generator, three primary NNR methods all measured REFUSED against one
    target, controls run in the same process:

        readable target                       -> 3 rules on dcblocked.mdilab.local,  0 warnings
        $null target                          -> 0 rules, unnameable warning, section skipped
        @{ dnsHostName = 'dcblocked' } target -> 3 rules on 'System.Collections.Hashtable', 0 warnings
        @('dca...','dcb...') target           -> 3 rules on 'dca.mdilab.local dcb.mdilab.local', 0 warnings

    The last is the worst of the four. TWO domain controllers that could not be resolved collapse
    into ONE name that belongs to no machine: the operator runs the generated script, it fails
    against a host that does not exist, and the two targets that really were blocked receive no rule
    at all - while the report the script was generated FROM names them as unresolvable. That is the
    same "collapsing every unnameable row into one host" failure this codebase has already fixed in
    the identity keys, arriving here in the surface that emits executable code.

    The sensor address is the security-relevant half. $sensorAddresses is the -RemoteAddress scope of
    an inbound rule opened on a domain controller for TCP 135, UDP 137 and TCP 3389:

        Addresses @(@('10.10.1.50','10.10.1.60')) -> $sensorAddresses = @('10.10.1.50 10.10.1.60')
        Addresses @(@{ ip = '10.10.1.50' })       -> $sensorAddresses = @('System.Collections.Hashtable')

    Two VALID sensor addresses fuse into one string that is neither of them, so the rule matches no
    traffic, every sensor's NNR probes stay blocked, and the operator is told the fix was applied.
    The guard the generated script itself carries against an unscoped rule tests IsNullOrWhiteSpace
    too, so the bogus non-blank value passes that as well - the one check written to prevent opening
    those ports to the whole network does not fire.

    THE FIX reads both through ConvertTo-mdiReadableDomainName, this codebase's single definition of
    "is this a name anybody read", which decides by TYPE rather than by spelling. An unreadable
    target is charged to the unnameable count that already exists, so the warning fires and the
    section is skipped rather than emitting a rule for a machine that is not there. An unreadable
    address is treated as no address, which routes the sensor into $sensorNoAddress and its existing
    warning.

    THE SCOPE OF THIS TEST IS THE EMITTED CODE. The generated script also ECHOES the report's issue
    list, and that echo still renders an unreadable target - "No NNR method could resolve
    System.Collections.Hashtable (10.10.1.99)" - because it is built by Get-mdiTargetLabel, which is
    shared with the HTML report and every other display surface. That is a real and separate finding
    with a much wider blast radius, and it is recorded as one rather than being folded in here.
    Asserting against the whole generated file would make this test fail for a defect it does not
    describe, so the two lists that become CODE are isolated and asserted on directly.

    THIS TEST MUST ALSO REFUSE THE OPPOSITE MISTAKE. Rejecting more than the unreadable values would
    be the worse defect, because it would silently drop real targets and real sensor addresses from a
    remediation the operator depends on. So a readable target, a MULTI-HOMED sensor keeping BOTH of
    its addresses, and the one-element collection shape the codebase deliberately accepts are all
    asserted to survive unchanged.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
. ([scriptblock]::Create($body))

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Got = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" }
    else { $script:fail++; Write-Host "  FAIL  $Name $Got" }
}

# Requirement must be 'AtLeastOne'. Get-mdiBlockingPortFailure only tags a record 'NnrMeasured' -
# which is what the generator keys the whole NNR section off - for a group whose requirement rank is
# 2. With 'Required' the records are tagged 'Required' instead, no NNR section is generated at all,
# and every case including the controls looks identical and clean.
function New-NnrRecord {
    param($Target, $TargetIP, [int] $Port)
    [pscustomobject]@{
        Id          = 'NnrRpc'
        Group       = 'NNR'
        Scope       = 'NetworkDevice'
        Requirement = 'AtLeastOne'
        Name        = ('port {0}' -f $Port)
        Port        = $Port
        Target      = $Target
        TargetIP    = $TargetIP
        Success     = $false
        Applicable  = $true
        Detail      = 'Connection refused'
    }
}

function Invoke-Generator {
    param($Target, $SensorAddresses, $SensorIP = '10.10.1.10')

    $sensor = [pscustomobject]@{
        FQDN          = 'sensor1.mdilab.local'
        IP            = $SensorIP
        Addresses     = $SensorAddresses
        SensorVersion = '2.235.0.0'
        Details       = [pscustomobject]@{ RequiredPortsDetails = [pscustomobject]@{ Results = @() } }
    }
    $blockedHost = [pscustomobject]@{
        FQDN          = 'dctarget.mdilab.local'
        IP            = '10.10.1.20'
        Addresses     = @('10.10.1.20')
        SensorVersion = 'Not installed'
        Details       = [pscustomobject]@{
            RequiredPortsDetails = [pscustomobject]@{
                Results = @(
                    (New-NnrRecord -Target $Target -TargetIP '10.10.1.99' -Port 135),
                    (New-NnrRecord -Target $Target -TargetIP '10.10.1.99' -Port 137),
                    (New-NnrRecord -Target $Target -TargetIP '10.10.1.99' -Port 3389)
                )
            }
        }
    }
    $report = [pscustomobject]@{
        DomainControllers   = @($sensor, $blockedHost)
        CAServers           = @()
        EntraConnectServers = @()
        Domains             = @()
    }

    $file = Join-Path $env:TEMP ('nnrgen-{0}.ps1' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $warnings = @()
    New-mdiRemediationScript -ReportData $report -FilePath $file -WarningVariable +warnings -WarningAction SilentlyContinue | Out-Null
    $generated = if (Test-Path $file) { Get-Content $file -Raw } else { '' }
    Remove-Item $file -Force -ErrorAction SilentlyContinue

    # The two lists that become CODE, isolated. Asserting against the whole file would also catch the
    # generated script's issue ECHO - 'No NNR method could resolve <rendering>' - which is produced by
    # Get-mdiTargetLabel on a different surface and is a separate finding, not this one. Pinning this
    # defect to the whole file would make this test fail for a reason it does not describe.
    $codeLists = New-Object -TypeName System.Collections.ArrayList
    $lines = $generated -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*\$sensorAddresses = @\(' -or $lines[$i] -match '^\s*foreach \(\$computer in @\(') {
            for ($j = $i; $j -lt $lines.Count; $j++) {
                [void] $codeLists.Add($lines[$j])
                if ($j -gt $i -and $lines[$j] -match '^\s*\)') { break }
            }
        }
    }

    [pscustomobject]@{
        Rules    = ([regex]::Matches($generated, 'New-NetFirewallRule')).Count
        Text     = $generated
        Code     = ($codeLists -join "`n")
        Warnings = @($warnings | ForEach-Object { [string] $_ })
    }
}

function Test-Warned {
    param($Result, [string] $Fragment)
    @($Result.Warnings | Where-Object { $_ -like ('*{0}*' -f $Fragment) }).Count -gt 0
}

Write-Host "`nCONTROL - a readable target and a readable address still generate the rules"
$controlReadable = Invoke-Generator -Target 'dcblocked.mdilab.local' -SensorAddresses @('10.10.1.10')
Assert-True 'a readable target generates three NNR rules' ($controlReadable.Rules -eq 3) ("got $($controlReadable.Rules)")
Assert-True 'the readable target is named in the generated script' ($controlReadable.Text -match "'dcblocked\.mdilab\.local'")
Assert-True 'the readable sensor address is the rule scope' ($controlReadable.Text -match "'10\.10\.1\.10'")
Assert-True 'nothing is warned about for a wholly readable estate' ($controlReadable.Warnings.Count -eq 0) ("got $($controlReadable.Warnings.Count)")

Write-Host "`nCONTROL - a blank target was already refused and must stay refused"
$controlNull = Invoke-Generator -Target $null -SensorAddresses @('10.10.1.10')
Assert-True 'a null target generates no rule' ($controlNull.Rules -eq 0) ("got $($controlNull.Rules)")
Assert-True 'a null target is charged to the unnameable warning' (Test-Warned $controlNull 'carry no readable target')
Assert-True 'the section is skipped and the reason stated' (Test-Warned $controlNull 'no target could be determined')

Write-Host "`nTHE DEFECT - a target nobody read must never become a computer name"
$hashTarget = Invoke-Generator -Target @{ dnsHostName = 'dcblocked.mdilab.local' } -SensorAddresses @('10.10.1.10')
Assert-True 'a hashtable target generates no rule' ($hashTarget.Rules -eq 0) ("got $($hashTarget.Rules)")
Assert-True 'a hashtable target never becomes a computer in the generated code' (-not ($hashTarget.Code -match 'System\.Collections\.Hashtable')) 'the .NET type name was emitted as a computer'
Assert-True 'a hashtable target is charged to the unnameable warning' (Test-Warned $hashTarget 'carry no readable target')
Assert-True 'a hashtable target skips the section rather than emitting it' (Test-Warned $hashTarget 'no target could be determined')

$listTarget = Invoke-Generator -Target @('dca.mdilab.local', 'dcb.mdilab.local') -SensorAddresses @('10.10.1.10')
Assert-True 'a two-element target list generates no rule' ($listTarget.Rules -eq 0) ("got $($listTarget.Rules)")
Assert-True 'two targets never fuse into one computer name' (-not ($listTarget.Code -match 'dca\.mdilab\.local dcb\.mdilab\.local')) 'two controllers were fused into one host'
Assert-True 'a two-element target list is charged to the unnameable warning' (Test-Warned $listTarget 'carry no readable target')

$boolTarget = Invoke-Generator -Target $true -SensorAddresses @('10.10.1.10')
Assert-True 'a boolean target generates no rule' ($boolTarget.Rules -eq 0) ("got $($boolTarget.Rules)")
Assert-True 'a boolean target does not become the computer True' (-not ($boolTarget.Text -match "foreach \(\`$computer in @\(\s*'True'")) 'True was emitted as a computer'

$objTarget = Invoke-Generator -Target ([pscustomobject]@{ DnsHostName = 'dcblocked.mdilab.local' }) -SensorAddresses @('10.10.1.10')
Assert-True 'a PSCustomObject target generates no rule' ($objTarget.Rules -eq 0) ("got $($objTarget.Rules)")
Assert-True 'a PSCustomObject target never becomes a computer in the generated code' (-not ($objTarget.Code -match '@\{DnsHostName=')) 'the object rendering was emitted as a computer'

Write-Host "`nTHE DEFECT - an address nobody read must never become the -RemoteAddress scope"
$nestedAddr = Invoke-Generator -Target 'dcblocked.mdilab.local' -SensorAddresses @(, @('10.10.1.50', '10.10.1.60'))
Assert-True 'two addresses never fuse into one scope entry' (-not ($nestedAddr.Code -match '10\.10\.1\.50 10\.10\.1\.60')) 'two sensor addresses were fused into one'
$hashAddr = Invoke-Generator -Target 'dcblocked.mdilab.local' -SensorAddresses @(@{ ip = '10.10.1.50' })
Assert-True 'a hashtable address never renders into the scope' (-not ($hashAddr.Code -match 'System\.Collections\.Hashtable')) 'the .NET type name was emitted as a source address'

# Nothing readable anywhere: no usable address in Addresses AND no usable IP to fall back to. The
# section must be skipped, not emitted with an empty or invented scope - an inbound rule with no
# -RemoteAddress opens these ports to the entire network.
$noAddr = Invoke-Generator -Target 'dcblocked.mdilab.local' -SensorAddresses @(, @('10.10.1.50', '10.10.1.60')) -SensorIP $null
Assert-True 'a sensor with no readable address anywhere generates no rule' ($noAddr.Rules -eq 0) ("got $($noAddr.Rules)")
Assert-True 'the missing source address is the stated reason' (Test-Warned $noAddr 'no sensor source address could be determined')
Assert-True 'no fused address survives into the skipped run' (-not ($noAddr.Text -match '10\.10\.1\.50 10\.10\.1\.60'))

Write-Host "`nREFUSING THE OPPOSITE MISTAKE - nothing that used to be read stops being read"
$multiHomed = Invoke-Generator -Target 'dcblocked.mdilab.local' -SensorAddresses @('10.10.1.50', '10.10.1.60')
Assert-True 'a multi-homed sensor still generates the rules' ($multiHomed.Rules -eq 3) ("got $($multiHomed.Rules)")
Assert-True 'a multi-homed sensor keeps its first address' ($multiHomed.Text -match "'10\.10\.1\.50'")
Assert-True 'a multi-homed sensor keeps its second address' ($multiHomed.Text -match "'10\.10\.1\.60'") 'an address the sensor really has was dropped'

$oneElementAddr = Invoke-Generator -Target 'dcblocked.mdilab.local' -SensorAddresses @(, @('10.10.1.50'))
Assert-True 'a one-element collection address is still read' ($oneElementAddr.Text -match "'10\.10\.1\.50'") 'the accepted one-element shape was refused'
Assert-True 'a one-element collection address still generates the rules' ($oneElementAddr.Rules -eq 3) ("got $($oneElementAddr.Rules)")

$oneElementTarget = Invoke-Generator -Target @(, 'dcblocked.mdilab.local') -SensorAddresses @('10.10.1.10')
Assert-True 'a one-element collection target is still read' ($oneElementTarget.Text -match "'dcblocked\.mdilab\.local'") 'the accepted one-element shape was refused'
Assert-True 'a one-element collection target still generates the rules' ($oneElementTarget.Rules -eq 3) ("got $($oneElementTarget.Rules)")
Assert-True 'a one-element collection target raises no unnameable warning' (-not (Test-Warned $oneElementTarget 'carry no readable target'))

# A numeric-looking name is a STRING from the directory and has always been accepted; refusing it
# here would be the same over-correction in a different spelling.
$numericTarget = Invoke-Generator -Target '12345' -SensorAddresses @('10.10.1.10')
Assert-True 'a numeric STRING target is still read' ($numericTarget.Rules -eq 3) ("got $($numericTarget.Rules)")
Assert-True 'the numeric string target is named in the script' ($numericTarget.Text -match "'12345'")

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
