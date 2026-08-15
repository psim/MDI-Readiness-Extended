# The generated remediation script silently applied the Network Name Resolution firewall rules to only
# the FIRST sensor address whenever it fell back to the WMI transport.
#
# Invoke-MdiRemote rebuilds its arguments as literals before sending them through Win32_Process.Create,
# because a scriptblock crossing that boundary carries no session state. It emitted them as an @(...)
# literal:
#
#     $__mdiArgs = @(@('10.0.0.1','10.0.0.2'))
#     & {param($RemoteAddress) ...} @__mdiArgs
#
# An @(...) literal FLATTENS a nested array, so that collapses to a TWO-element array. Splatting it
# bound '10.0.0.1' to $RemoteAddress and stranded '10.0.0.2' in $args, which the scriptblock ignores.
#
# The NNR section is exactly that shape - one argument, the array of sensor addresses - so on WMI every
# generated rule was scoped to one sensor. Measured on the shipped generator: three rules, each with
# RemoteAddress '10.0.0.1' only, from a source array containing both. The run then printed
# "Remediation complete", so an operator with two or more sensors was told NNR was fixed while every
# sensor but the first stayed blocked. WinRM passes the array through Invoke-Command -ArgumentList and
# was never affected, which is why this only ever showed on the fallback path.
#
# The fix assigns into a PRE-SIZED [object[]] one slot at a time. The obvious shorter fix - wrapping
# each literal with the comma operator, @((,$a),(,$b)) - is WRONG in the other direction and was
# measured so: it preserves a lone array argument but wraps every argument of a MULTI-argument call in
# an extra layer, delivering System.Object[] to each parameter. Both directions are pinned below.
#
# Behavioural, not textual: the generated script is EXECUTED with the WMI cmdlets doubled, its
# -EncodedCommand payload is decoded and run, and the assertions read the RemoteAddress that
# New-NetFirewallRule actually received.

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
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-NnrRecord {
    param([string] $Id, [string] $Protocol, [int] $Port)
    [PSCustomObject]@{
        Id = $Id; Name = $Id; Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'
        Protocol = $Protocol; Port = $Port; Target = 'workstation.contoso.test'; TargetIP = '10.0.0.50'
        Applicable = $true; Success = $false; Detail = 'Connection refused'
    }
}

function New-SensorServer {
    param([string] $Fqdn, [string] $Address, [object[]] $Records = @())
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.test'; IP = $Address; Addresses = @($Address)
        Unreachable = $false; PartialFailure = $false; SensorVersion = '2.246.0'
        RequiredPorts = $(if ($Records.Count) { $false } else { $true })
        Details = [ordered]@{
            RequiredPortsDetails = [PSCustomObject]@{
                FailedRequired = @()
                NnrFailedTargets = $(if ($Records.Count) { @('workstation.contoso.test') } else { @() })
                Results = @($Records)
            }
            SensorHealthDetails = [PSCustomObject]@{ Installed = $true }
        }
    }
}

$cleanDomain = [PSCustomObject]@{
    Domain = 'contoso.test'
    ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
    ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
    AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
    DeletedObjects = [PSCustomObject]@{
        isDeletedObjectsPermissionOk = $true
        details = [PSCustomObject]@{ Container = 'CN=Deleted Objects,DC=contoso,DC=test'; Detail = 'Permission present' }
    }
    DeletedObjectsMeasured = $true
}

$report = [PSCustomObject]@{
    Domain = 'contoso.test'; Forest = 'contoso.test'; DomainsInScope = @('contoso.test')
    DomainControllers = @(
        (New-SensorServer -Fqdn 'dc1.contoso.test' -Address '10.0.0.1' -Records @(
                (New-NnrRecord -Id 'NnrRpc' -Protocol 'TCP' -Port 135),
                (New-NnrRecord -Id 'NnrNetBios' -Protocol 'UDP' -Port 137),
                (New-NnrRecord -Id 'NnrRdp' -Protocol 'TCP' -Port 3389)
            )),
        (New-SensorServer -Fqdn 'dc2.contoso.test' -Address '10.0.0.2')
    )
    CAServers = @(); EntraConnectServers = @(); DomainAuditing = @($cleanDomain)
    LdapPlanGapDomains = @(); NnrUnresolvedTargets = @()
}

$generatedFile = Join-Path $env:TEMP ('mdi-wmiargs-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
New-mdiRemediationScript -ReportData $report -FilePath $generatedFile 3>$null | Out-Null
$generatedText = [IO.File]::ReadAllText($generatedFile)
Remove-Item -LiteralPath $generatedFile -Force -ErrorAction SilentlyContinue

$genErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($generatedText, [ref]$null, [ref]$genErrors)

# Doubles. The decoded -EncodedCommand payload is executed for real, so the assertions read what the
# firewall cmdlet actually received rather than what the emitted text appears to say.
$script:capturedStatus = 'FAIL: payload did not run'
$script:capturedRules = New-Object System.Collections.ArrayList
$script:innerArgs = New-Object System.Collections.ArrayList

function Set-Doubles {
    Set-Item -Path function:script:Set-Content -Value {
        param([Parameter(ValueFromPipeline = $true)] $InputObject, $Path, $Encoding)
        process { $script:capturedStatus = [string] $InputObject }
    }
    Set-Item -Path function:script:Get-NetFirewallRule -Value { param($Name, $ErrorAction) $null }
    Set-Item -Path function:script:New-NetFirewallRule -Value {
        param($Name, $DisplayName, $Direction, $Action, $Protocol, $LocalPort, $RemoteAddress, $Profile, $Enabled)
        [void] $script:capturedRules.Add([PSCustomObject]@{
                Name = [string] $Name; LocalPort = [string] $LocalPort
                RemoteCount = @($RemoteAddress).Count
                RemoteAddress = (@($RemoteAddress) -join '|')
                ExtraCount = @($args).Count
            })
    }
    Set-Item -Path function:script:Invoke-WmiMethod -Value {
        param($ComputerName, $Class, $Name, $ArgumentList, $ErrorAction)
        $encoded = ([string] $ArgumentList -split '\s+')[-1]
        $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
        & ([scriptblock]::Create($decoded))
        [PSCustomObject]@{ ReturnValue = 0; ProcessId = 4242 }
    }
    Set-Item -Path function:script:Get-WmiObject -Value { param($ComputerName, $Class, $Filter, $ErrorAction) $null }
    Set-Item -Path function:script:Get-Content -Value { param($Path, $ErrorAction, [switch] $Raw) $script:capturedStatus }
    Set-Item -Path function:script:Remove-Item -Value { param($Path, [switch] $Force, $ErrorAction) }
}
function Clear-Doubles {
    foreach ($n in 'Set-Content', 'Get-NetFirewallRule', 'New-NetFirewallRule', 'Invoke-WmiMethod',
        'Get-WmiObject', 'Get-Content', 'Remove-Item') {
        Microsoft.PowerShell.Management\Remove-Item -Path ('function:script:' + $n) -Force -ErrorAction SilentlyContinue
    }
}

'[wmi args] every NNR rule is scoped to EVERY sensor address, not just the first'
Assert-That 'the generated script parses' (@($genErrors).Count -eq 0) "(got $(@($genErrors).Count))"
Assert-That 'the source array carries both sensors' (
    ($generatedText -match "'10\.0\.0\.1'") -and ($generatedText -match "'10\.0\.0\.2'")
)

Set-Doubles
try {
    $runOutput = @(& ([scriptblock]::Create($generatedText)) -Transport WMI 3>&1 4>&1 5>&1 6>&1 |
            ForEach-Object { [string] $_ })
} finally { Clear-Doubles }

Assert-That 'firewall rules were created' ($script:capturedRules.Count -gt 0) "(got $($script:capturedRules.Count))"
# THE DEFECT: each rule received only '10.0.0.1'.
$shortRules = @($script:capturedRules | Where-Object { $_.RemoteCount -ne 2 })
Assert-That 'every rule received BOTH sensor addresses' ($shortRules.Count -eq 0) (
    "(short rules: " + (@($shortRules | ForEach-Object { $_.Name + '=' + $_.RemoteAddress }) -join ', ') + ")"
)
Assert-That '  ...in the right order and values' (
    @($script:capturedRules | Where-Object { $_.RemoteAddress -eq '10.0.0.1|10.0.0.2' }).Count -eq $script:capturedRules.Count
) "(got: $(@($script:capturedRules | ForEach-Object { $_.RemoteAddress }) -join ' / '))"
# Nothing may be stranded in $args - that is where the lost address went.
Assert-That 'no argument is stranded in $args' (
    @($script:capturedRules | Where-Object { $_.ExtraCount -ne 0 }).Count -eq 0
)
Assert-That 'the run still reports completion' (@($runOutput | Where-Object { $_ -match 'Remediation complete' }).Count -gt 0)

''
'[wmi args] the serializer round-trips every argument shape'
# Guards the opposite error: a fix that preserves a lone array but wraps each argument of a
# multi-argument call in an extra layer. Driven through the REAL generated Invoke-MdiRemote.
$genAst = [System.Management.Automation.Language.Parser]::ParseInput($generatedText, [ref]$null, [ref]$null)
$remoteFn = @($genAst.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-MdiRemote'
        }, $true))
Assert-That 'Invoke-MdiRemote is present in the generated script' ($remoteFn.Count -eq 1) "(got $($remoteFn.Count))"

if ($remoteFn.Count -eq 1) {
    Invoke-Expression $remoteFn[0].Extent.Text
    $script:mdiTransport = @{}
    $Transport = 'WMI'

    $probe = {
        param($First, $Second)
        $script:innerArgs.Add([PSCustomObject]@{
                FirstCount = @($First).Count; FirstValue = (@($First) -join '|')
                SecondCount = @($Second).Count; SecondValue = (@($Second) -join '|')
                ExtraCount = @($args).Count
            }) | Out-Null
    }

    $shapes = @(
        @{ Name = 'one array';      Args = (, @('10.0.0.1', '10.0.0.2')); F = '10.0.0.1|10.0.0.2'; S = '' }
        @{ Name = 'one scalar';     Args = @('solo');                     F = 'solo';              S = '' }
        @{ Name = 'array + scalar'; Args = @(@('a', 'b'), 'tail');        F = 'a|b';               S = 'tail' }
        @{ Name = 'scalar + array'; Args = @('head', @('c', 'd'));        F = 'head';              S = 'c|d' }
        @{ Name = 'two arrays';     Args = @(@('a', 'b'), @('c', 'd'));   F = 'a|b';               S = 'c|d' }
    )

    foreach ($shape in $shapes) {
        $script:innerArgs.Clear()
        Set-Doubles
        try {
            Invoke-MdiRemote -ComputerName 'dc1.contoso.test' -ScriptBlock $probe -ArgumentList $shape.Args | Out-Null
        } catch {
            # recorded by the assertion below as a missing result
        } finally { Clear-Doubles }

        if ($script:innerArgs.Count -ne 1) {
            Assert-That ("shape '$($shape.Name)' reached the scriptblock") $false "(results: $($script:innerArgs.Count))"
        } else {
            $r = $script:innerArgs[0]
            Assert-That ("shape '$($shape.Name)' delivers its arguments intact") (
                $r.FirstValue -eq $shape.F -and $r.SecondValue -eq $shape.S -and $r.ExtraCount -eq 0
            ) "(first=[$($r.FirstValue)] second=[$($r.SecondValue)] extra=$($r.ExtraCount))"
        }
    }
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
