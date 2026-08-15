# A server with NO SENSOR was treated as a sensor when choosing which addresses may send NNR probes.
#
# Get-mdiSensorVersion returns three things that are not versions, and they do not mean the same:
#   ''  / 'N/A'       the version could not be READ
#   'Not installed'   the WMI query was ANSWERED and there is no AATPSensor service on that machine
#
# The NNR remediation's sensor test excluded only empty and 'N/A', so 'Not installed' - the producer's
# positive statement that the machine has no sensor - counted as a sensor. Two consequences, both
# measured:
#
#  1. A sensorless server's address was written into the inbound firewall allow list on every NNR
#     target. The rules open TCP 135, UDP 137 and TCP 3389 inbound; the source list is the only thing
#     keeping that narrow, and the code comment beside it says so: "using every server in the report
#     opened those ports to certification authorities, Entra Connect servers and any other scanned
#     machine that will never send an NNR probe."
#
#  2. Worse, because the sensor list was then never empty, the pre-deployment fallback that scopes the
#     rules to the domain controllers NEVER RAN. An estate with no sensor deployed anywhere emitted
#     "# Sources (3): dc-none.contoso.com, ca1.contoso.com, ec1.contoso.com" and opened those three
#     ports inbound to a certification authority and an Entra Connect server.
#
# 'Not installed' is a main-path producer value, written by Get-mdiSensorVersion at the point where
# the service query succeeds and finds nothing - not an invented fixture value.

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

'[sensor presence] the predicate tells "no sensor" apart from "a version"'
Assert-That "'Not installed' is not a sensor version" (-not (Test-mdiSensorVersionPresent -Version 'Not installed'))
Assert-That "'N/A' is not a sensor version" (-not (Test-mdiSensorVersionPresent -Version 'N/A'))
Assert-That 'an empty string is not a sensor version' (-not (Test-mdiSensorVersionPresent -Version ''))
Assert-That 'whitespace is not a sensor version' (-not (Test-mdiSensorVersionPresent -Version '   '))
Assert-That '$null is not a sensor version' (-not (Test-mdiSensorVersionPresent -Version $null))
Assert-That 'a real version IS a sensor version' (Test-mdiSensorVersionPresent -Version '2.246.0')
Assert-That '  ...with surrounding whitespace too' (Test-mdiSensorVersionPresent -Version '  2.246.0  ')

# Built from the REAL probe table so the AtLeastOne requirement and the wording are the tool's own.
function New-RealNnrRec {
    param($Target)
    @($settings.RequiredPorts | Where-Object { $_.Group -eq 'NNR' } | ForEach-Object {
            [PSCustomObject]@{ Id = $_.Id; Name = $_.Name; Protocol = $_.Protocol; Port = $_.Port
                Scope = $_.Scope; Group = $_.Group; Requirement = $_.Requirement
                Target = $Target; TargetIP = '10.0.0.50'; Applicable = $true
                Success = $false; Detail = 'Connection refused'
            }
        })
}

function New-Srv {
    param($Fqdn, $Ip, $SensorVersion, $Results = @(), $Installed = $null)
    $health = if ($null -eq $Installed) { [PSCustomObject]@{} } else { [PSCustomObject]@{ Installed = $Installed } }
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; IP = $Ip; Addresses = @($Ip)
        Unreachable = $false; PartialFailure = $false
        SensorVersion = $SensorVersion; RequiredPorts = $false
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @('x'); NnrFailedTargets = @('wks1.contoso.com'); Results = $Results }
            SensorHealthDetails  = $health
        }
    }
}

function Get-Sources {
    param($Dcs = @(), $Cas = @(), $Ecs = @())
    $report = [PSCustomObject]@{
        DomainControllers = @($Dcs); CAServers = @($Cas); EntraConnectServers = @($Ecs)
        DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com'
    }
    $out = Join-Path $env:TEMP ('mdi-sensrc-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    New-mdiRemediationScript -ReportData $report -FilePath $out 3>$null | Out-Null
    $g = [IO.File]::ReadAllText($out)
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    $lines = $g -split "`r?`n"
    $addr = @()
    for ($k = 0; $k -lt $lines.Count; $k++) {
        if ($lines[$k] -match '^\s*\$sensorAddresses\s*=\s*@\(') {
            for ($j = $k + 1; $j -lt $lines.Count; $j++) {
                if ($lines[$j] -match '^\s*\)') { break }
                foreach ($m in [regex]::Matches($lines[$j], "'([^']*)'")) { $addr += $m.Groups[1].Value }
            }
            break
        }
    }
    [PSCustomObject]@{
        Comment   = (@($lines | Where-Object { $_ -match '^\s*#\s*Sources \(' }) -join ' ')
        Addresses = @($addr)
        Text      = $g
    }
}

''
'[sensor sources] a sensorless server is not an allowed NNR source'
$mixed = Get-Sources -Dcs @(
    (New-Srv 'dc-ok.contoso.com'   '10.0.0.1' '2.246.0'       (New-RealNnrRec -Target 'wks1.contoso.com'))
    (New-Srv 'dc-none.contoso.com' '10.0.0.2' 'Not installed')
)
Assert-That 'the real sensor is allowed' ($mixed.Addresses -contains '10.0.0.1') "(got: $($mixed.Addresses -join ','))"
Assert-That 'the sensorless server is NOT allowed' ($mixed.Addresses -notcontains '10.0.0.2') "(got: $($mixed.Addresses -join ','))"
Assert-That 'the sensorless server is not named as a source' ($mixed.Comment -notmatch 'dc-none') "(comment: $($mixed.Comment))"

''
'[sensor sources] with no sensor anywhere the DC-only fallback still runs'
# This is the half that made the defect dangerous: a non-empty sensor list suppressed the fallback,
# so a CA and an Entra Connect server became allowed sources on an estate with no sensor at all.
$none = Get-Sources -Dcs @(
    (New-Srv 'dc-none.contoso.com' '10.0.0.2' 'Not installed' (New-RealNnrRec -Target 'wks1.contoso.com'))
) -Cas @(
    (New-Srv 'ca1.contoso.com' '10.0.0.8' 'Not installed')
) -Ecs @(
    (New-Srv 'ec1.contoso.com' '10.0.0.9' 'Not installed')
)
Assert-That 'the domain controller is the source' ($none.Addresses -contains '10.0.0.2') "(got: $($none.Addresses -join ','))"
Assert-That 'the certification authority is NOT a source' ($none.Addresses -notcontains '10.0.0.8') "(got: $($none.Addresses -join ','))"
Assert-That 'the Entra Connect server is NOT a source' ($none.Addresses -notcontains '10.0.0.9') "(got: $($none.Addresses -join ','))"
Assert-That 'neither is named in the comment' (($none.Comment -notmatch 'ca1') -and ($none.Comment -notmatch 'ec1')) "(comment: $($none.Comment))"

''
'[sensor sources] the positive signals still work'
# An unread version ('N/A') is not a sensor either - the existing behaviour, pinned so the narrowing
# above cannot be "simplified" back into conflating the two markers.
$naCase = Get-Sources -Dcs @(
    (New-Srv 'dc-ok.contoso.com'   '10.0.0.1' '2.246.0' (New-RealNnrRec -Target 'wks1.contoso.com'))
    (New-Srv 'dc-unread.contoso.com' '10.0.0.3' 'N/A')
)
Assert-That 'a server whose version could not be read is not a source' ($naCase.Addresses -notcontains '10.0.0.3') "(got: $($naCase.Addresses -join ','))"
# ...but the health check finding the service IS a sensor, even with no version.
$healthCase = Get-Sources -Dcs @(
    (New-Srv 'dc-ok.contoso.com' '10.0.0.1' '2.246.0' (New-RealNnrRec -Target 'wks1.contoso.com'))
    (New-Srv 'dc-svc.contoso.com' '10.0.0.4' 'N/A' @() $true)
)
Assert-That 'a server whose sensor SERVICE was found is a source' ($healthCase.Addresses -contains '10.0.0.4') "(got: $($healthCase.Addresses -join ','))"
# A sensorless server whose health check explicitly says the service is absent stays out.
$notInstalledHealth = Get-Sources -Dcs @(
    (New-Srv 'dc-ok.contoso.com' '10.0.0.1' '2.246.0' (New-RealNnrRec -Target 'wks1.contoso.com'))
    (New-Srv 'dc-off.contoso.com' '10.0.0.5' 'Not installed' @() $false)
)
Assert-That 'a server the health check says has no sensor stays out' ($notInstalledHealth.Addresses -notcontains '10.0.0.5') "(got: $($notInstalledHealth.Addresses -join ','))"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
