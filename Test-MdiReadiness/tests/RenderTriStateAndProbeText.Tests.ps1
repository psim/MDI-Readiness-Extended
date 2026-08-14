<#
    Behavioural regression tests for the w21/w22 defects.

    Every test here asserts what a function RETURNS or RENDERS. None of them greps the source: a test
    that matches source text passes while the defect is reintroduced, which has happened on this
    project before. Each test is mutation-checked - the defect is put back and the test must go red.
#>

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:failed++; Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red }
}

Write-Host 'RenderTriStateAndProbeText.Tests.ps1' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------
# Compress-mdiScriptText must not change the VALUE of a multi-line string literal.
# Asserted by EXECUTING both copies and comparing what they return, not by inspecting the text.
# ---------------------------------------------------------------------------------------------
$paragraph = @'
function Get-MdiTestMessage {
    @"
The sensor could not be reached.

Open TCP 443 outbound and re-run.
"@
}
'@
$compressedParagraph = Compress-mdiScriptText -ScriptText $paragraph
$originalValue = & ([scriptblock]::Create($paragraph + "`nGet-MdiTestMessage"))
$compressedValue = & ([scriptblock]::Create($compressedParagraph + "`nGet-MdiTestMessage"))
Assert-True 'Compress-mdiScriptText keeps a blank line inside a here-string' `
    ($originalValue -eq $compressedValue) `
    ("original=[{0}] compressed=[{1}]" -f ($originalValue -replace "`r?`n", '<NL>'), ($compressedValue -replace "`r?`n", '<NL>'))

$padded = "function Get-MdiTestPad {`n    @`"`nvalue   `n`"@`n}"
$compressedPadded = Compress-mdiScriptText -ScriptText $padded
Assert-True 'Compress-mdiScriptText keeps trailing whitespace inside a here-string' `
    ((& ([scriptblock]::Create($padded + "`nGet-MdiTestPad"))) -eq (& ([scriptblock]::Create($compressedPadded + "`nGet-MdiTestPad"))))

# Control: it must still actually compress code that is NOT inside a literal.
$noisy = "function Get-MdiTestTwo {`n    # a comment that must go`n`n        `$x = 2`n`n    `$x`n}"
$compressedNoisy = Compress-mdiScriptText -ScriptText $noisy
Assert-True 'Compress-mdiScriptText still strips comments, blank lines and indentation outside literals' `
    ($compressedNoisy.Length -lt $noisy.Length -and $compressedNoisy -notmatch 'a comment that must go' -and
        $compressedNoisy -notmatch '(?m)^\s+\$x' -and (& ([scriptblock]::Create($compressedNoisy + "`nGet-MdiTestTwo"))) -eq 2) `
    ("compressed=[{0}]" -f ($compressedNoisy -replace "`n", '<NL>'))

# ---------------------------------------------------------------------------------------------
# Test-mdiProbeWasMeasured is the single fact "did this probe actually run".
# ---------------------------------------------------------------------------------------------
Assert-True 'a probe that applied and reported a result is measured' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $true; Success = $true; Detail = 'Connected in 3 ms' })) -eq $true)
# Success must be a REAL boolean, not merely present. A record that applied and carries no not-tested
# marker but whose Success normalised to $null has produced no result, and counting it as measured
# turned it into a MEASURED BLOCKED PORT - an operator sent to open a firewall port on a probe that
# never returned an answer. Verified against a live lab report: 202 of 220 real records carry a
# boolean Success and the 18 that do not are all already not-applicable "Not tested" rows.
Assert-True 'a probe with no boolean result is NOT measured' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $true; Success = $null; Detail = 'Connected in 3 ms' })) -eq $false)
Assert-True 'a probe whose detail carries a not-tested marker is NOT measured' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $true; Detail = 'Not tested - access denied' })) -eq $false)
Assert-True 'a probe with Applicable $null is NOT measured' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $null; Detail = 'Connection refused' })) -eq $false)
# Applicable is pinned INDEPENDENTLY of the boolean-Success rule. Once the predicate also began
# requiring a real boolean Success, a record with Applicable $null and no Success was rejected by
# whichever guard ran first - so mutating the Applicable test alone stopped changing the answer and
# the mutation harness correctly reported it as no longer caught. This record carries a genuine
# measured result, so ONLY the Applicable guard can reject it: "we do not know whether this probe
# applied" is not the same as "it applied and failed", and treating it as the latter is what painted
# an unmeasured record red in the ports-that-need-attention table.
Assert-True 'a probe with Applicable $null is NOT measured even when it carries a real result' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $null; Success = $false; Detail = 'Connection refused' })) -eq $false)
Assert-True 'and the same record with Applicable $true IS measured' `
    ((Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{ Applicable = $true; Success = $false; Detail = 'Connection refused' })) -eq $true)
Assert-True 'a null record is NOT measured' ((Test-mdiProbeWasMeasured -Record $null) -eq $false)

# ---------------------------------------------------------------------------------------------
# The NNR bar chart must not paint an unmeasured method as a measured failure.
# The assertion is on the RENDERED bar tone and caption, and on agreement with the KPI on the same page.
# ---------------------------------------------------------------------------------------------
function New-NnrServer {
    # Success is a PARAMETER, because "did this probe produce a result" is exactly what the tri-state
    # under test turns on. It used to be hard-coded to $null, which made the "measured failure" control
    # case unmeasurable by construction - the control could never have gone red however the code
    # behaved, so it proved nothing.
    param([string] $Detail, [bool] $Applicable = $true, $Success = $null)
    [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
        Details = [ordered]@{
            RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom = 'dc1.contoso.com'; FailedRequired = @(); NnrFailedTargets = @()
                Results = @(
                    [PSCustomObject]@{ Id = 'NnrNetBios'; Name = 'NNR - NetBIOS'; Protocol = 'UDP'; Port = 137
                        Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'
                        Target = 'ws1.contoso.com'; TargetIP = '10.0.0.9'
                        Applicable = $Applicable; Success = $Success; Detail = $Detail }
                )
            }
        }
    }
}

$unmeasuredReport = [PSCustomObject]@{
    DomainControllers = @(New-NnrServer -Detail 'Not tested - access is denied')
    CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com'); Forest = 'contoso.com'
}
$unmeasuredStats = Get-mdiReportStatistics -ReportData $unmeasuredReport
$unmeasuredHtml = Get-mdiOverviewHtml -Statistics $unmeasuredStats -ReportData $unmeasuredReport
$nnrSection = [regex]::Match($unmeasuredHtml, '<h3>Name resolution success rate by method</h3>.*?</section>').Value

Assert-True 'the statistics count an unmeasured NNR target as untested' `
    ([int] $unmeasuredStats.NnrUntested -eq 1) ("NnrUntested={0}" -f $unmeasuredStats.NnrUntested)
Assert-True 'an all-unmeasured NNR method bar is toned neutral, never red' `
    ($nnrSection -notmatch 'bar-fill bad') $nnrSection
Assert-True 'an all-unmeasured NNR method bar declares what was not read' `
    ($nnrSection -match 'not read') $nnrSection

# Control: a method that really WAS measured and failed must still be red.
$measuredReport = [PSCustomObject]@{
    DomainControllers = @(New-NnrServer -Detail 'Connection timed out' -Success $false)
    CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com'); Forest = 'contoso.com'
}
$measuredStats = Get-mdiReportStatistics -ReportData $measuredReport
$measuredSection = [regex]::Match((Get-mdiOverviewHtml -Statistics $measuredStats -ReportData $measuredReport),
    '<h3>Name resolution success rate by method</h3>.*?</section>').Value
Assert-True 'a measured NNR failure is still drawn red' `
    ($measuredSection -match 'bar-fill bad') $measuredSection

# ---------------------------------------------------------------------------------------------
# Protocol and Port reach the HTML through the encoder like every other environment-backed value.
# ---------------------------------------------------------------------------------------------
$hostile = 'X<svg onload="a(1)">&"Y'
$hostileServer = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
    Details = [ordered]@{
        RequiredPortsDetails = [PSCustomObject]@{
            ProbedFrom = 'dc1.contoso.com'; FailedRequired = @(); NnrFailedTargets = @()
            Results = @(
                [PSCustomObject]@{ Id = 'OrphanFail'; Name = $hostile; Protocol = $hostile; Port = $hostile
                    Scope = 'DomainController'; Group = ''; Requirement = 'Required'
                    Target = $hostile; TargetIP = '10.0.0.5'
                    Applicable = $true; Success = $false; Detail = $hostile }
                [PSCustomObject]@{ Id = 'OrphanSkip'; Name = $hostile; Protocol = $hostile; Port = $hostile
                    Scope = 'DomainController'; Group = ''; Requirement = 'Required'
                    Target = $hostile; TargetIP = '10.0.0.6'
                    Applicable = $true; Success = $null; Detail = 'Not tested - access is denied' }
            )
        }
    }
}
$portsHtml = Get-mdiRequiredPortsHtml -Server @($hostileServer)
Assert-True 'no unencoded markup from a port record reaches the required-ports HTML' `
    ($portsHtml -notmatch [regex]::Escape('<svg onload=')) `
    (([regex]::Matches($portsHtml, '.{0,90}<svg onload=.{0,20}') | ForEach-Object { $_.Value }) -join ' || ')
Assert-True 'the hostile value is present in encoded form (it was rendered, not dropped)' `
    ($portsHtml -match [regex]::Escape('&lt;svg onload='))

# ---------------------------------------------------------------------------------------------
# Tri-state render sites: only a value that NORMALISES to a boolean may be reported as measured.
# ---------------------------------------------------------------------------------------------
$unmeasuredValues = @($null, '', 'Unknown', 'N/A')

foreach ($value in $unmeasuredValues) {
    $label = if ($null -eq $value) { '$null' } elseif ($value -eq '') { "''" } else { $value }

    $v3Server = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; SensorV3Ready = $value
        Details = [ordered]@{ SensorV3ReadyDetails = [PSCustomObject]@{
                Checks = @(); SensorState = 'v2.x'; MigrationEligible = $null; Blockers = @() } }
    }
    $v3Html = Get-mdiSensorV3Html -Server @($v3Server)
    $v3Row = [regex]::Match($v3Html, '<tr><td style="text-align:left"><b>Meets the v3\.x prerequisites</b>.*?</tr>').Value
    Assert-True ("SensorV3Ready of {0} renders as not tested, not as a red No" -f $label) `
        ($v3Row -match 'Not tested' -and $v3Row -notmatch 'class="red"') $v3Row

    $healthServer = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; SensorHealth = $value; SensorVersion = $null
        Details = [ordered]@{ SensorHealthDetails = [PSCustomObject]@{
                Installed = $value; SensorService = ''; SensorStartMode = ''; UpdaterService = ''
                Detail = 'query returned no usable value' } }
    }
    $healthHtml = Get-mdiSensorHealthHtml -Server @($healthServer)
    Assert-True ("Sensor Installed of {0} renders as not tested, not as No" -f $label) `
        ($healthHtml -match 'Not tested') $healthHtml

    $timeServer = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; TimeSync = $value
        Details = [ordered]@{ TimeSyncDetails = [PSCustomObject]@{
                SkewSeconds = $null; RemoteUtc = ''; Detail = 'query returned no usable value' } }
    }
    $timeHtml = Get-mdiTimeSyncHtml -Server @($timeServer)
    Assert-True ("TimeSync of {0} renders as not tested, not as a red No" -f $label) `
        ($timeHtml -match 'Not tested' -and $timeHtml -notmatch 'class="red"') $timeHtml
}

# Controls: a real measurement must still render as the measurement it is.
$v3FalseHtml = Get-mdiSensorV3Html -Server @([PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; SensorV3Ready = $false
        Details = [ordered]@{ SensorV3ReadyDetails = [PSCustomObject]@{
                Checks = @(); SensorState = 'v2.x'; MigrationEligible = $null; Blockers = @() } } })
Assert-True 'a measured SensorV3Ready of $false still renders a red No' `
    (([regex]::Match($v3FalseHtml, '<tr><td style="text-align:left"><b>Meets the v3\.x prerequisites</b>.*?</tr>').Value) -match 'class="red">No')

$timeFalseHtml = Get-mdiTimeSyncHtml -Server @([PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; TimeSync = $false
        Details = [ordered]@{ TimeSyncDetails = [PSCustomObject]@{ SkewSeconds = 400; RemoteUtc = ''; Detail = 'skew' } } })
Assert-True 'a measured TimeSync of $false still renders a red No' ($timeFalseHtml -match 'class="red">No')

$timeTrueHtml = Get-mdiTimeSyncHtml -Server @([PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; TimeSync = $true
        Details = [ordered]@{ TimeSyncDetails = [PSCustomObject]@{ SkewSeconds = 1; RemoteUtc = ''; Detail = 'ok' } } })
Assert-True 'a measured TimeSync of $true still renders a green Yes' ($timeTrueHtml -match 'class="green">Yes')

$healthFalseHtml = Get-mdiSensorHealthHtml -Server @([PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; SensorHealth = $null; SensorVersion = $null
        Details = [ordered]@{ SensorHealthDetails = [PSCustomObject]@{
                Installed = $false; SensorService = ''; SensorStartMode = ''; UpdaterService = ''; Detail = 'no sensor' } } })
Assert-True 'a measured Installed of $false still renders No, not Not tested' `
    ($healthFalseHtml -match '>No<' -and $healthFalseHtml -notmatch 'Not tested') $healthFalseHtml

# A JSON round trip stores booleans as the strings 'True'/'False'; those are measurements and must survive.
$healthStringHtml = Get-mdiSensorHealthHtml -Server @([PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; SensorHealth = 'True'; SensorVersion = '2.0'
        Details = [ordered]@{ SensorHealthDetails = [PSCustomObject]@{
                Installed = 'True'; SensorService = 'Running'; SensorStartMode = 'Auto'; UpdaterService = 'Running'; Detail = 'ok' } } })
Assert-True 'a round-tripped Installed of the string True still renders Yes' `
    ($healthStringHtml -match 'class="green">Yes') $healthStringHtml

# ---------------------------------------------------------------------------------------------
# Sensor v3.x cumulative-update check against a build the script does not know.
#
# The CU table is keyed by OS build. A build newer than every entry cannot be compared against a
# known-good revision, and the detail beside it tells the operator to verify the update level by
# hand. It must therefore NOT render as a green pass - a cell claiming a pass next to an instruction
# to go and check manually is the report contradicting itself.
#
# It is an INFORMATIONAL N/A rather than a "Not tested" one, so it deliberately leaves the overall
# verdict intact: build numbers only increase, so a build past the table is almost certainly patched
# past it too, and turning every brand-new build into an unknown verdict would be noise. This test
# pins BOTH halves of that decision so neither can drift silently.
# ---------------------------------------------------------------------------------------------
function New-V3CuStub {
    param([int] $ProductType, [string] $Build, [int] $Ubr)
    Set-Item -Path function:script:Get-WmiObject -Value ([scriptblock]::Create(@"
param(`$ComputerName, `$Namespace, `$Class, `$Property, `$Filter, `$Query, `$ErrorAction)
if (`$Class -eq 'Win32_Service' -and `$Filter -match "= 'Sense'") {
    return [PSCustomObject]@{ Name = 'Sense'; State = 'Running'; StartMode = 'Auto'; PathName = 'C:\MsSense.exe' }
}
[PSCustomObject]@{ Caption = 'Windows Server test'; ProductType = $ProductType; BuildNumber = '$Build'; Version = '10.0.$Build' }
"@))
    Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value ([scriptblock]::Create(
            "param(`$ComputerName,`$Key,`$Value) [PSCustomObject]@{ Readable=`$true; Value=`$(if(`$Value -eq 'UBR'){$Ubr}else{1}); Error=`$null }"))
    Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'N/A' }
    Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
        param($ComputerName, $ServiceName)
        $svc = if ($ServiceName -eq 'Sense') { [PSCustomObject]@{ State = 'Running'; StartMode = 'Auto' } } else { $null }
        [PSCustomObject]@{ Service = $svc; Readable = $true; Error = $null }
    }
}
function Get-V3CuCase {
    param([string] $Build, [int] $Ubr)
    New-V3CuStub -ProductType 2 -Build $Build -Ubr $Ubr
    $r = Get-mdiSensorV3Readiness -ComputerName 'dc.contoso.com'
    [PSCustomObject]@{
        Ready = $r.isSensorV3Ready
        Cu    = @($r.details.Checks | Where-Object { $_.Name -like '*cumulative update*' })[0]
        Html  = Get-mdiSensorV3Html -Server @([PSCustomObject]@{ FQDN = 'dc.contoso.com'; SensorV3Ready = $r.isSensorV3Ready; Details = [ordered]@{ SensorV3ReadyDetails = $r.details } })
    }
}

# A build far beyond anything the table can know about.
$unknownBuild = ((@($settings.SensorV3.JulyCumulativeUpdate.Keys) | Measure-Object -Maximum).Maximum + 10000)
$newer = Get-V3CuCase -Build ([string] $unknownBuild) -Ubr 12345
Assert-True 'an OS build newer than the CU table does not report the update as a measured pass' `
    ($newer.Cu.Status -ne $true) ("status=[{0}]" -f $newer.Cu.Status)
Assert-True 'and says so in the detail, pointing the operator at a manual check' `
    ([string] $newer.Cu.Detail -match 'verify the cumulative update level manually') ([string] $newer.Cu.Detail)
Assert-True 'its cell is not rendered green' `
    (([regex]::Match($newer.Html, '<tr><td style="text-align:left">July 2026 or later cumulative update.*?</tr>').Value) -notmatch 'class="green"') `
    ([regex]::Match($newer.Html, '<tr><td style="text-align:left">July 2026 or later cumulative update.*?</tr>').Value)
# The other half of the decision: an informational N/A must not destabilise the verdict.
Assert-True 'a newer build is still not treated as an unreadable server' `
    ($newer.Cu.Measured -eq $true) ("measured=[{0}]" -f $newer.Cu.Measured)
Assert-True 'and raises no blocker' (@($newer.Cu | Where-Object { $_.Status -eq $false }).Count -eq 0)

$known = Get-V3CuCase -Build ([string] ((@($settings.SensorV3.JulyCumulativeUpdate.Keys) | Sort-Object)[-1])) -Ubr 999999
Assert-True 'control: a known build patched past the July 2026 level is ready' `
    ($known.Ready -eq $true -and $known.Cu.Status -eq $true) ("ready=[{0}] cu=[{1}]" -f $known.Ready, $known.Cu.Status)

$behind = Get-V3CuCase -Build ([string] ((@($settings.SensorV3.JulyCumulativeUpdate.Keys) | Sort-Object)[-1])) -Ubr 1
Assert-True 'control: a known build behind the July 2026 level is still blocked' `
    ($behind.Ready -eq $false -and $behind.Cu.Status -eq $false) ("ready=[{0}] cu=[{1}]" -f $behind.Ready, $behind.Cu.Status)

Remove-Item function:script:Get-WmiObject, function:script:Get-mdiRemoteRegistryResult,
function:script:Get-mdiCaptureComponent, function:script:Get-mdiServiceStateResult -ErrorAction SilentlyContinue

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }