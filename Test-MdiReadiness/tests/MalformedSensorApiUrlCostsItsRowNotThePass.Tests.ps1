# A MALFORMED SENSOR API URL DESTROYED THE WHOLE PORT PROBE PASS INSTEAD OF COSTING ONE ROW.
#
# New-mdiPortProbePlan builds the cloud probe's target by pasting the operator's -WorkspaceName
# straight into a hostname:
#
#     $sensorApiUrl = 'https://{0}' -f ($settings.SensorApiUrlFormat -f $WorkspaceName.Trim())
#
# with SensorApiUrlFormat = '{0}sensorapi.atp.azure.com'. Nothing validates the result beyond
# IsNullOrWhiteSpace at the producer and IsNullOrEmpty at the consumer. Invoke-mdiPortProbePlan then
# read the host back with a bare cast:
#
#     & $addResult $probe ([uri] $Plan.SensorApiUrl).Host $null $outcome
#
# A [uri] cast THROWS on a malformed URL, and this one was evaluated inside an argument list, inside
# the probe loop, with no try between it and the caller. So the failure was not the cloud row - it
# was the ENTIRE pass. Measured on the shipped functions with a two-probe plan (Cloud + Localhost):
#
#     -WorkspaceName 'contoso'                    no throw, 2 records
#     -WorkspaceName 'my workspace'  cloud first  THREW,    0 records
#     -WorkspaceName 'my workspace'  cloud LAST   THREW,    0 records
#
# The third line is what makes it serious: the Localhost probe had ALREADY run and been collected,
# and its record was still lost, because the function returns nothing at all rather than the results
# it held. A probe with no record cannot be counted as missing by anything downstream - the estate
# renders as though those ports were never required. Six ordinary inputs reach it: a space, a colon,
# a backslash, '[', a bad percent escape ('ws%zz') and a bare '%'. Invoke-mdiPortProbePlan is in the
# shipped function list, so it runs inside the remote command line on EVERY scanned server.
#
# THE SAME FUNCTION HAD ALREADY HAD THIS DEFECT ONCE. The DNS payload block a few lines below
# records it verbatim for New-mdiDnsQueryPacket's [byte] cast - "a 256-byte label took the pass from
# results to NONE, so every other probe beside it lost its record entirely rather than failing" -
# and guards it with try/catch, then records the refusal as Not tested. That hand was fixed; this
# one was not. One rule, two hands.
#
# SECOND HALF, SAME ROOT CAUSE, NO THROW AT ALL: a '/', '#' or '?' in the workspace name ENDS the
# authority, and '@' turns everything before it into userinfo. Those URLs parse cleanly and retarget
# the probe at a different machine, whose answer is then filed under the sensor API's name:
#
#     'ws/x'        -> https://ws/xsensorapi.atp.azure.com        host 'ws'
#     'ws#frag'     -> https://ws#fragsensorapi.atp.azure.com     host 'ws'
#     'ws?q=1'      -> https://ws?q=1sensorapi.atp.azure.com      host 'ws'
#     'ws@evil.com' -> https://ws@evil.comsensorapi.atp.azure.com host 'evil.comsensorapi...'
#
# A measurement of the wrong thing is the same harm as a measurement nobody took, so the fix
# requires the authority to be the WHOLE of what was built: no userinfo, no query, no fragment and
# an absolute path of '/'.
#
# The record for an unusable URL is Applicable=$false - the same choice the "no -WorkspaceName"
# branch already makes - so it cannot become a rank-3 measured failure and invent a blocked port.

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

# Two probes so the blast radius is visible: the Cloud probe that carries the URL, and one healthy
# Localhost probe beside it that has nothing wrong with it.
function Measure-Pass {
    param([string] $WorkspaceName, [switch] $CloudLast)
    $plan = New-mdiPortProbePlan -Domain 'fabrikam.local' -WorkspaceName $WorkspaceName
    $cloud = @($plan.Probes | Where-Object { $_.Scope -eq 'Cloud' })[0]
    $local = @($plan.Probes | Where-Object { $_.Scope -eq 'Localhost' })[0]
    $plan.Probes = if ($CloudLast) { @($local, $cloud) } else { @($cloud, $local) }
    $plan.TimeoutMs = 400
    $records = $null; $threw = $null
    try { $records = Invoke-mdiPortProbePlan -Plan $plan } catch { $threw = $_.Exception.Message }
    # @($null).Count is 1, not 0, so the absent case is counted explicitly.
    $n = if ($null -eq $records) { 0 } else { @($records).Count }
    $cloudRow = if ($null -eq $records) { $null } else { @($records | Where-Object { $_.Scope -eq 'Cloud' })[0] }
    [PSCustomObject]@{ Threw = $threw; Count = $n; Cloud = $cloudRow }
}

'[control] the shipped settings this test depends on'
$fmt = [string] $settings.SensorApiUrlFormat
Assert-That 'SensorApiUrlFormat still pastes the workspace name into a hostname' ($fmt -eq '{0}sensorapi.atp.azure.com') "(is '$fmt')"
$built = (New-mdiPortProbePlan -Domain 'fabrikam.local' -WorkspaceName 'my workspace').SensorApiUrl
Assert-That 'a workspace name with a space really does build a malformed URL' ($built -eq 'https://my workspacesensorapi.atp.azure.com') "(built '$built')"
# The cast this defect was made of still throws - if it ever stops, this test proves nothing.
$castThrew = $false
try { $null = ([uri] $built).Host } catch { $castThrew = $true }
Assert-That 'CONTROL: a bare [uri] cast on that URL still throws' $castThrew

''
'[the pass survives] a malformed sensor API URL costs its own row and nothing else'
$good = Measure-Pass -WorkspaceName 'contoso'
Assert-That 'a valid workspace name returns both records' ($null -eq $good.Threw -and $good.Count -eq 2) "(threw=$($good.Threw) count=$($good.Count))"

foreach ($bad in @('my workspace', 'ws:8080', 'ws\x', '[', 'ws%zz', '%')) {
    $r = Measure-Pass -WorkspaceName $bad
    Assert-That ("'{0}' does not throw out of the pass" -f $bad) ($null -eq $r.Threw) "($($r.Threw))"
    Assert-That ("  ...and both records still come back" -f $bad) ($r.Count -eq 2) "(count=$($r.Count))"
}

''
'[nothing already measured is thrown away] the healthy probe ran first and must survive'
$last = Measure-Pass -WorkspaceName 'my workspace' -CloudLast
Assert-That 'a probe measured BEFORE the bad URL keeps its record' ($last.Count -eq 2) "(count=$($last.Count))"

''
'[the row is honest] an unusable URL is not tested, not a measured failure'
$row = (Measure-Pass -WorkspaceName 'my workspace').Cloud
Assert-That 'the cloud row exists' ($null -ne $row)
if ($null -ne $row) {
    Assert-That 'it is marked NOT applicable' ($row.Applicable -eq $false) "(Applicable=$($row.Applicable))"
    Assert-That 'its Success is null, not a measurement' ($null -eq $row.Success) "(Success=$($row.Success))"
    Assert-That 'its detail carries the not-tested marker' (([string] $row.Detail) -match $script:mdiPortNotTestedPattern) "(Detail='$($row.Detail)')"
    # Rank 0 = "not applicable, carries no evidence at all", which is what Applicable=$false yields
    # and exactly what the "no -WorkspaceName" branch beside it already produces. The property that
    # matters is that it is NOT 3: a URL nobody could use must never become a measured failure.
    $rank = Get-mdiPortRecordRank -Record $row
    Assert-That 'it does NOT rank 3 = measured failure' ($rank -ne 3) "(rank $rank)"
    Assert-That 'it ranks 0 = not applicable, as the no-workspace branch does' ($rank -eq 0) "(rank $rank)"
}

''
'[the right host or none] a name that retargets the probe is refused, not silently followed'
# These parse cleanly, so only the authority check stops them.
foreach ($case in @(
        @{ Name = 'ws/x'; Host = 'ws' }
        @{ Name = 'ws#frag'; Host = 'ws' }
        @{ Name = 'ws?q=1'; Host = 'ws' }
        @{ Name = 'ws@evil.com'; Host = 'evil.comsensorapi.atp.azure.com' })) {
    $r = Measure-Pass -WorkspaceName $case.Name
    Assert-That ("'{0}' does not throw" -f $case.Name) ($null -eq $r.Threw) "($($r.Threw))"
    $t = if ($null -eq $r.Cloud) { '<no row>' } else { [string] $r.Cloud.Target }
    Assert-That ("'{0}' is not probed as '{1}'" -f $case.Name, $case.Host) ($t -ne $case.Host) "(Target='$t')"
    if ($null -ne $r.Cloud) {
        Assert-That ("  ...it is recorded as not applicable instead" -f $case.Name) ($r.Cloud.Applicable -eq $false) "(Applicable=$($r.Cloud.Applicable))"
    }
}

''
'[the good case is untouched] a normal workspace name still probes its own host'
$okRow = (Measure-Pass -WorkspaceName 'contoso').Cloud
Assert-That 'a valid name is still probed' ($null -ne $okRow -and $okRow.Applicable -eq $true) "(Applicable=$($okRow.Applicable))"
Assert-That 'and it is probed as its own host' (([string] $okRow.Target) -eq 'contososensorapi.atp.azure.com') "(Target='$($okRow.Target)')"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
