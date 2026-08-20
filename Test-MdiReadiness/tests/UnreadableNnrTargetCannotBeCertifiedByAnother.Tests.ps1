<#
    A TARGET NOBODY COULD READ MUST NOT BE CERTIFIED BY ANOTHER TARGET'S SUCCESS -
    AND MUST NOT TAKE THE WHOLE PORTS CHECK DOWN WITH IT.

    Get-mdiRequiredPorts decides isRequiredPortsOk, and the NNR half of that verdict is decided by
    grouping the probe records by target and failing a group in which no method succeeded. The same
    grouping draws the NNR matrix in the HTML report. All three sites grouped like this:

        Group-Object -Property Target, TargetIP

    Group-Object -Property groups on the STRING RENDERING of each property, which is the exact read
    this codebase keeps restating is not the value. Get-mdiProbeRecordTargetKey states the rule in
    its own header - "[string] tests the RENDERING, not the value" - and routes every target through
    ConvertTo-mdiReadableDomainName so that a probe which measured nothing cannot come back looking
    like a probe that measured something. The three grouping sites did not use it.

    The records are not built in this process. They are JSON produced by the probe script that ran ON
    the sensor and parsed back with ConvertFrom-Json, so a JSON object in the Target field arrives as
    a PSCustomObject and EVERY record gets its OWN instance.

    TWO LOSSES FOLLOWED, both measured on the shipped functions, over the estate a real NNR run
    produces - two targets, three methods each, one target resolving by NetBIOS and one resolving by
    no method at all:

    1. THE PORTS CHECK WAS DESTROYED. Group-Object compares two DISTINCT instances that render alike
       and raises "Cannot compare @{N=x} to @{N=x} because ... does not implement IComparable". That
       error is TERMINATING under the DEFAULT preference, not only under 'Stop':

           Target = a PSCustomObject   Get-mdiRequiredPorts     THREW
           Target = a hashtable        Get-mdiRequiredPorts     THREW
           Target = a PSCustomObject   Get-mdiRequiredPortsHtml THREW - the whole ports table lost

       ONE unreadable target took down the required-ports result for the WHOLE server - every other
       required port on that sensor included - rather than its own row. It threw even when the two
       hosts carried DIFFERENT addresses, because the name is compared first.

    2. A FALSE GREEN. Read from the other side, the rendering MERGES: $null and '' both render to the
       empty string, every hashtable to 'System.Collections.Hashtable', every Object[] to
       'System.Object[]'. Two DIFFERENT hosts then land in ONE group, and the group test is "did ANY
       member succeed", so the host that no NNR method could resolve left the failure list:

           Target = $null / '' / '   ' / $true / @('x','y')
               isRequiredPortsOk = True   with NnrFailedTargets EMPTY

       and in the HTML matrix the same merge rendered ONE row where two hosts had been probed, under
       a fabricated name - 'System.Collections.Hashtable' as a domain controller.

    THE FIX gives the three sites one key, Get-mdiProbeRecordGroupKey, which

      * returns a STRING, so the grouping can never throw, whatever the record carries;
      * routes BOTH halves through ConvertTo-mdiReadableDomainName - the codebase's single definition
        of "did anybody actually read this value" - and keeps them SEPARATE rather than falling back
        one to the other, so a multi-homed host stays one group per address; and
      * returns the empty string when NEITHER half was read.

    A record with an unattributable target is then routed to the UNMEASURED population rather than to
    the failed one, so the verdict is 'N/A' - not a pass and not a failure. That is the tri-state the
    surrounding code already documents in its own words: "A target with nothing measured is 'N/A' -
    not a failure and not a pass." An operator cannot act on "No NNR method could resolve
    System.Object[]", and must not be told the check passed either.

    WHAT THIS TEST ALSO REFUSES - the opposite mistakes, which are what make the fix worth pinning.

      * A READABLE estate must behave EXACTLY as before: an unresolvable cross-forest host is still
        named, and the verdict is still False. A fix that keyed everything blank would "pass" the
        no-false-green assertions by never failing anything again.
      * A MULTI-HOMED host must stay ONE GROUP PER ADDRESS. The comment at the HTML site records why:
        grouping by name alone "would report a host as resolvable on the strength of the NIC that
        answered while the other one, the one actually failing in the portal, disappeared".
      * An unreadable target must still RENDER A ROW in the HTML matrix, under a STATED marker. The
        precedent is one screen above it: an unreadable probe id "keys as a STATED MARKER rather than
        as $null", because "a loud failure replaced by a quiet one is not a fix".
      * That row's Resolvable cell must never read "Yes". A measurement that cannot be attributed to
        a host cannot certify one.
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

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# Only the TRANSPORT is stubbed. The function's own JSON parse, applicability filter, mandatory
# filter, measured predicate, NNR grouping and verdict all run.
$script:injectedJson = $null
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) $env:TEMP }
Set-Item -Path function:script:Get-mdiPortProbeCommandLine -Value { param($Plan, $OutputFile) 'stub' }
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
    $script:injectedJson
}

function New-NnrRecord {
    param($Id, $Protocol, $Port, $Target, $TargetIP, $Success, $Detail)
    [PSCustomObject]@{
        Id = $Id; Name = ('NNR - {0}' -f $Id); Protocol = $Protocol; Port = $Port
        Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'
        Target = $Target; TargetIP = $TargetIP; Applicable = $true
        Success = $Success; LatencyMs = 12; Detail = $Detail
    }
}

# Two ordinary REQUIRED probes that both succeed, so the mandatory half of the verdict is settled and
# the NNR half - the half under test - is what decides it.
function New-MandatoryRecords {
    @(
        [PSCustomObject]@{
            Id = 'CloudSsl'; Name = 'SSL to the MDI cloud service'; Protocol = 'TCP'; Port = 443
            Scope = 'Cloud'; Group = $null; Requirement = 'Required'
            Target = 'lab.atp.azure.com'; TargetIP = '20.1.1.1'; Applicable = $true
            Success = $true; LatencyMs = 30; Detail = 'Connected'
        }
        [PSCustomObject]@{
            Id = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
            Scope = 'DomainController'; Group = $null; Requirement = 'Required'
            Target = 'dc01.mdilab.local'; TargetIP = '10.10.1.12'; Applicable = $true
            Success = $true; LatencyMs = 3; Detail = 'Connected'
        }
    )
}

# One target resolves (NetBIOS answers); the other resolves by no method at all. This is the fan-out
# a real NNR run produces: 3+ records per target, all naming the same host.
function New-Estate {
    param($TargetA, $TargetB, $IpA, $IpB)
    @(New-MandatoryRecords) + @(
        New-NnrRecord 'NnrRpc'     'TCP' 135  $TargetA $IpA $false 'Connection refused'
        New-NnrRecord 'NnrNetBios' 'UDP' 137  $TargetA $IpA $true  'Answered'
        New-NnrRecord 'NnrRdp'     'TCP' 3389 $TargetA $IpA $false 'Connection refused'
        New-NnrRecord 'NnrRpc'     'TCP' 135  $TargetB $IpB $false 'Connection refused'
        New-NnrRecord 'NnrNetBios' 'UDP' 137  $TargetB $IpB $false 'No answer'
        New-NnrRecord 'NnrRdp'     'TCP' 3389 $TargetB $IpB $false 'Connection refused'
    )
}

$plan = New-mdiPortProbePlan -Domain 'mdilab.local' -TimeoutMs 1500 -WorkspaceName 'lab' `
    -NnrTarget @(
        [PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.1.12' }
        [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50' }
    ) `
    -DomainController @([PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.1.12' })

function Measure-Estate {
    param($Records)
    # The JSON round trip is how these records really reach the function.
    $script:injectedJson = ($Records | ConvertTo-Json -Depth 6 -Compress)
    $r = Get-mdiRequiredPorts -ComputerName 'dc01.mdilab.local' -Plan $plan
    [PSCustomObject]@{ Ok = $r.isRequiredPortsOk; Failed = @($r.details.NnrFailedTargets) }
}

# The shapes a JSON round trip, another tool's inventory or a hand-edited report really produces.
$unreadable = [ordered]@{
    'a PSCustomObject'    = ([PSCustomObject]@{ Name = 'dc01' })
    'a hashtable'         = @{ Name = 'dc01' }
    'a two-element array' = @('dc01', 'dc02')
    '$null'               = $null
    'an empty string'     = ''
    'whitespace'          = '   '
    'a boolean'           = $true
    'an integer'          = 12345
}

Write-Host "`n1. THE KEY ITSELF - a target nobody read is not a target"
foreach ($name in $unreadable.Keys) {
    $k = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = $unreadable[$name]; TargetIP = $null })
    Assert-True "$name keys as the empty string" ([string]::IsNullOrEmpty($k)) "got [$k]"
}
$kr = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = 'dc01.mdilab.local'; TargetIP = '10.10.1.12' })
Assert-True 'a readable name and address key together' (-not [string]::IsNullOrEmpty($kr)) "got [$kr]"
# Grouping must never throw, so the key must always be a string.
foreach ($name in $unreadable.Keys) {
    $k = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = $unreadable[$name]; TargetIP = $null })
    Assert-True "$name keys as a STRING, so the grouping cannot throw" ($k -is [string]) "got $($k.GetType().Name)"
}

Write-Host "`n2. MULTI-HOMED SEPARATION - one host per ADDRESS, which the old pair key preserved"
$m1 = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = 'dc01.mdilab.local'; TargetIP = '10.10.1.12' })
$m2 = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = 'dc01.mdilab.local'; TargetIP = '10.10.1.13' })
Assert-True 'two NICs of one host are two groups' ($m1 -ne $m2) "both keyed [$m1]"
$m3 = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = 'DC01.MDILAB.LOCAL'; TargetIP = '10.10.1.12' })
Assert-True 'the same path spelled in another case is ONE group' ($m1 -eq $m3) "[$m1] vs [$m3]"
# A name with no address and an address with no name are different measurements, not one.
$m4 = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = 'dc01.mdilab.local'; TargetIP = $null })
$m5 = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = $null; TargetIP = 'dc01.mdilab.local' })
Assert-True 'a nameless record does not merge into a named one' ($m4 -ne $m5) "both keyed [$m4]"
# An unreadable NAME with a readable ADDRESS is still a host that was probed.
$m6 = Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = @{ N = 'x' }; TargetIP = '10.10.1.50' })
Assert-True 'an unreadable name with a real address is still keyed' (-not [string]::IsNullOrEmpty($m6)) "got [$m6]"

Write-Host "`n3. CONTROL - a readable estate must behave EXACTLY as it did"
$control = Measure-Estate (New-Estate 'dc01.mdilab.local' 'dcfab01.fabrikam.local' '10.10.1.12' '10.10.1.50')
Assert-True 'an unresolvable cross-forest host still fails the check' ($control.Ok -eq $false) "got [$($control.Ok)]"
Assert-True 'and is still named to the operator' (@($control.Failed).Count -eq 1 -and @($control.Failed)[0] -match 'fabrikam') `
    "got [$(@($control.Failed) -join '; ')]"

Write-Host "`n4. THE CRASH - one unreadable target must not destroy the whole ports check"
foreach ($name in $unreadable.Keys) {
    foreach ($eap in 'Continue', 'Stop') {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = $eap
        $threw = $false
        $msg = ''
        try { $null = Measure-Estate (New-Estate $unreadable[$name] $unreadable[$name] $null $null) }
        catch { $threw = $true; $msg = $_.Exception.Message.Split([char]10)[0] }
        finally { $ErrorActionPreference = $prev }
        Assert-True "$name does not throw under `$ErrorActionPreference = '$eap'" (-not $threw) $msg
    }
}
# It threw even when the two hosts carried different addresses, because the NAME is compared first.
$threw3 = $false
try { $null = Measure-Estate (New-Estate ([PSCustomObject]@{ N = 1 }) ([PSCustomObject]@{ N = 2 }) '10.10.1.12' '10.10.1.50') }
catch { $threw3 = $true }
Assert-True 'two unreadable names at DIFFERENT addresses do not throw either' (-not $threw3)

Write-Host "`n5. THE FALSE GREEN - a host no method resolved must never leave the verdict passing"
foreach ($name in $unreadable.Keys) {
    # Caught rather than allowed to abort the file: when the defect returns it throws here, and a
    # test that dies reports one crash instead of naming every shape that broke.
    $ok = $null
    $failedList = @()
    $threw = $false
    try {
        $res = Measure-Estate (New-Estate $unreadable[$name] $unreadable[$name] $null $null)
        $ok = $res.Ok
        $failedList = @($res.Failed)
    } catch { $threw = $true }
    # 'N/A' (nothing attributable was measured) or False (named and failed) are both honest.
    # True is not: it certifies a target that no NNR method could resolve.
    Assert-True "$name does not certify the check" ((-not $threw) -and $ok -ne $true) "threw=$threw isRequiredPortsOk=[$ok]"
    # And the operator is never sent after a .NET type name.
    $fabricated = @($failedList | Where-Object { $_ -match 'System\.|@\{|^True$|^12345$' })
    Assert-True "$name is not reported as a resolvable host name" ((-not $threw) -and $fabricated.Count -eq 0) `
        "threw=$threw got [$($fabricated -join '; ')]"
}

Write-Host "`n6. TWO HOSTS AT DIFFERENT ADDRESSES ARE STILL TWO HOSTS WHEN THE NAMES ARE UNREADABLE"
$res6 = $null
$threw6 = $false
try { $res6 = Measure-Estate (New-Estate ([PSCustomObject]@{ N = 1 }) ([PSCustomObject]@{ N = 2 }) '10.10.1.12' '10.10.1.50') }
catch { $threw6 = $true }
Assert-True 'the address keeps them apart and the failing one is named' `
    ((-not $threw6) -and $res6.Ok -eq $false -and @($res6.Failed).Count -eq 1 -and @($res6.Failed)[0] -match '10\.10\.1\.50') `
    "threw=$threw6 ok=[$($res6.Ok)] failed=[$(@($res6.Failed) -join '; ')]"

Write-Host "`n7. THE HTML NNR MATRIX - the third site groups the same way"
function New-ServerRow {
    param($Records)
    [PSCustomObject]@{
        FQDN    = 'dc01.mdilab.local'
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $Records } }
    }
}
# Only the NNR MATRIX rows are judged - the rows this grouping draws, identified by the Resolvable
# verdict cell they end with. Other tables in the same report render the target with their own
# [string] casts; that is a different site and not what this test pins.
function Get-MatrixRow {
    param([string] $Html)
    @([regex]::Matches($Html, '<tr>(?:(?!</tr>).)*<td class="(?:green|red|muted-cell)">(?:Yes|No|Not tested)</td></tr>') |
        ForEach-Object { $_.Value })
}

$htmlControl = Get-mdiRequiredPortsHtml -Server @((New-ServerRow (New-Estate 'dc01.mdilab.local' 'dcfab01.fabrikam.local' '10.10.1.12' '10.10.1.50')))
$controlRows = @(Get-MatrixRow -Html $htmlControl)
Assert-True 'a readable estate still renders both targets' ($controlRows.Count -eq 2) "got $($controlRows.Count) row(s)"
Assert-True 'and still shows the unresolvable one as No' `
    (@($controlRows | Where-Object { $_ -match '<td class="red">No</td>' }).Count -eq 1)
Assert-True 'and still shows the resolvable one as Yes' `
    (@($controlRows | Where-Object { $_ -match '<td class="green">Yes</td>' }).Count -eq 1)

foreach ($name in $unreadable.Keys) {
    $rows = New-ServerRow (New-Estate $unreadable[$name] $unreadable[$name] $null $null)
    $threw = $false
    $html = ''
    try { $html = Get-mdiRequiredPortsHtml -Server @($rows) } catch { $threw = $true }
    Assert-True "$name does not take the ports TABLE down" (-not $threw)
    if ($threw) { continue }
    $matrix = @(Get-MatrixRow -Html $html)
    # A loud failure replaced by a quiet one is not a fix: the row must still be there.
    Assert-True "$name still renders a target row" ($matrix.Count -ge 1) "got $($matrix.Count) row(s)"
    # ...but not under a name no directory ever returned.
    $fabricated = @($matrix | Where-Object { $_ -match 'System\.Collections\.Hashtable|System\.Object|@\{' })
    Assert-True "$name is not rendered as a host name" ($fabricated.Count -eq 0) "fabricated name in the matrix row"
    # ...and it must not be certified: Resolvable "Yes" is a statement about a host, and there is no
    # host to make it about.
    $certified = @($matrix | Where-Object { $_ -match '<td class="green">Yes</td>' })
    Assert-True "$name is not reported Resolvable=Yes" ($certified.Count -eq 0)
    # ...and the row must SAY that the name was not recorded, rather than rendering blank - a blank
    # cell reads as a rendering glitch and is scrolled past.
    Assert-True "$name states that the target was not recorded" `
        (@($matrix | Where-Object { $_ -match 'not recorded' }).Count -ge 1)
}

Write-Host "`n8. ONE RULER - the group key and the host key must agree about what was read"
foreach ($name in $unreadable.Keys) {
    $byHost = -not [string]::IsNullOrWhiteSpace(
        (Get-mdiProbeRecordTargetKey -Record ([PSCustomObject]@{ Target = $unreadable[$name]; TargetIP = $null })))
    $byGroup = -not [string]::IsNullOrEmpty(
        (Get-mdiProbeRecordGroupKey -Record ([PSCustomObject]@{ Target = $unreadable[$name]; TargetIP = $null })))
    Assert-True "$name is refused by both keys" ($byHost -eq $byGroup) "hostKey=$byHost groupKey=$byGroup"
}

Write-Host ''
Write-Host ("RESULT  pass=$script:pass  fail=$script:fail")
if ($script:fail -gt 0) { exit 1 }
exit 0
