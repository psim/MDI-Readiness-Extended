<#
    A port's Requirement must be classified on the shared rank scale, never with a literal
    `-eq 'Required'`.

    THE DEFECT THIS PINS. Seven places classified a port probe's obligation by comparing its
    Requirement to the literal string 'Required':

        Get-mdiRequiredPorts     $mandatory = @($applicable | Where-Object { $_.Requirement -eq 'Required' })
        Get-mdiRequiredPorts     $dcRequiredDefined = ... $_.Requirement -eq 'Required'
        Get-mdiReportStatistics  PortsRequiredFail / PortsRequiredOpen / PortsRequiredTested
        Get-mdiRequiredPortsHtml $class = if ($failure.Requirement -eq 'Required') { 'red' } else { 'amber' }
        Get-mdiBlockingPortFailure  $atLeastOne = @($applicable | Where-Object { $_.Requirement -eq 'AtLeastOne' })

    while two OTHER places - Get-mdiBlockingPortFailure's Required/All filter and
    Get-mdiUnmeasuredRequiredProbe - used `-in @('Required', 'All')` instead. Those two decide the
    verdict and the issue list. So the surfaces an operator reads disagreed with the surface that
    decides readiness, in BOTH directions at once:

    A  FALSE GREEN on 'All'. 'All' ranks 3 on Get-mdiRequirementRank - "every one must pass, and a
       measured failure blocks the verdict" - and Get-mdiBlockingPortFailure blocks on it
       deliberately. The literal test does not match it. The note beside PortsRequiredUntested in
       Get-mdiReportStatistics already stated this exact rule, that an inline "-eq 'Required'"
       silently drops Requirement = 'All' probes; its three sibling counters on the lines
       immediately above it had been left on the literal anyway.

    B  FALSE RED on a value nobody read. PowerShell's -eq coerces its RIGHT operand to the LEFT
       operand's type. When Requirement is the BOOLEAN $true, `$true -eq 'Required'` evaluates
       'Required' AS A BOOLEAN - a non-empty string, so $true - and returns TRUE. A Requirement
       nobody could read was therefore promoted to a blocking requirement, charged as a required
       failure, and printed in the Requirement column as "True".

    B is not a synthetic shape on this path. Requirement makes a full JSON round trip: the plan is
    serialised to the sensor and read back there with ConvertFrom-Json, the results return as JSON
    and are parsed locally with ConvertFrom-Json, and NOTHING re-stamps Requirement from the plan
    afterwards - the only Add-Member on that path adds ProbedFrom. ConvertTo-Json/ConvertFrom-Json
    round-trips "Requirement":true back to a [bool]. This file already carries a fix for a previous
    defect of the same class, where a JSON round trip emptied Requirement and a refused required
    port stopped counting as a required failure.

    MEASURED ON THE SHIPPED FUNCTIONS BEFORE THE FIX. One sensor, LDAPS TCP 636 REFUSED to
    dcfab01.fabrikam.local, nothing differing but the Requirement spelling:

        Requirement    rank   "needs attention" cell   PortsRequiredFail   verdict mandatory?
        'Required'      3     red                      1                   yes
        'All'           3     amber                    0                   NO
        $true           0     red                      1                   YES
        'Optional'      0     amber                    0                   no

    So a port the verdict blocks on was painted advisory and counted zero by the statistics, and an
    unreadable value was painted blocking and charged as a required failure.

    WHY IT SURVIVED. -MultiForest is what puts real traffic on this path: it promotes LdapsTcp and
    LdapsGcTcp from Optional to Required, so in a cross-forest estate the LDAPS records that decide
    readiness are exactly the ones whose Requirement travels the JSON round trip. The lab only
    gained a real second forest on 17 August.

    THE FIX. One shared predicate, Test-mdiRequirementIsMandatory, routed through the existing
    Get-mdiRequirementRank scale (Required/All 3, AtLeastOne 2, Recommended 1, Optional or
    unrecognised 0), used by every one of those sites; and the AtLeastOne test moved onto rank 2.

    Pinned here:

    1. Test-mdiRequirementIsMandatory is true for 'Required' and 'All' and false for everything
       else, including the boolean $true that defeated the literal comparison.
    2. It agrees with Get-mdiRequirementRank -eq 3 on every shape, so the two cannot drift.
    3. The "Ports that need attention" cell is RED for a refused 'All' port and AMBER for a refused
       port whose Requirement is an unreadable boolean.
    4. PortsRequiredFail / PortsRequiredOpen / PortsRequiredTested count 'All' probes and do not
       count boolean ones.
    5. Those three counters describe the same population as PortsRequiredUntested, which was
       already routed through the shared helper - the arithmetic
       PortsRequiredTested - PortsRequiredOpen = PortsRequiredFail still holds.
    6. Get-mdiBlockingPortFailure - the verdict - already blocked on 'All' and must still do so, and
       must not classify a boolean Requirement as an NNR (AtLeastOne) group member.
    7. Optional and Recommended still never block, so the fix does not promote anything; and
       Get-mdiRequiredPorts itself - the function whose $mandatory selector decides
       isRequiredPortsOk and fills FailedRequired - fails the ports check for a refused 'All' port
       and does NOT charge one whose Requirement arrived from JSON as a boolean.
    8. No PORT surface compares Requirement to a literal any more. The sensor v3.x readiness checks
       are deliberately out of scope: they use a different vocabulary ('Required' / 'Migration' /
       'Recommended') that Get-mdiRequirementRank does not model, and that list is built locally
       through a [string]-typed $Requirement parameter rather than parsed from JSON.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$productPath = $target
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiRequiredPortsHtml') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-LdapsFailure {
    param($Requirement)
    [PSCustomObject]@{
        Server = 'dc01.mdilab.local'; Id = 'LdapsTcp'; Name = 'Secure LDAP (LDAPS)'
        Protocol = 'TCP'; Port = 636; Scope = 'DomainController'; Group = $null
        Requirement = $Requirement; Success = $false; Applicable = $true
        Target = 'dcfab01.fabrikam.local'; TargetIP = '10.10.1.50'
        Detail = 'Connection refused'; LatencyMs = $null; ProbedFrom = 'Sensor server (outbound)'
    }
}
function New-Server {
    param([object[]] $Results)
    [PSCustomObject]@{
        FQDN = 'dc01.mdilab.local'; Domain = 'mdilab.local'; OperatingSystem = 'Windows Server 2022'
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $Results } }
    }
}

'--- 1/2. the shared predicate, and its agreement with the rank scale ---'
# 'All' and the boolean are the two shapes the literal comparison got wrong, in opposite directions.
$mandatoryShapes = @('Required', 'All', 'required', 'ALL')
$notMandatory = @('Optional', 'AtLeastOne', 'Recommended', $true, $false, 636, 'Required.', ' Required', '', $null)
foreach ($v in $mandatoryShapes) {
    Assert-That "mandatory: '$v'" ((Test-mdiRequirementIsMandatory -Requirement $v) -eq $true)
}
foreach ($v in $notMandatory) {
    $shown = if ($null -eq $v) { '<null>' } elseif ("$v" -eq '') { "''" } else { "$v" }
    Assert-That "not mandatory: $shown" ((Test-mdiRequirementIsMandatory -Requirement $v) -eq $false)
}
# The literal comparison the defect was made of, kept here as the thing that must NOT be equivalent.
Assert-That 'the literal test really does match a boolean (the coercion this pins)' (($true -eq 'Required') -eq $true)
Assert-That 'the predicate does not' ((Test-mdiRequirementIsMandatory -Requirement $true) -eq $false)
foreach ($v in @($mandatoryShapes + $notMandatory)) {
    $shown = if ($null -eq $v) { '<null>' } elseif ("$v" -eq '') { "''" } else { "$v" }
    Assert-That "predicate agrees with rank -eq 3: $shown" `
    ((Test-mdiRequirementIsMandatory -Requirement $v) -eq ((Get-mdiRequirementRank -Requirement $v) -eq 3))
}
# A JSON round trip is how the boolean actually arrives.
$roundTripped = ([PSCustomObject]@{ Requirement = $true } | ConvertTo-Json -Compress | ConvertFrom-Json).Requirement
Assert-That 'a JSON round trip really yields a [bool]' ($roundTripped -is [bool])
Assert-That 'and it is not mandatory' ((Test-mdiRequirementIsMandatory -Requirement $roundTripped) -eq $false)

'--- 3. "Ports that need attention" cell colour ---'
function Get-AttentionClass {
    param($Requirement)
    $html = (Get-mdiRequiredPortsHtml -Server @(New-Server @(New-LdapsFailure $Requirement))) -join "`n"
    $at = $html.Substring([Math]::Max(0, $html.IndexOf('Ports that need attention')))
    if ($at -match '<td class="(red|amber)">636</td>') { $matches[1] } else { '<no row>' }
}
Assert-That "'Required' is red"  ((Get-AttentionClass 'Required') -eq 'red')
Assert-That "'All' is red"       ((Get-AttentionClass 'All') -eq 'red') 'a port the verdict blocks on must not be painted advisory'
Assert-That '$true is amber'     ((Get-AttentionClass $true) -eq 'amber') 'an unreadable requirement must not be painted blocking'
Assert-That '$false is amber'    ((Get-AttentionClass $false) -eq 'amber')
Assert-That "'Optional' is amber" ((Get-AttentionClass 'Optional') -eq 'amber')

'--- 4/5. the Required statistics, and their arithmetic ---'
function Get-Stats {
    param($Requirement)
    Get-mdiReportStatistics -ReportData ([PSCustomObject]@{ DomainControllers = @(New-Server @(New-LdapsFailure $Requirement)) })
}
foreach ($r in 'Required', 'All') {
    $s = Get-Stats $r
    Assert-That "'$r' counts as a required failure" ([int] $s.PortsRequiredFail -eq 1) "got $($s.PortsRequiredFail)"
    Assert-That "'$r' counts as required-tested"    ([int] $s.PortsRequiredTested -eq 1) "got $($s.PortsRequiredTested)"
}
foreach ($r in @($true, $false, 'Optional')) {
    $shown = if ("$r" -eq '') { "''" } else { "$r" }
    $s = Get-Stats $r
    Assert-That "$shown is not a required failure" ([int] $s.PortsRequiredFail -eq 0) "got $($s.PortsRequiredFail)"
    Assert-That "$shown is not required-tested"    ([int] $s.PortsRequiredTested -eq 0) "got $($s.PortsRequiredTested)"
}
foreach ($r in 'Required', 'All', 'Optional') {
    $s = Get-Stats $r
    Assert-That "tested - open = fail for '$r'" `
    (([int] $s.PortsRequiredTested - [int] $s.PortsRequiredOpen) -eq [int] $s.PortsRequiredFail)
}
# The counter that was already correct must still describe the same population.
$unmeasured = New-LdapsFailure 'All'
$unmeasured.Success = $null
$unmeasured.Detail = 'Not tested - the port probes could not be run'
$sU = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{ DomainControllers = @(New-Server @($unmeasured)) })
Assert-That "an unmeasured 'All' probe is counted as required-untested" ([int] $sU.PortsRequiredUntested -eq 1) "got $($sU.PortsRequiredUntested)"

'--- 6. the verdict still blocks on All, and never on an unreadable value ---'
Assert-That "'All' blocks the verdict"  (@(Get-mdiBlockingPortFailure -Record @(New-LdapsFailure 'All')).Count -eq 1)
Assert-That "'Required' blocks"         (@(Get-mdiBlockingPortFailure -Record @(New-LdapsFailure 'Required')).Count -eq 1)
Assert-That '$true does not block'      (@(Get-mdiBlockingPortFailure -Record @(New-LdapsFailure $true)).Count -eq 0) 'a boolean must not be judged as Required or as an NNR method'
Assert-That "'Optional' does not block" (@(Get-mdiBlockingPortFailure -Record @(New-LdapsFailure 'Optional')).Count -eq 0)
Assert-That "'Recommended' does not block" (@(Get-mdiBlockingPortFailure -Record @(New-LdapsFailure 'Recommended')).Count -eq 0)
# A boolean must not be swept into an AtLeastOne group either: `$true -eq 'AtLeastOne'` is also true.
$nnr = New-LdapsFailure $true
$nnr.Group = 'NNR'; $nnr.Id = 'NnrRpc'; $nnr.Port = 135
Assert-That 'a boolean Requirement is not judged as an NNR group member' (@(Get-mdiBlockingPortFailure -Record @($nnr)).Count -eq 0)
# ...while a genuine AtLeastOne group with no success still blocks.
$realNnr = New-LdapsFailure 'AtLeastOne'
$realNnr.Group = 'NNR'; $realNnr.Id = 'NnrRpc'; $realNnr.Port = 135
Assert-That 'a real AtLeastOne group with no success still blocks' (@(Get-mdiBlockingPortFailure -Record @($realNnr)).Count -eq 1)

'--- 7. the verdict itself: Get-mdiRequiredPorts, driven with a stubbed remote probe ---'
# This is the assertion that matters most, and it was the one only the static text guard covered.
# Get-mdiRequiredPorts is the function whose $mandatory selector decides isRequiredPortsOk and fills
# FailedRequired - the sentence an operator pastes into a firewall change request. It needs a remote
# server, so the two functions that reach one are stubbed and everything else runs for real,
# including the ConvertFrom-Json parse that produces the boolean in the first place.
$script:stubJson = '[]'
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) [IO.Path]::GetTempPath() }
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
    $script:stubJson
}

$dcTarget = [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50'; Domain = 'fabrikam.local'; MultiHomed = $false }
$plan = New-mdiPortProbePlan -Domain 'mdilab.local' -DomainController @($dcTarget) -NnrTarget @($dcTarget) -MultiForest

function Get-Verdict {
    param($Requirement)
    # Serialised and parsed exactly as the live path does, so a boolean Requirement arrives here the
    # way ConvertFrom-Json really delivers it rather than being hand-placed as one.
    $script:stubJson = @([PSCustomObject]@{
            Id = 'LdapsTcp'; Name = 'Secure LDAP (LDAPS)'; Protocol = 'TCP'; Port = 636
            Scope = 'DomainController'; Group = $null; Requirement = $Requirement
            Target = 'dcfab01.fabrikam.local'; TargetIP = '10.10.1.50'
            Applicable = $true; Success = $false; LatencyMs = $null; Detail = 'Connection refused'
        }) | ConvertTo-Json -Depth 6
    Get-mdiRequiredPorts -ComputerName 'dc01.mdilab.local' -Plan $plan
}

foreach ($r in 'Required', 'All') {
    $v = Get-Verdict $r
    Assert-That "a refused '$r' LDAPS port fails the ports check" ($v.isRequiredPortsOk -eq $false) "got $($v.isRequiredPortsOk)"
    Assert-That "...and is named in FailedRequired" (@($v.details.FailedRequired).Count -eq 1) "got $(@($v.details.FailedRequired).Count)"
}
$vBool = Get-Verdict $true
Assert-That 'a Requirement that arrived as a JSON boolean is not charged as a required failure' `
(@($vBool.details.FailedRequired).Count -eq 0) ("FailedRequired: " + (@($vBool.details.FailedRequired) -join ' | '))
$vOpt = Get-Verdict 'Optional'
Assert-That 'a refused Optional port is not charged as a required failure' (@($vOpt.details.FailedRequired).Count -eq 0)

'--- 8. no literal Requirement -eq ''Required'' comparison survives on a PORT surface ---'
# Scoped to the port-probe vocabulary deliberately. The sensor v3.x readiness checks use a DIFFERENT
# vocabulary - 'Required' / 'Migration' / 'Recommended' - which Get-mdiRequirementRank does not model
# ('Migration' is not on its scale), and that list is built locally through a [string]-typed
# $Requirement parameter, so it neither needs nor tolerates this predicate. Those sites are named
# here so the guard stays meaningful: a NEW literal comparison on any port surface fails this test.
$productText = Get-Content -LiteralPath $productPath -Raw
$code = @($productText -split "`n" | Where-Object { $_ -notmatch '^\s*#' })
$checkPopulation = '\$(checks|mergedChecks)\s*\|'
$literalHits = @($code | Where-Object {
        $_ -match "\.Requirement\s+-eq\s+'(Required|AtLeastOne)'" -and $_ -notmatch $checkPopulation
    })
Assert-That 'no port surface compares .Requirement to a literal' ($literalHits.Count -eq 0) ("found: " + ($literalHits -join ' | '))
# ...and the v3-check sites really are the only ones excluded, so the exclusion cannot quietly widen.
$excluded = @($code | Where-Object { $_ -match "\.Requirement\s+-eq\s+'Required'" -and $_ -match $checkPopulation })
Assert-That 'exactly 4 v3-check sites are out of scope' ($excluded.Count -eq 4) "got $($excluded.Count)"

''
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
