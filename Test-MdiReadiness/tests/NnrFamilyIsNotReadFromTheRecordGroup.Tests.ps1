<#
    The headline NNR count and the NNR matrix on the same page disagreed about which targets exist,
    and the verdict raised "no NNR method could resolve X" for a target it had measured resolving.

    Both come from the same cause: the probe FAMILY was read raw off the record's Group field.
    Group is stamped from the PLAN, makes the full JSON round trip to the sensor and back, and
    nothing re-stamps it afterwards - the identical path documented on Test-mdiRequirementIsMandatory.
    Get-mdiPortResultRecord normalises only Success and Applicable, so Group reaches every consumer
    unprotected: $null, '', a number and a collection are all shapes another tool's JSON, a merged
    report, a hand-edited report or an older version can hand back. An empty Group is a real SHIPPED
    value as well - NnrReverseDns carries Scope NetworkDevice with Group '' because it is recommended
    rather than primary - so "no Group" cannot be read as "not an NNR method".

    DEFECT 1 - the KPI lost the targets the matrix was drawing.

    Get-mdiRequiredPortsHtml admits its matrix rows by SCOPE ($_.Scope -eq 'NetworkDevice'), and
    commit 1419fd4 moved that table's verdict onto the shipped definitions by Id for exactly this
    reason. Get-mdiReportStatistics, which counts the very targets that table draws, still admitted
    them with "$_.Group -eq 'NNR'". Measured on the shipped functions before the fix, one target with
    all three primary methods MEASURED REFUSED and nothing differing but the Group field:

        Group 'NNR'   KPI targets=1 resolvable=0   matrix verdict "No"   (agreed)
        Group $null   KPI targets=0 resolvable=0   matrix verdict "No"
        Group ''      KPI targets=0 resolvable=0   matrix verdict "No"
        Group 12345   KPI targets=0 resolvable=0   matrix verdict "No"

    A target proven unresolvable therefore VANISHED from the headline count of resolvable targets
    while the matrix one screen below still drew it in red - losing a row improving the headline.
    The same record moved into the ordinary-ports population at the same time
    (PortDistinctTargetCount 0 -> 1), because the sampling filter tested the same raw field, so an
    NNR row was counted as a host the ports probe had visited.

    DEFECT 2 - the verdict raised a false red for a target it had measured resolving.

    Get-mdiBlockingPortFailure groups AtLeastOne records per target and lets one measured success
    rescue its siblings. Group was part of that grouping key, and a key containing any blank field is
    deliberately replaced by a GUID so it is judged alone - a conservative rule that exists for a
    missing SERVER, TARGET or ADDRESS. With Group blank the rule fired on the family instead, every
    method of one target got its own key, and the sibling that SUCCEEDED could no longer rescue the
    one that failed. Measured on the shipped function, RPC measured OPEN and NetBIOS measured
    REFUSED against one target, nothing differing but Group:

        Group 'NNR'   blocking <none>        (correct - RPC resolved the target)
        Group $null   blocking NnrMeasured   "no NNR method could resolve ..."
        Group ''      blocking NnrMeasured   "no NNR method could resolve ..."

    That fails the run and sends an operator to open a firewall port on a host whose name resolution
    was measured working. It also duplicated the finding on an all-blocked target, raising one
    blocking record per method instead of one per target.

    DEFECT 3 - the remediation script was silent about the target the verdict had just condemned.

    New-mdiRemediationScript picks the rows it writes New-NetFirewallRule for from two things: the
    keys Get-mdiBlockingPortFailure marked 'NnrMeasured', and a second filter that read Group raw.
    Once the verdict resolved the family by Id and the filter beside it did not, the two halves of
    one decision disagreed. Measured on the shipped functions, one target with all three primary
    methods MEASURED REFUSED and a sensor carrying a usable source address:

        Group 'NNR'   verdict NnrMeasured=1   script emits RPC, NetBIOS and RDP rules
        Group $null   verdict NnrMeasured=1   script emits NOTHING
        Group ''      verdict NnrMeasured=1   script emits NOTHING
        Group 12345   verdict NnrMeasured=1   script emits NOTHING

    The report said "no NNR method could resolve X" and the script generated from that same report
    was silent about X, so an operator runs the fix, believes the finding is addressed, and the ports
    that lower the active name resolution success rate stay shut.

    THE FIX resolves the family from the shipped definitions by Id through Get-mdiProbeGroupKey and
    the shared Test-mdiProbeIsPrimaryNnr predicate, which the KPI, the sampling population, the
    matrix, the verdict and the remediation script now all use. An Id the shipped table does not know
    still falls back to its own Group, so a method added in a later version keeps working. The family
    is no longer part of the blank-key test: an unreadable family must not split one target, whereas
    an unreadable target identity must still be judged alone.

    This test pins both directions on both surfaces, and pins that the fix did not make reverse DNS
    into a primary method or turn a genuinely unmeasured target into a measured one.
#>

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0

# The suite runner counts assertions by matching lines that BEGIN with PASS or FAIL, so every
# assertion has to emit one. A file that prints only a summary reports 0/0 and is recorded as having
# run no assertions at all, which the tree gate treats as RED.
function Assert-Equal {
    param($Expected, $Actual, [string] $Because)
    if ([string] $Expected -eq [string] $Actual) {
        $script:pass++
        "  PASS  $Because"
    } else {
        $script:fail++
        "  FAIL  $Because (expected '$Expected', got '$Actual')"
    }
}

function Resolve-ProductScript {
    $dir = $PSScriptRoot
    while ($dir) {
        $sibling = Join-Path $dir 'Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $sibling) { return (Resolve-Path -LiteralPath $sibling).Path }
        $nested = Join-Path $dir 'Test-MdiReadiness\Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $nested) { return (Resolve-Path -LiteralPath $nested).Path }
        $parent = Split-Path -Parent $dir
        if ($parent -eq $dir) { break }
        $dir = $parent
    }
    throw 'Could not resolve Test-MdiReadiness.ps1 from $PSScriptRoot (sibling first, then parent).'
}

$product = Resolve-ProductScript
$text = Get-Content -LiteralPath $product -Raw
$cut = $text.IndexOf('#region Main')
if ($cut -lt 0) { throw 'Could not find #region Main' }
. ([scriptblock]::Create($text.Substring(0, $cut)))

function New-NnrRecord {
    param($Id, $Port, $Protocol, $Target, $TargetIP, $Success, $Detail, $Group)
    [PSCustomObject]@{
        Id         = $Id; Name = "NNR - $Id"; Protocol = $Protocol; Port = $Port
        Scope      = 'NetworkDevice'; Group = $Group; Requirement = 'AtLeastOne'
        Target     = $Target; TargetIP = $TargetIP
        Applicable = $true; Success = $Success; LatencyMs = $null; Detail = $Detail
    }
}

function New-ServerWith {
    param($Records)
    [PSCustomObject]@{
        FQDN    = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; OS = 'Windows Server 2022'
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom     = 'Sensor server (outbound)'
                FailedRequired = @(); NnrFailedTargets = @()
                Results        = @($Records)
            }
        }
    }
}

function New-ReportDataWith {
    param($Server)
    [PSCustomObject]@{
        DomainControllers   = @($Server)
        CAServers           = @()
        EntraConnectServers = @()
        Domain              = 'fabrikam.local'
    }
}

function Get-GroupLabel {
    param($Group)
    if ($null -eq $Group) { return '$null' }
    if ($Group -is [array]) { return '@(NNR)' }
    if ("$Group" -eq '') { return "''" }
    "$Group"
}

$target = 'memfab01.fabrikam.local'
$targetIp = '10.10.1.51'
# Every shape Group can arrive in once it has been through a JSON round trip or another tool, plus
# the shipped control. 12345 is included because it is NOT blank: it exercises the family-resolution
# path rather than the blank-key path, and the two failed differently before the fix.
$groupShapes = @('NNR', $null, '', 12345, @('NNR'), 'Nnr')

# --- DEFECT 1: a target measured unresolvable is counted by the KPI, whatever its Group says ------
foreach ($group in $groupShapes) {
    $label = Get-GroupLabel -Group $group
    $srv = New-ServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
    )
    $stats = Get-mdiReportStatistics -ReportData (New-ReportDataWith -Server $srv)
    Assert-Equal -Expected 1 -Actual $stats.NnrTargetCount `
        -Because ("a target measured unresolvable with Group {0} must still be counted by the NNR KPI" -f $label)
    Assert-Equal -Expected 0 -Actual $stats.NnrResolvable `
        -Because ("a target measured unresolvable with Group {0} must not count as resolvable" -f $label)
    # The same record must not also be counted as a host the ORDINARY port probes visited. That
    # population is the denominator of the ports sampling disclosure, and an NNR row is not a member.
    Assert-Equal -Expected 0 -Actual $stats.PortDistinctTargetCount `
        -Because ("an NNR record with Group {0} must not be counted in the ordinary-ports population" -f $label)
}

# --- DEFECT 1: a target measured resolvable is counted as resolvable, whatever its Group says -----
foreach ($group in $groupShapes) {
    $label = Get-GroupLabel -Group $group
    $srv = New-ServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Open' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Open' -Group $group)
    )
    $stats = Get-mdiReportStatistics -ReportData (New-ReportDataWith -Server $srv)
    Assert-Equal -Expected 1 -Actual $stats.NnrResolvable `
        -Because ("a target measured resolvable with Group {0} must be counted as resolvable" -f $label)
}

# --- DEFECT 2: one measured success still rescues its siblings, whatever its Group says -----------
# RPC measured OPEN and NetBIOS measured REFUSED against one target is a RESOLVABLE target: the
# AtLeastOne group is satisfied. No blocking record of any kind may be raised for it.
foreach ($group in $groupShapes) {
    $label = Get-GroupLabel -Group $group
    $srv = New-ServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Open' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
    )
    $blocking = @(Get-mdiBlockingPortFailure -Record @(Get-mdiPortResultRecord -Server @($srv)))
    Assert-Equal -Expected 0 -Actual $blocking.Count `
        -Because ("a target one primary method resolved with Group {0} must raise no blocking failure" -f $label)
}

# --- DEFECT 2: an all-blocked target raises ONE finding per target, not one per method ------------
foreach ($group in $groupShapes) {
    $label = Get-GroupLabel -Group $group
    $srv = New-ServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
    )
    $blocking = @(Get-mdiBlockingPortFailure -Record @(Get-mdiPortResultRecord -Server @($srv)) |
            Where-Object { [string] $_.BlockingKind -eq 'NnrMeasured' })
    Assert-Equal -Expected 1 -Actual $blocking.Count `
        -Because ("an all-blocked target with Group {0} must raise one NnrMeasured finding, not one per method" -f $label)
}

# --- the honest untested case survives the fix ----------------------------------------------------
# Success $null with a "not tested" detail is what a probe that never ran records. It must stay on
# the untested path: nothing was observed shut, so it is a gap to re-measure, not a firewall to open.
foreach ($group in @('NNR', $null, '')) {
    $label = Get-GroupLabel -Group $group
    $srv = New-ServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $null -Detail 'Not tested - no route to host' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $null -Detail 'Not tested - no route to host' -Group $group)
    )
    $stats = Get-mdiReportStatistics -ReportData (New-ReportDataWith -Server $srv)
    Assert-Equal -Expected 1 -Actual $stats.NnrUntested `
        -Because ("a target nothing was measured against with Group {0} must be counted untested, not unresolvable" -f $label)
    $kinds = @(Get-mdiBlockingPortFailure -Record @(Get-mdiPortResultRecord -Server @($srv)) |
            ForEach-Object { [string] $_.BlockingKind } | Select-Object -Unique)
    Assert-Equal -Expected 'NnrUntested' -Actual ($kinds -join ',') `
        -Because ("a target nothing was measured against with Group {0} must block as NnrUntested, never NnrMeasured" -f $label)
}

# --- reverse DNS is RECOMMENDED, not primary, and the shared predicate must keep it that way -------
# NnrReverseDns ships with Scope NetworkDevice and Group '' deliberately. Resolving the family from
# the shipped table by Id must not sweep it into the primary set just because its Group is blank -
# that would be the fix curing the disease by making every unreadable value a primary method.
Assert-Equal -Expected $false `
    -Actual (Test-mdiProbeIsPrimaryNnr -Record ([PSCustomObject]@{ Id = 'NnrReverseDns'; Group = 'NNR' })) `
    -Because 'NnrReverseDns is recommended, not primary, even when the record claims Group NNR'
Assert-Equal -Expected $true `
    -Actual (Test-mdiProbeIsPrimaryNnr -Record ([PSCustomObject]@{ Id = 'NnrRpc'; Group = $null })) `
    -Because 'NnrRpc is primary from the shipped table even when the record carries no Group'
Assert-Equal -Expected $true `
    -Actual (Test-mdiProbeIsPrimaryNnr -Record ([PSCustomObject]@{ Id = 'NnrFutureMethod'; Group = 'NNR' })) `
    -Because 'an Id the shipped table does not know falls back to its own Group, so a later method still counts'
Assert-Equal -Expected $false `
    -Actual (Test-mdiProbeIsPrimaryNnr -Record ([PSCustomObject]@{ Id = 'LdapsTcp'; Group = 'NNR' })) `
    -Because 'a shipped non-NNR probe is not made primary by a Group field claiming otherwise'

# A target where ONLY reverse DNS succeeded has had no primary method succeed and is not resolvable.
$srvReverseOnly = New-ServerWith -Records @(
    (New-NnrRecord -Id 'NnrReverseDns' -Port 53 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Resolved' -Group '')
    (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $null)
    (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $null)
)
$statsReverse = Get-mdiReportStatistics -ReportData (New-ReportDataWith -Server $srvReverseOnly)
Assert-Equal -Expected 0 -Actual $statsReverse.NnrResolvable `
    -Because 'a successful reverse DNS lookup must not make a target resolvable in the KPI'
Assert-Equal -Expected 1 -Actual $statsReverse.NnrTargetCount `
    -Because 'the target whose primary methods were refused is still counted, with reverse DNS present'

# --- DEFECT 3: the remediation script opens the ports the verdict condemned -----------------------
# The sensor server shape here is the one New-mdiRemediationScript actually reads: Addresses first,
# then IP. Without a usable source address the whole NNR section is skipped, which would make every
# case below emit nothing and the test pass for the wrong reason - so the CONTROL is asserted to
# emit rules before any other case is believed.
function New-SensorServerWith {
    param($Records)
    [PSCustomObject]@{
        FQDN          = 'dcfab01.fabrikam.local'
        Domain        = 'fabrikam.local'
        OS            = 'Windows Server 2022'
        IP            = '10.10.1.50'
        Addresses     = @('10.10.1.50')
        SensorVersion = '2.240.0.0'
        Details       = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom     = 'Sensor server (outbound)'
                FailedRequired = @(); NnrFailedTargets = @()
                Results        = @($Records)
            }
            SensorHealthDetails  = [PSCustomObject]@{ Installed = $true }
        }
    }
}

function Get-EmittedNnrRule {
    param($Server)
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mdi-nnrfamily-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    $body = ''
    try {
        New-mdiRemediationScript -ReportData (New-ReportDataWith -Server $Server) -FilePath $tmp -WarningAction SilentlyContinue | Out-Null
        if (Test-Path -LiteralPath $tmp) { $body = Get-Content -LiteralPath $tmp -Raw }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    $rules = @([regex]::Matches($body, 'MDI-NNR-[A-Za-z]+-In') | ForEach-Object { $_.Value } | Select-Object -Unique | Sort-Object)
    if ($rules.Count -eq 0) { return '<none>' }
    $rules -join ','
}

$expectedRules = 'MDI-NNR-NetBIOS-In,MDI-NNR-RDP-In,MDI-NNR-RPC-In'
foreach ($group in $groupShapes) {
    $label = Get-GroupLabel -Group $group
    $srv = New-SensorServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
        (New-NnrRecord -Id 'NnrRdp' -Port 3389 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
    )
    Assert-Equal -Expected $expectedRules -Actual (Get-EmittedNnrRule -Server $srv) `
        -Because ("a target the verdict condemned with Group {0} must have its NNR ports opened by the generated script" -f $label)
}

# The other direction: a target one primary method RESOLVED is not unresolvable, so no rule may be
# written for it. Without this the fix could be "emit rules for everything", which passes the
# assertions above and opens ports on hosts whose name resolution was measured working.
foreach ($group in @('NNR', $null, '')) {
    $label = Get-GroupLabel -Group $group
    $srv = New-SensorServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Open' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
    )
    Assert-Equal -Expected '<none>' -Actual (Get-EmittedNnrRule -Server $srv) `
        -Because ("a target one primary method resolved with Group {0} must have no firewall rule written for it" -f $label)
}

# A target nothing was measured against observed nothing shut, so it must never reach the script
# either - that is the "open a port on evidence that does not exist" case.
foreach ($group in @('NNR', $null)) {
    $label = Get-GroupLabel -Group $group
    $srv = New-SensorServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $null -Detail 'Not tested - no route to host' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $null -Detail 'Not tested - no route to host' -Group $group)
    )
    Assert-Equal -Expected '<none>' -Actual (Get-EmittedNnrRule -Server $srv) `
        -Because ("a target nothing was measured against with Group {0} must have no firewall rule written for it" -f $label)
}

Write-Host ("assertions passed={0} failed={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
