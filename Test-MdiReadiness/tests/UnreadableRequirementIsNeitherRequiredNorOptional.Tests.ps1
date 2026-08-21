# [w155/w156] A Requirement this script COULD NOT READ must not be silently treated as one it read
# and found optional. It must keep the run out of READY - without being painted as a measured
# failure, and without being counted as a required failure.
#
# THE DEFECT. Get-mdiRequirementRank ranks anything unrecognised at 0, and
# Test-mdiRequirementIsMandatory is (rank -eq 3). Those two are CORRECT and must not change:
# promoting a value nobody could read into one that blocks the verdict is the exact inversion
# Get-mdiRequirementRank exists to prevent, and three regression tests pin it
# (PortRequirementIsRankedNotComparedToALiteral, MergedV3MandatoryUsesTheSharedRule,
# MandatoryFailureIsNeverPaintedAdvisory). But a two-state scale has no way to say "the obligation
# itself is unknown", so an unreadable Requirement was indistinguishable from a measured 'Optional'
# and the judgement was made, in silence, in favour of READY.
#
# MEASURED on the shipped v1.1.8 - a known-READY two-forest estate, ONE record added, LDAPS 636 (the
# port -MultiForest promotes to Required), nothing differing but the spelling of Requirement:
#
#     Requirement                      w155 refused port        w156 never-probed port
#     'Required'                       blocking=1 READY=False   unmeasReq=1 READY=False   (control)
#     'All'                            blocking=1 READY=False   unmeasReq=1 READY=False   (control)
#     'Optional'                       blocking=0 READY=True    unmeasReq=0 READY=True    (control)
#     $null                            blocking=0 READY=TRUE    unmeasReq=0 READY=TRUE    <<<
#     ''                               blocking=0 READY=TRUE    unmeasReq=0 READY=TRUE    <<<
#     $true  (JSON "Requirement":true) blocking=0 READY=TRUE    unmeasReq=0 READY=TRUE    <<<
#     12345                            blocking=0 READY=TRUE    unmeasReq=0 READY=TRUE    <<<
#     a hashtable                      blocking=0 READY=TRUE    unmeasReq=0 READY=TRUE    <<<
#     'Required ' (trailing space)     blocking=0 READY=TRUE    -                         <<<
#
# HOW IT ARRIVES, and it is not hypothetical: Requirement makes a full JSON round trip - the plan is
# serialised to the sensor and the results are parsed back with ConvertFrom-Json - and nothing
# re-stamps it from the plan afterwards. Test-mdiRequirementIsMandatory's own header records
# "Requirement":true producing the BOOLEAN $true on that path. -MultiForest is what makes it matter:
# it promotes LdapsTcp and LdapsGcTcp from Optional to Required, so in a cross-forest estate the
# LDAPS records that DECIDE readiness are exactly the ones travelling that round trip.
#
# THE THIRD STATE. Test-mdiRequirementIsUnreadable names the closed readable set - Required, All,
# AtLeastOne, Recommended, Optional - and Get-mdiUnreadableRequirementProbe collects the applicable
# records outside it that were not measured OPEN. The verdict withholds READY over that population,
# the same way it does for a required probe nobody measured. Nothing is trimmed and nothing is
# re-ranked.
#
# WHAT MUST NOT CHANGE, asserted here as strictly as the defect:
#   - the rank scale: ' Required ' still ranks 0 and is still NOT mandatory, and $true likewise.
#   - 'Optional' and 'Recommended' refused still leave the run READY - they were READ.
#   - a port measured OPEN with an unreadable Requirement stays READY. An open port satisfies every
#     obligation on the scale, so charging it would be a false red on a path proven fine.
#   - an unreadable Requirement is NEVER counted in PortsRequiredFail and never appears in
#     Get-mdiBlockingPortFailure. It is not a measured failure and must not be painted as one.
# Without those controls a fix that simply charged everything, or that trimmed, would pass.
#
# Run under Windows PowerShell 5.1.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Test-mdiReadinessResult') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# The known-READY baseline: two controllers, one per forest, every check passing. The only thing that
# can make this run anything other than READY is the single port record added below. The stored
# RequiredPorts summary is held at $true on every row deliberately - the scanner computes it with the
# same mandatory predicate, so a record whose Requirement it could not read would not have been
# counted against the summary either. That isolates Requirement as the single variable.
function New-Estate {
    param(
        [object] $Requirement,
        [object] $Success = $false,
        [switch] $NoPortRecord,
        [object] $Applicable = $true
    )
    $dc1 = [PSCustomObject]@{ FQDN = 'dc01.mdilab.local'; Domain = 'mdilab.local'; isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
    $dc2 = [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
    if (-not $NoPortRecord) {
        $detail = if ($null -eq $Success) { 'Not tested' } elseif ($Success -eq $true) { 'Open' } else { 'Connection refused' }
        $rec = [PSCustomObject]@{
            Id = 'LdapsTcp'; Group = 'Ports'; Scope = 'DomainController'; Requirement = $Requirement
            Protocol = 'TCP'; Port = 636; Target = 'dcfab01.fabrikam.local'; TargetIP = '10.10.1.50'
            Applicable = $Applicable; Success = $Success; Detail = $detail
        }
        $dc2 | Add-Member -NotePropertyName RequiredPorts -NotePropertyValue $true -Force
        $dc2 | Add-Member -NotePropertyName Details -NotePropertyValue ([PSCustomObject]@{
                RequiredPortsDetails = [PSCustomObject]@{ Results = @($rec) }
            }) -Force
    }
    [PSCustomObject]@{
        Domain              = 'mdilab.local'
        Domains             = @('mdilab.local', 'fabrikam.local')
        DomainsInScope      = @('mdilab.local', 'fabrikam.local')
        DomainControllers   = @($dc1, $dc2)
        CAServers           = @()
        EntraConnectServers = @()
    }
}

# Every surface an operator acts on, read through ONE call, so a fix that repairs the verdict and
# leaves the statistics, the issue list or the per-server port state behind cannot pass.
function Measure-Surfaces {
    param($Data)
    $stats = Get-mdiReportStatistics -ReportData $Data
    $records = @(Get-mdiPortResultRecord -Server $Data.DomainControllers)
    $list = @(Get-mdiIssueList -Statistics $stats -ReportData $Data)
    $unreadIssues = @($list | Where-Object {
            (@($_.PSObject.Properties | ForEach-Object { [string] $_.Value }) -join ' ') -match 'could not read'
        })
    [PSCustomObject]@{
        Ready             = [bool] (Test-mdiReadinessResult -ReportData $Data)
        RequiredFail      = [int] $stats.PortsRequiredFail
        RequiredUntested  = [int] $stats.PortsRequiredUntested
        RequirementUnread = [int] $stats.PortsRequirementUnread
        Blocking          = @(Get-mdiBlockingPortFailure -Record $records).Count
        UnreadablePop     = @(Get-mdiUnreadableRequirementProbe -Record $records).Count
        PortState         = [string] (Get-mdiEffectivePortState -Server $Data.DomainControllers[1])
        UnreadIssues      = $unreadIssues.Count
    }
}

# The spellings the codebase itself calls non-hypothetical, plus the padded one. Named so a failure
# reports which shape broke.
$unreadable = @(
    @{ Label = '$null'; Value = $null }
    @{ Label = "''"; Value = '' }
    @{ Label = '$true (JSON true)'; Value = $true }
    @{ Label = '12345'; Value = 12345 }
    @{ Label = 'a hashtable'; Value = @{ a = 1 } }
    @{ Label = "'Required ' (padded)"; Value = 'Required ' }
)

''
'--- CONTROLS: the rank scale must not move ---'

Assert-That "' Required ' still ranks 0" ((Get-mdiRequirementRank -Requirement ' Required ') -eq 0) ("got $(Get-mdiRequirementRank -Requirement ' Required ')")
Assert-That "' Required ' is still NOT mandatory" (-not (Test-mdiRequirementIsMandatory -Requirement ' Required ')) 'it was promoted'
Assert-That '$true is still NOT mandatory' (-not (Test-mdiRequirementIsMandatory -Requirement $true)) 'it was promoted'
Assert-That "'Required' is still mandatory" (Test-mdiRequirementIsMandatory -Requirement 'Required') 'the control broke'
Assert-That "'All' is still mandatory" (Test-mdiRequirementIsMandatory -Requirement 'All') 'the control broke'

'--- CONTROLS: what the readable set answers ---'
foreach ($readable in 'Required', 'All', 'AtLeastOne', 'Recommended', 'Optional') {
    Assert-That "'$readable' is READABLE" (-not (Test-mdiRequirementIsUnreadable -Requirement $readable)) 'it was called unreadable'
}
foreach ($u in $unreadable) {
    Assert-That "$($u.Label) is UNREADABLE" (Test-mdiRequirementIsUnreadable -Requirement $u.Value) 'it was called readable'
}

''
'--- CONTROLS: the estate and the read spellings ---'

$m = Measure-Surfaces (New-Estate -NoPortRecord)
Assert-That 'the BASELINE with no port record is READY' ($m.Ready) ("got Ready=$($m.Ready)")

$m = Measure-Surfaces (New-Estate -Requirement 'Required')
Assert-That "'Required' refused is NOT READY" (-not $m.Ready) ("got Ready=$($m.Ready)")
Assert-That "'Required' refused is a required failure" ($m.RequiredFail -eq 1) ("got $($m.RequiredFail)")
Assert-That "'Required' refused is blocking" ($m.Blocking -eq 1) ("got $($m.Blocking)")

$m = Measure-Surfaces (New-Estate -Requirement 'All')
Assert-That "'All' refused is NOT READY" (-not $m.Ready) ("got Ready=$($m.Ready)")

$m = Measure-Surfaces (New-Estate -Requirement 'Optional')
Assert-That "'Optional' refused is still READY - it was READ" ($m.Ready) ("got Ready=$($m.Ready)")
Assert-That "'Optional' refused charges no unread requirement" ($m.RequirementUnread -eq 0) ("got $($m.RequirementUnread)")

$m = Measure-Surfaces (New-Estate -Requirement 'Recommended')
Assert-That "'Recommended' refused is still READY - it was READ" ($m.Ready) ("got Ready=$($m.Ready)")

''
'--- THE DEFECT w155: a REFUSED required port demoted by an unreadable Requirement ---'

foreach ($u in $unreadable) {
    $m = Measure-Surfaces (New-Estate -Requirement $u.Value -Success $false)
    Assert-That "refused + $($u.Label) is NOT READY" (-not $m.Ready) ("got Ready=$($m.Ready)")
    Assert-That "refused + $($u.Label) is counted as an unread requirement" ($m.RequirementUnread -ge 1) ("got $($m.RequirementUnread)")
    Assert-That "refused + $($u.Label) puts the server's ports in Unread" ($m.PortState -eq 'Unread') ("got '$($m.PortState)'")
    Assert-That "refused + $($u.Label) raises a finding that says so" ($m.UnreadIssues -ge 1) ("got $($m.UnreadIssues)")
    # The other half of the contract: it must NOT become a measured failure.
    Assert-That "refused + $($u.Label) is NOT a required failure" ($m.RequiredFail -eq 0) ("got $($m.RequiredFail)")
    Assert-That "refused + $($u.Label) is NOT blocking" ($m.Blocking -eq 0) ("got $($m.Blocking)")
}

''
'--- THE DEFECT w156: a NEVER-PROBED required port hidden by an unreadable Requirement ---'

foreach ($u in $unreadable) {
    $m = Measure-Surfaces (New-Estate -Requirement $u.Value -Success $null)
    Assert-That "never probed + $($u.Label) is NOT READY" (-not $m.Ready) ("got Ready=$($m.Ready)")
    Assert-That "never probed + $($u.Label) is counted as an unread requirement" ($m.RequirementUnread -ge 1) ("got $($m.RequirementUnread)")
    Assert-That "never probed + $($u.Label) is NOT a required failure" ($m.RequiredFail -eq 0) ("got $($m.RequiredFail)")
    Assert-That "never probed + $($u.Label) is NOT blocking" ($m.Blocking -eq 0) ("got $($m.Blocking)")
}

$m = Measure-Surfaces (New-Estate -Requirement 'Required' -Success $null)
Assert-That "never probed + 'Required' is still the unmeasured-required control" ($m.RequiredUntested -ge 1) ("got $($m.RequiredUntested)")
Assert-That "never probed + 'Required' is NOT READY" (-not $m.Ready) ("got Ready=$($m.Ready)")

''
'--- CONTROLS: an unreadable Requirement must not invent a failure ---'

# A port measured OPEN satisfies every obligation on the scale, so the unreadable spelling cannot
# change the answer. Charging it would be a false red on a path that was proven fine - the mirror
# image of the defect, and the direction Get-mdiRequirementRank exists to refuse.
foreach ($u in $unreadable) {
    $m = Measure-Surfaces (New-Estate -Requirement $u.Value -Success $true)
    Assert-That "OPEN + $($u.Label) is still READY" ($m.Ready) ("got Ready=$($m.Ready)")
    Assert-That "OPEN + $($u.Label) charges no unread requirement" ($m.RequirementUnread -eq 0) ("got $($m.RequirementUnread)")
}

# A record that explicitly does not apply carries no obligation to read, exactly as it carries none
# for the mandatory population.
$m = Measure-Surfaces (New-Estate -Requirement $null -Success $false -Applicable $false)
Assert-That 'a NOT APPLICABLE record with an unreadable Requirement is still READY' ($m.Ready) ("got Ready=$($m.Ready)")
Assert-That 'a NOT APPLICABLE record charges no unread requirement' ($m.RequirementUnread -eq 0) ("got $($m.RequirementUnread)")

''
'--- CROSS-SURFACE: the statistics and the population must agree ---'

foreach ($u in $unreadable) {
    $m = Measure-Surfaces (New-Estate -Requirement $u.Value -Success $false)
    Assert-That "refused + $($u.Label): PortsRequirementUnread equals the population" ($m.RequirementUnread -eq $m.UnreadablePop) ("stat=$($m.RequirementUnread) pop=$($m.UnreadablePop)")
}

''
'--- CROSS-SURFACE: the ports card must not call an unreadable obligation optional ---'

# The w155 shape - measured shut, requirement unreadable - satisfies BOTH the unreadable branch and
# the PortsBlocked branch of the card's sub-label. If the unreadable branch is not reached first, the
# card tells the operator a REQUIRED port that was measured shut is "optional or recommended", which
# is precisely the misclassification this state exists to end.
foreach ($u in $unreadable) {
    $data = New-Estate -Requirement $u.Value -Success $false
    $stats = Get-mdiReportStatistics -ReportData $data 3> $null
    $html = Get-mdiOverviewHtml -ReportData $data -Statistics $stats 3> $null | Out-String
    Assert-That "refused + $($u.Label): the card says the requirement could not be read" ($html -match 'requirement that could not be read') 'the card never said so'
    Assert-That "refused + $($u.Label): the card does NOT call it optional or recommended" ($html -notmatch 'optional or recommended probe\(s\) blocked') 'it was misclassified on the card'
}

# And the control: a genuinely optional blocked probe must still say exactly that.
$data = New-Estate -Requirement 'Optional' -Success $false
$stats = Get-mdiReportStatistics -ReportData $data 3> $null
$html = Get-mdiOverviewHtml -ReportData $data -Statistics $stats 3> $null | Out-String
Assert-That "'Optional' blocked is still described as optional or recommended" ($html -match 'optional or recommended probe\(s\) blocked') 'the control branch was lost'

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
