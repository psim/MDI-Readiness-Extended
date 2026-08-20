<#
    AN NNR IDENTITY NOBODY COULD READ MUST NOT MERGE TWO HOSTS INSIDE THE READY VERDICT.

    Get-mdiBlockingPortFailure is the set of detail records that must keep a run out of READY. Its own
    header states that it is used by BOTH Get-mdiIssueList (to raise a finding) and
    Test-mdiReadinessResult (to fail the verdict), "so the two cannot diverge". It is therefore the
    single place where a merge does not merely spoil a report card - it decides READY.

    Its 'AtLeastOne' (NNR) half groups the probe records by target and clears a group as soon as one
    member SUCCEEDED. The grouping key already knew that an unreadable identity is dangerous, and its
    comment says exactly what it intends:

        "a record with any null or empty IDENTITY key is given a unique key and judged alone, which is
         the conservative choice because a lone failure still blocks and can mask nothing"

    THE DEFECT. That intent was implemented as

        $keys = @($_.Server, $_.Target, $_.TargetIP)
        if (@($keys | Where-Object { [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0) { ... }

    IsNullOrWhiteSpace([string] $_) is a test of the RENDERING, not of the value - the read this
    codebase keeps restating is not the value, and which ConvertTo-mdiReadableDomainName exists to be
    the single definition of. Every unreadable NON-STRING renders to something non-blank, so it never
    reaches the "judge it alone" branch at all. Worse, the shapes that survive the test render to a
    CONSTANT that ignores their contents:

        a hashtable        -> 'System.Collections.Hashtable'   whatever it contains
        a nested Object[]  -> 'System.Object[]'                whatever it contains

    so TWO DIFFERENT HOSTS produce the SAME key, land in ONE group, and the group is cleared by
    `Success -eq $true` on any member. The records are not built in this process - they are JSON
    produced by the probe script that ran ON the sensor and parsed back with ConvertFrom-Json - so a
    JSON array in Target arrives as Object[] and a JSON object as PSCustomObject. Get-mdiProbeRecordGroupKey
    states this in its own header.

    MEASURED ON THE SHIPPED FUNCTION, one sensor and the estate a real cross-forest NNR run produces -
    ws4.mdilab.local resolving by NetBIOS, ws9.fabrikam.local resolving by NO method at all, three
    methods each, nothing differing but the SHAPE of the two identity fields:

        identity shape                     blocking findings
        plain strings                      1     (correct - ws9 is named)
        one-element collections            1     (correct - the shape is readable and is unwrapped)
        two distinct hashtables            0     <-- ws9 vanished from the verdict
        two distinct nested Object[]       0     <-- ws9 vanished from the verdict
        two distinct multi-element Object[] 1    (unreadable, but renders content-dependently)

    A host that NO name-resolution method could reach was certified by a DIFFERENT host's NetBIOS
    answer, and the run came back READY. This is the same family as the grouping defect pinned by
    UnreadableNnrTargetCannotBeCertifiedByAnother.Tests.ps1, but at the site that decides the verdict
    rather than one report table.

    COLLISION NEEDS BOTH HALVES TO RENDER ALIKE, which is why the last row above did not lose its
    host: a multi-element Object[] renders its contents space-joined, so two different hosts render
    differently and were never merged, exactly as a PSCustomObject renders '@{Name=ws4}' against
    '@{Name=ws9}'. Those shapes are unreadable WITHOUT being a collision. They are still asserted
    here - an unreadable identity must block whether or not it happens to collide - but the test says
    which mechanism each one demonstrates, because a test that claimed they all collide would be
    asserting something the codebase does not do.

    THE FIX routes the three identity keys through ConvertTo-mdiReadableDomainName before the blank
    test, so an identity nobody read normalises to $null, fails the EXISTING test, and takes the
    EXISTING conservative unique-key branch that judges the record alone. It reuses the codebase's one
    ruler rather than inventing a second, exactly as Get-mdiProbeRecordGroupKey does for the same two
    fields ("routes BOTH halves through ConvertTo-mdiReadableDomainName - the codebase's single
    definition of did anybody actually read this value").

    WHAT THIS TEST ALSO REFUSES - the opposite mistakes, which are what make the fix worth pinning.

      * A READABLE estate must behave EXACTLY as before: ws4 is still cleared by its NetBIOS success
        and ws9 is still the single finding. A fix that keyed everything uniquely would "pass" the
        no-false-green assertions by reporting a firewall change on a host whose name resolution was
        measured WORKING - a false red this codebase has already been bitten by at this exact site,
        recorded in the comment above the grouping block.
      * A ONE-ELEMENT COLLECTION is READABLE and must stay readable. ConvertTo-mdiReadableDomainName
        unwraps it deliberately, "because that is the shape this estate really produces", and
        @('fabrikam.local') is a shape the cross-forest rows genuinely carry.
      * The two rulers must AGREE. Whatever ConvertTo-mdiReadableDomainName refuses must be refused as
        a merge key here too, or the verdict is once again deciding readability by its own private
        rule.

    THE SAME KEY IS USED TWICE, AND BOTH SITES ARE PINNED HERE.

    Get-mdiReportStatistics groups the same records the same way, with the same blank-key guard on the
    same raw rendering, to publish the headline "N of M resolvable". Measured on the shipped function
    with host A resolving by NetBIOS, host B resolving by no method at all, and both identities
    arriving as distinct hashtables, that KPI read

        "1 of 1" resolvable

    for an estate containing a host nothing could resolve - a merge that did not merely lose a host
    but rendered the whole estate PERFECT, while the verdict on the same page still raised a blocking
    finding from the very same records. Two views of one fact, disagreeing, with the headline being
    the one that looked clean. Fixing the verdict alone would have left the summary number asserting
    the opposite, so section 7 pins the statistics site as well.
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

# The function's own applicability filter, mandatory filter, measured predicate, family resolution,
# NNR grouping and blocking-kind tagging all run. Nothing about the grouping is stubbed.
function New-NnrRecord {
    param($Server, $Id, $Protocol, $Port, $Target, $TargetIP, $Success, $Detail)
    [PSCustomObject]@{
        Server = $Server; Id = $Id; Name = ('NNR - {0}' -f $Id); Protocol = $Protocol; Port = $Port
        Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'
        Target = $Target; TargetIP = $TargetIP; Applicable = $true
        Success = $Success; LatencyMs = 12; Detail = $Detail
    }
}

# The estate a real cross-forest NNR run produces: one sensor, two targets, three methods each.
# Host A resolves by NetBIOS. Host B resolves by nothing at all, so host B MUST be reported however
# its identity is spelled.
function New-Estate {
    param($TargetA, $IpA, $TargetB, $IpB)
    @(
        New-NnrRecord 'sensor1.mdilab.local' 'NnrRpc' 'TCP' 135 $TargetA $IpA $false 'Connection refused'
        New-NnrRecord 'sensor1.mdilab.local' 'NnrNetBios' 'UDP' 137 $TargetA $IpA $true 'Node status answered'
        New-NnrRecord 'sensor1.mdilab.local' 'NnrRdp' 'TCP' 3389 $TargetA $IpA $false 'Connection refused'
        New-NnrRecord 'sensor1.mdilab.local' 'NnrRpc' 'TCP' 135 $TargetB $IpB $false 'Connection refused'
        New-NnrRecord 'sensor1.mdilab.local' 'NnrNetBios' 'UDP' 137 $TargetB $IpB $false 'No node status answer'
        New-NnrRecord 'sensor1.mdilab.local' 'NnrRdp' 'TCP' 3389 $TargetB $IpB $false 'Connection refused'
    )
}

function Get-BlockingCount {
    param($Records)
    @(Get-mdiBlockingPortFailure -Record $Records).Count
}

Write-Host "`n1. CONTROL - a readable estate must be judged exactly as before"
$control = @(Get-mdiBlockingPortFailure -Record (New-Estate 'ws4.mdilab.local' '10.10.0.4' 'ws9.fabrikam.local' '10.10.1.9'))
Assert-True 'a readable estate yields exactly one blocking NNR finding' ($control.Count -eq 1) "got=$($control.Count)"
Assert-True 'the finding names the host that resolved by nothing' (
    ($control.Count -eq 1) -and ([string] $control[0].Target) -eq 'ws9.fabrikam.local') "got=$([string] $control[0].Target)"
Assert-True 'the host that resolved by NetBIOS is not reported' (
    @($control | Where-Object { ([string] $_.Target) -eq 'ws4.mdilab.local' }).Count -eq 0)
Assert-True 'the finding is tagged as a measured NNR failure' (
    ($control.Count -eq 1) -and ([string] $control[0].BlockingKind) -eq 'NnrMeasured') "got=$([string] $control[0].BlockingKind)"

Write-Host "`n2. NO FALSE GREEN - an unreadable identity must never clear a host nobody could resolve"
# Both halves of BOTH hosts are unreadable, and the two hosts carry DISTINCT values whose renderings
# are identical. Under the defect these collapsed into one group and the NetBIOS success cleared it.
$unreadableShapes = [ordered]@{
    'two distinct hashtables' = @{
        Collides = $true
        A  = @{ Name = 'ws4' }; AIp = @{ Addr = '10.10.0.4' }
        B  = @{ Name = 'ws9' }; BIp = @{ Addr = '10.10.1.9' }
    }
    'two distinct nested Object[]' = @{
        Collides = $true
        A  = [object[]] @(, [object[]] @('ws4', 'mdilab')); AIp = [object[]] @(, [object[]] @('10.10.0.4', 'v4'))
        B  = [object[]] @(, [object[]] @('ws9', 'fabrikam')); BIp = [object[]] @(, [object[]] @('10.10.1.9', 'v4'))
    }
    'two distinct multi-element Object[]' = @{
        Collides = $false
        A  = [object[]] @('ws4', 'mdilab', 'local'); AIp = [object[]] @('10.10.0.4', 'v4', 'x')
        B  = [object[]] @('ws9', 'fabrikam', 'local'); BIp = [object[]] @('10.10.1.9', 'v4', 'x')
    }
}
foreach ($shapeName in $unreadableShapes.Keys) {
    $s = $unreadableShapes[$shapeName]
    $n = Get-BlockingCount (New-Estate $s.A $s.AIp $s.B $s.BIp)
    Assert-True "$shapeName still block the verdict" ($n -gt 0) "got=$n blocking finding(s)"
}

Write-Host "`n3. WHICH RENDERINGS COLLIDE - the premise of the defect, stated as a measurement"
# Not every unreadable shape collides, and saying so is the difference between a test that pins the
# mechanism and one that merely asserts a mood. A hashtable and a NESTED Object[] render to a
# CONSTANT that ignores their contents, so two different hosts key alike and merge. A MULTI-ELEMENT
# Object[] renders its contents space-joined, so two different hosts render differently and never
# merged even under the defect - it is unreadable without being a collision, exactly as a
# PSCustomObject is. It stays in the assertion above because it must still block, and it is excluded
# here because claiming it collides would be a measurement this codebase does not produce.
foreach ($shapeName in $unreadableShapes.Keys) {
    $s = $unreadableShapes[$shapeName]
    $sameName = ([string] $s.A) -eq ([string] $s.B)
    $sameAddr = ([string] $s.AIp) -eq ([string] $s.BIp)
    $blank = [string]::IsNullOrWhiteSpace([string] $s.B)
    if ($s.Collides) {
        Assert-True "$shapeName render identically for two different hosts" ($sameName -and $sameAddr) "name=$sameName addr=$sameAddr"
    } else {
        Assert-True "$shapeName render DIFFERENTLY, so they never merged" (-not ($sameName -and $sameAddr)) "name=$sameName addr=$sameAddr"
    }
    Assert-True "$shapeName are NOT caught by the raw blank test" (-not $blank) "IsNullOrWhiteSpace=$blank"
}

Write-Host "`n4. NO FALSE RED - shapes that ARE readable must keep being read"
$readable = [ordered]@{
    'plain strings'           = @{ A = 'ws4.mdilab.local'; AIp = '10.10.0.4'; B = 'ws9.fabrikam.local'; BIp = '10.10.1.9' }
    'one-element collections' = @{
        A  = [object[]] @('ws4.mdilab.local'); AIp = [object[]] @('10.10.0.4')
        B  = [object[]] @('ws9.fabrikam.local'); BIp = [object[]] @('10.10.1.9')
    }
    'numeric-string labels'   = @{ A = 'ws4.12345.local'; AIp = '10.10.0.4'; B = 'ws9.12345.local'; BIp = '10.10.1.9' }
}
foreach ($shapeName in $readable.Keys) {
    $s = $readable[$shapeName]
    $n = Get-BlockingCount (New-Estate $s.A $s.AIp $s.B $s.BIp)
    Assert-True "$shapeName yield exactly one finding - the host that resolved is still cleared" ($n -eq 1) "got=$n"
}

Write-Host "`n5. A MULTI-HOMED HOST STAYS ONE GROUP PER ADDRESS"
# One name, two addresses, each address probed independently. The address that resolves must not
# certify the address that does not.
$multiHomed = @(
    New-NnrRecord 'sensor1.mdilab.local' 'NnrRpc' 'TCP' 135 'dcfab01.fabrikam.local' '10.10.1.50' $false 'Connection refused'
    New-NnrRecord 'sensor1.mdilab.local' 'NnrNetBios' 'UDP' 137 'dcfab01.fabrikam.local' '10.10.1.50' $true 'Node status answered'
    New-NnrRecord 'sensor1.mdilab.local' 'NnrRpc' 'TCP' 135 'dcfab01.fabrikam.local' '10.10.2.50' $false 'Connection refused'
    New-NnrRecord 'sensor1.mdilab.local' 'NnrNetBios' 'UDP' 137 'dcfab01.fabrikam.local' '10.10.2.50' $false 'No node status answer'
)
$mh = @(Get-mdiBlockingPortFailure -Record $multiHomed)
Assert-True 'the unresolvable address of a multi-homed host is still reported' ($mh.Count -eq 1) "got=$($mh.Count)"
Assert-True 'and it is the address that failed' (
    ($mh.Count -eq 1) -and ([string] $mh[0].TargetIP) -eq '10.10.2.50') "got=$([string] $mh[0].TargetIP)"

Write-Host "`n6. ONE RULER - the verdict must decide readability the way the codebase decides it"
# Whatever ConvertTo-mdiReadableDomainName refuses must not survive as a merge key in the verdict.
$rulerCases = [ordered]@{
    'null'                = $null
    'empty string'        = ''
    'whitespace'          = '   '
    'boolean'             = $true
    'integer'             = 12345
    'hashtable'           = @{ Name = 'ws9' }
    'nested Object[]'     = [object[]] @(, [object[]] @('ws9', 'fabrikam'))
    'multi-element list'  = [object[]] @('ws9', 'fabrikam')
    'one-element list'    = [object[]] @('ws9.fabrikam.local')
    'plain string'        = 'ws9.fabrikam.local'
    'numeric string'      = '12345'
}
foreach ($caseName in $rulerCases.Keys) {
    $value = $rulerCases[$caseName]
    $wasRead = $null -ne (ConvertTo-mdiReadableDomainName -Value $value)
    # An estate in which host B carries this identity on BOTH halves. When the value was not read,
    # host B cannot be certified by host A whatever the renderings do; when it WAS read, host B is a
    # normal named host and must produce exactly one finding.
    $n = Get-BlockingCount (New-Estate 'ws4.mdilab.local' '10.10.0.4' $value $value)
    if ($wasRead) {
        Assert-True "$caseName is read, so host B is named exactly once" ($n -eq 1) "got=$n"
    } else {
        Assert-True "$caseName is refused, so host B cannot be cleared by host A" ($n -gt 0) "got=$n"
    }
}

Write-Host "`n7. THE SAME MERGE IN THE HEADLINE KPI - Get-mdiReportStatistics"
# Get-mdiBlockingPortFailure is not the only ruler built on this key. Get-mdiReportStatistics groups
# the same records the same way to publish "N of M resolvable", the number a reader takes as the
# summary of name resolution for the whole estate, and it carried the identical blank-key guard on
# the identical raw rendering. Measured on the shipped function with the estate below - host A
# resolving by NetBIOS, host B resolving by nothing, and both identities unreadable - the KPI read
#
#     "1 of 1" resolvable
#
# for an estate that contained a host nothing could resolve: not merely a merge, but a merge that
# rendered the estate PERFECT. The two views of one fact then disagreed, because the verdict on the
# same page still raised a blocking finding for the same records. A fix at the verdict alone would
# have left the headline number saying the opposite.
#
# The assertion is deliberately not on an exact pair of numbers. What must never be true is that
# every target counts as resolvable while a host that resolved by NO method is present - which is
# precisely what "1 of 1" claimed.
function New-NnrReport {
    param($TargetA, $IpA, $TargetB, $IpB)
    [PSCustomObject]@{
        DomainsInScope       = @('mdilab.local')
        DomainControllers    = @([PSCustomObject]@{
                FQDN    = 'sensor1.mdilab.local'; Domain = 'mdilab.local'; Unreachable = $false
                Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = (New-Estate $TargetA $IpA $TargetB $IpB) } }
            })
        CAServers            = @(); EntraConnectServers = @()
        DomainAuditing       = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
}

$kpiControl = Get-mdiReportStatistics -ReportData (New-NnrReport 'ws4.mdilab.local' '10.10.0.4' 'ws9.fabrikam.local' '10.10.1.9')
Assert-True 'the readable estate counts both hosts as targets' ([int] $kpiControl.NnrTargetCount -eq 2) `
    "targets=$($kpiControl.NnrTargetCount)"
Assert-True 'the readable estate reports only the host that resolved as resolvable' `
    ([int] $kpiControl.NnrResolvable -eq 1) "resolvable=$($kpiControl.NnrResolvable)"
Assert-True 'the readable estate does not claim every target resolved' `
    ([int] $kpiControl.NnrResolvable -lt [int] $kpiControl.NnrTargetCount) `
    "$($kpiControl.NnrResolvable) of $($kpiControl.NnrTargetCount)"

$kpiShapes = [ordered]@{
    'two distinct hashtables' = @{ A = @{ Name = 'ws4' }; AIp = @{ Ip = '10.10.0.4' }; B = @{ Name = 'ws9' }; BIp = @{ Ip = '10.10.1.9' } }
    'two nested collections'  = @{
        A   = [object[]] @(, [object[]] @('ws4', 'mdilab')); AIp = [object[]] @(, [object[]] @('10', '10'))
        B   = [object[]] @(, [object[]] @('ws9', 'fabrikam')); BIp = [object[]] @(, [object[]] @('10', '11'))
    }
    'null identities on both' = @{ A = $null; AIp = $null; B = $null; BIp = $null }
    'booleans on both'        = @{ A = $true; AIp = $true; B = $false; BIp = $false }
}
foreach ($shapeName in $kpiShapes.Keys) {
    $s = $kpiShapes[$shapeName]
    $kpi = Get-mdiReportStatistics -ReportData (New-NnrReport $s.A $s.AIp $s.B $s.BIp)
    Assert-True "KPI: $shapeName never reports every target as resolvable" `
        ([int] $kpi.NnrResolvable -lt [int] $kpi.NnrTargetCount) `
        "$($kpi.NnrResolvable) of $($kpi.NnrTargetCount)"
    Assert-True "KPI: $shapeName still counts more than one target" `
        ([int] $kpi.NnrTargetCount -gt 1) "targets=$($kpi.NnrTargetCount)"
}

Write-Host ''
Write-Host ("RESULT  pass=$script:pass  fail=$script:fail")
if ($script:fail -gt 0) { exit 1 }
exit 0
