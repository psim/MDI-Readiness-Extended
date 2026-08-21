<#
    THE PORT SAMPLING DISCLOSURE MUST COUNT THE SAME POPULATION IT MEASURES AGAINST.

    "Required ports open ... N of M host(s) in scope were probed" is a RATIO, and its two halves were
    drawn from two different populations:

        PortCandidateHostCount   the DENOMINATOR - domain controllers only. Built from
                                 $ReportData.DomainControllers filtered by Test-mdiServerIsProbeCandidate.
        PortDistinctTargetCount  the NUMERATOR - built from every probe record that was not a PRIMARY
                                 NNR row, i.e. filtered only by `-not (Test-mdiProbeIsPrimaryNnr ...)`.

    Test-mdiProbeIsPrimaryNnr answers on the GROUP key being 'NNR'. Its own header says NnrReverseDns
    is "deliberately NOT one of them: it shares the NetworkDevice scope but is recommended". So a
    reverse-DNS row - Scope 'NetworkDevice', Group $null by catalogue definition - SURVIVED that
    filter and put a host into a numerator whose denominator counts domain controllers.

    THE TRIGGER IS THE SCRIPT'S OWN DOCUMENTED USAGE, not an exotic estate. The example in the help is

        .\Test-MdiReadiness.ps1 -Forest ... -NnrTargetComputer 'WKS001', 'SRV042' -OpenHtmlReport

    a workstation and a member server. The NetworkDevice branch of the probe dispatcher records them
    under their own names, and every record reaches the counter through ONE flat list, because
    Get-mdiPortResultRecord reads Details.RequiredPortsDetails.Results and nothing else. The product
    already knows these hosts are special: when -NnrTargetComputer is supplied it sets
    NnrCandidateCount to the distinct target count precisely so that "the operator chose the list and
    no sampling claim should be made". The PORT card had no such protection.

    MEASURED ON THE SHIPPED FUNCTIONS, two of four domain controllers actually probed in every row:

        estate                                    scope  probed  discloses sampling
        baseline, no named hosts                    4      2      True     <- honest
        + WKS001                                    4      3      True     <- reads "3 of 4"
        + WKS001 and SRV042                         4      4      FALSE    <- SUPPRESSED
        CONTROL: the same two as PRIMARY NNR rows   4      2      True     <- unmoved

    Two named workstations erased the fact that half the estate was never probed, on the card an
    operator reads first after an alert about blocked traffic. Get-mdiProbeRecordTargetKey's own
    header describes the same harm from the other direction - "three domain controllers that were
    never probed, one of them the only controller in an AD site, were reported as a fully probed
    estate". That earlier fix gave the two halves one SPELLING ruler; it did not give them one
    POPULATION, which is what this test pins.

    THE CONTROL ROW IS THE POINT. The exclusion DOES work for the rows it was written for - primary
    NNR rows never entered the numerator - so this is not "NNR leaks into the ports card" in general.
    It is specifically the RECOMMENDED NetworkDevice rows that were missed.

    WHY THE FIX IS NOT "REQUIRE Scope -eq 'DomainController'". Measured: that collapses the numerator
    to ZERO on real estates, because port records do not reliably carry Scope -
    SampledEstateStillSaysItWasSampled.Tests.ps1 goes 14 pass / 7 fail with "four distinct hosts were
    probed got 0". The device population is excluded instead.

    KNOWN AND DELIBERATELY NOT PINNED HERE: an UNREADABLE Scope - $null, '', 'Unknown', 12345, a
    hashtable - still enters the numerator. Excluding those needs the numerator to be intersected with
    the candidate population rather than filtered on Scope, and that first needs
    Get-mdiProbeRecordTargetKey and Get-mdiServerIdentityKey proven key-comparable. Separate item.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function New-PortRecord {
    param($Target, $Port = 389)
    [PSCustomObject]@{
        Id = ('p-TCP-{0}' -f $Port); Group = 'Ports'; Scope = 'DomainController'; Requirement = 'Required'
        Protocol = 'TCP'; Port = $Port; Target = $Target; TargetIP = '10.10.1.9'
        Applicable = $true; Success = $true; Detail = 'Open'
    }
}

# The SHIPPED shape of the reverse-DNS row: Scope 'NetworkDevice', Group $null, Recommended, UDP 53.
# An empty Group is a real shipped value and the test must not invent one.
function New-ReverseDnsRecord {
    param($Target, $TargetIP)
    [PSCustomObject]@{
        Id = 'NnrReverseDns'; Group = $null; Scope = 'NetworkDevice'; Requirement = 'Recommended'
        Protocol = 'UDP'; Port = 53; Target = $Target; TargetIP = $TargetIP
        Applicable = $true; Success = $true; Detail = 'PTR answered'
    }
}

# A PRIMARY NNR row against the same host - Group 'NNR' is what makes it primary.
function New-PrimaryNnrRecord {
    param($Target, $TargetIP)
    [PSCustomObject]@{
        Id = 'NnrNetBios'; Group = 'NNR'; Scope = 'NetworkDevice'; Requirement = 'Recommended'
        Protocol = 'UDP'; Port = 137; Target = $Target; TargetIP = $TargetIP
        Applicable = $true; Success = $true; Detail = 'Resolved'
    }
}

function New-Estate {
    param($TotalDc = 4, $ProbedDc = 2, $Extra = @())
    $dcs = @(1..$TotalDc | ForEach-Object {
            $o = [PSCustomObject]@{
                FQDN = ('dc{0}.mdilab.local' -f $_); Domain = 'mdilab.local'; Unreachable = $false
                Comment = $null; SensorVersion = '2.245.0.0'; Details = [PSCustomObject]@{}
            }
            $o | Add-Member -NotePropertyName NtlmAuditing -NotePropertyValue $true -Force
            $o
        })
    $records = @(1..$ProbedDc | ForEach-Object { New-PortRecord -Target ('dc{0}.mdilab.local' -f $_) })
    $records += @($Extra)
    $dcs[0] | Add-Member -NotePropertyName RequiredPorts -NotePropertyValue $true -Force
    $dcs[0].Details | Add-Member -NotePropertyName RequiredPortsDetails -NotePropertyValue ([PSCustomObject]@{ Results = $records }) -Force
    [PSCustomObject]@{
        DomainControllers = $dcs; CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('mdilab.local'); Domain = 'mdilab.local'; Forest = 'mdilab.local'
    }
}

function Measure-Disclosure {
    param($Report)
    $st = Get-mdiReportStatistics -ReportData $Report
    [PSCustomObject]@{
        Scope     = [int] $st.PortCandidateHostCount
        Probed    = [int] $st.PortDistinctTargetCount
        Discloses = ([int] $st.PortCandidateHostCount) -gt ([int] $st.PortDistinctTargetCount)
    }
}

Write-Host 'The port sampling disclosure counts only the population it measures against' -ForegroundColor Cyan

$wks = New-ReverseDnsRecord -Target 'WKS001.mdilab.local' -TargetIP '10.10.3.20'
$srv = New-ReverseDnsRecord -Target 'SRV042.mdilab.local' -TargetIP '10.10.3.21'

# The rows really do escape the primary-NNR filter - if this stops being true the rest of the test is
# measuring nothing, so it is asserted rather than assumed.
Assert-That 'a recommended reverse-DNS row is NOT a primary NNR row' (
    -not (Test-mdiProbeIsPrimaryNnr -Record $wks)) 'it is, so the numerator filter would already exclude it'
Assert-That 'a primary NNR row IS one' (
    Test-mdiProbeIsPrimaryNnr -Record (New-PrimaryNnrRecord -Target 'WKS001.mdilab.local' -TargetIP '10.10.3.20'))

$base = Measure-Disclosure (New-Estate -TotalDc 4 -ProbedDc 2)
Assert-That 'the honest baseline: 2 of 4 probed' (
    $base.Scope -eq 4 -and $base.Probed -eq 2) "(scope=$($base.Scope) probed=$($base.Probed))"
Assert-That 'the honest baseline discloses that it sampled' $base.Discloses

$one = Measure-Disclosure (New-Estate -TotalDc 4 -ProbedDc 2 -Extra @($wks))
Assert-That 'ONE named non-DC host does not inflate the numerator' (
    $one.Probed -eq 2) "(probed=$($one.Probed), expected 2 - a workstation is not a domain controller)"
Assert-That '  ...and the sample is still disclosed' $one.Discloses

$two = Measure-Disclosure (New-Estate -TotalDc 4 -ProbedDc 2 -Extra @($wks, $srv))
Assert-That 'TWO named non-DC hosts do not close the gap' (
    $two.Probed -eq 2) "(probed=$($two.Probed), expected 2)"
Assert-That '  ...and the sample is STILL disclosed - this is the suppression the defect caused' $two.Discloses

# THE CONTROL. Primary NNR rows were always excluded, and must stay excluded, so a fix that simply
# dropped every NNR-ish row would pass the rows above and this one identically - but a fix that broke
# the ORIGINAL exclusion would show up here.
$ctrl = Measure-Disclosure (New-Estate -TotalDc 4 -ProbedDc 2 -Extra @(
        (New-PrimaryNnrRecord -Target 'WKS001.mdilab.local' -TargetIP '10.10.3.20')
        (New-PrimaryNnrRecord -Target 'SRV042.mdilab.local' -TargetIP '10.10.3.21')))
Assert-That 'CONTROL: primary NNR rows are still excluded from the numerator' (
    $ctrl.Probed -eq 2) "(probed=$($ctrl.Probed), expected 2)"

# THE OPPOSITE DIRECTION. A genuinely complete run must not start claiming it sampled.
$full = Measure-Disclosure (New-Estate -TotalDc 4 -ProbedDc 4)
Assert-That 'a fully probed estate counts every domain controller' (
    $full.Scope -eq 4 -and $full.Probed -eq 4) "(scope=$($full.Scope) probed=$($full.Probed))"
Assert-That 'a fully probed estate makes NO sampling claim' (-not $full.Discloses)

# And a fully probed estate with named non-DC hosts must still make no claim - the fix must not push
# the numerator BELOW the denominator either.
$fullNamed = Measure-Disclosure (New-Estate -TotalDc 4 -ProbedDc 4 -Extra @($wks, $srv))
Assert-That 'a fully probed estate with named NNR hosts still makes no sampling claim' (
    -not $fullNamed.Discloses) "(scope=$($fullNamed.Scope) probed=$($fullNamed.Probed))"

''
"RESULT pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
