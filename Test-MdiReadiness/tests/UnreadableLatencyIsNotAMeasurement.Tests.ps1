<#
    A PROBE LATENCY THAT WAS NEVER MEASURED IS NOT A FAST PROBE, AND IT MUST NOT TAKE THE PAGE DOWN.

    The probe-latency table in Get-mdiRequiredPortsHtml selected its population with a BARE $null guard

        $timed = @($records | Where-Object { $null -ne $_.LatencyMs -and $_.Success })

    and then cast HARD three times: Sort-Object { [int] $_.LatencyMs }, a [int] [math]::Round over
    Measure-Object -Average, and $latency = [int] $row.LatencyMs for the cell.

    Success IS normalised - Get-mdiPortResultRecord runs it through ConvertTo-mdiBoolean for precisely
    this reason - but LatencyMs reached the table exactly as it arrived, and a bare $null guard admits
    every shape that is not $null. Measured on the shipped function with one otherwise complete
    successful LDAPS record, LatencyMs replaced one shape at a time:

        130         '130 ms' amber                     correct
        $null       excluded                           correct
        ''          '0 ms' GREEN                       <- the fastest possible probe, for one nobody timed
        $true       '1 ms' GREEN                       <- the same illusion, from a flag
        '   '       THREW Cannot convert value "   " to type "System.Int32"
        'n/a'       THREW Cannot convert value "n/a" to type "System.Int32"
        'timed out' THREW Cannot convert value "timed out" to type "System.Int32"
        @{}         THREW Cannot convert the "System.Collections.Hashtable" value ... to "System.Int32"
        huge string THREW Value was either too large or too small for an Int32

    Both halves are wrong in the way this tool must never be wrong. The empty string and the boolean
    print a hard green figure for a path that was never timed, and they move the stated average with
    them: three good rows averaging 274 ms read 206 ms once a fourth unreadable row was admitted as
    zero. The throw is worse still, because Get-mdiRequiredPortsHtml also renders "Ports that need
    attention" - the readiness-critical table - and one unreadable latency beside three perfectly good
    rows produced NO network ports section at all.

    The sibling sort forty lines above already used the defensive form, [int] ($_.Port -as [int]), and
    its comment asserted "The same cast is already applied to LatencyMs a few lines below for exactly
    this reason". It was not the same cast, and that false claim of parity is what kept this hidden.

    This is an ordinary shape now rather than a contrived one. Sensors sit in HQ-Site, EMEA-Site and
    Branch-Site and probe across the fabrikam.local forest trust, so a probe that succeeded without a
    stopwatch reading is routine, and a report that has been through a JSON round trip in another tool,
    hand-edited, or produced by an older version is the second source this table is fed from.

    These assertions drive the REAL renderer end to end - through Get-mdiPortResultRecord, so the record
    normalisation is exercised too - and read the numbers back out of the emitted HTML.
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

# A sensor server carrying one successful LDAPS probe. Everything except LatencyMs is a complete,
# ordinary record, so nothing but the latency shape can be responsible for what the table does.
function New-TimedServer {
    param([string] $Fqdn, [object] $LatencyMs, [string] $TargetName)
    [PSCustomObject]@{
        FQDN    = $Fqdn
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom = 'dc1.mdilab.local'
                Results    = @(
                    [PSCustomObject]@{
                        Id          = 'LdapS'; Name = 'LDAPS'; Protocol = 'TCP'; Port = 636
                        Scope       = 'DomainController'; Group = 'LDAP'; Requirement = 'Required'
                        Applicable  = $true; Success = $true; Detail = 'Connected'
                        Target      = $TargetName; TargetIP = '10.10.1.50'; LatencyMs = $LatencyMs
                    }
                )
            }
        }
    }
}

# The three readable probes every case below is measured against: a near HQ-Site DC, an EMEA-Site DC
# across the WAN, and a Branch-Site DC. Their true mean is 274 ms.
function Get-ReadableEstate {
    @(
        (New-TimedServer -Fqdn 'dc1.mdilab.local' -LatencyMs 3 -TargetName 'dc2.mdilab.local')
        (New-TimedServer -Fqdn 'dc3.mdilab.local' -LatencyMs 180 -TargetName 'dc4.emea.mdilab.local')
        (New-TimedServer -Fqdn 'dc5.mdilab.local' -LatencyMs 640 -TargetName 'dc6.mdilab.local')
    )
}
$script:readableMean = 274

function Get-LatencyCells {
    param([string] $Html)
    @([regex]::Matches($Html, '<td class="(?:red|amber|green)">([^<]*) ms</td>') |
            ForEach-Object { $_.Groups[1].Value })
}
function Get-StatedAverage {
    param([string] $Html)
    $m = [regex]::Match($Html, 'Average (-?\d+) ms')
    if (-not $m.Success) { return -1 }
    [int] $m.Groups[1].Value
}

# Every shape that is not a readable number. Each one must be treated as "nothing was measured".
$unreadable = @(
    @{ Label = 'empty string'; Value = '' }
    @{ Label = 'whitespace string'; Value = '   ' }
    @{ Label = 'non-numeric string "n/a"'; Value = 'n/a' }
    @{ Label = 'non-numeric string "timed out"'; Value = 'timed out' }
    @{ Label = 'boolean $true'; Value = $true }
    @{ Label = 'boolean $false'; Value = $false }
    @{ Label = 'hashtable'; Value = @{} }
    @{ Label = 'array'; Value = @(120) }
)

Write-Host 'Probe latency: an unreadable reading is neither a measurement nor a crash' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------
# THE CRASH. One unreadable latency beside three good rows must not cost the whole network ports
# section - the "Ports that need attention" table is rendered by the same function.
# ---------------------------------------------------------------------------------------------------
foreach ($case in $unreadable) {
    $estate = @(Get-ReadableEstate) +
    @(New-TimedServer -Fqdn 'dcfab01.fabrikam.local' -LatencyMs $case.Value -TargetName 'memfab01.fabrikam.local')
    $html = $null
    $threw = ''
    try { $html = (Get-mdiRequiredPortsHtml -Server $estate) -join "`n" } catch { $threw = $_.Exception.Message }

    Assert-That ('renders at all with LatencyMs = {0}' -f $case.Label) ($threw -eq '') $threw
    if ($threw -ne '') { continue }

    Assert-That ('keeps the ports table with LatencyMs = {0}' -f $case.Label) `
    ($html -match 'Sensor server') 'the whole network ports section was lost'

    $cells = Get-LatencyCells -Html $html
    Assert-That ('does not render a latency cell for LatencyMs = {0}' -f $case.Label) `
    ($cells.Count -eq 3) ('cells=[{0}]' -f ($cells -join ','))

    # The specific false measurement: '' and $true used to print 0 ms and 1 ms, both painted green.
    Assert-That ('invents no zero-latency row for LatencyMs = {0}' -f $case.Label) `
    ($cells -notcontains '0' -and $cells -notcontains '1') ('cells=[{0}]' -f ($cells -join ','))

    Assert-That ('leaves the stated average untouched by LatencyMs = {0}' -f $case.Label) `
    ((Get-StatedAverage -Html $html) -eq $script:readableMean) `
    ('stated={0} expected={1}' -f (Get-StatedAverage -Html $html), $script:readableMean)

    # Silently dropping it would trade the crash for a page that looks complete. The count must be said.
    Assert-That ('states that a probe went untimed for LatencyMs = {0}' -f $case.Label) `
    ($html -match 'no readable round-trip time') 'the omission was not disclosed'
}

# ---------------------------------------------------------------------------------------------------
# READABLE SHAPES ARE STILL READ. A fix that answered every non-[int] with "unmeasured" would throw
# away the numeric string a JSON round trip produces, which is a real measurement.
# ---------------------------------------------------------------------------------------------------
$readable = @(
    @{ Label = 'int 42'; Value = 42; Expect = '42'; Class = 'green' }
    @{ Label = 'numeric string "730"'; Value = '730'; Expect = '730'; Class = 'amber' }
    @{ Label = 'numeric string "1500"'; Value = '1500'; Expect = '1500'; Class = 'red' }
    @{ Label = 'double 18.6'; Value = [double] 18.6; Expect = '19'; Class = 'green' }
    @{ Label = 'decimal string "12.7"'; Value = '12.7'; Expect = '13'; Class = 'green' }
    @{ Label = 'zero'; Value = 0; Expect = '0'; Class = 'green' }
)
foreach ($case in $readable) {
    $html = (Get-mdiRequiredPortsHtml -Server @(
            New-TimedServer -Fqdn 'dc1.mdilab.local' -LatencyMs $case.Value -TargetName 'dcfab01.fabrikam.local')) -join "`n"
    $cells = Get-LatencyCells -Html $html
    Assert-That ('reads LatencyMs = {0} as {1} ms' -f $case.Label, $case.Expect) `
    (($cells -join ',') -eq $case.Expect) ('cells=[{0}]' -f ($cells -join ','))
    Assert-That ('keeps the {0} threshold for LatencyMs = {1}' -f $case.Class, $case.Label) `
    ($html -match ('<td class="{0}">{1} ms</td>' -f $case.Class, $case.Expect))
    Assert-That ('claims no untimed probe for LatencyMs = {0}' -f $case.Label) `
    ($html -notmatch 'no readable round-trip time')
}

# ---------------------------------------------------------------------------------------------------
# A READING TOO LARGE FOR Int32. Absurd as a round trip, but perfectly readable as a number, and it
# used to overflow the cell cast AND the average cast and destroy the page.
# ---------------------------------------------------------------------------------------------------
$bigHtml = $null
$bigThrew = ''
try {
    $bigHtml = (Get-mdiRequiredPortsHtml -Server (@(Get-ReadableEstate) +
            @(New-TimedServer -Fqdn 'dcfab01.fabrikam.local' -LatencyMs '99999999999999' -TargetName 'memfab01.fabrikam.local'))) -join "`n"
}
catch { $bigThrew = $_.Exception.Message }
Assert-That 'a latency beyond Int32 does not destroy the table' ($bigThrew -eq '') $bigThrew
if ($bigThrew -eq '') {
    Assert-That 'a latency beyond Int32 renders its digits' ((Get-LatencyCells -Html $bigHtml) -contains '99999999999999') `
    ('cells=[{0}]' -f ((Get-LatencyCells -Html $bigHtml) -join ','))
    Assert-That 'a latency beyond Int32 is painted red' ($bigHtml -match '<td class="red">99999999999999 ms</td>')
}

# ---------------------------------------------------------------------------------------------------
# $null STILL MEANS "nothing was measured", and it is the ordinary way to say so - it must be excluded
# from the rows and from the average exactly as before, and it must not be reported as a surprise.
# ---------------------------------------------------------------------------------------------------
$nullHtml = (Get-mdiRequiredPortsHtml -Server (@(Get-ReadableEstate) +
        @(New-TimedServer -Fqdn 'dcfab01.fabrikam.local' -LatencyMs $null -TargetName 'memfab01.fabrikam.local'))) -join "`n"
Assert-That 'a $null latency contributes no row' ((Get-LatencyCells -Html $nullHtml).Count -eq 3) `
('cells=[{0}]' -f ((Get-LatencyCells -Html $nullHtml) -join ','))
Assert-That 'a $null latency does not move the average' ((Get-StatedAverage -Html $nullHtml) -eq $script:readableMean) `
('stated={0}' -f (Get-StatedAverage -Html $nullHtml))

# ---------------------------------------------------------------------------------------------------
# EVERY SUCCESSFUL PROBE UNREADABLE. Rendering nothing at all would read as "nothing was slow" rather
# than as "nothing was timed", which is the quieter version of the same lie.
# ---------------------------------------------------------------------------------------------------
$allBadHtml = (Get-mdiRequiredPortsHtml -Server @(
        (New-TimedServer -Fqdn 'dcfab01.fabrikam.local' -LatencyMs 'n/a' -TargetName 'memfab01.fabrikam.local')
        (New-TimedServer -Fqdn 'dc7.mdilab.local' -LatencyMs '' -TargetName 'dc8.mdilab.local')
    )) -join "`n"
Assert-That 'an entirely untimed estate still gets a latency heading' ($allBadHtml -match '<h4>Probe latency</h4>')
Assert-That 'an entirely untimed estate renders no latency cell' ((Get-LatencyCells -Html $allBadHtml).Count -eq 0) `
('cells=[{0}]' -f ((Get-LatencyCells -Html $allBadHtml) -join ','))
Assert-That 'an entirely untimed estate states no average' ((Get-StatedAverage -Html $allBadHtml) -eq -1)
Assert-That 'an entirely untimed estate says the probes were not timed' ($allBadHtml -match 'no readable round-trip time')
Assert-That 'an entirely untimed estate makes no claim about speed' ($allBadHtml -match 'says nothing about whether those paths are slow')

# ---------------------------------------------------------------------------------------------------
# THE COMPARISON THAT NAMES THE FIX. Format-mdiLatencyMs answers the unreadable shapes with nothing and
# the readable ones with digits, at any magnitude.
# ---------------------------------------------------------------------------------------------------
foreach ($case in $unreadable) {
    Assert-That ('Format-mdiLatencyMs refuses {0}' -f $case.Label) `
    ((Format-mdiLatencyMs -Value $case.Value) -eq '') ('got [{0}]' -f (Format-mdiLatencyMs -Value $case.Value))
}
Assert-That 'Format-mdiLatencyMs refuses $null' ((Format-mdiLatencyMs -Value $null) -eq '')
Assert-That 'Format-mdiLatencyMs refuses NaN' ((Format-mdiLatencyMs -Value ([double]::NaN)) -eq '')
Assert-That 'Format-mdiLatencyMs refuses infinity' ((Format-mdiLatencyMs -Value ([double]::PositiveInfinity)) -eq '')
Assert-That 'Format-mdiLatencyMs keeps a plain integer' ((Format-mdiLatencyMs -Value 250) -eq '250')
Assert-That 'Format-mdiLatencyMs survives beyond Int32' ((Format-mdiLatencyMs -Value 4294967296) -eq '4294967296')
# No group separator and no localised decimal comma may reach the page.
Assert-That 'Format-mdiLatencyMs emits digits only' ((Format-mdiLatencyMs -Value 1234567) -eq '1234567')

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $(if ($script:fail) { 1 } else { 0 })
