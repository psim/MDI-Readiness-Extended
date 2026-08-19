<#
    NO SINGLE UNREADABLE FIELD MAY DESTROY THE SECTION IT APPEARS IN.

    Three defects found on 19 August were the same shape in three different renderers: a value that
    could not be read reached a hard cast, or a parameter that could not be bound, and the exception
    was raised while BUILDING the page - so one field on one server cost the whole card, including the
    rows of every server that had been read perfectly well.

    This test does not pin one line. It drives every renderer with every field of its detail block
    replaced, one at a time, by every shape a value can arrive as when it did not come straight from a
    live scan - and requires that the section still renders. That is the invariant the three fixes
    below all serve, and it is what stops a fourth instance appearing in a renderer nobody has touched
    yet.

    THE THREE DEFECTS THIS PINS, all measured on the shipped functions before the fix:

    1. Get-mdiTimeSyncHtml, the clock skew cell.

           $skew = if ($null -ne $sync.SkewSeconds) { [string] ([long] $sync.SkewSeconds) + ' s' } else { 'n/a' }

       A bare $null guard, then a hard [long]. '' rendered '0 s' - a perfectly synchronised clock for
       a server nobody timed, on a row that can be painted green - $true rendered '1 s', and '   ',
       'n/a', 'unknown', a hashtable and a value beyond Int64 all THREW.

    2. Get-mdiCapacityHtml, the packet-rate and sample columns.

       These already normalised correctly with ConvertTo-mdiMeasuredNumber and then CAST the result,
       which reintroduces the failure the normaliser exists to prevent - this time for a value that is
       perfectly readable and merely large:

           BusyPacketsPerSec = 1e30   THREW  Cannot convert value "1E+30" to type "System.Int64"
           SampleSeconds     = 1e30   THREW  Cannot convert value "1E+30" to type "System.Int32"

       "1E+30" in the message is the proof the parse had already succeeded and the cast is what failed.

    3. ConvertTo-mdiHtmlEncoded, every renderer at once.

       -Text was [string], and a [string] parameter cannot be bound from a COLLECTION - PowerShell
       refuses the transformation before the body runs, so the throw lands in the CALLER. @(42),
       @(1,2), @() and [byte[]] all failed to bind; every scalar bound fine. Measured end to end:
       Get-mdiSensorV3Html with SensorState = @(42) and Get-mdiRequiredPortsHtml with a port record
       whose Name = @(42) both lost their entire section. An AST walk counted 130 call sites, 75 of
       them passing a value with no [string] cast of their own, mostly direct record-field reads.

    An array is an ordinary shape here, not a contrived one: Get-mdiProbeTargetKey's own header
    records "a six-row estate holding one row whose Domain was @('fabrikam.local')" from a JSON round
    trip. The estate below is the extended lab - a server in EMEA-Site and one across the
    fabrikam.local trust - so the rows that must survive are the cross-site and cross-forest ones.

    This test asserts BEHAVIOUR - that the section renders and that the readable rows are still in it.
    It never asserts the text of the script, so it holds across any rewrite that keeps the behaviour.
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
    if ($condition) { $script:pass++ }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# Every shape a value can arrive as when it did not come from a live scan: a JSON round trip through
# another tool, a hand-edited report, or an older version of this script.
$shapes = @(
    @{ L = '$null'; V = $null }
    @{ L = "''"; V = '' }
    @{ L = 'whitespace'; V = '   ' }
    @{ L = "'n/a'"; V = 'n/a' }
    @{ L = "'unknown'"; V = 'unknown' }
    @{ L = "'N/A'"; V = 'N/A' }
    @{ L = '$true'; V = $true }
    @{ L = '$false'; V = $false }
    @{ L = 'hashtable'; V = @{} }
    @{ L = 'empty array'; V = @() }
    @{ L = 'one-element array'; V = @(42) }
    @{ L = 'multi-element array'; V = @(1, 2) }
    @{ L = 'byte array'; V = [byte[]] @(1, 2) }
    @{ L = 'PSCustomObject'; V = ([PSCustomObject]@{ a = 1 }) }
    @{ L = 'beyond Int32'; V = [long] 5000000000 }
    @{ L = 'beyond Int64 as text'; V = '1000000000000000000000000000000' }
    @{ L = 'negative'; V = -1 }
    @{ L = 'decimal string'; V = '12.7' }
)

function New-FullServer {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN         = $Fqdn
        TimeSync     = $true
        SensorHealth = $true
        Details      = [PSCustomObject]@{
            TimeSyncDetails      = [PSCustomObject]@{
                SkewSeconds = 3; RemoteUtc = '2026-08-19T07:00:00Z'; Detail = 'ok'; MaxSkewMinutes = 5
            }
            CapacityDetails      = [PSCustomObject]@{
                BusyPacketsPerSec = 4200; AveragePacketsPerSec = 3100; PeakPacketsPerSec = 5200
                Band = '0-10K'; Cores = 8; TotalRamGb = 32; HyperThreaded = $false
                SampleSeconds = 900; FullBusyWindow = $true; SampleCount = 90; Detail = 'ok'
            }
            SensorHealthDetails  = [PSCustomObject]@{
                Installed = $true; UpdaterService = 'Running'; Version = '2.245.0'; Detail = 'ok'
            }
            SensorV3ReadyDetails = [PSCustomObject]@{
                SensorState = 'Running'; MigrationEligible = $true; Blockers = @(); Checks = @(); Detail = 'ok'
            }
            RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom = 'dc1.mdilab.local'
                Results    = @([PSCustomObject]@{
                        Id = 'LdapS'; Name = 'LDAPS'; Protocol = 'TCP'; Port = 636; Scope = 'DomainController'
                        Group = 'LDAP'; Requirement = 'Required'; Applicable = $true; Success = $true
                        Detail = 'Connected'; Target = 'dcfab01.fabrikam.local'; TargetIP = '10.10.1.50'
                        LatencyMs = 130
                    })
            }
        }
    }
}

# The rows that must survive: one in another site, one across the forest trust.
function Get-GoodEstate {
    @((New-FullServer -Fqdn 'dc3.emea.mdilab.local'), (New-FullServer -Fqdn 'dcfab01.fabrikam.local'))
}

$renderers = @(
    @{ Name = 'Get-mdiTimeSyncHtml'; Block = 'TimeSyncDetails' }
    @{ Name = 'Get-mdiCapacityHtml'; Block = 'CapacityDetails' }
    @{ Name = 'Get-mdiSensorHealthHtml'; Block = 'SensorHealthDetails' }
    @{ Name = 'Get-mdiSensorV3Html'; Block = 'SensorV3ReadyDetails' }
    @{ Name = 'Get-mdiRequiredPortsHtml'; Block = 'RequiredPortsDetails' }
)

Write-Host 'No single unreadable field may destroy the section it appears in' -ForegroundColor Cyan

foreach ($r in $renderers) {
    Assert-That ("{0} exists" -f $r.Name) ($null -ne (Get-Command $r.Name -ErrorAction SilentlyContinue))
    $fields = @((New-FullServer -Fqdn 'x').Details.($r.Block).PSObject.Properties.Name)
    Assert-That ("{0} has fields to fuzz" -f $r.Name) ($fields.Count -gt 0)
    foreach ($field in $fields) {
        foreach ($shape in $shapes) {
            $bad = New-FullServer -Fqdn 'dc9.branch.mdilab.local'
            $bad.Details.($r.Block).$field = $shape.V
            $html = $null
            $threw = ''
            try { $html = (& $r.Name -Server (@(Get-GoodEstate) + @($bad))) -join "`n" }
            catch { $threw = $_.Exception.Message }
            Assert-That ("{0} survives {1} = {2}" -f $r.Name, $field, $shape.L) ($threw -eq '') $threw
            if ($threw -eq '') {
                # The servers that WERE read must still be on the page. A fix that swallowed the whole
                # estate would satisfy "did not throw" while being just as wrong.
                Assert-That ("{0} keeps the cross-forest row despite {1} = {2}" -f $r.Name, $field, $shape.L) `
                ($html -match 'dcfab01') 'the readable rows were lost'
            }
        }
    }
}

# The port RESULT records are a second shape layer inside RequiredPortsDetails and are read by a
# different code path, so they are fuzzed separately.
$portFields = @((New-FullServer -Fqdn 'x').Details.RequiredPortsDetails.Results[0].PSObject.Properties.Name)
Assert-That 'the port record has fields to fuzz' ($portFields.Count -gt 0)
foreach ($field in $portFields) {
    foreach ($shape in $shapes) {
        $bad = New-FullServer -Fqdn 'dc9.branch.mdilab.local'
        $bad.Details.RequiredPortsDetails.Results[0].$field = $shape.V
        $threw = ''
        try { $null = Get-mdiRequiredPortsHtml -Server (@(Get-GoodEstate) + @($bad)) }
        catch { $threw = $_.Exception.Message }
        Assert-That ("the ports table survives a record whose {0} = {1}" -f $field, $shape.L) ($threw -eq '') $threw
    }
}

# ---------------------------------------------------------------------------------------------------
# THE TWO RULES THAT OWN THIS, pinned directly so a renderer cannot quietly stop relying on them.
# ---------------------------------------------------------------------------------------------------
Assert-That 'ConvertTo-mdiHtmlEncoded accepts a one-element array' ((ConvertTo-mdiHtmlEncoded @(42)) -eq '42')
Assert-That 'ConvertTo-mdiHtmlEncoded accepts a multi-element array' ((ConvertTo-mdiHtmlEncoded @(1, 2)) -eq '1 2')
Assert-That 'ConvertTo-mdiHtmlEncoded accepts an empty array' ((ConvertTo-mdiHtmlEncoded @()) -eq '')
Assert-That 'ConvertTo-mdiHtmlEncoded accepts $null' ((ConvertTo-mdiHtmlEncoded $null) -eq '')
Assert-That 'ConvertTo-mdiHtmlEncoded still encodes the five characters' `
((ConvertTo-mdiHtmlEncoded '<a href="x">&</a>') -eq '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;')
Assert-That 'ConvertTo-mdiHtmlEncoded still encodes a scalar unchanged otherwise' `
((ConvertTo-mdiHtmlEncoded 'plain') -eq 'plain')

Assert-That 'Format-mdiWholeNumber survives beyond Int64' ((Format-mdiWholeNumber -Value 1e30) -ne '')
Assert-That 'Format-mdiWholeNumber refuses an unreadable value' ((Format-mdiWholeNumber -Value 'n/a') -eq '')
Assert-That 'Format-mdiWholeNumber refuses $null' ((Format-mdiWholeNumber -Value $null) -eq '')
Assert-That 'Format-mdiWholeNumber keeps a plain integer' ((Format-mdiWholeNumber -Value 4200) -eq '4200')
Assert-That 'Format-mdiWholeNumber emits digits only, no separators' ((Format-mdiWholeNumber -Value 1234567) -eq '1234567')
Assert-That 'Format-mdiLatencyMs still answers through the shared rule' `
((Format-mdiLatencyMs -Value 250) -eq '250' -and (Format-mdiLatencyMs -Value 'n/a') -eq '')

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $(if ($script:fail) { 1 } else { 0 })
