<#
    A COLUMN HEADED "REQUIREMENT" WAS FILLED WITH THE PROBE NAME.

    Both port exception tables in the HTML report - "Ports that need attention" and "Ports that could
    not be tested" - headed their second column `Requirement` and filled it from `.Name`:

        Sensor server | Requirement | Protocol | Port | Target | Result
        dc01          | LDAP        | TCP      | 389  | dc02   | Connection refused

    So `LDAP` and `DNS` were presented to the reader as requirement classifications, and the fact the
    column claimed to carry - Required or Recommended - never reached the page at all. That fact is
    the one that decides whether a blocked port is a readiness failure or a suggestion. The JSON
    output carried it correctly the whole time, so the two surfaces of one fact disagreed.

    It was available to the renderer as well: the row colour is chosen from `.Requirement` three
    lines below the cell that dropped it. Colour is not a statement, and the "could not be tested"
    table has no colour distinction at all - every one of its rows is muted - so there a reader had
    no way whatsoever to tell an unmeasured REQUIRED port from an unmeasured optional one.

    These assertions drive the shipped renderer with real port records and read the emitted HTML.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

function New-PortRecord {
    param(
        [string] $Name, [string] $Requirement, [string] $Protocol,
        [int] $Port, [string] $Target, [string] $Detail, $Success, $Applicable = $true
    )
    [PSCustomObject]@{
        Name = $Name; Requirement = $Requirement; Protocol = $Protocol
        Port = $Port; Target = $Target; Detail = $Detail; Success = $Success
        Applicable = $Applicable; Scope = 'Server'; Group = $null; LatencyMs = $null; TargetIP = $null
        Id = ($Name -replace '\W', '')
    }
}

# One blocked REQUIRED port, one blocked RECOMMENDED port, one unmeasured REQUIRED port and one
# unmeasured record with no requirement at all. Fed through the shipped server shape, so the records
# reach the renderer the way a real scan produces them.
$server = [PSCustomObject]@{
    FQDN    = 'dc01.contoso.com'
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{
            Results = @(
                New-PortRecord -Name 'LDAP' -Requirement 'Required' -Protocol 'TCP' `
                    -Port 389 -Target 'dc02.contoso.com' -Detail 'Connection refused' -Success $false
                New-PortRecord -Name 'NNR - RDP' -Requirement 'Recommended' -Protocol 'TCP' `
                    -Port 3389 -Target 'wks01.contoso.com' -Detail 'Connection refused' -Success $false
                New-PortRecord -Name 'DNS' -Requirement 'Required' -Protocol 'TCP' `
                    -Port 53 -Target 'dns01.contoso.com' -Detail 'Not tested - the remote probe timed out before this check ran' -Success $null
                New-PortRecord -Name 'Kerberos' -Requirement '' -Protocol 'TCP' `
                    -Port 88 -Target 'dc02.contoso.com' -Detail 'Not tested - no result was returned' -Success $null
            )
        }
    }
}

$html = Get-mdiRequiredPortsHtml -Server @($server)

# The harness has to have produced both tables, or the assertions below are vacuous.
if ($html -notmatch 'Ports that need attention') { throw "the renderer produced no attention table:`n$html" }
if ($html -notmatch 'Ports that could not be tested') { throw "the renderer produced no untested table:`n$html" }

function Get-TableRows {
    param([string] $Html, [string] $Heading)
    $start = $Html.IndexOf($Heading)
    if ($start -lt 0) { return @() }
    $end = $Html.IndexOf('<h4>', $start + $Heading.Length)
    if ($end -lt 0) { $end = $Html.Length }
    $section = $Html.Substring($start, $end - $start)
    @([regex]::Matches($section, '<tr>(.*?)</tr>') | ForEach-Object {
            , @([regex]::Matches($_.Groups[1].Value, '<t[hd][^>]*>(.*?)</t[hd]>') | ForEach-Object { $_.Groups[1].Value })
        })
}

Write-Host 'Ports that need attention' -ForegroundColor Cyan
$attention = Get-TableRows -Html $html -Heading 'Ports that need attention'
$header = @($attention)[0]
Assert-That 'the table was found' ($attention.Count -ge 2) "($($attention.Count) rows)"
$reqIndex = [array]::IndexOf($header, 'Requirement')
Assert-That 'there is a column headed Requirement' ($reqIndex -ge 0) ($header -join ' | ')

$ldap = @($attention | Where-Object { $_ -contains 'LDAP' })[0]
Assert-That 'the required blocked port has a row' ($null -ne $ldap) ($header -join ' | ')
Assert-That 'the Requirement column says Required, not the probe name' (
    $null -ne $ldap -and $ldap[$reqIndex] -eq 'Required') (
    "row: $($ldap -join ' | ')")
Assert-That 'and the probe name is still shown somewhere in the row' (
    $null -ne $ldap -and ($ldap -contains 'LDAP')) "row: $($ldap -join ' | ')"

$rdp = @($attention | Where-Object { $_ -contains 'NNR - RDP' })[0]
Assert-That 'a recommended blocked port says Recommended' (
    $null -ne $rdp -and $rdp[$reqIndex] -eq 'Recommended') "row: $($rdp -join ' | ')"
Assert-That 'so the two classifications are distinguishable in text, not only by colour' (
    $null -ne $ldap -and $null -ne $rdp -and $ldap[$reqIndex] -ne $rdp[$reqIndex])

Write-Host ''
Write-Host 'Ports that could not be tested' -ForegroundColor Cyan
$untested = Get-TableRows -Html $html -Heading 'Ports that could not be tested'
$uHeader = @($untested)[0]
$uReqIndex = [array]::IndexOf($uHeader, 'Requirement')
Assert-That 'there is a column headed Requirement' ($uReqIndex -ge 0) ($uHeader -join ' | ')

$dns = @($untested | Where-Object { $_ -contains 'DNS' })[0]
Assert-That 'the unmeasured required port has a row' ($null -ne $dns) ($uHeader -join ' | ')
Assert-That 'and it says Required rather than the probe name' (
    $null -ne $dns -and $dns[$uReqIndex] -eq 'Required') "row: $($dns -join ' | ')"

# These rows carry no colour, so if the requirement is not written down it is not available at all.
$blank = @($untested | Where-Object { $_ -contains 'Kerberos' })[0]
Assert-That 'a record with no requirement says so rather than reading as not required' (
    $null -ne $blank -and $blank[$uReqIndex] -eq 'Not stated') "row: $($blank -join ' | ')"

Write-Host ''
Write-Host 'The requirement must agree with the colour the same row is given' -ForegroundColor Cyan
# The colour is chosen from .Requirement, so a row that reads Required and is not red would mean the
# two uses of one fact had drifted apart again.
Assert-That 'the Required row is red' (
    $html -match '<td class="red">389</td>') 'the required blocked port is not red'
Assert-That 'the Recommended row is amber' (
    $html -match '<td class="amber">3389</td>') 'the recommended blocked port is not amber'

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
