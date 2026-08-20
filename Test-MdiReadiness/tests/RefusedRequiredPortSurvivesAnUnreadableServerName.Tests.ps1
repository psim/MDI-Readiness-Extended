# [w107] A host whose name could not be read must not take a REFUSED required port out of the table.
#
# The network ports matrix is the headline table of the report: one row per required port, one column
# per sensor, and a cell saying whether that port was open on that host. Its column axis was derived
# with
#
#     $servers = @($records | Select-Object -ExpandProperty Server -Unique | Sort-Object)
#
# and its cells were matched with "$_.Server -eq $srv". Both read the Server property RAW.
# Get-mdiPortResultRecord normalises Success, Applicable, Target and TargetIP, but it sets
# Server = $srv.FQDN verbatim, so whatever the discovery produced for FQDN arrives here untouched.
#
# Two separate faults follow from that, and they compound. "Select-Object -Unique" DROPS a null from
# the pipeline - canonical already records that exact measurement a few lines further down, for the
# probe-id axis, and hardened THAT axis with a stated '(unidentified probe)' marker. The Server axis
# was never given the same treatment. And "$_.Server -eq $srv" compares the raw property, which for
# anything that is not a string is REFERENCE equality, so even a record that did produce a column
# could fail to match it.
#
# Measured on the shipped function with host A clean and host B holding REQUIRED LdapTcp 389 measured
# as REFUSED - a port an operator is expected to go and open:
#
#   readable FQDNs (control)   2 columns, 2 cells   OK ~ 0/1 open      <- correct
#   FQDN $null on both hosts   0 columns, 0 cells   the entire LDAP row vanished
#   FQDN $null on one host     1 column,  1 cell    OK
#   FQDN '' on both hosts      1 column,  1 cell    1/2 open
#   FQDN whitespace on both    1 column,  1 cell    1/2 open
#   two distinct hashtables    1 column,  1 cell    OK
#
# Five of the six unreadable shapes lost a host from the matrix while that host had a required port
# measured as refused, and three of them printed a green OK where the refusal belonged. That is worse
# than a missing row: the report positively asserts that a port which was observed shut is open, on
# the one table the operator works from. The scan HAD the measurement; only the host's name was
# unreadable.
#
# The fix mirrors the probe-id axis exactly: an unreadable server name keys to a STATED marker instead
# of being dropped, and BOTH the column list and the cell predicate are reduced through the SAME
# string key, so the two reads of one identity cannot disagree.
#
# What this file pins:
#   * a refused REQUIRED port stays visible for every unreadable server-name shape;
#   * no unreadable shape ever renders a bare OK where a refusal was measured;
#   * a host with no readable name is STATED in the header, never silently dropped;
#   * the LDAP row always has at least one cell - the row never disappears entirely;
#   * a wholly readable estate renders exactly as before.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
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

# The probe id is read from the SHIPPED settings rather than assumed, so this file cannot pass by
# testing a port that does not exist or is not actually Required.
$ldapDefinition = @($settings.RequiredPorts | Where-Object { $_.Id -eq 'LdapTcp' })[0]
Assert-That 'the shipped settings still define LdapTcp' ($null -ne $ldapDefinition)
Assert-That 'and LdapTcp is still a REQUIRED port' ([string] $ldapDefinition.Requirement -eq 'Required') `
    "requirement=[$($ldapDefinition.Requirement)]"

function New-PortServer {
    param($Fqdn, [bool] $Ok)
    [PSCustomObject]@{
        FQDN    = $Fqdn
        Domain  = 'mdilab.local'
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{
                Results = @([PSCustomObject]@{
                        Id      = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
                        Scope   = 'DomainController'; Group = $null; Requirement = 'Required'
                        Target  = 'dc1.mdilab.local'; TargetIP = '10.10.0.10'; Applicable = $true
                        Success = $Ok; LatencyMs = 9
                        Detail  = $(if ($Ok) { 'Connected' } else { 'Connection refused' })
                    })
            }
        }
    }
}

# Host A clean, host B refused on a REQUIRED port. Everything below reads the RENDERED table.
function Measure-PortMatrix {
    param([object] $FqdnA, [object] $FqdnB)
    $html = [string] (Get-mdiRequiredPortsHtml -Server @((New-PortServer $FqdnA $true), (New-PortServer $FqdnB $false)))

    $columns = -1
    $headerText = ''
    $hm = [regex]::Match($html, '<tr><th style="text-align:left">Requirement</th>(.*?)</tr>')
    if ($hm.Success) {
        $headerText = $hm.Groups[1].Value
        # Four fixed description columns: Requirement, Protocol, Port, Scope. One of them is the
        # left-aligned Requirement header already consumed by the match, so three remain.
        $columns = ([regex]::Matches($headerText, '<th>')).Count - 3
    }

    $rowCells = @()
    foreach ($rm in [regex]::Matches($html, '<tr>(?:(?!</tr>).)*?</tr>')) {
        $row = $rm.Value
        if ($row -notmatch 'LDAP') { continue }
        if ($row -match '389') {
            $rowCells = @([regex]::Matches($row, '<td[^>]*>(.*?)</td>') | ForEach-Object {
                    ($_.Groups[1].Value -replace '<[^>]+>', '' -replace '\s+', ' ').Trim()
                })
            break
        }
    }
    $serverCells = @()
    if ($rowCells.Count -gt 4) { $serverCells = @($rowCells[4..($rowCells.Count - 1)]) }

    [PSCustomObject]@{
        Columns = $columns
        Header  = (($headerText -replace '<[^>]+>', ' ') -replace '\s+', ' ').Trim()
        Cells   = $serverCells
        Joined  = $(if (@($serverCells).Count -eq 0) { '<NO LDAP ROW CELLS>' } else { ($serverCells -join ' ~ ') })
    }
}

$hashA = @{ Name = 'dcfab01' }
$hashB = @{ Name = 'memfab01' }

# ---------------------------------------------------------------------------------------------
'[w107] control: a readable estate shows both hosts and shows the refusal'
$control = Measure-PortMatrix 'dc1.mdilab.local' 'dcfab01.fabrikam.local'
Assert-That 'a readable estate keeps one column per host' ($control.Columns -eq 2) `
    "columns=$($control.Columns) header=[$($control.Header)]"
Assert-That 'a readable estate keeps one cell per host' (@($control.Cells).Count -eq 2) `
    "cells=[$($control.Joined)]"
Assert-That 'a readable estate reports the refused required port' ($control.Joined -match 'open') `
    "cells=[$($control.Joined)]"

# ---------------------------------------------------------------------------------------------
# Each unreadable shape below carries the SAME measurement as the control: one host clean, one host
# with a required port observed shut. Whatever the report does about the unreadable NAME, it may not
# lose the MEASUREMENT and it may not claim the port is open.
$cases = @(
    @{ Label = 'no name on either host'; A = $null; B = $null }
    @{ Label = 'no name on the refused host'; A = 'dc1.mdilab.local'; B = $null }
    @{ Label = 'no name on the clean host'; A = $null; B = 'dcfab01.fabrikam.local' }
    @{ Label = 'empty name on both hosts'; A = ''; B = '' }
    @{ Label = 'whitespace name on both hosts'; A = '   '; B = "`t" }
    @{ Label = 'two names that are not strings at all'; A = $hashA; B = $hashB }
    @{ Label = 'a readable host beside one that is not a string'; A = 'dc1.mdilab.local'; B = $hashB }
)

foreach ($case in $cases) {
    "[w107] $($case.Label)"
    $m = Measure-PortMatrix $case.A $case.B

    Assert-That "$($case.Label): the required-port row still exists" (@($m.Cells).Count -ge 1) `
        "columns=$($m.Columns) cells=[$($m.Joined)]"
    Assert-That "$($case.Label): the refused required port is still reported" ($m.Joined -match 'open') `
        "columns=$($m.Columns) cells=[$($m.Joined)]"
    Assert-That "$($case.Label): the row never reads simply OK while a required port was refused" `
        ($m.Joined -notmatch '^(OK)( ~ OK)*$') "columns=$($m.Columns) cells=[$($m.Joined)]"
    Assert-That "$($case.Label): every column that exists has a cell" `
        (@($m.Cells).Count -eq $m.Columns) "columns=$($m.Columns) cells=[$($m.Joined)]"
}

# ---------------------------------------------------------------------------------------------
# A host with no readable name must be STATED. A blank column header reads as a rendering glitch and
# is scrolled past; the whole point of the marker is that the reader can see something is unnamed.
'[w107] an unreadable server name is stated in the header rather than left blank or dropped'
$unnamed = Measure-PortMatrix $null $null
Assert-That 'an estate with no readable names still produces a column' ($unnamed.Columns -ge 1) `
    "columns=$($unnamed.Columns) header=[$($unnamed.Header)]"
Assert-That 'an unreadable server name is stated in the header' ($unnamed.Header -match 'unidentified') `
    "header=[$($unnamed.Header)]"

# ---------------------------------------------------------------------------------------------
"RESULT: $($script:pass) passed / $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
