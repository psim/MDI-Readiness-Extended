# [w108] The Sensor v3.x prerequisites table must NAME every host it passes judgement on.
#
# Get-mdiSensorV3Html built its column axis from $_.FQDN read RAW:
#
#     $serverHeaders = ($servers | ForEach-Object { '<th>{0}</th>' -f (ConvertTo-mdiHtmlEncoded $_.FQDN) }) -join ''
#
# Unlike the network ports matrix, this table iterates the server OBJECTS for its cells rather than
# matching records back to a column key, so no host is dropped and no measurement is lost. The
# failure mode is narrower and entirely about IDENTITY: the column survives with NO HEADING AT ALL.
#
# That is not cosmetic here, because this table is where the per-host v3.x verdict is published:
#   * every v3.x prerequisite, painted RED when a MANDATORY one failed
#   * "Current sensor state"
#   * "Eligible for in-place migration"
#
# Measured on the shipped function with one host passing and one failing a REQUIRED check, the only
# variable being the FQDN shape:
#
#   readable FQDNs (control)     [dc1.mdilab.local | dcfab01.fabrikam.local]  Pass ~ Fail  Yes ~ No
#   FQDN $null on both hosts     [<BLANK> | <BLANK>]                          Pass ~ Fail  Yes ~ No
#   FQDN $null on failing host   [dc1.mdilab.local | <BLANK>]                 Pass ~ Fail  Yes ~ No
#   FQDN '' on both hosts        [<BLANK> | <BLANK>]                          Pass ~ Fail  Yes ~ No
#   FQDN whitespace on both      [<BLANK> | <BLANK>]                          Pass ~ Fail  Yes ~ No
#
# So a red MANDATORY prerequisite failure and a "not eligible for in-place migration" verdict were
# published against a host the operator cannot identify - and with two unnamed hosts, two blank
# headings carrying DIFFERENT verdicts and nothing whatever to tell them apart. A blank heading
# reads as a rendering glitch and is scrolled past; this file has already ruled that twice, for the
# orphan probe name and for the ports matrix server axis. This was the third read of the same
# identity and the only one still unhardened.
#
# The cross-forest lab is what makes an unreadable FQDN ordinary rather than synthetic: dcfab01 and
# memfab01 are discovered across a trust into a forest with a DISJOINT NetBIOS name, and a host
# whose FQDN comes back unreadable while its sensor checks succeeded is exactly that shape.
#
# What this file pins:
#   * no column heading is ever blank, for any unreadable FQDN shape;
#   * an unreadable FQDN is STATED with a marker that cannot collide with a real FQDN;
#   * the per-host verdicts are unchanged by the naming - the REQUIRED failure and the migration
#     advice still land on the right column, in the right order;
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

function New-V3Server {
    param($Fqdn, [bool] $Pass)
    [PSCustomObject]@{
        FQDN    = $Fqdn
        Domain  = 'fabrikam.local'
        Details = [PSCustomObject]@{
            SensorV3ReadyDetails = [PSCustomObject]@{
                SensorState       = $(if ($Pass) { 'Running' } else { 'Stopped' })
                MigrationEligible = $Pass
                Ready             = $Pass
                Checks            = @([PSCustomObject]@{
                        Name        = 'Operating system'
                        Requirement = 'Required'
                        Status      = $Pass
                        Measured    = $true
                        Detail      = $(if ($Pass) { 'Windows Server 2022' } else { 'Windows Server 2012 R2 is not supported' })
                    })
            }
        }
    }
}

function Measure-V3Table {
    param([object] $FqdnA, [object] $FqdnB)
    $html = [string] (Get-mdiSensorV3Html -Server @((New-V3Server $FqdnA $true), (New-V3Server $FqdnB $false)))

    $headers = @()
    $hm = [regex]::Match($html, '<tr><th style="text-align:left">Prerequisite</th><th>Type</th>(.*?)</tr>')
    if ($hm.Success) {
        $headers = @([regex]::Matches($hm.Groups[1].Value, '<th>(.*?)</th>') | ForEach-Object { $_.Groups[1].Value })
    }

    function Get-RowCells {
        param([string] $Html, [string] $Match)
        foreach ($rm in [regex]::Matches($Html, '<tr>(?:(?!</tr>).)*?</tr>')) {
            if ($rm.Value -notmatch $Match) { continue }
            $all = @([regex]::Matches($rm.Value, '<td[^>]*>(.*?)</td>') | ForEach-Object { ($_.Groups[1].Value -replace '<[^>]+>', '').Trim() })
            if ($all.Count -gt 2) { return @($all[2..($all.Count - 1)]) }
            return @()
        }
        return @()
    }

    [PSCustomObject]@{
        Headers   = $headers
        Blank     = @($headers | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count
        HeaderTxt = '[' + (($headers | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_)) { '<BLANK>' } else { $_ } }) -join ' | ') + ']'
        Os        = ((Get-RowCells $html 'Operating system') -join ' ~ ')
        Migration = ((Get-RowCells $html 'in-place migration') -join ' ~ ')
    }
}

# ---------------------------------------------------------------------------------------------
'[w108] control: a readable estate names both hosts and judges them correctly'
$control = Measure-V3Table 'dc1.mdilab.local' 'dcfab01.fabrikam.local'
Assert-That 'a readable estate produces one heading per host' (@($control.Headers).Count -eq 2) `
    "headers=$($control.HeaderTxt)"
Assert-That 'a readable estate leaves no heading blank' ($control.Blank -eq 0) "headers=$($control.HeaderTxt)"
Assert-That 'a readable estate names the hosts it was given' `
    ($control.HeaderTxt -match 'dc1\.mdilab\.local' -and $control.HeaderTxt -match 'dcfab01\.fabrikam\.local') `
    "headers=$($control.HeaderTxt)"
Assert-That 'the REQUIRED prerequisite verdict lands one per host' ($control.Os -eq 'Pass ~ Fail') "os=[$($control.Os)]"
Assert-That 'the migration advice lands one per host' ($control.Migration -eq 'Yes ~ No') "migration=[$($control.Migration)]"

# ---------------------------------------------------------------------------------------------
# Every case below carries the SAME judgement as the control: one host meets the REQUIRED
# prerequisite, one fails it and is not eligible for migration. Whatever the report does about the
# unreadable NAME, it may not publish that judgement against a column with no heading.
$cases = @(
    @{ Label = 'no FQDN on either host'; A = $null; B = $null }
    @{ Label = 'no FQDN on the failing host'; A = 'dc1.mdilab.local'; B = $null }
    @{ Label = 'no FQDN on the passing host'; A = $null; B = 'dcfab01.fabrikam.local' }
    @{ Label = 'empty FQDN on both hosts'; A = ''; B = '' }
    @{ Label = 'whitespace FQDN on both hosts'; A = '   '; B = "`t" }
    @{ Label = 'an FQDN that is not a string at all'; A = @{ Name = 'dcfab01' }; B = @{ Name = 'memfab01' } }
)

foreach ($case in $cases) {
    "[w108] $($case.Label)"
    $m = Measure-V3Table $case.A $case.B

    Assert-That "$($case.Label): every host still has a heading" (@($m.Headers).Count -eq 2) `
        "headers=$($m.HeaderTxt)"
    Assert-That "$($case.Label): no heading is left blank" ($m.Blank -eq 0) `
        "headers=$($m.HeaderTxt)"
    Assert-That "$($case.Label): the REQUIRED prerequisite verdict is unchanged" ($m.Os -eq 'Pass ~ Fail') `
        "os=[$($m.Os)] headers=$($m.HeaderTxt)"
    Assert-That "$($case.Label): the migration advice is unchanged" ($m.Migration -eq 'Yes ~ No') `
        "migration=[$($m.Migration)] headers=$($m.HeaderTxt)"
}

# ---------------------------------------------------------------------------------------------
# The marker must SAY that the host could not be identified. A heading that is merely non-empty -
# a space, a dash - would satisfy the blankness assertions above while telling the reader nothing.
'[w108] an unreadable FQDN is stated rather than left blank'
$unnamed = Measure-V3Table $null $null
Assert-That 'an estate with no readable FQDNs states that the hosts are unidentified' `
    ($unnamed.HeaderTxt -match 'unidentified') "headers=$($unnamed.HeaderTxt)"
Assert-That 'the marker cannot be mistaken for a real FQDN' `
    ($unnamed.HeaderTxt -notmatch '(?m)^\[[a-z0-9.-]+ \| [a-z0-9.-]+\]$') "headers=$($unnamed.HeaderTxt)"

# ---------------------------------------------------------------------------------------------
"RESULT: $($script:pass) passed / $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
