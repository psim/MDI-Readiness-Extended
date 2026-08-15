# The generated remediation script named sensor servers as the SOURCE of the NNR firewall rules that
# the rules do not actually allow.
#
# The NNR section scopes inbound TCP 135 / UDP 137 / TCP 3389 with -RemoteAddress $sensorAddresses,
# built from every sensor server's addresses. A sensor whose addresses are all unknown contributes
# nothing to that array - but it was still listed in the "# Sources" comment the operator reads. The
# generated file therefore said:
#
#     # Sources (1): dc1.contoso.com, dc2.contoso.com
#     $sensorAddresses = @(
#         '10.0.0.1'
#     )
#
# a count and a name list that contradict each other, over a rule that allows exactly one sensor. The
# operator applies the fix, is told both sensors are the source, re-runs the scan, and dc2's NNR
# probes are still blocked with nothing in the script, the console or the report saying why.
#
# It needs no unusual input: the scanner's own discovery fallback builds
# @{ FQDN = $name; IP = $null; Addresses = @() } whenever a server's computer object cannot be read.
#
# Behavioural, not textual: every assertion below compares what the comment CLAIMS against what the
# emitted $sensorAddresses array actually contains.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# Built from the REAL probe table so the wording and the AtLeastOne requirement are the tool's own.
function New-RealNnrRec {
    param($Target, $Detail = 'Connection refused')
    @($settings.RequiredPorts | Where-Object { $_.Group -eq 'NNR' } | ForEach-Object {
            [PSCustomObject]@{ Id = $_.Id; Name = $_.Name; Protocol = $_.Protocol; Port = $_.Port
                Scope = $_.Scope; Group = $_.Group; Requirement = $_.Requirement
                Target = $Target; TargetIP = '10.0.0.50'; Applicable = $true
                Success = $false; Detail = $Detail
            }
        })
}

function New-SensorDc {
    param($Fqdn, $Ip, $Addresses, $Results = @())
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; IP = $Ip; Addresses = $Addresses
        Unreachable = $false; PartialFailure = $false
        OSVersion = $true; NPCAP = $true; SensorVersion = '2.246.0'; RequiredPorts = $false
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @('x'); NnrFailedTargets = @('wks1.contoso.com'); Results = $Results }
            SensorHealthDetails  = [PSCustomObject]@{ Installed = $true }
        }
    }
}

function Get-NnrSection {
    param([object[]] $Dcs)
    $report = [PSCustomObject]@{
        DomainControllers = @($Dcs); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com'
    }
    $out = Join-Path $env:TEMP ('mdi-nnrsrc-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    $warn = $null
    New-mdiRemediationScript -ReportData $report -FilePath $out -WarningVariable warn 3>$null | Out-Null
    $g = [IO.File]::ReadAllText($out)
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($g, [ref]$null, [ref]$perr)

    $lines = $g -split "`r?`n"
    # The addresses the rule is actually scoped to, read out of the emitted array rather than assumed.
    $emitted = @()
    for ($k = 0; $k -lt $lines.Count; $k++) {
        if ($lines[$k] -match '^\s*\$sensorAddresses\s*=\s*@\(') {
            for ($j = $k + 1; $j -lt $lines.Count; $j++) {
                if ($lines[$j] -match '^\s*\)') { break }
                foreach ($m in [regex]::Matches($lines[$j], "'([^']*)'")) { $emitted += $m.Groups[1].Value }
            }
            break
        }
    }
    [PSCustomObject]@{
        Text          = $g
        ParseErrors   = @($perr).Count
        HasSection    = [bool]($g -match 'Network Name Resolution inbound firewall rules')
        SourceComment = (@($lines | Where-Object { $_ -match '^\s*#\s*Sources \(' }) -join ' ')
        Addresses     = @($emitted)
        Warnings      = @($warn | ForEach-Object { [string] $_ })
    }
}

'[nnr sources] a sensor with no determinable address is not claimed as an allowed source'
# dc2 carries the shape the scanner's own discovery fallback produces when the computer object
# cannot be read: IP $null, Addresses empty.
$mixed = Get-NnrSection @(
    (New-SensorDc 'dc1.contoso.com' '10.0.0.1' @('10.0.0.1') (New-RealNnrRec -Target 'wks1.contoso.com'))
    (New-SensorDc 'dc2.contoso.com' $null @())
)
Assert-That 'the NNR firewall section is generated' $mixed.HasSection
Assert-That 'the generated script parses' ($mixed.ParseErrors -eq 0) "(got $($mixed.ParseErrors))"
Assert-That 'the reachable sensor is allowed' ($mixed.Addresses -contains '10.0.0.1') "(got: $($mixed.Addresses -join ','))"
Assert-That 'the Sources comment names the allowed sensor' ($mixed.SourceComment -match 'dc1\.contoso\.com')
# THE DEFECT: dc2 contributes no address, so naming it as a source is a claim the rule does not honour.
Assert-That 'the Sources comment does NOT name the sensor the rule excludes' (
    $mixed.SourceComment -notmatch 'dc2\.contoso\.com'
) "(comment: $($mixed.SourceComment))"
# The count and the name list have to be the same fact.
# NOTE ON THE EXTRACTION BELOW: the label was widened from "# Sources (N)" to
# "# Sources (N address(es) on M sensor server(s))" because a bare N over a list of host names was
# itself ambiguous - a multi-homed sensor produced "(2): dc1", indistinguishable from a two-sensor
# estate that had lost a name. See NnrSourceCountMatchesList.Tests.ps1, which pins the new format.
# Only the EXTRACTION changed here; every assertion below is unchanged, and N is still the address
# count, which is what these assertions are about.
$claimed = 0
if ($mixed.SourceComment -match '#\s*Sources \((\d+)') { $claimed = [int] $Matches[1] }
$named = @(($mixed.SourceComment -replace '^.*?\):\s*', '') -split ',\s*' | Where-Object { $_ }).Count
Assert-That 'the Sources count equals the number of addresses emitted' ($claimed -eq $mixed.Addresses.Count) "(claimed $claimed, emitted $($mixed.Addresses.Count))"
Assert-That 'the Sources count is not contradicted by the names beside it' ($claimed -ge $named) "(claimed $claimed, named $named)"
# ...and the exclusion must be SAID, not merely omitted, or the operator cannot know NNR is still broken.
Assert-That 'the excluded sensor is disclosed in the generated script' ($mixed.Text -match 'NOT COVERED') "(no disclosure emitted)"
Assert-That '  ...naming the server that is still blocked' ($mixed.Text -match 'still fail: dc2\.contoso\.com')
Assert-That '  ...and the console warns as well' (
    @($mixed.Warnings | Where-Object { $_ -match 'dc2\.contoso\.com' }).Count -gt 0
) "(warnings: $($mixed.Warnings -join ' | '))"

''
'[nnr sources] a whitespace-only address is not counted as a source'
# " " is a truthy string, so it survived the old truthiness filter, was counted, passed the emptiness
# guard, and was then discarded when the literal list was written - a section whose source array was
# empty and whose count claimed otherwise.
$blank = Get-NnrSection @(
    (New-SensorDc 'dc1.contoso.com' '10.0.0.1' @('10.0.0.1') (New-RealNnrRec -Target 'wks1.contoso.com'))
    (New-SensorDc 'dc3.contoso.com' '   ' @('   '))
)
$blankClaimed = 0
if ($blank.SourceComment -match '#\s*Sources \((\d+)') { $blankClaimed = [int] $Matches[1] }
Assert-That 'the whitespace address is not emitted' (@($blank.Addresses | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) "(got: [$($blank.Addresses -join '][')])"
Assert-That 'the Sources count matches the emitted addresses' ($blankClaimed -eq $blank.Addresses.Count) "(claimed $blankClaimed, emitted $($blank.Addresses.Count))"
Assert-That 'the whitespace-only sensor is not named as a source' ($blank.SourceComment -notmatch 'dc3\.contoso\.com') "(comment: $($blank.SourceComment))"
Assert-That 'the whitespace-only sensor is disclosed as not covered' ($blank.Text -match 'still fail:.*dc3\.contoso\.com')

''
'[nnr sources] when every sensor resolves, nothing is falsely disclosed'
# The disclosure must not fire on a healthy estate, or it becomes noise the operator learns to skip.
$clean = Get-NnrSection @(
    (New-SensorDc 'dc1.contoso.com' '10.0.0.1' @('10.0.0.1', '10.0.0.9') (New-RealNnrRec -Target 'wks1.contoso.com'))
    (New-SensorDc 'dc2.contoso.com' '10.0.0.2' @('10.0.0.2'))
)
$cleanClaimed = 0
if ($clean.SourceComment -match '#\s*Sources \((\d+)') { $cleanClaimed = [int] $Matches[1] }
Assert-That 'both sensors are named as sources' (($clean.SourceComment -match 'dc1\.contoso\.com') -and ($clean.SourceComment -match 'dc2\.contoso\.com'))
Assert-That 'every address of the multi-homed sensor is allowed' (
    ($clean.Addresses -contains '10.0.0.1') -and ($clean.Addresses -contains '10.0.0.9') -and ($clean.Addresses -contains '10.0.0.2')
) "(got: $($clean.Addresses -join ','))"
Assert-That 'the Sources count matches the emitted addresses' ($cleanClaimed -eq $clean.Addresses.Count) "(claimed $cleanClaimed, emitted $($clean.Addresses.Count))"
Assert-That 'no false NOT COVERED disclosure' ($clean.Text -notmatch 'NOT COVERED')
Assert-That 'no false console warning' (@($clean.Warnings | Where-Object { $_ -match 'could not determine an address' }).Count -eq 0) "(warnings: $($clean.Warnings -join ' | '))"
Assert-That 'the generated script parses' ($clean.ParseErrors -eq 0) "(got $($clean.ParseErrors))"

''
'[nnr sources] no sensor resolves at all - the section is skipped, not opened to the world'
# With no source address the rule would be created unscoped, opening TCP 135/137/3389 to the whole
# network on every target. The section must be skipped and the reason stated.
$none = Get-NnrSection @(
    (New-SensorDc 'dc1.contoso.com' $null @() (New-RealNnrRec -Target 'wks1.contoso.com'))
)
Assert-That 'the NNR firewall section is not emitted' (-not $none.HasSection)
Assert-That 'no unscoped firewall rule is written' ($none.Text -notmatch 'New-NetFirewallRule')
Assert-That 'the skip is explained on the console' (
    @($none.Warnings | Where-Object { $_ -match 'no sensor source address could be determined' }).Count -gt 0
) "(warnings: $($none.Warnings -join ' | '))"
Assert-That 'the finding is still surfaced to the operator' ($none.Text -match 'manual attention')

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
