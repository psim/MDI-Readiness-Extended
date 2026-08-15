# The generated remediation script told the operator "# Sources (2): dc1.contoso.test" - a count of
# two over a list of one.
#
# The NNR inbound firewall section labels its source list with $sensorIps.Count, a count of ADDRESSES,
# chosen deliberately so it matches the $sensorAddresses array emitted immediately below it. But the
# text it labels is a list of HOST NAMES. A multi-homed sensor - one machine, two NICs - therefore
# produced a count larger than the list, identical to what a two-sensor estate emits when one of the
# names has gone missing.
#
# Measured on the shipped New-mdiRemediationScript, reading the file it actually writes:
#
#   one sensor,  one address    claimed 1   listed 1
#   one sensor,  TWO addresses  claimed 2   listed 1     <- the defect
#   two sensors, one each       claimed 2   listed 2
#
# The last two emit a BYTE-IDENTICAL comment. An operator who counts the names is told one is missing;
# an operator who trusts the count believes two machines are covered when one is.
#
# This is the same class of defect the address-less case was already fixed for a few lines above - the
# code comment there says the script read "# Sources (1): dc1.contoso.com, dc2.contoso.com", "a count
# and a name list that contradict each other". That fix closed the direction where a NAMED host
# contributed no address. This one closes the direction where ONE host contributes several.
#
# Both numbers are now stated. Reducing to a host count alone would break the property the address
# count exists to hold - that the number the operator reads is the number of entries in
# $sensorAddresses - which is asserted below so a future simplification cannot quietly drop it.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$source = [IO.File]::ReadAllText($target)
$source = $source -replace '(?m)^\s*#Requires.*$', ''
$source = $source -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$main = $source.IndexOf('#region Main')
if ($main -lt 1) { throw 'Could not isolate the canonical function definitions.' }
Invoke-Expression $source.Substring(0, $main)
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$outDir = Join-Path ([IO.Path]::GetTempPath()) ('nnrsrc-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $outDir -Force

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Sensor {
    param([string] $Fqdn, [string[]] $Addresses)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.test'
        IP = $Addresses[0]; Addresses = @($Addresses)
        Unreachable = $false; PartialFailure = $false
        SensorVersion = '2.245.0.0'
        Details = [PSCustomObject]@{ SensorHealthDetails = [PSCustomObject]@{ Installed = $true } }
    }
}

# One blocked NNR record per sensor, all naming the SAME target, so the failed-target side is constant
# across populations and only the SOURCE side varies.
function Get-Emitted {
    param([object[]] $Servers, [string] $Tag)

    $script:probeRecords = @($Servers | ForEach-Object {
            [PSCustomObject]@{
                Server = $_.FQDN; Target = 'ws1.contoso.test'; TargetIP = '10.9.9.9'
                Group = 'NNR'; Port = 137; Protocol = 'UDP'
                Success = $false; Applicable = $true; Detail = 'No NNR method could resolve ws1.contoso.test'
            } })
    # Script-scoped: `function global:` does NOT override the script's own copies.
    Set-Item -Path function:script:Get-mdiPortResultRecord -Value { param($Server) $script:probeRecords }
    Set-Item -Path function:script:Get-mdiBlockingPortFailure -Value {
        param($Record)
        @($script:probeRecords | ForEach-Object {
                [PSCustomObject]@{ Server = $_.Server; Target = $_.Target; TargetIP = $_.TargetIP; BlockingKind = 'NnrMeasured' } })
    }

    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.test'; Forest = 'contoso.test'
        DomainsInScope = @('contoso.test')
        DomainControllers = @($Servers)
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); SkippedAreas = @()
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @()
    }
    $path = Join-Path $outDir ("$Tag.ps1")
    [void] (New-mdiRemediationScript -ReportData $report -FilePath $path)
    $text = [IO.File]::ReadAllText($path)

    $line = [regex]::Match($text, '(?m)^# Sources \((.+)\): (.+)$')
    $addrBlock = [regex]::Match($text, '(?s)\$sensorAddresses = @\((.*?)\r?\n\)')
    [PSCustomObject]@{
        Found     = $line.Success
        Line      = $line.Value
        Label     = $line.Groups[1].Value
        Names     = @($line.Groups[2].Value -split ',\s*' | Where-Object { $_ })
        Addresses = @([regex]::Matches($addrBlock.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
    }
}

$single = Get-Emitted -Servers @((New-Sensor 'dc1.contoso.test' @('10.0.0.1'))) -Tag 'single'
$multiHomed = Get-Emitted -Servers @((New-Sensor 'dc1.contoso.test' @('10.0.0.1', '10.0.0.2'))) -Tag 'multihomed'
$twoSensors = Get-Emitted -Servers @((New-Sensor 'dc1.contoso.test' @('10.0.0.1')), (New-Sensor 'dc2.contoso.test' @('10.0.0.2'))) -Tag 'twosensors'

'[nnr sources] the section is emitted for every population'
foreach ($case in @(@{ N = 'one sensor one address'; R = $single }, @{ N = 'one sensor two addresses'; R = $multiHomed }, @{ N = 'two sensors'; R = $twoSensors })) {
    Assert-That ("{0}: a '# Sources' line is emitted" -f $case.N) ($case.R.Found) '(no line found)'
    "      $($case.N): $($case.R.Line)"
}

''
'[nnr sources] the label states the ADDRESS count, and it matches the emitted array'
# The reason the address count is there at all: the operator must be able to check the number they
# read against the -RemoteAddress list the rules are actually scoped by.
foreach ($case in @(@{ N = 'one sensor one address'; R = $single; A = 1 }, @{ N = 'one sensor two addresses'; R = $multiHomed; A = 2 }, @{ N = 'two sensors'; R = $twoSensors; A = 2 })) {
    Assert-That ("{0}: the label names {1} address(es)" -f $case.N, $case.A) (
        $case.R.Label -match ('(^|\D){0} address' -f $case.A)) "(label '$($case.R.Label)')"
    Assert-That ('{0}: the emitted source array really holds {1}' -f $case.N, $case.A) (
        $case.R.Addresses.Count -eq $case.A) "(array held $($case.R.Addresses.Count))"
}

''
'[nnr sources] the label also states the HOST count, so it agrees with the list it labels'
# THE DEFECT: a bare "(2)" over one name.
foreach ($case in @(@{ N = 'one sensor one address'; R = $single; H = 1 }, @{ N = 'one sensor two addresses'; R = $multiHomed; H = 1 }, @{ N = 'two sensors'; R = $twoSensors; H = 2 })) {
    Assert-That ("{0}: the label names {1} sensor server(s)" -f $case.N, $case.H) (
        $case.R.Label -match ('(^|\D){0} sensor' -f $case.H)) "(label '$($case.R.Label)')"
    Assert-That ("{0}: {1} name(s) are actually listed" -f $case.N, $case.H) (
        $case.R.Names.Count -eq $case.H) "(listed $($case.R.Names.Count): $($case.R.Names -join '|'))"
}

''
'[nnr sources] a multi-homed sensor is distinguishable from two sensors'
# The two populations previously emitted a byte-identical comment. If they ever do again, an operator
# reading "(2)" over one name cannot tell a second NIC from a lost machine.
Assert-That 'the two comments differ' ($multiHomed.Line -ne $twoSensors.Line) `
    "(both emitted '$($multiHomed.Line)')"
Assert-That 'the multi-homed comment names exactly one host' ($multiHomed.Names.Count -eq 1) `
    "(named $($multiHomed.Names -join ', '))"
Assert-That 'the two-sensor comment names exactly two hosts' ($twoSensors.Names.Count -eq 2) `
    "(named $($twoSensors.Names -join ', '))"
Assert-That 'both still scope the rules by two addresses' (
    $multiHomed.Addresses.Count -eq 2 -and $twoSensors.Addresses.Count -eq 2) `
    "(multi $($multiHomed.Addresses.Count), two $($twoSensors.Addresses.Count))"

''
'[nnr sources] the invariant: no number in the label contradicts what it labels'
foreach ($case in @(@{ N = 'one sensor one address'; R = $single }, @{ N = 'one sensor two addresses'; R = $multiHomed }, @{ N = 'two sensors'; R = $twoSensors })) {
    $numbers = @([regex]::Matches($case.R.Label, '\d+') | ForEach-Object { [int] $_.Value })
    Assert-That ("{0}: every number in the label is accounted for" -f $case.N) (
        $numbers.Count -ge 2 -and
        ($numbers -contains $case.R.Addresses.Count) -and
        ($numbers -contains $case.R.Names.Count)) `
        "(label '$($case.R.Label)' vs $($case.R.Addresses.Count) address(es), $($case.R.Names.Count) name(s))"
    # A bare count with no unit is what made the original ambiguous.
    Assert-That ("{0}: the label is not a bare number" -f $case.N) (
        $case.R.Label -notmatch '^\s*\d+\s*$') "(label '$($case.R.Label)')"
}

Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
