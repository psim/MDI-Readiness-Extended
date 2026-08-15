# Two defects in how the generated remediation script and the merge report the SAME fact twice.
#
# 1. Blocked NNR ports were auto-scripted as firewall rules AND repeated under "Findings that need
#    manual attention", telling the operator to fix by hand what the script had just done. The NNR
#    section was the only scripted section that never populated the $covered set.
# 2. When two roles' copies of one probe tied on evidence rank and on requirement rank, the FIRST one
#    merged won, so the detail text depended on discovery order. Not a false green - but the trend
#    comparison diffs that text, so an unchanged estate appeared to have changed.

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

function New-PortRec {
    param($Port, $Proto, $Target, $Detail, $Success = $false, $Req = 'Required', $Group = 'NNR', $Applicable = $true)
    [PSCustomObject]@{ Id = 'Nnr' + $Port; Name = 'NNR ' + $Port; Group = $Group; Protocol = $Proto
        Port = $Port; Target = $Target; TargetIP = '10.0.0.50'; Requirement = $Req
        Success = $Success; Detail = $Detail; Applicable = $Applicable
    }
}
function New-RealNnrRec {
    # Built from the REAL probe table, not by hand. The first version of this test invented records
    # with Requirement='Required'; the real NNR probes are 'AtLeastOne', which the issue list words
    # completely differently - so the test passed against a fix that was dead code.
    param($Target, $Detail = 'Connection refused', [int[]] $OnlyPorts = @())
    @($settings.RequiredPorts | Where-Object { $_.Group -eq 'NNR' } | ForEach-Object {
            if ($OnlyPorts.Count -gt 0 -and ([int] $_.Port) -notin $OnlyPorts) { return }
            [PSCustomObject]@{ Id = $_.Id; Name = $_.Name; Protocol = $_.Protocol; Port = $_.Port
                Scope = $_.Scope; Group = $_.Group; Requirement = $_.Requirement
                Target = $Target; TargetIP = '10.0.0.50'; Applicable = $true
                Success = $false; Detail = $Detail
            }
        })
}
function New-NnrReport {
    param([object[]] $Results)
    $dc = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        OSVersion = $true; NPCAP = $true; SensorVersion = '2.246.0'; RequiredPorts = $false
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @('x'); NnrFailedTargets = @('wks1.contoso.com'); Results = $Results }
            SensorHealthDetails = [PSCustomObject]@{ Installed = $true }
        }
    }
    [PSCustomObject]@{ DomainControllers = @($dc); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @()
    }
}
function Get-Generated {
    param($Report)
    $out = Join-Path $env:TEMP ('mdi-remtest-{0}.ps1' -f [guid]::NewGuid())
    New-mdiRemediationScript -ReportData $Report -FilePath $out 3>$null | Out-Null
    $g = Get-Content -LiteralPath $out -Raw
    Remove-Item $out -Force -ErrorAction SilentlyContinue
    $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($g, [ref]$null, [ref]$perr)
    [PSCustomObject]@{ Text = $g; ParseErrors = @($perr).Count
        Advisory = @($g -split "`r?`n" | Where-Object { $_ -match '^\s*Write-Host ''    \[' })
    }
}

'[remediation] a finding the script fixes is not also listed as needing manual attention'
# Uses the REAL NNR probe definitions, so the wording under test is the wording the tool produces.
$scripted = Get-Generated (New-NnrReport (New-RealNnrRec -Target 'wks1.contoso.com'))
Assert-That 'the generated script parses' ($scripted.ParseErrors -eq 0) "(got $($scripted.ParseErrors))"
Assert-That 'the NNR firewall section is still generated' ($scripted.Text -match 'Network Name Resolution inbound firewall rules')
Assert-That 'no scripted NNR finding is repeated as manual' (
    @($scripted.Advisory | Where-Object { $_ -match 'NNR method could resolve' }).Count -eq 0
) "(advisory: $($scripted.Advisory -join ' | '))"

'[remediation] the NNR wording has ONE source'
# The generator matches findings by TEXT. Keying it on the per-port wording made the fix dead code,
# because AtLeastOne probes are reported once per TARGET and never per port.
$realRecs = New-RealNnrRec -Target 'wks1.contoso.com'
$nnrReport = New-NnrReport $realRecs
$nnrStats = Get-mdiReportStatistics -ReportData $nnrReport
$nnrIssues = @(Get-mdiIssueList -Statistics $nnrStats -ReportData $nnrReport |
        Where-Object { $_.Area -eq 'Name resolution' })
Assert-That 'the issue list raises exactly one NNR finding per target' (@($nnrIssues).Count -eq 1) "(got $(@($nnrIssues).Count))"
Assert-That 'and it uses the shared NNR wording helper' (
    @($nnrIssues).Count -ge 1 -and
    ([string] @($nnrIssues)[0].Issue -eq (Get-mdiNnrIssueText -Target 'wks1.contoso.com' -TargetIP '10.0.0.50'))
) "(got '$(@($nnrIssues)[0].Issue)')"
# The invariant this file defends is that the wording has ONE SOURCE - not that it is any particular
# sentence. The helper gained a -TargetIP parameter so a multi-homed target names the address that
# actually failed, and pinning the old exact string would have made this test fight that change
# rather than defend the invariant. It is asserted by CALLING the helper with the same inputs the
# issue list had, so any future rewording is followed automatically and a private copy of the string
# still fails.
Assert-That '  ...and the helper is what carries the failing address' (
    (Get-mdiNnrIssueText -Target 'wks1.contoso.com' -TargetIP '10.0.0.50') -match '10\.0\.0\.50')
Assert-That 'the real NNR probes are AtLeastOne, not Required' (
    @($realRecs | Where-Object { [string] $_.Requirement -ne 'AtLeastOne' }).Count -eq 0)

'[remediation] but a target the script cannot fully fix must still be surfaced'
# A target whose failing set includes a method with no firewall rule (port 88 here) is not fully
# addressed by the section, so the conservative rule keeps its finding visible.
$partial = @(New-RealNnrRec -Target 'wks2.contoso.com') + @(
    [PSCustomObject]@{ Id = 'NnrOther'; Name = 'NNR 88'; Protocol = 'TCP'; Port = 88; Scope = 'NetworkDevice'
        Group = 'NNR'; Requirement = 'AtLeastOne'; Target = 'wks2.contoso.com'; TargetIP = '10.0.0.51'
        Applicable = $true; Success = $false; Detail = 'Connection refused'
    })
$mixed = Get-Generated (New-NnrReport $partial)
Assert-That 'the generated script parses' ($mixed.ParseErrors -eq 0)
Assert-That 'a partially-fixable target keeps its finding' (
    @($mixed.Advisory | Where-Object { $_ -match 'NNR method could resolve wks2' }).Count -ge 1
) "(advisory: $($mixed.Advisory -join ' | '))"

'[remediation] two targets, one fully scripted and one not'
$twoTargets = @(New-RealNnrRec -Target 'wks1.contoso.com') + @(New-RealNnrRec -Target 'wks3.contoso.com') + @(
    [PSCustomObject]@{ Id = 'NnrOther'; Name = 'NNR 88'; Protocol = 'TCP'; Port = 88; Scope = 'NetworkDevice'
        Group = 'NNR'; Requirement = 'AtLeastOne'; Target = 'wks3.contoso.com'; TargetIP = '10.0.0.53'
        Applicable = $true; Success = $false; Detail = 'Connection refused'
    })
$both = Get-Generated (New-NnrReport $twoTargets)
Assert-That 'the generated script parses' ($both.ParseErrors -eq 0)
Assert-That 'the fully scripted target is suppressed' (
    @($both.Advisory | Where-Object { $_ -match 'resolve wks1' }).Count -eq 0
) "(advisory: $($both.Advisory -join ' | '))"
Assert-That 'the partially scripted target is still listed' (
    @($both.Advisory | Where-Object { $_ -match 'resolve wks3' }).Count -ge 1
) "(advisory: $($both.Advisory -join ' | '))"

'[remediation] when the section cannot be generated, nothing may be suppressed'
# No sensor address can be determined, so the section is skipped - the finding is still outstanding.
$noSource = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; IP = ''; Addresses = @(); Unreachable = $false; PartialFailure = $false
    OSVersion = $true; NPCAP = $true; SensorVersion = 'N/A'; RequiredPorts = $false
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @('x'); NnrFailedTargets = @('wks1.contoso.com')
            Results = @((New-PortRec 135 'TCP' 'wks1.contoso.com' 'Connection refused'))
        }
        SensorHealthDetails = [PSCustomObject]@{ Installed = $false }
    }
}
$skipped = Get-Generated ([PSCustomObject]@{ DomainControllers = @($noSource); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @()
    })
Assert-That 'the generated script parses' ($skipped.ParseErrors -eq 0)
if ($skipped.Text -notmatch 'Network Name Resolution inbound firewall rules') {
    Assert-That 'an unscripted finding is still surfaced' (@($skipped.Advisory | Where-Object { $_ -match 'TCP/135' }).Count -ge 1)
}

'[remediation] a probe that was never tested is never scripted'
$untested = Get-Generated (New-NnrReport @(
        (New-PortRec 135 'TCP' 'wks1.contoso.com' 'Not tested - name resolution failed for wks1.contoso.com')
    ))
Assert-That 'no firewall rule is generated from an untested probe' (
    $untested.Text -notmatch 'Network Name Resolution inbound firewall rules')

'[remediation] the issue wording has ONE source'
# The generator matches findings by their TEXT, so a second copy of that string would silently stop
# matching the moment either was reworded.
$rec = New-PortRec 135 'TCP' 'wks1.contoso.com' 'Connection refused'
$fromHelper = Get-mdiPortIssueText -Record $rec
$stats = Get-mdiReportStatistics -ReportData (New-NnrReport @($rec))
$fromIssueList = @(Get-mdiIssueList -Statistics $stats -ReportData (New-NnrReport @($rec)) |
        Where-Object { $_.Issue -match 'network probe was measured as blocked' })
Assert-That 'the issue list uses the shared wording helper' (
    @($fromIssueList).Count -ge 1 -and ([string] @($fromIssueList)[0].Issue -eq $fromHelper)
) "(helper '$fromHelper' vs list '$(@($fromIssueList)[0].Issue)')"

'[merge] merging two roles is commutative'
function Wrap { param($Rec) [PSCustomObject]@{ ProbedFrom = 'Sensor'; FailedRequired = @(); NnrFailedTargets = @(); Results = @($Rec) } }
function Test-Commutative {
    param($Name, $A, $B)
    $ab = Merge-mdiRequiredPortsDetails -First (Wrap $A) -Second (Wrap $B)
    $ba = Merge-mdiRequiredPortsDetails -First (Wrap $B) -Second (Wrap $A)
    $x = @($ab.Results)[0]; $y = @($ba.Results)[0]
    Assert-That $Name (
        ([string] $x.Detail -eq [string] $y.Detail) -and
        ([string] $x.Success -eq [string] $y.Success) -and
        ([string] $x.Requirement -eq [string] $y.Requirement)
    ) "('$($x.Detail)' vs '$($y.Detail)')"
}
$p = @{ Port = 389; Proto = 'TCP'; Target = 'dc2.contoso.com'; Group = 'LDAP' }
Test-Commutative 'two measured failures with different details' `
    (New-PortRec @p -Detail 'Connection refused') (New-PortRec @p -Detail 'Connection timed out')
Test-Commutative 'two measured successes with different details' `
    (New-PortRec @p -Detail 'Replied with 47 bytes' -Success $true) (New-PortRec @p -Detail 'Answered by a DNS server' -Success $true)
Test-Commutative 'two not-tested records with different reasons' `
    (New-PortRec @p -Detail 'Not tested - name resolution failed') (New-PortRec @p -Detail 'Not tested - the probe never ran')
Test-Commutative 'a failure against a success (evidence rank decides)' `
    (New-PortRec @p -Detail 'Connection refused') (New-PortRec @p -Detail 'Connected' -Success $true)
Test-Commutative 'Required against Recommended (obligation decides)' `
    (New-PortRec @p -Detail 'Connection refused' -Req 'Required') (New-PortRec @p -Detail 'Connection refused' -Req 'Recommended')
Test-Commutative 'identical records' `
    (New-PortRec @p -Detail 'Connection refused') (New-PortRec @p -Detail 'Connection refused')

# The stronger evidence must still win regardless of order - the tie-break must not have weakened it.
$failFirst = Merge-mdiRequiredPortsDetails -First (Wrap (New-PortRec @p -Detail 'Connection refused')) `
    -Second (Wrap (New-PortRec @p -Detail 'Connected' -Success $true))
Assert-That 'a measured failure still beats a measured success' (
    (ConvertTo-mdiBoolean @($failFirst.Results)[0].Success) -eq $false)
$reqFirst = Merge-mdiRequiredPortsDetails -First (Wrap (New-PortRec @p -Detail 'Connection refused' -Req 'Recommended')) `
    -Second (Wrap (New-PortRec @p -Detail 'Connection refused' -Req 'Required'))
Assert-That 'the stronger obligation still wins' ([string] @($reqFirst.Results)[0].Requirement -eq 'Required')


# ---------------------------------------------------------------------------------------------
# NNR remediation must share ONE definition of 'blocked target' with the verdict.
#
# NNR probes are Requirement='AtLeastOne': a device is resolvable as soon as one method answers.
# The generator used to select every individually-unsuccessful record, so a device that resolves
# fine over NetBIOS still had inbound TCP 135 opened on it - a real firewall change on a production
# endpoint, to fix a problem the tool's own issue list did not report.
function New-NnrRec {
    param($Id, $Proto, $Port, $Success, $Target, $Ip)
    [PSCustomObject]@{ Id = $Id; Name = $Id; Group = 'NNR'; Scope = 'NetworkDevice'
        Protocol = $Proto; Port = $Port; Target = $Target; TargetIP = $Ip
        Requirement = 'AtLeastOne'; Success = $Success; Applicable = $true
        Detail = $(if ($Success) { 'Replied' } else { 'Connection timed out' }) }
}
function New-NnrReport {
    param($Records)
    $s = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
        Addresses = @('10.0.0.1'); IP = '10.0.0.1'
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
            FailedRequired = @(); NnrFailedTargets = @(); Results = @($Records) } } }
    [PSCustomObject]@{ DomainControllers = @($s); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com' }
}
function Get-NnrGenerated {
    param($Report)
    $f = Join-Path $env:TEMP ('mdi-nnr-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0,8))
    New-mdiRemediationScript -ReportData $Report -FilePath $f 3>$null | Out-Null
    $t = [IO.File]::ReadAllText($f)
    Remove-Item $f -Force -ErrorAction SilentlyContinue
    $t
}

$resolvableReport = New-NnrReport @((New-NnrRec 'NnrRpc' 'TCP' 135 $false 'winclient.contoso.com' '10.0.0.50'), (New-NnrRec 'NnrNetBios' 'UDP' 137 $true 'winclient.contoso.com' '10.0.0.50'))
$resolvableStats = Get-mdiReportStatistics -ReportData $resolvableReport
$resolvableText = Get-NnrGenerated $resolvableReport
Assert-That 'the report considers the target resolvable' ($resolvableStats.NnrResolvable -eq 1)
Assert-That '  ...and raises no finding for it' (@(Get-mdiIssueList -Statistics $resolvableStats -ReportData $resolvableReport).Count -eq 0)
Assert-That '  ...so no firewall rule is generated' ($resolvableText -notmatch 'New-NetFirewallRule')
Assert-That '  ...and the healthy host is not named' ($resolvableText -notmatch 'winclient\.contoso\.com')

# The other direction: a genuinely unresolvable target must STILL be remediated.
$brokenReport = New-NnrReport @((New-NnrRec 'NnrRpc' 'TCP' 135 $false 'bad.contoso.com' '10.0.0.61'), (New-NnrRec 'NnrNetBios' 'UDP' 137 $false 'bad.contoso.com' '10.0.0.61'))
$brokenText = Get-NnrGenerated $brokenReport
Assert-That 'a target with every method blocked is remediated' ($brokenText -match 'New-NetFirewallRule')
Assert-That '  ...and is named in the script' ($brokenText -match 'bad\.contoso\.com')

# Mixed estate: the broken host is fixed and the healthy one is untouched, in the same run.
$mixedText = Get-NnrGenerated (New-NnrReport @(
    (New-NnrRec 'NnrRpc' 'TCP' 135 $false 'good.contoso.com' '10.0.0.60')
    (New-NnrRec 'NnrNetBios' 'UDP' 137 $true 'good.contoso.com' '10.0.0.60')
    (New-NnrRec 'NnrRpc' 'TCP' 135 $false 'bad2.contoso.com' '10.0.0.62')
    (New-NnrRec 'NnrNetBios' 'UDP' 137 $false 'bad2.contoso.com' '10.0.0.62')))
Assert-That 'in a mixed estate the broken host is remediated' ($mixedText -match 'bad2\.contoso\.com')
Assert-That '  ...and the healthy host is left alone' ($mixedText -notmatch 'good\.contoso\.com')

# Coverage drift: a fix the script performs must never also be advertised as manual work.
$noDetailServer = [PSCustomObject]@{ FQDN = 'dc9.contoso.com'; Unreachable = $false; PartialFailure = $false
    TimeSync = $false; SensorHealth = $false
    Details = [PSCustomObject]@{ TimeSyncDetails = $null
        SensorHealthDetails = [PSCustomObject]@{ Installed = $true; Issues = @() } } }
$noDetailText = Get-NnrGenerated ([PSCustomObject]@{ DomainControllers = @($noDetailServer); CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com' })
$manualSection = ''
if ($noDetailText -match '(?s)Findings that need manual attention(.*?)#endregion') { $manualSection = $Matches[1] }
Assert-That 'the clock fix is scripted' ($noDetailText -match 'w32tm')
Assert-That '  ...and is not ALSO listed as manual' ($manualSection -notmatch 'Time Sync check failed')
Assert-That 'the sensor fix is scripted' ($noDetailText -match 'Defender for Identity sensor services')
Assert-That '  ...and is not ALSO listed as manual' ($manualSection -notmatch 'Sensor Health check failed')

# ...but a sensor that is not installed cannot be fixed by script and must still be surfaced.
$notInstalledServer = [PSCustomObject]@{ FQDN = 'dc8.contoso.com'; Unreachable = $false; PartialFailure = $false
    SensorHealth = $false
    Details = [PSCustomObject]@{ SensorHealthDetails = [PSCustomObject]@{ Installed = $false
        Issues = @('The AATPSensor service is not installed') } } }
$notInstalledText = Get-NnrGenerated ([PSCustomObject]@{ DomainControllers = @($notInstalledServer); CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com' })
Assert-That 'an unfixable sensor finding still reaches the operator' ($notInstalledText -match 'not installed')

# The generated script's own closing summary must be truthful. mdiFailed is appended to once per
# failing SECTION, not once per server, so one unreachable domain controller that missed five
# sections was reported as "failures on 5 server(s)" beside a list containing a single name - a
# number five times too large, contradicted by the list next to it.
$dedupeText = Get-NnrGenerated (New-NnrReport @((New-NnrRec 'NnrRpc' 'TCP' 135 $false 'bad.contoso.com' '10.0.0.61'), (New-NnrRec 'NnrNetBios' 'UDP' 137 $false 'bad.contoso.com' '10.0.0.61')))
Assert-That 'the failure list is de-duplicated before it is counted' (
    $dedupeText -match '\$mdiFailedHosts = @\(\$script:mdiFailed \| Select-Object -Unique\)')
Assert-That '  ...and the count comes from the de-duplicated list' ($dedupeText -match '\$mdiFailedHosts\.Count')
Assert-That '  ...not from the raw section list' ($dedupeText -notmatch '\$script:mdiFailed\.Count -gt 0')

# -WhatIf suppresses every Invoke-MdiRemote call, so the closing banner must not claim completion.
# A maintenance-window dry run was ending with "Remediation complete" having changed nothing, and
# the transcript is what the next person reads - not the "What if:" lines above it.
$whatIfServer = [PSCustomObject]@{ FQDN = 'dc-whatif.contoso.com'; Unreachable = $false; PartialFailure = $false
    TimeSync = $false
    Details = [PSCustomObject]@{ TimeSyncDetails = [PSCustomObject]@{ Detail = 'clock is 12 minutes behind' } } }
$whatIfText = Get-NnrGenerated ([PSCustomObject]@{
        DomainControllers = @($whatIfServer); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com' })
Assert-That 'the closing banner is gated on WhatIfPreference' ($whatIfText -match '\$WhatIfPreference')
Assert-That '  ...and says nothing was changed under -WhatIf' ($whatIfText -match 'WhatIf: nothing was changed')
Assert-That '  ...while still claiming completion on a real run' ($whatIfText -match 'Remediation complete')

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
