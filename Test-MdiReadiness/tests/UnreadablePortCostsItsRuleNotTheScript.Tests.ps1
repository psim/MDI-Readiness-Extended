<#
    AN UNREADABLE PORT MUST COST ITS OWN FIREWALL RULE, NOT THE WHOLE REMEDIATION SCRIPT.

    THE DEFECT THIS PINS. New-mdiRemediationScript builds the NNR inbound firewall rules by looking
    each blocked probe's port up in the rule map:

        foreach ($port in @($blockedNnr | ForEach-Object { $_.Port } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | Select-Object -Unique | Sort-Object)) {
            $rule = $ruleMap[[int] $port]

    The comment above that loop already stated the intent - "An unreadable port maps to no rule and
    is filtered here rather than left to be dropped silently ... so the rules the OTHER records are
    entitled to are still emitted" - but the filter only removed BLANKS. Every non-numeric shape
    passed it and reached the hard [int] cast, which THROWS. The throw leaves New-mdiRemediationScript
    entirely, so the operator got no file at all: not a script missing one rule, no script.

    Measured on the shipped function, one sensor that cannot resolve ws4.fabrikam.local by any NNR
    method - the case this generator exists for - with the RDP record's Port replaced one shape at a
    time and nothing else differing:

        3389 (control)   317 lines, 3 firewall rules
        '3389'           317 lines, 3 rules      a JSON round trip routinely produces this
        $null            292 lines, 2 rules      already filtered as blank
        $true            292 lines, 2 rules
        'n/a'              0 lines, NO SCRIPT    Cannot convert value "n/a" to type "System.Int32"
        'timed out'        0 lines, NO SCRIPT
        @{}                0 lines, NO SCRIPT    [string] @{} is not whitespace, so it passed
        '99999999999999999999'  0 lines, NO SCRIPT   too large for an Int32

    The remediation script is the artefact an operator actually executes against production domain
    controllers, and it was lost over a field that is not even the one being remediated: two other
    NNR ports on the same host were perfectly readable and their rules went with it.

    A SECOND READER, same function, same field: the covered-marker loop used
    `$ruleMap.ContainsKey([int] $_.Port)` with no guard at all. It is fixed with the same defensive
    form so the two cannot disagree about which findings the script covers.

    WHY IT SURVIVED. Ports originate as hard-coded integers in the settings table, so a live run
    never produces one of these. They arrive the way every row shape in this file does - another
    tool's JSON, an -AsJson round trip, a hand-edited report, an older version. This is the same
    family as the LatencyMs defect in Get-mdiRequiredPortsHtml, and the same asymmetry gave it away:
    Merge-mdiRequiredPortsDetails already ranks these very records with the defensive
    `[int] ($_.Port -as [int])` while these two readers did not.

    Pinned here:

    1. A numeric port still produces the full script and all three NNR rules - the control, so a
       failure below cannot be blamed on the estate.
    2. A numeric STRING port behaves identically to the integer, because a JSON round trip produces
       one and it is perfectly readable.
    3. Every unreadable shape still produces a script - the throw is the defect.
    4. The OTHER records' rules survive: an unreadable port costs exactly one rule.
    5. The record whose port could not be read gets no rule invented for it.
    6. The finding is NOT marked as covered by a rule that was never written, so it stays in the
       manual-attention list rather than disappearing.
    7. The covered-marker reader tolerates the same shapes, so the two readers agree.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function New-mdiRemediationScript') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
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

function New-NnrRecord {
    param([string] $Id, [string] $Name, [string] $Protocol, [object] $Port)
    [PSCustomObject]@{
        Id = $Id; Name = $Name; Protocol = $Protocol; Port = $Port
        Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'
        Server = 'dcfab01.fabrikam.local'
        Target = 'ws4.fabrikam.local'; TargetIP = '10.10.3.44'
        Applicable = $true; Success = $false; Detail = 'connection refused'
    }
}

# One cross-forest sensor that cannot resolve a workstation by ANY primary NNR method - the case
# the generator writes inbound firewall rules for. Two ports are always readable so the script has
# real work to do; only the third carries the shape under test.
function New-Estate {
    param([object] $RdpPort)
    [PSCustomObject]@{
        Domain              = 'fabrikam.local'
        Domains             = @('fabrikam.local')
        DomainControllers   = @(
            [PSCustomObject]@{
                FQDN                 = 'dcfab01.fabrikam.local'
                Domain               = 'fabrikam.local'
                Unreachable          = $false
                IP                   = '10.10.1.50'
                isAdvancedAuditingOk = $true
                RequiredPorts        = $false
                Details              = [PSCustomObject]@{
                    RequiredPortsDetails = [PSCustomObject]@{
                        ProbedFrom       = 'Sensor server (outbound)'
                        NnrFailedTargets = @('ws4.fabrikam.local')
                        Results          = @(
                            (New-NnrRecord 'NnrRpc' 'NNR - NTLM over RPC' 'TCP' 135),
                            (New-NnrRecord 'NnrNetBios' 'NNR - NetBIOS' 'UDP' 137),
                            (New-NnrRecord 'NnrRdp' 'NNR - RDP' 'TCP' $RdpPort)
                        )
                    }
                }
            }
        )
        CAServers           = @()
        EntraConnectServers = @()
    }
}

function Get-Generated {
    param([object] $RdpPort)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ('mdi-portshape-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
    $threw = $null
    $lines = @()
    try {
        [void] (New-mdiRemediationScript -ReportData (New-Estate -RdpPort $RdpPort) -FilePath $path)
        if (Test-Path -LiteralPath $path) { $lines = @(Get-Content -LiteralPath $path) }
    } catch {
        $threw = $_.Exception.Message
    } finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    [PSCustomObject]@{
        Threw    = $threw
        Lines    = $lines
        RuleNames = @($lines | ForEach-Object {
                if ($_ -match "\`$ruleName = '(MDI-NNR-[^']+)'") { $Matches[1] }
            } | Select-Object -Unique | Sort-Object)
    }
}

''
'--- 1/2  the control, and the numeric string a JSON round trip produces ---'
$control = Get-Generated -RdpPort 3389
Assert-That 'a numeric port generates a script' ($null -eq $control.Threw) "threw: $($control.Threw)"
Assert-That 'the control writes all three NNR rules' ($control.RuleNames.Count -eq 3) "got [$($control.RuleNames -join ', ')]"
Assert-That '  ...including the RDP rule' ($control.RuleNames -contains 'MDI-NNR-RDP-In') "got [$($control.RuleNames -join ', ')]"

$asString = Get-Generated -RdpPort '3389'
Assert-That "a port written as the string '3389' generates a script" ($null -eq $asString.Threw) "threw: $($asString.Threw)"
Assert-That "  ...and writes exactly the same rules as the integer" `
((@($asString.RuleNames) -join ',') -eq (@($control.RuleNames) -join ',')) `
"got [$($asString.RuleNames -join ', ')] want [$($control.RuleNames -join ', ')]"

''
'--- 3/4/5  every unreadable shape costs one rule, never the script ---'
foreach ($shape in @(
        @{ L = '$null'; V = $null },
        @{ L = "''"; V = '' },
        @{ L = "'   '"; V = '   ' },
        @{ L = "'n/a'"; V = 'n/a' },
        @{ L = "'timed out'"; V = 'timed out' },
        @{ L = '$true'; V = $true },
        @{ L = 'a hashtable'; V = @{} },
        @{ L = 'a huge numeric string'; V = '99999999999999999999' },
        @{ L = 'a negative port'; V = -1 }
    )) {
    $g = Get-Generated -RdpPort $shape.V
    Assert-That "a port of $($shape.L) still generates a script" ($null -eq $g.Threw) "threw: $($g.Threw)"
    Assert-That "  ...and the script is not empty" (@($g.Lines).Count -gt 0) "got $(@($g.Lines).Count) line(s)"
    # 4. The readable siblings keep their rules - the whole point of filtering rather than throwing.
    Assert-That "  ...and the two readable ports keep their rules" `
    (($g.RuleNames -contains 'MDI-NNR-RPC-In') -and ($g.RuleNames -contains 'MDI-NNR-NetBIOS-In')) `
    "got [$($g.RuleNames -join ', ')]"
    # 5. No rule is invented for the record nobody could read.
    Assert-That "  ...and no RDP rule is invented for it" `
    (-not ($g.RuleNames -contains 'MDI-NNR-RDP-In')) "got [$($g.RuleNames -join ', ')]"
}

''
'--- 6/7  the finding is not marked covered by a rule that was never written ---'
# The covered-marker loop is the SECOND reader of Port in this function. If it tolerates the shape
# while the rule loop skips it, the target would be marked covered and the finding would vanish from
# the manual-attention list - a firewall the operator still has to open, silently dropped.
$manualLine = { param($L) @($L | Where-Object { $_ -match 'cannot be fixed by this script' }) -join ' ' }
$controlManual = & $manualLine $control.Lines
foreach ($shape in @(
        @{ L = "'n/a'"; V = 'n/a' },
        @{ L = 'a hashtable'; V = @{} },
        @{ L = '$true'; V = $true }
    )) {
    $g = Get-Generated -RdpPort $shape.V
    $covered = @($g.Lines | Where-Object { $_ -match 'ws4\.fabrikam\.local' -and $_ -match 'MDI-NNR-RDP-In' })
    Assert-That "a port of $($shape.L) does not claim an RDP rule for ws4" ($covered.Count -eq 0) "got [$($covered -join ' | ')]"
    Assert-That "  ...and the script still reports work needing manual attention" `
    (-not [string]::IsNullOrWhiteSpace((& $manualLine $g.Lines))) 'the manual-attention line vanished'
}
Assert-That 'the control covers every finding, so it reports NO manual attention' `
([string]::IsNullOrWhiteSpace($controlManual)) `
"got [$controlManual] - if the control already needs manual attention, the checks above prove nothing"

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
