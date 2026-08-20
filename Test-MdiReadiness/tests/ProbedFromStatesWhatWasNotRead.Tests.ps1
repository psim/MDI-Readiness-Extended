# [w110] The report must not state WHERE the port probes ran when that provenance was never read,
# and must not present a PARTIAL provenance as if it were the whole story.
#
# The network-ports section ends with a provenance line - "Probed from: ..." - that tells the
# operator which direction the required-port probes were actually measured in. It was built with
#
#     $probedFrom = @($Server | ForEach-Object { $_.Details.RequiredPortsDetails.ProbedFrom } |
#                     Where-Object { $_ } | Select-Object -Unique)
#     [void] $lines.Add('<p><small>Probed from: {0}</small></p>' -f ...)
#
# and the line was emitted UNCONDITIONALLY, whatever came back from that read.
#
# The value being read is not free-form. Merge-mdiServer resolves ProbedFrom with the hardened
# filter "-not [string]::IsNullOrWhiteSpace([string] $_)" and RETURNS $null on its else branch when
# neither direction carried a readable value. So an unreadable ProbedFrom is precisely what shipped
# code emits when nothing was measured - it is not a synthetic shape. The producer was hardened;
# this consumer was not, and the bare "Where-Object { $_ }" here does not agree with it on
# whitespace, and does not reject a value that is not a string at all.
#
# Measured on the shipped function with two sensor servers:
#
#   both readable, same (control)   [Sensor server (outbound)]
#   both readable, MIXED direction  [Sensor server (outbound); This computer (inbound to...)]
#   both $null                      []                              <- empty, stated as fact
#   readable + $null                [Sensor server (outbound)]      <- PARTIAL shown as COMPLETE
#   $null + readable                [This computer (inbound to...)] <- PARTIAL shown as COMPLETE
#   both '' empty string            []                              <- empty, stated as fact
#   both whitespace                 [   ; <tab>]                    <- whitespace survived the filter
#   readable + whitespace           [Sensor server (outbound);   ]
#   wrong type (hashtable)          [System.Collections.Hashtable]  <- rendered as a probe SOURCE
#
# The partial case is the harmful one and is the family every defect in this project has belonged
# to: one host's provenance was never read, the report still stated a single source, and the reader
# concludes every probe ran from there. The direction matters - "Sensor server (outbound)" is the
# path MDI actually requires, while the inbound fallback measures the reverse path and is reported
# elsewhere as "not tested in the required direction". In a multi-site forest this line is also the
# cross-site affinity axis: it is how an operator learns a branch DC was probed from a sensor
# sitting in another site.
#
# Ten lines above this read, the SAME function already holds itself to the right standard: when
# every successful probe carried no readable round-trip time it says so explicitly instead of
# silently omitting the section. The provenance line now meets that standard too.
#
# What this file pins:
#   * a wholly readable estate renders exactly as before, and is NOT marked incomplete;
#   * a mixed-direction estate still lists BOTH directions;
#   * when nothing was readable the line STATES that, instead of printing an empty provenance;
#   * when only some hosts were readable the line is marked INCOMPLETE, so a partial read is never
#     presented as the complete set of probe sources;
#   * whitespace never survives as a listed probe source;
#   * a value that is not a string is never rendered as a probe source.

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
# rendering a section built from a port that does not exist or is not actually Required.
$ldapDefinition = @($settings.RequiredPorts | Where-Object { $_.Id -eq 'LdapTcp' })[0]
Assert-That 'the shipped settings still define LdapTcp' ($null -ne $ldapDefinition)
Assert-That 'and LdapTcp is still a REQUIRED port' ([string] $ldapDefinition.Requirement -eq 'Required') `
    "requirement=[$($ldapDefinition.Requirement)]"

$OUTBOUND = 'Sensor server (outbound)'
$INBOUND = 'This computer (inbound to the server)'

function New-PortServer {
    param($Fqdn, $ProbedFrom, [bool] $Ok)
    $portDetails = [PSCustomObject]@{
        Results = @([PSCustomObject]@{
                Id      = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
                Scope   = 'DomainController'; Group = $null; Requirement = 'Required'
                Target  = 'dc1.mdilab.local'; TargetIP = '10.10.0.10'; Applicable = $true
                Success = $Ok; LatencyMs = 9
                Detail  = $(if ($Ok) { 'Connected' } else { 'Connection refused' })
            })
    }
    # ProbedFrom is carried on the details object, which is where the merge sets it and where the
    # HTML layer reads it from.
    $portDetails | Add-Member -MemberType NoteProperty -Name 'ProbedFrom' -Value $ProbedFrom -Force
    [PSCustomObject]@{
        FQDN    = $Fqdn
        Domain  = 'mdilab.local'
        Details = [PSCustomObject]@{ RequiredPortsDetails = $portDetails }
    }
}

# Everything below reads the RENDERED provenance line rather than any internal variable.
function Measure-Provenance {
    param($FromA, $FromB)
    $html = [string] (Get-mdiRequiredPortsHtml -Server @(
            (New-PortServer 'dc1.mdilab.local' $FromA $true),
            (New-PortServer 'dcfab01.fabrikam.local' $FromB $false)))

    $m = [regex]::Match($html, '<p><small>Probed from:(.*?)</small></p>')
    $raw = $(if ($m.Success) { $m.Groups[1].Value } else { '' })
    [PSCustomObject]@{
        Emitted = $m.Success
        Raw     = $raw
        Text    = (($raw -replace '<[^>]+>', ' ') -replace '\s+', ' ').Trim()
    }
}

$hashA = @{ Host = 'mem03' }
$hashB = @{ Host = 'mem04' }

# ---------------------------------------------------------------------------------------------
'[w110] control: a wholly readable estate renders its provenance unchanged'
$control = Measure-Provenance $OUTBOUND $OUTBOUND
Assert-That 'a readable estate still emits the provenance line' ($control.Emitted) `
    "raw=[$($control.Raw)]"
Assert-That 'a readable estate names the direction that was measured' ($control.Text -match [regex]::Escape($OUTBOUND)) `
    "text=[$($control.Text)]"
Assert-That 'a readable estate is NOT marked incomplete' ($control.Text -notmatch 'incomplete|not recorded') `
    "text=[$($control.Text)]"

'[w110] a mixed-direction estate still lists both directions'
$mixed = Measure-Provenance $OUTBOUND $INBOUND
Assert-That 'the required outbound direction is listed' ($mixed.Text -match [regex]::Escape($OUTBOUND)) `
    "text=[$($mixed.Text)]"
Assert-That 'the inbound fallback direction is also listed' ($mixed.Text -match 'inbound') `
    "text=[$($mixed.Text)]"
Assert-That 'a fully readable mixed estate is NOT marked incomplete' ($mixed.Text -notmatch 'incomplete|not recorded') `
    "text=[$($mixed.Text)]"

# ---------------------------------------------------------------------------------------------
# Nothing readable at all. The merge itself returns $null here, so this is a shipped shape. An
# empty provenance printed as a statement of fact is the thing being pinned out.
'[w110] when no provenance was readable the report says so instead of printing an empty one'
$noneCases = @(
    @{ Label = 'no provenance on either host'; A = $null; B = $null }
    @{ Label = 'empty provenance on both hosts'; A = ''; B = '' }
    @{ Label = 'whitespace provenance on both hosts'; A = '   '; B = "`t" }
    @{ Label = 'provenance that is not a string on either host'; A = $hashA; B = $hashB }
)
foreach ($case in $noneCases) {
    $m = Measure-Provenance $case.A $case.B
    Assert-That "$($case.Label): the provenance is never left blank" `
        (-not ($m.Emitted -and $m.Text.Length -eq 0)) "text=[$($m.Text)]"
    Assert-That "$($case.Label): the report states that no probe source was readable" `
        ($m.Text -match 'not recorded') "text=[$($m.Text)]"
    Assert-That "$($case.Label): no unreadable value is rendered as a probe source" `
        ($m.Text -notmatch 'System\.Collections|System\.Object') "text=[$($m.Text)]"
}

# ---------------------------------------------------------------------------------------------
# The harmful case: SOME hosts readable, some not. The list that survives is true but incomplete,
# and printing it alone invites the reader to conclude every probe ran from the sources named.
'[w110] a partially readable provenance is marked incomplete rather than shown as the whole set'
$partialCases = @(
    @{ Label = 'readable host beside one with no provenance'; A = $OUTBOUND; B = $null; Expect = $OUTBOUND }
    @{ Label = 'unreadable host beside one that was readable'; A = $null; B = $INBOUND; Expect = $INBOUND }
    @{ Label = 'readable host beside an empty provenance'; A = $OUTBOUND; B = ''; Expect = $OUTBOUND }
    @{ Label = 'readable host beside a whitespace provenance'; A = $OUTBOUND; B = '   '; Expect = $OUTBOUND }
    @{ Label = 'readable host beside a non-string provenance'; A = $OUTBOUND; B = $hashB; Expect = $OUTBOUND }
)
foreach ($case in $partialCases) {
    $m = Measure-Provenance $case.A $case.B
    Assert-That "$($case.Label): the provenance that WAS read is still shown" `
        ($m.Text -match [regex]::Escape($case.Expect)) "text=[$($m.Text)]"
    Assert-That "$($case.Label): the line is marked incomplete" `
        ($m.Text -match 'incomplete') "text=[$($m.Text)]"
    Assert-That "$($case.Label): no unreadable value is listed beside the readable one" `
        ($m.Text -notmatch 'System\.Collections|System\.Object') "text=[$($m.Text)]"
}

# ---------------------------------------------------------------------------------------------
# Whitespace is the shape the two ends disagreed on: the merge rejects it, this read accepted it,
# and it renders as a separator with nothing after it.
'[w110] whitespace never survives as a listed probe source'
$ws = Measure-Provenance $OUTBOUND "`t"
Assert-That 'a whitespace probe source does not become a second entry' ($ws.Text -notmatch ';') `
    "text=[$($ws.Text)]"

# ---------------------------------------------------------------------------------------------
"RESULT: $($script:pass) passed / $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
