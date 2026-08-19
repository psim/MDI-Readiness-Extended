<#
    A port result record that is MISSING a property must cost that record's field, never the whole
    table and never the whole remediation script.

    THE DEFECT THIS PINS. Four readers of the port result records reached for a field with
    `Select-Object -ExpandProperty`:

        $recordProbeId  = @($records   | Select-Object -ExpandProperty Id -Unique)          (ports table)
        $rankedRequirement = @($probeRecords | Select-Object -ExpandProperty Requirement ...)(ports table)
        $blockedTargets = @($blockedNnr | Select-Object -ExpandProperty Target -Unique ...) (remediation)
        foreach ($port in @($blockedNnr | Select-Object -ExpandProperty Port -Unique ...))  (remediation)

    -ExpandProperty over an object whose property is $null yields $null. Over an object that HAS NO
    SUCH PROPERTY it raises ExpandPropertyNotFound - a red error record under the default preference,
    and a TERMINATING error under $ErrorActionPreference = 'Stop', which the generated remediation
    script sets on its own first line and which any caller may set.

    That shape is not exotic. Get-mdiPortResultRecord builds each record with `Select-Object -Property
    *` off ConvertTo-mdiRecordObject, so a dictionary-shaped result that simply has no 'Requirement'
    key - another tool's JSON, an older version, a hand-edited or merged report, the arrival vector
    ConvertTo-mdiRecordObject exists for - produces a record with no Requirement PROPERTY. A
    cross-forest run is where that stops being hypothetical: -MultiForest promotes LdapsTcp and
    LdapsGcTcp from Optional to Required, so a report covering both a same-forest and a cross-forest
    scan carries several spellings of one probe id and is assembled from more than one producer.

    Measured on the shipped Get-mdiRequiredPortsHtml, one otherwise complete LDAPS record built by
    Get-mdiPortResultRecord from a dictionary-shaped result, one key removed at a time:

        key removed    result
        Requirement    THREW  'Property "Requirement" cannot be found.'
        Id             THREW  'Property "Id" cannot be found.'
        Name           table rendered
        Protocol       table rendered
        Port           table rendered
        Scope          table rendered
        Detail         table rendered
        Target         table rendered
        TargetIP       table rendered

    Seven absent keys are absorbed and two destroy the entire network ports table - which is what
    proves the fault is in the READ and not in the record. The loss is total and silent in the worst
    direction: the table that exists to show which required ports are blocked is the thing that
    disappears, and under 'Stop' it takes the report with it. The cell colour six lines below the
    Requirement read already used member enumeration ($failed.Requirement) and absorbed the very same
    record, so two readers of one field disagreed about how that field is read.

    THE REMEDIATION SCRIPT HALF IS A DIFFERENT FAILURE, and the difference is stated here because the
    probe that found it guessed wrong the first time. Get-mdiPortResultRecord re-stamps Target and
    TargetIP on every record it builds, so those two can be $null but never ABSENT, and the
    -ExpandProperty read of Target cannot raise. What it did instead is the quiet version of the same
    harm: -ExpandProperty yields the nulls, `-Unique` DROPS them, $blockedTargets came back empty and
    the whole NNR firewall section - gated on $blockedTargets.Count - was omitted with nothing said.
    Measured on the shipped New-mdiRemediationScript, three primary NNR methods all measured REFUSED
    against one target whose Target field could not be read: 3 rules for readable targets, 0 rules
    and no warning for unreadable ones. That is precisely the contradiction the Group-resolution
    comment in that function already names - the report says "no NNR method could resolve X" and the
    script generated from that same report is silent about X. Port is NOT re-stamped, so the Port
    read is the loud failure: one record missing it lost every generated NNR rule.

    THE FIX. All four reads go through ForEach-Object, which yields $null for an absent property
    exactly as it does for a null one. Because `Select-Object -Unique` drops a null, that alone would
    trade a crash for silent loss, so the two reads that key a row or gate a section do more: an
    unreadable probe id keys as a stated marker so the record still gets a row, and unreadable NNR
    targets are counted and WARNED about rather than quietly reducing the section to nothing. Nothing
    else changes: unreadable requirements ($null, '', whitespace, 636, 'Required.', $true) still rank
    0 and still lose to a readable one, and a record with no port still maps to no firewall rule.

    Pinned here, driving the shipped functions and reading their real output back:

    1. Removing ANY single key from a complete record leaves the ports table rendered, under both
       $ErrorActionPreference = 'Continue' and 'Stop'.
    2. A cross-forest REQUIRED port measured as REFUSED still labels the row Required and paints the
       cell red when the same-forest record beside it carries no Requirement property at all - and
       for every unreadable requirement shape, in both record orders.
    3. A record with no Id still produces a row, that row has a non-blank heading, it keeps its
       measured refusal, and it does NOT merge into a shipped probe's row.
    4. New-mdiRemediationScript still generates when a blocked NNR record has no readable Target, and
       says so in a warning instead of dropping the section in silence; and it still generates when a
       record is missing Port.
    5. Complete records are unchanged - the same label, the same colours, the same rules as before.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiRequiredPortsHtml') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# A port result as it arrives from a report: a DICTIONARY, which ConvertTo-mdiRecordObject and then
# Get-mdiPortResultRecord turn into the record under test. Nothing is omitted by hand on the record
# itself - the key is simply absent from the source, which is the real arrival vector.
$completeLdaps = [ordered]@{
    Id = 'LdapsTcp'; Name = 'Secure LDAP'; Protocol = 'TCP'; Port = 636; Scope = 'DomainController'
    Requirement = 'Required'; Success = $false; Applicable = $true
    Target = 'dcfab01.fabrikam.local'; TargetIP = '10.10.1.50'; Detail = 'Refused'
}

function New-Result {
    param([hashtable] $Base, [string] $Omit, [hashtable] $Override = @{})
    $o = [ordered]@{}
    foreach ($k in $Base.Keys) {
        if ($k -eq $Omit) { continue }
        $o[$k] = if ($Override.ContainsKey($k)) { $Override[$k] } else { $Base[$k] }
    }
    foreach ($k in $Override.Keys) { if (-not $o.Contains($k)) { $o[$k] = $Override[$k] } }
    $o
}

function New-Server {
    param([string] $Fqdn, [object[]] $Results)
    [PSCustomObject]@{
        FQDN      = $Fqdn
        Domain    = ($Fqdn -replace '^[^.]+\.', '')
        IP        = '10.10.0.21'
        Addresses = @('10.10.0.21')
        Details   = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = @($Results) } }
    }
}

function Get-PortRow {
    param([string] $Html, [string] $PortCell = '<td>636</td>')
    $rows = [regex]::Matches($Html, '<tr>.*?</tr>', 'Singleline')
    foreach ($m in $rows) { if ($m.Value -match [regex]::Escape($PortCell)) { return $m.Value } }
    $null
}
function Get-RowLabel {
    param([string] $Row)
    if ($null -ne $Row -and $Row -match '<small>([^<]*)</small>') { $Matches[1] } else { '<none>' }
}
function Get-RowHeading {
    param([string] $Row)
    if ($null -ne $Row -and $Row -match '<td style="text-align:left"[^>]*>(.*?)<br/>') { $Matches[1] } else { '<none>' }
}
function Get-RowColours {
    param([string] $Row)
    if ($null -eq $Row) { return '' }
    (([regex]::Matches($Row, '<td class="(green|amber|red)"')) | ForEach-Object { $_.Groups[1].Value }) -join ','
}

'1. an absent key costs its own field, never the whole ports table'
foreach ($pref in @('Continue', 'Stop')) {
    foreach ($key in @('Id', 'Requirement', 'Name', 'Protocol', 'Port', 'Scope', 'Detail', 'Target', 'TargetIP')) {
        $srv = New-Server -Fqdn 'mem01.mdilab.local' -Results @((New-Result -Base $completeLdaps -Omit $key))
        $rendered = $false
        $detail = ''
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = $pref
            $html = Get-mdiRequiredPortsHtml -Server @($srv) 2>$null
            $rendered = ($null -ne $html -and $html.Length -gt 0 -and $html -match '<table>')
        } catch {
            $detail = '-> THREW: ' + $_.Exception.Message
        } finally { $ErrorActionPreference = $saved }
        Assert-That "the ports table renders with '$key' absent (`$ErrorActionPreference=$pref)" $rendered $detail
    }
}

''
'2. a promoted-Required refused port still reads Required and red beside an unreadable sibling'
# -MultiForest promotes LdapsTcp to Required, so a cross-forest report carries both spellings.
$sameForestBase = [ordered]@{
    Id = 'LdapsTcp'; Name = 'Secure LDAP'; Protocol = 'TCP'; Port = 636; Scope = 'DomainController'
    Requirement = 'Optional'; Success = $true; Applicable = $true
    Target = 'dc01.mdilab.local'; TargetIP = '10.10.0.11'; Detail = 'Connected'
}
$siblingShape = @(
    @{ Tag = 'Optional'; Omit = ''; Value = 'Optional' }
    @{ Tag = '$null'; Omit = ''; Value = $null }
    @{ Tag = "''"; Omit = ''; Value = '' }
    @{ Tag = 'whitespace'; Omit = ''; Value = '   ' }
    @{ Tag = '636'; Omit = ''; Value = 636 }
    @{ Tag = "'Required.'"; Omit = ''; Value = 'Required.' }
    @{ Tag = '$true'; Omit = ''; Value = $true }
    @{ Tag = 'NO Requirement property'; Omit = 'Requirement'; Value = $null }
)
foreach ($shape in $siblingShape) {
    $same = if ($shape.Omit) {
        New-Result -Base $sameForestBase -Omit 'Requirement'
    } else {
        New-Result -Base $sameForestBase -Omit '' -Override @{ Requirement = $shape.Value }
    }
    $cross = New-Result -Base $completeLdaps -Omit ''
    foreach ($order in @('same first', 'cross first')) {
        $results = if ($order -eq 'same first') { @($same, $cross) } else { @($cross, $same) }
        $srv = New-Server -Fqdn 'mem01.mdilab.local' -Results $results
        $label = '<threw>'; $colours = ''
        try {
            $row = Get-PortRow -Html (Get-mdiRequiredPortsHtml -Server @($srv))
            $label = Get-RowLabel -Row $row
            $colours = Get-RowColours -Row $row
        } catch { $label = 'THREW: ' + $_.Exception.Message }
        Assert-That "sibling $($shape.Tag), $order : row label is Required" ($label -eq 'Required') "-> got '$label'"
        Assert-That "sibling $($shape.Tag), $order : the refused required port is red" ($colours -match 'red') "-> got '$colours'"
    }
}

''
'3. a record with no Id still gets a row, and that row is named'
$noId = New-Result -Base $completeLdaps -Omit 'Id'
$srv = New-Server -Fqdn 'mem01.mdilab.local' -Results @($noId)
$html = Get-mdiRequiredPortsHtml -Server @($srv)
$row = Get-PortRow -Html $html
Assert-That 'the record with no Id produces a row' ($null -ne $row) "-> html was '$html'"
$heading = Get-RowHeading -Row $row
Assert-That 'that row has a non-blank heading' ($null -ne $row -and -not [string]::IsNullOrWhiteSpace($heading) -and $heading -ne '<none>') "-> got '$heading'"
Assert-That 'that row keeps its measured refusal (red)' ((Get-RowColours -Row $row) -match 'red') "-> got '$(Get-RowColours -Row $row)'"
# The record's own Name is preferred over the marker when it has one.
Assert-That 'the row heading prefers the record name' ($heading -match 'Secure LDAP') "-> got '$heading'"
$noIdNoName = New-Result -Base $completeLdaps -Omit 'Id'
$noIdNoName.Remove('Name')
$srv2 = New-Server -Fqdn 'mem01.mdilab.local' -Results @($noIdNoName)
$row2 = Get-PortRow -Html (Get-mdiRequiredPortsHtml -Server @($srv2))
$heading2 = Get-RowHeading -Row $row2
Assert-That 'a record with neither Id nor Name still produces a row' ($null -ne $row2) '-> no row'
Assert-That 'a record with neither Id nor Name is still named in the table' ($null -ne $row2 -and -not [string]::IsNullOrWhiteSpace($heading2) -and $heading2 -ne '<none>') "-> got '$heading2'"
Assert-That 'that record keeps its measured refusal too' ((Get-RowColours -Row $row2) -match 'red') "-> got '$(Get-RowColours -Row $row2)'"
# An unreadable Id must not merge into a shipped probe's row.
$mixed = New-Server -Fqdn 'mem01.mdilab.local' -Results @((New-Result -Base $completeLdaps -Omit ''), $noIdNoName)
$mixedHtml = Get-mdiRequiredPortsHtml -Server @($mixed)
$mixedRows = @([regex]::Matches($mixedHtml, '<tr>.*?</tr>', 'Singleline') | Where-Object { $_.Value -match '<td>636</td>' })
Assert-That 'an unreadable Id gets its OWN row, not the shipped probe''s' (@($mixedRows).Count -eq 2) "-> got $(@($mixedRows).Count) row(s)"

''
'4. the remediation script survives a blocked NNR record missing Target or Port'
# Three primary NNR methods, all MEASURED REFUSED against one target, which is what puts a record
# into $blockedNnr and makes the generator emit the inbound firewall rules.
function New-NnrResults {
    param([string] $Omit = '')
    $out = New-Object System.Collections.ArrayList
    foreach ($p in @(@{ Id = 'NnrRpc'; Port = 135; Protocol = 'TCP' }, @{ Id = 'NnrNetBios'; Port = 137; Protocol = 'UDP' }, @{ Id = 'NnrRdp'; Port = 3389; Protocol = 'TCP' })) {
        $base = [ordered]@{
            Id = $p.Id; Name = $p.Id; Protocol = $p.Protocol; Port = $p.Port; Scope = 'NetworkDevice'
            Group = 'NNR'; Requirement = 'AtLeastOne'; Success = $false; Applicable = $true
            Target = 'ws4.fabrikam.local'; TargetIP = '10.10.1.77'; Detail = 'Timed out'
        }
        $r = [ordered]@{}
        foreach ($k in $base.Keys) { if ($k -ne $Omit) { $r[$k] = $base[$k] } }
        [void] $out.Add($r)
    }
    , @($out.ToArray())
}
function Get-Remediation {
    param([string] $Omit = '', [ref] $Warnings)
    $srv = New-Server -Fqdn 'mem01.mdilab.local' -Results (New-NnrResults -Omit $Omit)
    $data = [PSCustomObject]@{
        DomainControllers   = @($srv)
        CAServers           = @()
        EntraConnectServers = @()
        Domain              = 'mdilab.local'
    }
    $captured = New-Object System.Collections.ArrayList
    Set-Item -Path function:script:Write-mdiWarning -Value ([scriptblock]::Create('param($Message) [void] $script:capturedWarnings.Add([string] $Message)'))
    $script:capturedWarnings = $captured
    $file = Join-Path ([IO.Path]::GetTempPath()) ("mdi-rem-" + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
    try {
        New-mdiRemediationScript -ReportData $data -FilePath $file | Out-Null
        if ($null -ne $Warnings) { $Warnings.Value = @($captured.ToArray()) }
        if (Test-Path $file) { Get-Content -LiteralPath $file -Raw } else { '' }
    } finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
    }
}

$baseline = ''
try { $baseline = Get-Remediation } catch { Assert-That 'the remediation script is generated for complete records' $false ('-> THREW: ' + $_.Exception.Message) }
$baselineRules = @('MDI-NNR-RPC-In', 'MDI-NNR-NetBIOS-In', 'MDI-NNR-RDP-In') | Where-Object { $baseline -match $_ }
Assert-That 'complete records emit all three NNR firewall rules' (@($baselineRules).Count -eq 3) "-> got $(@($baselineRules).Count)"

# A blocked NNR record with NO TARGET cannot receive a firewall rule - a rule is created ON the named
# computer - but the generator must not go silent about it, because the report it was produced from
# still reports that target as unresolvable. Before the fix this THREW and lost the entire script.
$warnings = @()
$noTarget = $null
try { $noTarget = Get-Remediation -Omit 'Target' -Warnings ([ref] $warnings) } catch { }
Assert-That "the remediation script is still generated with 'Target' absent" ($null -ne $noTarget -and $noTarget.Length -gt 0) '-> generation failed'
Assert-That 'a blocked NNR record with no readable target is WARNED about, not dropped in silence' (@($warnings | Where-Object { $_ -match 'no readable target' }).Count -gt 0) "-> warnings: $($warnings -join ' | ')"

# One record missing its PORT must cost that record's rule, not the other two.
$noPort = $null
try { $noPort = Get-Remediation -Omit 'Port' } catch { }
Assert-That "the remediation script is still generated with 'Port' absent" ($null -ne $noPort -and $noPort.Length -gt 0) '-> generation failed'

''
'5. complete records are unchanged'
$same = New-Result -Base $sameForestBase -Omit ''
$cross = New-Result -Base $completeLdaps -Omit ''
$rowA = Get-PortRow -Html (Get-mdiRequiredPortsHtml -Server @((New-Server -Fqdn 'mem01.mdilab.local' -Results @($same, $cross))))
$rowB = Get-PortRow -Html (Get-mdiRequiredPortsHtml -Server @((New-Server -Fqdn 'mem01.mdilab.local' -Results @($cross, $same))))
Assert-That 'the mixed cross-forest row still reads Required in both orders' ((Get-RowLabel -Row $rowA) -eq 'Required' -and (Get-RowLabel -Row $rowB) -eq 'Required') "-> '$(Get-RowLabel -Row $rowA)' / '$(Get-RowLabel -Row $rowB)'"
Assert-That 'the mixed cross-forest row still paints red in both orders' ((Get-RowColours -Row $rowA) -match 'red' -and (Get-RowColours -Row $rowB) -match 'red')
$plain = New-mdiPortProbePlan -Domain 'mdilab.local'
$multi = New-mdiPortProbePlan -Domain 'mdilab.local' -MultiForest
foreach ($id in @('LdapsTcp', 'LdapsGcTcp')) {
    $a = @($plain.Probes | Where-Object { $_.Id -eq $id })[0]
    $b = @($multi.Probes | Where-Object { $_.Id -eq $id })[0]
    Assert-That "$id is Optional without -MultiForest and Required with it" ($a.Requirement -eq 'Optional' -and $b.Requirement -eq 'Required') "-> '$($a.Requirement)' / '$($b.Requirement)'"
}
$known = New-Server -Fqdn 'mem01.mdilab.local' -Results @($cross)
$knownRow = Get-PortRow -Html (Get-mdiRequiredPortsHtml -Server @($known))
Assert-That 'a shipped probe id still uses its shipped name, not the orphan marker' ((Get-RowHeading -Row $knownRow) -notmatch 'Unidentified probe') "-> '$(Get-RowHeading -Row $knownRow)'"

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
