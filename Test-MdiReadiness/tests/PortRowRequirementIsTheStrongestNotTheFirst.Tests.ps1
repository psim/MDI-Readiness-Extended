<#
    A port row's Requirement heading must not be decided by which server sorted first.

    THE DEFECT THIS PINS. Get-mdiRequiredPortsHtml builds one row per probe id and one cell per
    server. The row heading used to be:

        $requirement = @($probeRecords | Select-Object -ExpandProperty Requirement -Unique)[0]

    $probeRecords is every record for that probe id across EVERY server, so the heading was whichever
    Requirement value happened to come first. When servers disagree about one port, the same estate
    with the same measurements produced two different headings depending only on the order the
    servers arrived in.

    This is the second half of a fix that was applied to the cell colour and stopped three lines
    short of the label. The colour code immediately above already says why:

        "The requirement is read from THIS server's own failing records, not from $probeRecords[0] -
         which is the first record across every server in the table. A row where one server's probe
         is Optional and another's is Required took its colour from whichever happened to sort first,
         so a genuinely blocked REQUIRED port was painted amber (advisory) because a different
         server's probe for the same port was optional."

    Measured on the shipped function BEFORE the fix, two servers, one probe (LDAPS TCP 636):
    Optional and open on dc01.mdilab.local, Required and REFUSED on dcfab01.fabrikam.local.

        dc01 first     label=Optional   cells=green,red
        dcfab01 first  label=Required   cells=green,red

    The cells were correct in both. That is what makes the label the dangerous half: the colour tells
    the operator to act and the heading over it says the port is Optional, so a blocking required port
    reads as advisory. A reader who scans the Requirement column - which is what that column is for -
    filters it out.

    WHY IT SURVIVED. It needs one probe id carrying two different Requirement values in a single
    report, which a single-forest run cannot produce: the plan is built once and every server shares
    it. -MultiForest is what creates the mixed state - LdapsTcp and LdapsGcTcp ship as Optional and
    are promoted to Required in a multi-forest plan - so a report covering both a same-forest and a
    cross-forest scan carries both spellings for one id. The lab only gained a real second forest on
    17 August.

    THE FIX. The heading is now the STRONGEST requirement any server reported, ranked with the
    existing Get-mdiRequirementRank (Required/All 3, AtLeastOne 2, Recommended 1, Optional or
    unrecognised 0) - the helper that exists so "two roles that describe the same probe differently
    merge to the stronger one instead of to whichever was read first". A value that ranks 0 is either
    a genuine Optional or something unreadable and the two are not guessed between: the shipped
    definition is preferred when no record offers anything recognised, and only a probe with neither
    a shipped definition nor a readable requirement is labelled Unknown.

    Pinned here:

    1. Servers disagreeing Optional/Required produce the SAME heading in both server orders, and that
       heading is Required - the stronger obligation, which is the one the operator must act on.
    2. A row containing a red (blocked, required) cell is never headed Optional.
    3. The per-server cell colours are unchanged by the fix and stay order-independent - the half
       that was already correct must not regress.
    4. Unreadable Requirement values ($null, '', whitespace, a number, a boolean) never become the
       heading; the readable one on the other server wins.
    5. When every server agrees, the heading is that agreed value - Optional stays Optional, so the
       fix does not silently promote a whole row.
    6. AtLeastOne and Recommended rank between Optional and Required, so an NNR row headed by a
       mixture reports the stronger of the two rather than the first.
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

# The server shape Get-mdiPortResultRecord reads: FQDN, and Details.RequiredPortsDetails.Results.
function New-Server {
    param([string] $Fqdn, [object[]] $Results)
    [PSCustomObject]@{
        FQDN    = $Fqdn
        Domain  = ($Fqdn -replace '^[^.]+\.', '')
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $Results } }
    }
}
function New-PortResult {
    param([string] $Id, [string] $Name, [string] $Protocol, $Port, [string] $Scope, $Requirement,
        [bool] $Success, [string] $Target, [string] $TargetIP, [string] $Detail)
    [PSCustomObject]@{
        Id = $Id; Name = $Name; Protocol = $Protocol; Port = $Port; Scope = $Scope
        Requirement = $Requirement; Success = $Success; Applicable = $true
        Target = $Target; TargetIP = $TargetIP; Detail = $Detail
    }
}

# The heading lives in the <small> of the row's FIRST cell, beside the probe name - not in a cell of
# its own. Read from the generated HTML rather than from an internal variable, so the assertion is
# about what the operator actually sees.
function Get-RowFacts {
    param([string] $Html, [string] $ProbeName)
    foreach ($r in [regex]::Matches($Html, '(?s)<tr>(?<cells>.*?)</tr>')) {
        $cells = $r.Groups['cells'].Value
        if ($cells -notmatch [regex]::Escape($ProbeName)) { continue }
        $label = if ($cells -match '(?s)<small>(?<req>.*?)</small>') {
            ($matches['req'] -replace '<[^>]+>', '').Trim()
        } else { '<no small>' }
        $classes = @(foreach ($t in [regex]::Matches($cells, '(?s)<td[^>]*>.*?</td>')) {
                if ($t.Value -match 'class="([^"]+)"') { $matches[1] } else { '-' }
            })
        return [PSCustomObject]@{ Label = $label; Classes = @($classes) }
    }
    [PSCustomObject]@{ Label = '<row not found>'; Classes = @() }
}

$ldapsName = 'Secure LDAP (LDAPS)'
function New-Ldaps {
    param($Requirement, [bool] $Success, [string] $Target, [string] $TargetIP, [string] $Detail)
    New-PortResult -Id 'LdapsTcp' -Name $ldapsName -Protocol 'TCP' -Port 636 -Scope 'DomainController' `
        -Requirement $Requirement -Success $Success -Target $Target -TargetIP $TargetIP -Detail $Detail
}

# Optional and open in the single-forest part of the estate; Required and refused across the trust.
$optionalOpen = New-Ldaps -Requirement 'Optional' -Success $true -Target 'dc01.mdilab.local' -TargetIP '10.10.1.10' -Detail 'open'
$requiredShut = New-Ldaps -Requirement 'Required' -Success $false -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50' -Detail 'connection refused'

$orderA = @(
    (New-Server -Fqdn 'dc01.mdilab.local' -Results @($optionalOpen))
    (New-Server -Fqdn 'dcfab01.fabrikam.local' -Results @($requiredShut))
)
$orderB = @(
    (New-Server -Fqdn 'dcfab01.fabrikam.local' -Results @($requiredShut))
    (New-Server -Fqdn 'dc01.mdilab.local' -Results @($optionalOpen))
)
$a = Get-RowFacts -Html (Get-mdiRequiredPortsHtml -Server $orderA) -ProbeName $ldapsName
$b = Get-RowFacts -Html (Get-mdiRequiredPortsHtml -Server $orderB) -ProbeName $ldapsName

'1. The heading does not depend on the order the servers arrive in'
Assert-That 'both orders produce the same heading' ($a.Label -eq $b.Label) "A=[$($a.Label)] B=[$($b.Label)]"
Assert-That 'the heading is the STRONGER obligation, Required' ($a.Label -eq 'Required') "got [$($a.Label)]"
Assert-That 'and it is Required in the reversed order too' ($b.Label -eq 'Required') "got [$($b.Label)]"

'2. A row carrying a blocked required port is never headed Optional'
foreach ($case in @(@{ N = 'order A'; F = $a }, @{ N = 'order B'; F = $b })) {
    $hasRed = @($case.F.Classes | Where-Object { $_ -eq 'red' }).Count -gt 0
    Assert-That "$($case.N): the blocked required cell is red" $hasRed "classes=[$($case.F.Classes -join ',')]"
    Assert-That "$($case.N): a row with a red cell is not headed Optional" `
        (-not ($hasRed -and $case.F.Label -eq 'Optional')) "label=[$($case.F.Label)]"
}

'3. The per-server cell colours are unchanged and order-independent'
$sortedA = (@($a.Classes) | Sort-Object) -join ','
$sortedB = (@($b.Classes) | Sort-Object) -join ','
Assert-That 'the same cell colours appear in both orders' ($sortedA -eq $sortedB) "A=[$sortedA] B=[$sortedB]"
Assert-That 'the open Optional probe is still green, not amber or red' `
    (@($a.Classes | Where-Object { $_ -eq 'green' }).Count -eq 1) "classes=[$($a.Classes -join ',')]"

'4. An unreadable Requirement never becomes the heading'
foreach ($shape in @(
        @{ Name = '$null'; Value = $null }
        @{ Name = 'an empty string'; Value = '' }
        @{ Name = 'whitespace'; Value = '   ' }
        @{ Name = 'a number'; Value = 636 }
        @{ Name = 'a boolean'; Value = $true }
        @{ Name = 'an unrecognised word'; Value = 'Mandatory' }
    )) {
    $odd = New-Ldaps -Requirement $shape.Value -Success $true -Target 'dc02.mdilab.local' -TargetIP '10.10.1.11' -Detail 'open'
    $servers = @(
        (New-Server -Fqdn 'dc02.mdilab.local' -Results @($odd))
        (New-Server -Fqdn 'dcfab01.fabrikam.local' -Results @($requiredShut))
    )
    $f = Get-RowFacts -Html (Get-mdiRequiredPortsHtml -Server $servers) -ProbeName $ldapsName
    Assert-That "a Requirement of $($shape.Name) does not become the heading" ($f.Label -eq 'Required') "got [$($f.Label)]"
    Assert-That "a Requirement of $($shape.Name) is not printed verbatim" `
        ($f.Label -ne ([string] $shape.Value) -or [string]::IsNullOrWhiteSpace([string] $shape.Value)) "got [$($f.Label)]"
}

'5. When every server agrees the heading is that agreed value'
foreach ($req in 'Optional', 'Recommended', 'Required') {
    $x = New-Ldaps -Requirement $req -Success $false -Target 'dc01.mdilab.local' -TargetIP '10.10.1.10' -Detail 'refused'
    $y = New-Ldaps -Requirement $req -Success $false -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50' -Detail 'refused'
    $f = Get-RowFacts -Html (Get-mdiRequiredPortsHtml -Server @(
                (New-Server -Fqdn 'dc01.mdilab.local' -Results @($x))
                (New-Server -Fqdn 'dcfab01.fabrikam.local' -Results @($y))
            )) -ProbeName $ldapsName
    Assert-That "all servers $req keeps the heading $req" ($f.Label -eq $req) "got [$($f.Label)]"
}

'6. The rank order between the middle values is respected'
# AtLeastOne (2) outranks Recommended (1), and both outrank Optional (0).
foreach ($pair in @(
        @{ Low = 'Recommended'; High = 'AtLeastOne' }
        @{ Low = 'Optional'; High = 'Recommended' }
        @{ Low = 'AtLeastOne'; High = 'Required' }
    )) {
    $lo = New-Ldaps -Requirement $pair.Low -Success $true -Target 'dc01.mdilab.local' -TargetIP '10.10.1.10' -Detail 'open'
    $hi = New-Ldaps -Requirement $pair.High -Success $true -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50' -Detail 'open'
    $f = Get-RowFacts -Html (Get-mdiRequiredPortsHtml -Server @(
                (New-Server -Fqdn 'dc01.mdilab.local' -Results @($lo))
                (New-Server -Fqdn 'dcfab01.fabrikam.local' -Results @($hi))
            )) -ProbeName $ldapsName
    Assert-That "$($pair.High) outranks $($pair.Low) in the heading" ($f.Label -eq $pair.High) "got [$($f.Label)]"
}

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
