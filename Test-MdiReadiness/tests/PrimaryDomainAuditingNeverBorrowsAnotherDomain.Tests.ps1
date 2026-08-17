<#
    The headline domain auditing properties must never borrow another domain's measurement.

    THE DEFECT THIS PINS. Get-mdiPrimaryDomainAuditing selects the one DomainAuditing row whose
    Domain equals the domain the run was aimed at. When no row matched it fell back to @($rows)[0] -
    the FIRST row, whichever domain that row happened to belong to - and Main feeds that row into
    five report properties:

        DomainAdfsAuditing  DomainObjectAuditing  DomainExchangeAuditing
        DomainDeletedObjects  DomainSchemaVersion

    So a domain whose directory services configuration was never read was reported using a DIFFERENT
    domain's result, under this run's headline domain name, with nothing on any surface saying a
    substitution had happened. That is the family this project keeps finding: a value that was never
    measured for this thing coming back looking like a measurement of it.

    WHY IT SURVIVED 224 TEST FILES. In a single-domain forest the fallback cannot be wrong -
    $domainsInScope holds exactly one name, so row[0] IS the run's domain no matter how the operator
    spelled it. The mismatch needs BOTH more than one domain in scope AND a -Domain that no row's DNS
    name equals. The lab gained both on 17 August: a second forest, fabrikam.local, reached over a
    bidirectional cross-forest trust, carrying the DISJOINT NetBIOS name FABCORP.

    Both halves are ordinary rather than contrived. -Domain is documented as "Domain Name or FQDN";
    $domainsInScope is built at the scope boundary from the DNS names discovery returned. The two
    disagree whenever the operator types the NetBIOS name of a disjoint namespace - FABCORP is not a
    case variant or a trailing-dot variant of fabrikam.local, it is a different string, and the
    existing normalisation (trim, TrimEnd('.'), case-insensitive compare) cannot bridge it - or names
    a domain controller rather than its domain, or names a domain in the trusted forest that this
    forest's enumeration does not contain.

    Measured on the shipped function BEFORE the fix, with rows for mdilab.local and fabrikam.local:

        -Domain FABCORP                 picked_domain=mdilab.local
        -Domain fabcorp                 picked_domain=mdilab.local
        -Domain branch.fabrikam.local   picked_domain=mdilab.local

    - a domain in a different forest, across a trust, reported as this domain's own configuration.

    THE FIX, and what it deliberately does NOT change. One row is still returned unconditionally:
    with a single row there is nothing to confuse it with, so the baseline compatibility the fallback
    was written for is preserved exactly and single-domain runs are untouched. With two or more rows
    and no match, $null is returned and a warning is emitted; the per-domain DomainAuditing list still
    carries every domain that WAS read, and the headline properties come back unread rather than
    borrowed. Main has always tolerated $null here - an empty DomainAuditing collection produces it -
    and the product script sets no StrictMode, so the property reads yield $null, which every
    consumer already treats as not measured.

    Pinned here:

    1. An exact match still wins, and still wins when the spelling differs only by case or a
       trailing dot - the normalisation this function already did must not regress.
    2. Two domains in scope, -Domain naming neither: NOTHING is returned. Specifically it is not
       row[0], and not any row - the assertion is made against every row's tag, so a future
       "return the root domain instead" would fail here too.
    3. The disjoint NetBIOS case by name, upper and lower: FABCORP against fabrikam.local.
    4. A single row is STILL returned when nothing matches, so the baseline case is not regressed.
    5. Rows whose Domain is unreadable ($null, empty, whitespace, a number, a boolean) do not
       displace the real match and do not throw.
    6. An empty row collection returns nothing rather than throwing, and a null ROW is refused at the
       parameter boundary so the row count this decision rests on cannot be inflated by non-rows.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiPrimaryDomainAuditing') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
# Captured rather than silenced: suppressing the headline properties without telling the operator why
# would trade one silent answer for another, so the warning is part of the fix and is asserted.
$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The row shape Main builds: Domain plus the five checks whose results become the headline
# properties. Tag identifies which domain a returned row came from, which is the whole question.
function New-AuditRow {
    param($DomainValue, [string] $Tag)
    [PSCustomObject]@{
        Domain           = $DomainValue
        AdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $Tag }
        ObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $Tag }
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $Tag }
        DeletedObjects   = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $Tag }
        SchemaVersion    = [PSCustomObject]@{ schemaVersion = $Tag }
    }
}
function Get-Tag {
    param($Row)
    if ($null -eq $Row) { return '<null>' }
    [string] $Row.ObjectAuditing.isObjectAuditingOk
}

# mdilab.local FIRST, so row[0] is the wrong answer and picking it is visible. fabrikam.local is the
# second forest, reached over the bidirectional cross-forest trust, whose NetBIOS name is FABCORP.
$twoForests = @(
    (New-AuditRow -DomainValue 'mdilab.local' -Tag 'MDILAB')
    (New-AuditRow -DomainValue 'fabrikam.local' -Tag 'FABRIKAM')
)

'1. An exact match still wins, however it is spelled'
foreach ($spelling in 'fabrikam.local', 'FABRIKAM.LOCAL', 'fabrikam.local.', '  fabrikam.local  ') {
    $r = Get-mdiPrimaryDomainAuditing -Domain $spelling -DomainAuditing $twoForests
    Assert-That "-Domain '$spelling' selects the fabrikam.local row" ((Get-Tag $r) -eq 'FABRIKAM') "got [$(Get-Tag $r)]"
}
$r = Get-mdiPrimaryDomainAuditing -Domain 'mdilab.local' -DomainAuditing $twoForests
Assert-That '-Domain mdilab.local selects the mdilab.local row' ((Get-Tag $r) -eq 'MDILAB') "got [$(Get-Tag $r)]"

'2. A disjoint NetBIOS name takes NOTHING rather than another domain''s measurement'
foreach ($netbios in 'FABCORP', 'fabcorp', 'FabCorp') {
    $script:warnings.Clear()
    $r = Get-mdiPrimaryDomainAuditing -Domain $netbios -DomainAuditing $twoForests
    Assert-That "-Domain '$netbios' returns nothing" ($null -eq $r) "got [$(Get-Tag $r)]"
    # Asserted against EVERY row, not only row[0]: substituting a different row would be the same
    # defect wearing a different index.
    Assert-That "-Domain '$netbios' returns no row at all" `
        (@($twoForests | Where-Object { $null -ne $r -and (Get-Tag $_) -eq (Get-Tag $r) }).Count -eq 0)
    Assert-That "-Domain '$netbios' says why the properties are blank" `
        (@($script:warnings | Where-Object { $_ -match [regex]::Escape($netbios) }).Count -gt 0) `
        "warnings=[$($script:warnings -join ' | ')]"
}

'3. A domain absent from the scope takes nothing either'
foreach ($absent in 'branch.fabrikam.local', 'dcfab01.fabrikam.local', 'contoso.com') {
    $r = Get-mdiPrimaryDomainAuditing -Domain $absent -DomainAuditing $twoForests
    Assert-That "-Domain '$absent' returns nothing" ($null -eq $r) "got [$(Get-Tag $r)]"
}

'4. The single-row baseline is NOT regressed'
$oneRow = @( (New-AuditRow -DomainValue 'mdilab.local' -Tag 'MDILAB') )
foreach ($asked in 'mdilab.local', 'MDILAB', 'mdilab', 'dc01.mdilab.local') {
    $r = Get-mdiPrimaryDomainAuditing -Domain $asked -DomainAuditing $oneRow
    Assert-That "one row, -Domain '$asked' still returns it" ((Get-Tag $r) -eq 'MDILAB') "got [$(Get-Tag $r)]"
}
# A null ELEMENT is rejected at the parameter boundary - Mandatory on a collection makes PowerShell
# validate every element - so the row count this decision rests on cannot be inflated by nulls that
# were never rows. Pinned rather than assumed: it is what makes "one row" mean one row. Main builds
# $domainAuditing with @(foreach ...) emitting [PSCustomObject] $entry every time, so the shipped
# path never produces one either.
$nullElementRejected = $false
try {
    [void] (Get-mdiPrimaryDomainAuditing -Domain 'FABCORP' -DomainAuditing @($null, (New-AuditRow -DomainValue 'mdilab.local' -Tag 'MDILAB')))
} catch {
    $nullElementRejected = $true
}
Assert-That 'a null row is refused at the parameter boundary, not counted' $nullElementRejected

'5. Unreadable Domain values neither displace the match nor throw'
foreach ($shape in @(
        @{ Name = '$null'; Value = $null }
        @{ Name = 'an empty string'; Value = '' }
        @{ Name = 'whitespace'; Value = '   ' }
        @{ Name = 'a number'; Value = 636 }
        @{ Name = 'a boolean'; Value = $true }
        @{ Name = 'a hashtable'; Value = @{ x = 1 } }
    )) {
    $rows = @( (New-AuditRow -DomainValue $shape.Value -Tag 'UNREADABLE'), (New-AuditRow -DomainValue 'fabrikam.local' -Tag 'FABRIKAM') )
    try {
        $r = Get-mdiPrimaryDomainAuditing -Domain 'fabrikam.local' -DomainAuditing $rows
        Assert-That "a row whose Domain is $($shape.Name) does not displace the real match" ((Get-Tag $r) -eq 'FABRIKAM') "got [$(Get-Tag $r)]"
    } catch {
        Assert-That "a row whose Domain is $($shape.Name) does not throw" $false $_.Exception.Message
    }
    # The unreadable row is row[0], so it is also what the old fallback would have handed back.
    try {
        $r = Get-mdiPrimaryDomainAuditing -Domain 'FABCORP' -DomainAuditing $rows
        Assert-That "an unreadable $($shape.Name) row is not handed back for FABCORP" ((Get-Tag $r) -ne 'UNREADABLE') "got [$(Get-Tag $r)]"
    } catch {
        Assert-That "an unreadable $($shape.Name) row does not throw for FABCORP" $false $_.Exception.Message
    }
}

'6. An empty collection returns nothing rather than throwing'
try {
    $r = Get-mdiPrimaryDomainAuditing -Domain 'fabrikam.local' -DomainAuditing @()
    Assert-That 'an empty DomainAuditing returns nothing' ($null -eq $r) "got [$(Get-Tag $r)]"
} catch {
    Assert-That 'an empty DomainAuditing does not throw' $false $_.Exception.Message
}

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
