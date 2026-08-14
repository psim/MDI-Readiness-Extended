<#
    A short name and its own FQDN are ONE server when the record says which domain it is in.

    Merge-mdiServerByFqdn keyed on the textual name alone. A controller discovered once by its short
    NetBIOS spelling - an operator-supplied -NnrTargetComputer, a name split out of a comma-separated
    list, a directory attribute returning the sAMAccountName-style form - and once by its FQDN keyed
    differently and became TWO servers. Measured on the shipped functions, one host spelled both ways
    rendered "2 server(s)", a denominator of 4, one PASSING check contributed by the healthy half, an
    overall score of 25%, a duplicate issue row and exit code 3, where the identical host spelled
    consistently rendered 1 server, a denominator of 2, 0% and exit code 2.

    That is the same failure the trailing-dot and whitespace rules already close, in its worst form:
    discovering a server a SECOND time made the estate look BETTER.

    The two guards matter as much as the merge, and they are why this is keyed on the record's own
    Domain rather than on the bare label:

      - a bare short name with NO domain on the record cannot be proven to belong to any domain -
        "dc1" may be dc1.fabrikam.com - so it must still key separately. That case is pinned by
        ServerMergeKeyNormalisation.Tests.ps1 and must not regress.
      - "MEM03" in mdilab.local must NOT collide with mem03.fabrikam.com. Qualifying with the
        record's own domain is what keeps them apart; matching on the first label alone would merge
        two genuinely different machines and hide one of them entirely - a far worse defect than the
        one being fixed, because it removes a server from the estate rather than adding one.

    Asserted on the merged OUTCOME and on the rendered statistics, not on the text of the key
    expression, so the test still fails if the behaviour is reimplemented differently.
#>

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
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Row {
    param([string] $Fqdn, [string] $Domain, [object] $Ntlm, [string] $Role = 'DC')
    $o = [PSCustomObject]@{
        FQDN = $Fqdn; Role = $Role; NtlmAuditing = $Ntlm
        Unreachable = $false; PartialFailure = $false; Comment = ''
        Details = [PSCustomObject]@{}
    }
    if ($Domain) { Add-Member -InputObject $o -NotePropertyName Domain -NotePropertyValue $Domain }
    $o
}
function Get-MergedCount {
    # The first spelling PASSES and the second FAILS, so a merge must also be shown to be pessimistic.
    param([string] $A, [string] $ADomain, [string] $B, [string] $BDomain)
    @(Merge-mdiServerByFqdn -Server @(
            (New-Row -Fqdn $A -Domain $ADomain -Ntlm $true -Role 'DC'),
            (New-Row -Fqdn $B -Domain $BDomain -Ntlm $false -Role 'CA')))
}

'[short name] a dotless name is qualified by the domain on its own record'
$merged = @(Get-MergedCount -A 'MEM03' -ADomain 'mdilab.local' -B 'mem03.mdilab.local' -BDomain 'mdilab.local')
Assert-That 'the same host under both spellings is ONE server' ($merged.Count -eq 1) "got $($merged.Count) rows"
if ($merged.Count -eq 1) {
    Assert-That '  ...and the FAILING verdict still wins' ($merged[0].NtlmAuditing -eq $false) "got '$($merged[0].NtlmAuditing)'"
}
$mixedCase = @(Get-MergedCount -A ' MEM03 ' -ADomain 'MDILAB.LOCAL.' -B 'mem03.mdilab.local' -BDomain 'mdilab.local')
Assert-That 'the qualification survives case, padding and a trailing dot' ($mixedCase.Count -eq 1) "got $($mixedCase.Count) rows"

'[guard] a short name with NO domain cannot be proven to be any particular host'
$noDomain = @(Get-MergedCount -A 'dc1' -ADomain '' -B 'dc1.contoso.com' -BDomain '')
Assert-That 'a bare short name still keys separately' ($noDomain.Count -eq 2) "got $($noDomain.Count) rows"

'[guard] the same label in a DIFFERENT domain is a different machine'
$otherDomain = @(Get-MergedCount -A 'MEM03' -ADomain 'mdilab.local' -B 'mem03.fabrikam.com' -BDomain 'fabrikam.com')
Assert-That 'a short name does not swallow a same-label host elsewhere' ($otherDomain.Count -eq 2) "got $($otherDomain.Count) rows"
$bothShort = @(Get-MergedCount -A 'MEM03' -ADomain 'mdilab.local' -B 'MEM03' -BDomain 'fabrikam.com')
Assert-That 'two short names in different domains stay apart' ($bothShort.Count -eq 2) "got $($bothShort.Count) rows"

'[guard] two short names in the SAME domain are still the same host'
$sameShort = @(Get-MergedCount -A 'MEM03' -ADomain 'mdilab.local' -B 'mem03' -BDomain 'mdilab.local')
Assert-That 'the same short name twice is ONE server' ($sameShort.Count -eq 1) "got $($sameShort.Count) rows"

'[estate] the duplicate must not inflate the server count or the readiness score'
$cleanDomainAuditing = [PSCustomObject]@{
    Domain = 'mdilab.local'
    ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
    ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured = $true; ExchangeAuditingMeasured = $true
    AdfsAuditingMeasured = $true; DeletedObjectsMeasured = $true
}
function New-EstateRow {
    param([string] $Fqdn, [object] $Ntlm)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'mdilab.local'
        Unreachable = $false; PartialFailure = $false; Comment = ''
        Details = [PSCustomObject]@{}
        AdvancedAuditing = $true; NtlmAuditing = $Ntlm; PowerSettings = $true
        RequiredPorts = $true; TimeSync = $true; SensorHealth = $true
    }
}
function Get-EstateStats {
    param($Dcs)
    Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
            Domain = 'mdilab.local'; Forest = 'mdilab.local'; DomainsInScope = @('mdilab.local')
            DomainControllers = @($Dcs); CAServers = @(); EntraConnectServers = @()
            DomainAuditing = @($cleanDomainAuditing); ForestDiscovery = $null
            DomainSchemaVersion = [PSCustomObject]@{ details = 'x'; schemaVersion = 1 }
            LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
        })
}
# One failing host, spelled consistently, is the reference the aliased estate must match exactly.
$reference = Get-EstateStats @((New-EstateRow -Fqdn 'mem03.mdilab.local' -Ntlm $false))
$aliased = Get-EstateStats @((New-EstateRow -Fqdn 'MEM03' -Ntlm $true), (New-EstateRow -Fqdn 'mem03.mdilab.local' -Ntlm $false))
Assert-That 'the aliased estate counts ONE server, like the reference' ($aliased.TotalServers -eq $reference.TotalServers) "got $($aliased.TotalServers), reference $($reference.TotalServers)"
Assert-That 'the aliased estate has the SAME check denominator' ($aliased.ChecksTotal -eq $reference.ChecksTotal) "got $($aliased.ChecksTotal), reference $($reference.ChecksTotal)"
Assert-That 'the healthy alias does not add a passing check' ($aliased.ChecksPassed -eq $reference.ChecksPassed) "got $($aliased.ChecksPassed), reference $($reference.ChecksPassed)"
Assert-That 'finding the host again does not raise the score' ($aliased.ChecksPassed -le $reference.ChecksPassed) "got $($aliased.ChecksPassed) vs $($reference.ChecksPassed)"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
