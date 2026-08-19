<#
    COVERAGE MUST NOT BE CLAIMED BY ONE UNREADABLE VALUE MATCHING ANOTHER.

    Get-mdiUnexaminedDomain is THE definition of "which scoped domains produced no servers", and the
    file says so: the comparison used to be written out three times - in the statistics, in the issue
    list and in the verdict - and was collapsed into this one function precisely so the three could
    not drift. All three call it with $ReportData.DomainsInScope and $ReportData.DomainControllers,
    read back off the REPORT, which is the object that travels through -AsJson, -PassThru, a baseline
    file and any tool that hands a report on.

    THE DEFECT. Every comparison inside that function ran through one lambda:

        $normalise = { param($n) ([string] $n).Trim().TrimEnd('.') }

    A bare [string] cast tested with IsNullOrWhiteSpace is a test of the RENDERING, not of the value.
    ConvertTo-mdiReadableDomainName was written for exactly this and its header lists the renderings:
    a hashtable to 'System.Collections.Hashtable', a PSCustomObject to '@{DnsRoot=fabrikam.local}',
    12345 to '12345', $true to 'True'. Five readers in this script already route domain values
    through it - Get-mdiProbeDomainKey, both forest walkers, Get-mdiServerIdentityKey, and
    Get-mdiProbeTargetKey through the first. This function was the sixth, and the only one of the six
    whose answer decides the verdict and the exit code.

    Admitting an unreadable value was not the whole of it. A rendering test also makes two unreadable
    values COMPARE EQUAL whenever they render alike - and whatever mangles a domain mangles it the
    same way wherever it appears, so a scope entry and the domain-controller row that should have
    matched it are mangled TOGETHER. The domain then marks itself examined. Measured on the shipped
    function, mdilab.local scanned normally beside a second scoped domain:

        scope readable,   rows readable            no finding      (control)
        scope UNREADABLE, rows readable            charged
        scope readable,   rows UNREADABLE          charged
        scope AND rows unreadable, hashtable       NO FINDING      <- certified as examined
        scope AND rows unreadable, pscustomobject  NO FINDING      <- certified as examined
        scope AND rows unreadable, 12345           NO FINDING      <- certified as examined
        scope AND rows unreadable, $true           NO FINDING      <- certified as examined
        scope AND rows unreadable, DIFFERENT       charged

    The four middle rows returned nothing at all, so domainsExamined came back $true, no Discovery
    finding was raised and no domain-level unread check was charged - on all three surfaces at once.
    That is this function's own stated worst case, in the words of its comment on the escape hatch:
    "an estate nobody could name was certified READY with no finding of any kind - the largest false
    green this tool can produce". Get-mdiServerIdentityKey, reading the SAME Domain field on the SAME
    rows, refused every one of those values.

    A CROSS-FOREST REPORT IS WHERE THE SHAPE STOPS BEING HYPOTHETICAL, for the reason
    Test-mdiForestEnumerationIncomplete gives about the same object: a multi-forest run is the one
    most likely to be round-tripped through -AsJson, handed between tools or hand-edited, which is
    the arrival vector ConvertTo-mdiRecordObject exists for.

    THE FIX narrows only the two COVERAGE sets - $examined, built from the server rows, and
    $dcDomains, built from the domain-controller rows - to names ConvertTo-mdiReadableDomainName is
    willing to call domain names. The scope list itself is deliberately left on the old lambda.

    THIS TEST MUST ALSO REFUSE THE OPPOSITE MISTAKES, and it asserts three of them.

    First, an unreadable SCOPE entry must still be charged, and still be shown to the operator under
    whatever it renders as. Dropping it from the scope would have replaced a visible false red with a
    silent loss, which is the worse failure of the two.

    Second, the three cases that were already charging correctly must keep charging - a fix that
    only ever adds findings is indistinguishable from one that charges everything.

    Third, the readable estate must be entirely unaffected, including the shapes this codebase reads
    on purpose: a one-element collection @('fabrikam.local'), a PSObject-wrapped string of the kind a
    pipeline really hands to a PSCustomObject property, a trailing DNS root dot, and a case variant.
    A domain that WAS examined must never be charged.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
. ([scriptblock]::Create($body))

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Got = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" }
    else { $script:fail++; Write-Host "  FAIL  $Name $Got" }
}

function New-Dc {
    param($Fqdn, $Domain)
    [PSCustomObject]@{ FQDN = $Fqdn; Domain = $Domain; Unreachable = $false; OperatingSystem = 'Windows Server 2022' }
}

# mdilab.local is always scanned normally, so no case below is an empty scan and the $anyServerSeen
# escape hatch can never be what decides the answer. The second scoped domain is the one under test.
function Get-Unexamined {
    param($ScopeValue, $RowValue)
    $scope = @('mdilab.local', $ScopeValue)
    $dcs = @(
        (New-Dc -Fqdn 'dc2022.mdilab.local' -Domain 'mdilab.local'),
        (New-Dc -Fqdn 'dcfab01.fabrikam.local' -Domain $RowValue)
    )
    @(Get-mdiUnexaminedDomain -ScopedDomain $scope -Server $dcs -DomainControllerServer $dcs)
}
function Test-SecondDomainCharged {
    param($ScopeValue, $RowValue)
    $un = Get-Unexamined -ScopeValue $ScopeValue -RowValue $RowValue
    @($un | Where-Object { ([string] $_) -ne 'mdilab.local' }).Count -gt 0
}

$mangledHashtable = @{ DnsRoot = 'fabrikam.local' }
$mangledObject = [PSCustomObject]@{ DnsRoot = 'fabrikam.local' }

Write-Host "`nThe reader this function should have been using refuses every one of these values"
foreach ($shape in @(
        @{ Name = 'a hashtable'; Value = $mangledHashtable },
        @{ Name = 'a PSCustomObject'; Value = $mangledObject },
        @{ Name = 'a number'; Value = 12345 },
        @{ Name = 'a boolean'; Value = $true },
        @{ Name = 'a nested collection'; Value = @(@('a'), @('b')) })) {
    $readable = ConvertTo-mdiReadableDomainName -Value $shape.Value
    $rendered = ([string] $shape.Value).Trim()
    Assert-True "$($shape.Name) is not a readable domain name" ($null -eq $readable) ("got '$readable'")
    Assert-True "$($shape.Name) nevertheless RENDERS to something non-blank" (-not [string]::IsNullOrWhiteSpace($rendered)) ("got '$rendered'")
}

Write-Host "`nTHE DEFECT - a domain nobody could name must not certify ITSELF as examined"
# Scope entry and row carry the SAME unreadable value, which is what a serialiser produces: it
# mangles a domain the same way wherever that domain appears.
Assert-True 'a hashtable on both sides is still charged' `
(Test-SecondDomainCharged -ScopeValue $mangledHashtable -RowValue @{ DnsRoot = 'fabrikam.local' })
Assert-True 'a PSCustomObject on both sides is still charged' `
(Test-SecondDomainCharged -ScopeValue $mangledObject -RowValue ([PSCustomObject]@{ DnsRoot = 'fabrikam.local' }))
Assert-True 'a number on both sides is still charged' `
(Test-SecondDomainCharged -ScopeValue 12345 -RowValue 12345)
Assert-True 'a boolean on both sides is still charged' `
(Test-SecondDomainCharged -ScopeValue $true -RowValue $true)
Assert-True 'a nested collection on both sides is still charged' `
(Test-SecondDomainCharged -ScopeValue @(@('a'), @('b')) -RowValue @(@('a'), @('b')))

Write-Host "`nAnd the verdict that reads this definition follows it"
$un = Get-Unexamined -ScopeValue $mangledHashtable -RowValue @{ DnsRoot = 'fabrikam.local' }
Assert-True 'domainsExamined is FALSE over an estate nobody could name' (@($un).Count -ne 0) ("got $(@($un).Count) unexamined")
Assert-True 'and the finding names the entry as the operator would see it' `
(@($un | ForEach-Object { [string] $_ }) -contains 'System.Collections.Hashtable') ("got '$(@($un | ForEach-Object { [string] $_ }) -join ', ')'")

Write-Host "`nTHE OPPOSITE MISTAKE - an unreadable scope entry must still be CHARGED, not dropped"
# Dropping it would replace a visible false red with a silent loss. The row is readable here, so
# nothing could have matched the scope entry either way.
Assert-True 'an unreadable scope entry beside readable rows is charged' `
(Test-SecondDomainCharged -ScopeValue $mangledHashtable -RowValue 'fabrikam.local')
Assert-True 'an unreadable ROW does not cover a readable scoped domain' `
(Test-SecondDomainCharged -ScopeValue 'fabrikam.local' -RowValue $mangledHashtable)
Assert-True 'two DIFFERENT unreadable values are still charged' `
(Test-SecondDomainCharged -ScopeValue $mangledHashtable -RowValue 12345)

Write-Host "`nCONTROL - a readable estate is untouched, including the shapes read on purpose"
Assert-True 'a domain scanned under its own name is NOT charged' `
(-not (Test-SecondDomainCharged -ScopeValue 'fabrikam.local' -RowValue 'fabrikam.local'))
Assert-True 'a one-element collection is unwrapped, not refused' `
(-not (Test-SecondDomainCharged -ScopeValue 'fabrikam.local' -RowValue @('fabrikam.local')))
Assert-True 'a one-element collection in the SCOPE is unwrapped too' `
(-not (Test-SecondDomainCharged -ScopeValue @('fabrikam.local') -RowValue 'fabrikam.local'))
$wrapped = @('fabrikam.local') | Select-Object -Unique | ForEach-Object { $_ }
$wrappedRow = [PSCustomObject]@{ Domain = $wrapped }
Assert-True 'a PSObject-wrapped name from a pipeline is still a name' `
(-not (Test-SecondDomainCharged -ScopeValue 'fabrikam.local' -RowValue $wrappedRow.Domain))
Assert-True 'the DNS root dot still folds' `
(-not (Test-SecondDomainCharged -ScopeValue 'fabrikam.local.' -RowValue 'fabrikam.local'))
Assert-True 'and case still folds' `
(-not (Test-SecondDomainCharged -ScopeValue 'FABRIKAM.LOCAL' -RowValue 'fabrikam.local'))
Assert-True 'a domain genuinely never scanned is still charged' `
(Test-SecondDomainCharged -ScopeValue 'fabrikam.local' -RowValue 'apac.mdilab.local')

Write-Host "`n$($script:pass) passed, $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
