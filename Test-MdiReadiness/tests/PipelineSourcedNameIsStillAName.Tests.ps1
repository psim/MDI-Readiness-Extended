<#
    THE DEFECT THIS TEST PINS

    A domain name that had been read perfectly well came back as a name nobody could read, purely
    because it had passed through a pipeline - and two domain controllers in two different FORESTS
    then merged into a single host.

    ConvertTo-mdiReadableDomainName is this codebase's single definition of "is this a domain name
    anybody read". Its first act was to unwrap a PSObject:

        if ($candidate -is [System.Management.Automation.PSObject]) { $candidate = $candidate.BaseObject }

    That test is TRUE for any value that has come out of a pipeline cmdlet. Select-Object,
    Sort-Object, Where-Object and ForEach-Object all hand back a PSObject-wrapped string, the wrapper
    SURVIVES parameter binding to [object], and .BaseObject on it is $null. So the line replaced a
    readable name with $null and the function reported that nobody had read it. GetType() still
    answers System.String throughout, which is why this survived inspection - and every existing test
    passed a LITERAL, which is the one shape that does not carry a wrapper.

    A PSCustomObject STORES the wrapper. Rows are built inside pipelines,
    `$names | Select-Object -Unique | ForEach-Object { [PSCustomObject]@{ FQDN = 'dc1'; Domain = $_ } }`,
    and the wrapper is handed straight back on property access. So the loss did not stop at a label:
    it reached the two IDENTITY KEYS built on top of this function. Measured on the shipped
    functions with rows built exactly that way:

        Get-mdiProbeDomainKey     mdilab.local -> ''     fabrikam.local -> ''     both domains lost
        Get-mdiServerIdentityKey  dc1@mdilab   -> 'dc1'  dc1@fabrikam   -> 'dc1'  ONE KEY, TWO FORESTS

    Two controllers that share a short name and differ only by forest are exactly what a cross-forest
    estate contains. Merged into one key, their two halves can carry opposite verdicts, and the
    healthy half then appears in the ready count - the "collapsing every unnameable row into one
    host" failure this codebase has already fixed twice, arriving this time through the shape of a
    value rather than through its content.

    The shipped Get-mdiAddresslessDomainController reproduces the offending input on its own, with no
    test scaffolding at all: its last pipeline stage is `| Select-Object -Unique`, so every entry it
    returns is wrapped, and feeding its real output back into ConvertTo-mdiReadableDomainName
    produced $null for a name it had just successfully built.

    THE FIX unwraps only when there is something to unwrap - a PSObject whose BaseObject is $null
    carries nothing - so it cannot lose a value. Both unwrap sites are corrected, the second being
    the one applied after a one-element collection is opened.

    THIS TEST MUST ALSO REFUSE THE OPPOSITE MISTAKE. Widening what counts as a readable name would be
    a worse defect than the one being fixed, because this function is what stops an unreadable value
    being certified as an enumerated domain. Every shape that was refused before is asserted to be
    refused still.
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

Write-Host "`nA name that has passed through a pipeline cmdlet is still a name that was read"
# Each of these producers wraps its output in a PSObject whose BaseObject is $null. All four are
# used throughout the product, and Get-mdiAddresslessDomainController ends with Select-Object.
$producers = [ordered]@{
    'Select-Object -Unique' = @('fabrikam.local' | Select-Object -Unique)[0]
    'Sort-Object'           = @('fabrikam.local' | Sort-Object)[0]
    'Where-Object'          = @('fabrikam.local' | Where-Object { $true })[0]
    'ForEach-Object'        = @('fabrikam.local' | ForEach-Object { $_ })[0]
}
foreach ($name in $producers.Keys) {
    $value = $producers[$name]
    Assert-True ("a name from $name is read as itself") `
    ((ConvertTo-mdiReadableDomainName -Value $value) -eq 'fabrikam.local') `
    ("got '$(ConvertTo-mdiReadableDomainName -Value $value)'")
}
Assert-True 'a literal name is unaffected' ((ConvertTo-mdiReadableDomainName -Value 'fabrikam.local') -eq 'fabrikam.local')

Write-Host "`nThe wrapper survives parameter binding, so the guard cannot rely on binding to strip it"
$wrapped = @('fabrikam.local' | Sort-Object)[0]
Assert-True 'the pipeline value really is PSObject-wrapped' ($wrapped -is [System.Management.Automation.PSObject])
Assert-True 'and its BaseObject really is $null' ($null -eq $wrapped.BaseObject)
Assert-True 'it renders as the name regardless' (([string] $wrapped) -eq 'fabrikam.local')

Write-Host "`nA one-element collection holding a pipeline-sourced name is still opened and read"
Assert-True 'a wrapped one-element list is read' ((ConvertTo-mdiReadableDomainName -Value @($wrapped)) -eq 'fabrikam.local') `
("got '$(ConvertTo-mdiReadableDomainName -Value @($wrapped))'")
Assert-True 'a literal one-element list is still read' ((ConvertTo-mdiReadableDomainName -Value @('fabrikam.local')) -eq 'fabrikam.local')

Write-Host "`nThe shipped producer's own output is readable by the shipped reader"
# No scaffolding: this is Get-mdiAddresslessDomainController's real return value, fed straight back.
$inventory = @(
    [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = $null; Addresses = @() }
    [PSCustomObject]@{ Name = 'dc2022.mdilab.local'; Domain = 'mdilab.local'; IP = '10.10.1.62'; Addresses = @('10.10.1.62') }
)
$addressless = @(Get-mdiAddresslessDomainController -Inventory $inventory)
Assert-True 'the addressless controller is found' (@($addressless).Count -eq 1) ("got $(@($addressless).Count)")
foreach ($entry in $addressless) {
    Assert-True 'its entry is readable, not $null' ($null -ne (ConvertTo-mdiReadableDomainName -Value $entry)) `
    ("entry rendered as '$entry'")
    Assert-True 'and it reads back as the name the producer built' `
    ((ConvertTo-mdiReadableDomainName -Value $entry) -eq 'dcfab01.fabrikam.local') `
    ("got '$(ConvertTo-mdiReadableDomainName -Value $entry)'")
}

Write-Host "`nTwo controllers that differ only by forest do not collapse into one host"
# The cost of the defect, asserted through the two identity keys rather than through the helper.
$rows = @(@('mdilab.local', 'fabrikam.local') | Select-Object -Unique |
        ForEach-Object { [PSCustomObject]@{ FQDN = 'dc1'; Domain = $_ } })
Assert-True 'the rows really do carry a wrapped Domain' (@($rows)[0].Domain -is [System.Management.Automation.PSObject])
$identityKeys = @($rows | ForEach-Object { Get-mdiServerIdentityKey -Server $_ })
Assert-True 'each identity key still carries its own domain' `
(@($identityKeys | Select-Object -Unique).Count -eq 2) ("got $($identityKeys -join ', ')")
Assert-True 'the mdilab controller keys under mdilab.local' ($identityKeys -contains 'dc1.mdilab.local') ("got $($identityKeys -join ', ')")
Assert-True 'the fabrikam controller keys under fabrikam.local' ($identityKeys -contains 'dc1.fabrikam.local') ("got $($identityKeys -join ', ')")

$domainKeys = @($rows | ForEach-Object { Get-mdiProbeDomainKey -Domain $_.Domain })
Assert-True 'each domain key is non-empty' (@($domainKeys | Where-Object { [string]::IsNullOrEmpty($_) }).Count -eq 0) `
("got '$($domainKeys -join "', '")'")
Assert-True 'the two domains do not share a key' (@($domainKeys | Select-Object -Unique).Count -eq 2) ("got $($domainKeys -join ', ')")

Write-Host "`nA row built from literals behaves exactly as it always did"
$literalRows = @(
    [PSCustomObject]@{ FQDN = 'dc1'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ FQDN = 'dc1'; Domain = 'fabrikam.local' }
)
$literalKeys = @($literalRows | ForEach-Object { Get-mdiServerIdentityKey -Server $_ })
Assert-True 'literal rows key apart too' (@($literalKeys | Select-Object -Unique).Count -eq 2) ("got $($literalKeys -join ', ')")

Write-Host "`nTHE OPPOSITE MISTAKE - every unreadable shape is still refused"
# Widening acceptance here would let a value nobody read be certified as an enumerated domain, which
# is the failure this function exists to prevent. Both the raw shape and the same shape delivered
# through a pipeline are asserted.
$mustRefuse = [ordered]@{
    'a $null'                 = $null
    'an empty string'         = ''
    'a whitespace string'     = '   '
    'a hashtable'             = @{ DnsRoot = 'emea.mdilab.local' }
    'a PSCustomObject'        = [PSCustomObject]@{ DnsRoot = 'emea.mdilab.local' }
    'a boolean'               = $true
    'an integer'              = 12345
    'a two-element list'      = @('a.local', 'b.local')
    'an empty list'           = @()
    'a nested collection'     = @(@('a.local'), @('b.local'))
}
foreach ($shape in $mustRefuse.Keys) {
    Assert-True "$shape is still not a name" ($null -eq (ConvertTo-mdiReadableDomainName -Value $mustRefuse[$shape])) `
    ("got '$(ConvertTo-mdiReadableDomainName -Value $mustRefuse[$shape])'")
}
foreach ($shape in @('a hashtable', 'a boolean', 'an integer')) {
    $piped = @($mustRefuse[$shape] | ForEach-Object { $_ })[0]
    Assert-True "$shape delivered through a pipeline is still not a name" `
    ($null -eq (ConvertTo-mdiReadableDomainName -Value $piped)) `
    ("got '$(ConvertTo-mdiReadableDomainName -Value $piped)'")
}
Assert-True 'the numeric STRING 12345 is still accepted, as a directory really returns it' `
((ConvertTo-mdiReadableDomainName -Value '12345') -eq '12345')
Assert-True 'a wrapped numeric string is accepted too' `
((ConvertTo-mdiReadableDomainName -Value @('12345' | Sort-Object)[0]) -eq '12345')

Write-Host "`nCONTROL - an unreadable domain on a row still leaves the name BARE rather than inventing one"
$unreadableRow = [PSCustomObject]@{ FQDN = 'dc9'; Domain = @{ X = 'y' } }
Assert-True 'a row whose domain is a hashtable keys unqualified' `
((Get-mdiServerIdentityKey -Server $unreadableRow) -eq 'dc9') ("got '$(Get-mdiServerIdentityKey -Server $unreadableRow)'")

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
