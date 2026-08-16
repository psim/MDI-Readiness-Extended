<#
    Two spellings of one address are one endpoint, not two.

    An IPv6 address can be written many equivalent ways, and an IPv4-mapped IPv6 address names an IPv4
    host. Identity was taken from the text rather than from the address, so the same endpoint discovered
    under two spellings survived as two records: one machine counted twice, and a merge that should have
    kept the stronger measured failure could keep the weaker half instead, so a real failure was
    reported alongside a healthy-looking duplicate of the same host.

    Pinned here: equivalent address-only identities match and equivalent IPv6 endpoint records merge to
    one; the stronger measured failure survives that merge; Target and TargetIP are canonical in the
    report record; and an address is never rendered as name-plus-address nor fabricated into a DNS name.
    Controls confirm different hostnames stay distinct even when they share an address, and that
    identity stays hostname-based whenever a hostname exists.
#>

$ErrorActionPreference = 'Stop'
$canonical = $(if ($env:MDI_CANONICAL) { $env:MDI_CANONICAL } else { $c = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1'; if (Test-Path -LiteralPath $c) { $c } else { Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1' } })
$loaded = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $loaded)) { $loaded = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$loadedHash = (Get-FileHash -LiteralPath $loaded -Algorithm SHA256).Hash
$canonicalHash = $(if (Test-Path -LiteralPath $canonical) { (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash } else { '<canonical not found>' })
"LOADED_PATH=$loaded"
"LOADED_SHA256=$loadedHash"
"CANONICAL_SHA256=$canonicalHash"
"HASH_MATCH=$($loadedHash -eq $canonicalHash)"
# NOT fatal when the hashes differ. Run-Suite.ps1 deliberately runs every test against an ISOLATED
# SNAPSHOT of the tree, so the canonical file legitimately moves on while the suite is running - and
# throwing here killed the file before a single assertion ran. Five tests reported "no assertions"
# in a suite where they passed standalone, which reads as a quiet file rather than as a dead one.
# The disclosure above is what actually guards against loading a stale copy; the hard guard below
# proves the loaded file is the product script rather than proving it is byte-current.
if ($loadedHash -ne $canonicalHash) {
    "NOTE=loaded copy differs from the canonical file (expected inside an isolated suite copy)"
}
$text = [IO.File]::ReadAllText($loaded) -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
# The guard that actually matters: the file loaded must BE the product script. A stale or truncated
# copy sitting next to a test has silently satisfied a whole test file here before.
if ($text -notmatch '(?m)^function ConvertTo-mdiBoolean') { throw "The file loaded from $loaded is not the Test-MdiReadiness product script." }
$main = $text.IndexOf('#region Main'); if ($main -gt 0) { $text = $text.Substring(0, $main) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
$script:pass = 0; $script:fail = 0
function Assert-That([string] $Name, [bool] $Condition, [string] $Detail = '') {
    if ($Condition) { $script:pass++; "  PASS  $Name" }
    else { $script:fail++; "  FAIL  $Name $Detail" }
}
function New-Record([string] $Target, [string] $Address, [bool] $Success) {
    [PSCustomObject]@{
        Id = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
        Scope = 'DomainController'; Group = 'Directory'; Requirement = 'Required'
        Target = $Target; TargetIP = $Address; Applicable = $true; Success = $Success
        Detail = $(if ($Success) { 'Connected' } else { 'Closed - connection refused' })
    }
}
function New-Details($Record) {
    [PSCustomObject]@{ ProbedFrom = 'Sensor server (outbound)'; FailedRequired = @()
        NnrFailedTargets = @(); Results = @($Record) }
}
$short = '2001:db8::1'
$expanded = '2001:0db8:0:0:0:0:0:1'

'[display identity] equivalent numeric spellings are one endpoint'
$label = Get-mdiTargetLabel -Target $expanded -TargetIP $short
Assert-That 'an equivalent address is not rendered as name plus address' ($label -eq $short) "label=[$label]"
$keyA = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = $short; Domain = 'example.test' })
$keyB = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = $expanded; Domain = 'example.test' })
Assert-That 'equivalent address-only server identities match' ($keyA -eq $keyB -and $keyA -eq $short) "keys=[$keyA]/[$keyB]"
Assert-That 'an address is never fabricated into a DNS name' ($keyA -notlike '*.example.test') "key=[$keyA]"

'[merge identity] equivalent endpoints cannot survive as contradictory records'
$merged = Merge-mdiRequiredPortsDetails `
    -First (New-Details (New-Record 'dc1.example.test' $short $true)) `
    -Second (New-Details (New-Record 'dc1.example.test' $expanded $false))
Assert-That 'equivalent IPv6 endpoint records merge once' (@($merged.Results).Count -eq 1) "count=$(@($merged.Results).Count)"
Assert-That 'the stronger measured failure survives the merge' (@($merged.Results)[0].Success -eq $false)

'[report identity] records are canonical before verdict grouping and rendering'
$server = [PSCustomObject]@{
    FQDN = 'sensor.example.test'
    Details = [PSCustomObject]@{ RequiredPortsDetails = New-Details (New-Record $expanded $expanded $false) }
}
$record = @(Get-mdiPortResultRecord -Server @($server))[0]
Assert-That 'Target is canonical in the report record' ($record.Target -eq $short) "Target=[$($record.Target)]"
Assert-That 'TargetIP is canonical in the report record' ($record.TargetIP -eq $short) "TargetIP=[$($record.TargetIP)]"

'[control] address equality never merges two genuinely different named machines'
$different = Merge-mdiRequiredPortsDetails `
    -First (New-Details (New-Record 'dc1.example.test' $short $true)) `
    -Second (New-Details (New-Record 'dc2.example.test' $short $false))
Assert-That 'different hostnames remain distinct even at one address' (@($different.Results).Count -eq 2) "count=$(@($different.Results).Count)"
$hostKeyA = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = 'dc1.example.test'; IP = $short })
$hostKeyB = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = 'dc2.example.test'; IP = $short })
Assert-That 'server identity remains hostname-based when a hostname exists' ($hostKeyA -ne $hostKeyB) "keys=[$hostKeyA]/[$hostKeyB]"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail) { exit 1 }
