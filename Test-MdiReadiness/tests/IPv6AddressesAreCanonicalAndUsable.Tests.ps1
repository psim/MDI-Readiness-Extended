<#
    An address that cannot be a service address must not become a probe target, and the host that owns
    it must not silently disappear.

    Loopback, APIPA, the unspecified address, link-local IPv6 and their IPv4-mapped forms cannot reach a
    service, yet they were accepted as probe targets. The probes against them could only fail, and the
    failure was reported as though a real endpoint had refused. The opposite error rode along with it: a
    domain controller whose only addresses were unusable was silently dropped from the estate instead of
    being kept and explained.

    Pinned here: a global IPv6 literal is retained and IPv4-mapped IPv6 is folded to IPv4; equivalent
    IPv6 spellings produce one endpoint; loopback, APIPA, unspecified, scoped link-local, the mapped
    forms of each and malformed text are all rejected as service addresses; the enumerated DC is not
    dropped, its unusable address is never restored as a probe target, and its row explains that no
    usable address was available; both the AD IPv4 and IPv6 values are validated; a selected host
    retains every NIC; and an unresolved name stays in the gap list.
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
'[address discovery] IPv6 and mapped addresses are canonical service endpoints'
$global = @(Get-mdiComputerAddress -ComputerName '2001:0db8:0:0:0:0:0:42')
Assert-That 'a global IPv6 literal is retained' ($global.Count -eq 1 -and $global[0] -eq '2001:db8::42') "got [$($global -join ',')]"
$mapped = @(Get-mdiComputerAddress -ComputerName '::ffff:10.0.0.5')
Assert-That 'IPv4-mapped IPv6 is folded to IPv4' ($mapped.Count -eq 1 -and $mapped[0] -eq '10.0.0.5') "got [$($mapped -join ',')]"
$deduped = @(Get-mdiComputerAddress -ComputerName '2001:db8::1' -KnownAddress @(
        '2001:0db8:0:0:0:0:0:1', '2001:db8::1'))
Assert-That 'equivalent IPv6 spellings produce one endpoint' ($deduped.Count -eq 1 -and $deduped[0] -eq '2001:db8::1') "got [$($deduped -join ',')]"

'[address discovery] values that cannot identify a remote computer are rejected'
foreach ($case in @(
        @{ Name = 'all of IPv4 loopback'; Value = '127.1.2.3' },
        @{ Name = 'IPv4 APIPA'; Value = '169.254.10.20' },
        @{ Name = 'IPv4 unspecified'; Value = '0.0.0.0' },
        @{ Name = 'IPv6 loopback'; Value = '::1' },
        @{ Name = 'scoped IPv6 link-local'; Value = 'fe80::1%12' },
        @{ Name = 'IPv6 unspecified'; Value = '::' },
        @{ Name = 'mapped IPv4 loopback'; Value = '::ffff:127.0.0.1' },
        @{ Name = 'mapped IPv4 APIPA'; Value = '::ffff:169.254.10.20' },
        @{ Name = 'malformed text'; Value = 'not-an-address' }
    )) {
    $actual = @(Get-mdiComputerAddress -ComputerName $case.Value -KnownAddress $case.Value)
    Assert-That "$($case.Name) is not a service address" ($actual.Count -eq 0) "got [$($actual -join ',')]"
}

'[inventory] a rejected directory address remains visible as an untested computer'
Set-Item -Path function:script:Resolve-mdiDomainController -Value {
    param([string] $Domain)
    [PSCustomObject]@{
        Servers = @([PSCustomObject]@{ Name = 'unusable.invalid'; IP = '127.1.2.3'; Addresses = @('127.1.2.3') })
        Method = 'fixture'; Error = $null; Unnamed = 0
    }
}
$inventory = @(Get-mdiDomainControllerInventory -Domain @('example.test'))
Assert-That 'the enumerated DC is not silently dropped' ($inventory.Count -eq 1) "count=$($inventory.Count)"
Assert-That 'its unusable address is never restored as a probe target' (
    $null -eq $inventory[0].IP -and @($inventory[0].Addresses).Count -eq 0) "IP=[$($inventory[0].IP)]"
Assert-That 'the row explains that no usable address was available' (
    [string] $inventory[0].Error -match 'No usable IP address') "error=[$($inventory[0].Error)]"

'[resolution] every AD address family reaches the NNR target list'
$script:capturedKnown = @()
Set-Item -Path function:script:Get-ADComputer -Value {
    param($Identity, $Properties, $ErrorAction, $Server)
    [PSCustomObject]@{
        DNSHostName = 'dual.example.test'; Name = 'dual'
        IPv4Address = '10.0.0.10'; IPv6Address = '2001:db8::10'
    }
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param([string] $ComputerName, [string[]] $KnownAddress)
    $script:capturedKnown = @($KnownAddress)
    @($KnownAddress | Where-Object { $_ })
}
$targets = @(Resolve-mdiNnrTarget -NnrTargetComputer @('dual') -Domain 'example.test' -DomainControllers @() -MaxTargets 1)
Assert-That 'AD IPv4 and IPv6 values are both passed to address validation' (
    $script:capturedKnown -contains '10.0.0.10' -and $script:capturedKnown -contains '2001:db8::10') "known=[$($script:capturedKnown -join ',')]"
Assert-That 'one selected host retains every NIC' (
    $targets.Count -eq 2 -and @($targets.IP | Select-Object -Unique).Count -eq 2) "targets=[$($targets.IP -join ',')]"

'[resolution] a name resolving to nothing is a gap, not a measured port failure'
$gap = @(Get-mdiUnresolvedNnrTarget -Requested @('missing.invalid') -Resolved @())
Assert-That 'the unresolved name remains in the gap list' ($gap.Count -eq 1 -and $gap[0] -eq 'missing.invalid') "gap=[$($gap -join ',')]"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail) { exit 1 }
