<#
    A reverse lookup that returns the address back is not a resolved hostname.

    When a PTR query produced text that is merely another spelling of the address queried, that text was
    accepted as the resolved name. Nothing had been resolved: the check reported a successful reverse
    resolution that was never measured, and the operator was never told the PTR record is missing - the
    one fact the check exists to establish.

    Pinned here: equivalent IPv6 text does not count as a reverse resolution and the operator is told
    there is no PTR record. Controls confirm a genuine non-address PTR hostname still passes and is
    named in the result.
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
'[reverse DNS] returning the input address in another spelling is not a PTR hostname'
$script:ptrName = '2001:db8::1'
Set-Item -Path function:script:Get-mdiPtrHostEntry -Value {
    param([string] $IPAddress, [int] $TimeoutMs)
    [PSCustomObject]@{ TimedOut = $false; HostEntry = [PSCustomObject]@{ HostName = $script:ptrName } }
}
$sameAddress = Test-mdiReverseDns -IPAddress '2001:0db8:0:0:0:0:0:1'
Assert-That 'equivalent IPv6 text does not count as a reverse resolution' (
    $sameAddress.Success -eq $false) "detail=[$($sameAddress.Detail)]"
Assert-That 'the operator is told there is no PTR record' (
    [string] $sameAddress.Detail -like 'No PTR record*') "detail=[$($sameAddress.Detail)]"

'[control] a real DNS hostname still passes'
$script:ptrName = 'dc1.example.test'
$hostname = Test-mdiReverseDns -IPAddress '2001:db8::1'
Assert-That 'a non-address PTR hostname passes' ($hostname.Success -eq $true) "detail=[$($hostname.Detail)]"
Assert-That 'the hostname is named in the result' (
    [string] $hostname.Detail -match 'dc1\.example\.test') "detail=[$($hostname.Detail)]"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail) { exit 1 }
