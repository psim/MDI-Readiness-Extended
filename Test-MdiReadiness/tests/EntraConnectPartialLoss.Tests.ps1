<#
    A named server that was never assessed is never silent.

    Entra Connect servers are discovered from the description of the directory-synchronization
    account. Two things can go wrong per account: the description does not parse, or the name it
    yields does not resolve in the directory. Both were reported only through Write-mdiVerbose, which
    the default $VerbosePreference discards.

    That mattered because the two honest paths beside it both gate on TOTAL loss: the not-measured
    flag and the "Entra Connect (not identified)" placeholder row only fire when NO candidate
    resolved. A PARTIAL loss - two sync accounts, one resolvable - fell through both.

    Measured before the fix: the HTML report and the JSON report were BYTE-FOR-BYTE IDENTICAL between
    "one Entra Connect server exists" and "two are named, one of them was never assessed". Same
    SHA256 on both artefacts. No row, no issue, no unread charge, no statistics delta, no verdict
    change - the operator was told nothing at all about a server their directory says exists.

    The fix is deliberately ONLY a warning. A placeholder row or an unread charge would fabricate a
    permanently unclearable failure out of what is usually a stale sync account naming a
    decommissioned host, which would be a worse defect than the one being fixed. Say it plainly and
    let the operator decide.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# Captures what a DEFAULT run would actually show: warnings are visible, verbose is not.
$script:capturedWarnings = New-Object System.Collections.ArrayList
$script:capturedVerbose = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:capturedWarnings.Add([string] $Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) [void] $script:capturedVerbose.Add([string] $Message) }

# Drives the real discovery with the directory stubbed. Each account description either parses or
# does not; each parsed name either resolves or does not.
#
# Get-mdiEntraConnectReadiness continues past discovery into per-server readiness work that needs a
# live host, so the call is wrapped: everything asserted here is emitted during DISCOVERY, and the
# warnings captured up to that point are exactly what a default run would print. Asserting on the
# warning stream rather than on the return value keeps this independent of how far the rest of the
# function gets in a stubbed environment.
function Invoke-Discovery {
    param([object[]] $Accounts, [string[]] $Resolvable)
    $script:capturedWarnings.Clear()
    $script:capturedVerbose.Clear()
    Set-Item -Path function:script:Get-ADUser -Value ([scriptblock]::Create(
            'param($LDAPFilter, $Properties, $Server, $ErrorAction) ' +
            ('@({0})' -f (($Accounts | ForEach-Object { "[PSCustomObject]@{{ description = '{0}'; sAMAccountName = '{1}' }}" -f ($_.Description -replace "'", "''"), $_.Name }) -join ','))
        ))
    Set-Item -Path function:script:Get-ADComputer -Value ([scriptblock]::Create(
            'param($Identity, $Server, $ErrorAction) ' +
            ('$ok = @({0}); ' -f (($Resolvable | ForEach-Object { "'$_'" }) -join ',')) +
            'if ($ok -contains [string] $Identity) { return [PSCustomObject]@{ distinguishedName = ("CN=" + $Identity) } } ' +
            'throw "not found"'
        ))
    # Everything past discovery needs a reachable host; stubbed so the function does not spend the
    # test waiting on network timeouts.
    Set-Item -Path function:script:Test-mdiServerAvailable -Value { param($ComputerName) $false }
    try { $null = Get-mdiEntraConnectReadiness -Domain 'a.example' 3>$null 4>$null 6>$null } catch { }
    [PSCustomObject]@{
        Warnings = @($script:capturedWarnings.ToArray())
        Verbose = @($script:capturedVerbose.ToArray())
    }
}

$goodDesc = 'Account created by Microsoft Entra Connect running on AADC01 configured to synchronize'
$secondDesc = 'Account created by Microsoft Entra Connect running on AADC02 configured to synchronize'
$unparsableDesc = 'Konto erstellt fuer die Verzeichnissynchronisierung'

Write-Host 'A partially lost Entra Connect server is announced' -ForegroundColor Cyan
$partial = Invoke-Discovery -Accounts @(
    @{ Name = 'MSOL_1'; Description = $goodDesc }
    @{ Name = 'MSOL_2'; Description = $secondDesc }
) -Resolvable @('AADC01')
Assert-That 'the resolvable server is still discovered' (
    @($partial.Verbose | Where-Object { $_ -match 'Found 1 Entra Connect' }).Count -ge 1) "(verbose: $($partial.Verbose -join ' | '))"
Assert-That 'the unresolvable one produces a WARNING, not just verbose' (
    @($partial.Warnings | Where-Object { $_ -match 'AADC02' }).Count -ge 1) "(warnings: $($partial.Warnings -join ' | '))"
Assert-That '  ...the warning says it was NOT verified' (
    @($partial.Warnings | Where-Object { $_ -match 'AADC02' -and $_ -match 'NOT verified' }).Count -ge 1)
Assert-That '  ...and points at -EntraConnectServer' (
    @($partial.Warnings | Where-Object { $_ -match 'AADC02' -and $_ -match '-EntraConnectServer' }).Count -ge 1)

Write-Host 'An unparsable description is announced too' -ForegroundColor Cyan
# The sibling path: the account exists, the name cannot be read, the server is never assessed.
$unparsable = Invoke-Discovery -Accounts @(
    @{ Name = 'MSOL_1'; Description = $goodDesc }
    @{ Name = 'MSOL_2'; Description = $unparsableDesc }
) -Resolvable @('AADC01')
Assert-That 'an unreadable description produces a warning' (
    @($unparsable.Warnings | Where-Object { $_ -match 'could not be read' }).Count -ge 1) "(warnings: $($unparsable.Warnings -join ' | '))"
Assert-That '  ...and still says NOT verified' (
    @($unparsable.Warnings | Where-Object { $_ -match 'NOT verified' }).Count -ge 1)

Write-Host 'A clean discovery stays quiet' -ForegroundColor Cyan
# Over-warning is its own defect: a run where everything resolved must say nothing.
$clean = Invoke-Discovery -Accounts @(@{ Name = 'MSOL_1'; Description = $goodDesc }) -Resolvable @('AADC01')
Assert-That 'one account that resolves is discovered' (
    @($clean.Verbose | Where-Object { $_ -match 'Found 1 Entra Connect' }).Count -ge 1) "(verbose: $($clean.Verbose -join ' | '))"
Assert-That '  ...and warns about nothing' (
    @($clean.Warnings | Where-Object { $_ -match 'NOT verified' }).Count -eq 0) "(warnings: $($clean.Warnings -join ' | '))"

Write-Host 'A domain with no sync accounts stays quiet' -ForegroundColor Cyan
$none = Invoke-Discovery -Accounts @() -Resolvable @()
Assert-That 'no accounts means no warning' (
    @($none.Warnings | Where-Object { $_ -match 'NOT verified' }).Count -eq 0) "(warnings: $($none.Warnings -join ' | '))"

Write-Host 'Total loss keeps its existing, louder handling' -ForegroundColor Cyan
# The all-fail path already warns and raises a placeholder; the per-candidate warning must not
# replace it, because that message carries the non-English-locale explanation.
$allFail = Invoke-Discovery -Accounts @(
    @{ Name = 'MSOL_1'; Description = $goodDesc }
    @{ Name = 'MSOL_2'; Description = $secondDesc }
) -Resolvable @()
Assert-That 'nothing is discovered when nothing resolves' (
    @($allFail.Verbose | Where-Object { $_ -match 'Found 0 Entra Connect' }).Count -ge 1) "(verbose: $($allFail.Verbose -join ' | '))"
Assert-That '  ...each candidate is named' (
    @($allFail.Warnings | Where-Object { $_ -match 'AADC01' }).Count -ge 1 -and
    @($allFail.Warnings | Where-Object { $_ -match 'AADC02' }).Count -ge 1) "(warnings: $($allFail.Warnings -join ' | '))"
Assert-That '  ...and the documented summary warning is still raised' (
    @($allFail.Warnings | Where-Object { $_ -match 'directory-synchronization account\(s\)' -and $_ -match 'non-English locale' }).Count -ge 1) `
    "(warnings: $($allFail.Warnings -join ' | '))"

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
