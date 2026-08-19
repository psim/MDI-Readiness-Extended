<#
    THE DEFECT THIS TEST PINS

    A domain whose directory ANSWERED was reported as a domain that could not be reached, and the
    operator was sent to fix a network path and a permission that were both in perfect order.

    Resolve-mdiDomainController has a branch for records the directory returned but could not name.
    It returns them as a COUNT, with no error, because nothing failed:

        @{ Servers = @(); Method = 'LDAP'; Error = $null; Unnamed = 3 }

    Two functions read that record. Get-mdiDomainControllerInventory asks the question correctly,
    and its own comment records why:

        # Servers.Count -eq 0 is not by itself a failed enumeration. The directory can ANSWER and
        # return records that carry no usable name, in which case Unnamed holds how many - and this
        # branch then reported "... over Active Directory Web Services or LDAP: " with nothing
        # after the colon, because there was no error to interpolate.

        if ($resolved.Servers.Count -eq 0 -and [int] $resolved.Unnamed -eq 0) { ... }

    Get-mdiDomainControllerReadiness - the OTHER half of the same pair, reading the same record from
    the same producer - still asked it the old way:

        if ($resolved.Servers.Count -eq 0) { ... }

    So the fix had landed on one sibling of two. Measured on the shipped functions, one domain
    answering with 3 nameless records:

        Unable to enumerate the domain controllers of fabrikam.local over Active Directory Web
        Services or LDAP:                                  <- nothing after the colon
        No domain controller was checked. Verify that this computer can reach a domain controller
        and that the account running the script is allowed to read the directory.

    The first message is empty for exactly the reason the sibling's comment gives: Error is $null on
    that branch, because there was no error. The second is worse than empty - it is WRONG. It names
    reachability and directory-read permission as the things to check, when the directory had just
    answered and the true cause is computer objects carrying neither dNSHostName nor name. That
    cause was already stated twice in the same run, by Resolve-mdiDomainController's own warning and
    by the placeholder rows this function goes on to emit, so a single run diagnosed a single estate
    two contradictory ways at once and the loudest of the three was the false one.

    A CROSS-FOREST READ IS WHAT MAKES THE SHAPE ORDINARY. Over a forest trust the caller is a
    foreign principal, and dNSHostName is not in the partial attribute set a global catalog
    replicates - so the domain answers and the names do not. The single-forest estate this code
    shipped against had no way to produce it.

    THE FIX asks the question the way its sibling already did: an empty Servers list with a non-zero
    Unnamed is a directory that answered, and is reported as such.

    THIS TEST MUST ALSO REFUSE THE OPPOSITE MISTAKE. A GENUINELY failed enumeration - nothing
    returned, nothing named, an error to interpolate - must still raise both original warnings. A
    discovery failure silently downgraded to "the directory answered" would be a far worse defect
    than the one being fixed, because an empty server list produces a clean-looking report of
    nothing. Both directions are asserted here, and so is the population: the unnamed records must
    still reach the report as unmeasured servers, which is what stops them being lost entirely.
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

# The record under test is produced by the SHIPPED Resolve-mdiDomainController, with only its two
# transports stubbed - so the shape being asserted about is one the product really emits, not one
# this test invented. ADWS is made to fail the way a cross-forest call does; the LDAP walker answers
# with three records it could not name.
function Get-ADDomainController { throw 'ADWS is not reachable across the forest trust' }
function Get-mdiDomainControllerFromLdap {
    param($Domain, [ref] $UnnamedCount)
    if ($null -ne $UnnamedCount) { $UnnamedCount.Value = 3 }
    @()
}

Write-Host "`nThe producer really does return an empty server list with no error and a count"
$produced = Resolve-mdiDomainController -Domain 'fabrikam.local' 3>$null
Assert-True 'no servers came back' (@($produced.Servers).Count -eq 0) ("got $(@($produced.Servers).Count)")
Assert-True 'three records were counted as unnamed' ([int] $produced.Unnamed -eq 3) ("got '$($produced.Unnamed)'")
Assert-True 'and there is NO error to interpolate' ($null -eq $produced.Error) ("got '$($produced.Error)'")

# Captured from the shipped function. Both siblings are driven from one stub so they cannot be
# handed different records - the whole point of the defect is that they disagreed about one.
function Get-Warnings {
    param([int] $Unnamed, [string] $ErrorText)
    $captured = @()
    Set-Item -Path function:Resolve-mdiDomainController -Value ([scriptblock]::Create(
            'param($Domain) [PSCustomObject]@{ Servers = @(); Method = ''LDAP''; Error = $script:stubError; Unnamed = $script:stubUnnamed }'))
    $script:stubUnnamed = $Unnamed
    $script:stubError = $ErrorText
    $null = Get-mdiDomainControllerReadiness -Domain 'fabrikam.local' `
        -WarningVariable +captured -WarningAction SilentlyContinue 3>$null 2>$null
    , @($captured | ForEach-Object { [string] $_ })
}

Write-Host "`nA directory that ANSWERED with nameless records is not a failed enumeration"
$answered = Get-Warnings -Unnamed 3 -ErrorText $null
Assert-True 'no warning ends at "...LDAP:" with nothing after it' `
(@($answered | Where-Object { $_ -match 'over Active Directory Web Services or LDAP:\s*$' }).Count -eq 0) `
("got: " + (($answered | Where-Object { $_ -match 'LDAP:\s*$' }) -join ' | '))
Assert-True 'the operator is NOT sent to check reachability and permissions' `
(@($answered | Where-Object { $_ -match 'allowed to read the directory' }).Count -eq 0) `
("got: " + (($answered | Where-Object { $_ -match 'allowed to read' }) -join ' | '))
Assert-True 'the run says the directory answered' `
(@($answered | Where-Object { $_ -match 'answered' }).Count -ge 1) ("got: " + ($answered -join ' | '))
Assert-True 'and says what was actually wrong with the records' `
(@($answered | Where-Object { $_ -match 'neither a DNS host name nor a name' }).Count -ge 1) `
("got: " + ($answered -join ' | '))

Write-Host "`nTHE OPPOSITE MISTAKE - a genuinely failed enumeration must still be raised in full"
$failed = Get-Warnings -Unnamed 0 -ErrorText 'The server is not operational'
Assert-True 'the enumeration failure is still reported' `
(@($failed | Where-Object { $_ -match 'Unable to enumerate the domain controllers of fabrikam\.local' }).Count -eq 1) `
("got: " + ($failed -join ' | '))
Assert-True 'and it carries the error rather than ending at the colon' `
(@($failed | Where-Object { $_ -match 'The server is not operational' }).Count -eq 1) `
("got: " + ($failed -join ' | '))
Assert-True 'and the reachability/permission advice is still given HERE' `
(@($failed | Where-Object { $_ -match 'allowed to read the directory' }).Count -eq 1) `
("got: " + ($failed -join ' | '))
Assert-True 'a real failure is NOT described as a directory that answered' `
(@($failed | Where-Object { $_ -match 'answered' }).Count -eq 0) ("got: " + ($failed -join ' | '))

Write-Host "`nThe unnamed records still reach the report as population nobody examined"
# Losing them is the outcome this codebase calls its most damaging: the report would read as a
# complete scan of a domain whose entire controller population had never been looked at.
Set-Item -Path function:Resolve-mdiDomainController -Value ([scriptblock]::Create(
        'param($Domain) [PSCustomObject]@{ Servers = @(); Method = ''LDAP''; Error = $null; Unnamed = 3 }'))
$inventory = @(Get-mdiDomainControllerInventory -Domain @('fabrikam.local') 3>$null)
Assert-True 'the sibling emits one row per unnamed record' ($inventory.Count -eq 3) ("got $($inventory.Count)")
Assert-True 'every row is marked as having been enumerated' `
(@($inventory | Where-Object { $_.Enumerated -eq $true }).Count -eq 3) ("got $(@($inventory | Where-Object { $_.Enumerated -eq $true }).Count)")
Assert-True 'and no row carries a name to connect to' `
(@($inventory | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Name) }).Count -eq 3) ("got $(@($inventory | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Name) }).Count)")
Assert-True 'each row states why it could not be scanned' `
(@($inventory | Where-Object { $_.Error -match 'neither a DNS host name nor a name' }).Count -eq 3) `
("got $(@($inventory | Where-Object { $_.Error -match 'neither a DNS host name nor a name' }).Count)")

Write-Host "`nCONTROL - a domain that answered with NOTHING at all is still a failed enumeration"
Set-Item -Path function:Resolve-mdiDomainController -Value ([scriptblock]::Create(
        'param($Domain) [PSCustomObject]@{ Servers = @(); Method = ''None''; Error = ''the query succeeded but returned no domain controllers''; Unnamed = 0 }'))
$empty = @(Get-mdiDomainControllerInventory -Domain @('fabrikam.local') 3>$null)
Assert-True 'one placeholder row is emitted for the domain' ($empty.Count -eq 1) ("got $($empty.Count)")
Assert-True 'and it is marked as NOT enumerated' (@($empty)[0].Enumerated -eq $false) ("got $(@($empty)[0].Enumerated)")

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
