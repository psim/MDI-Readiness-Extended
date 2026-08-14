# [w92] A TOTAL loss of the Entra Connect estate must be charged like a PARTIAL one.
#
# Get-mdiEntraConnectReadiness has two terminal branches. The `if` fires when NOTHING resolved and
# emits ONE row for the whole domain; the `elseif` underneath fires when SOME resolved and emits one
# row PER lost sync account. They are chained, so the per-account path is unreachable in exactly the
# case where the MOST was lost - and the `if` never looks at $unreadableSyncAccount, though it is
# fully populated by then.
#
# The consequence is an inversion: losing MORE of the estate made the report look BETTER.
#
#     3 accounts, 2 of 3 lost   ->  3 rows, 3 unread, 81%
#     3 accounts, 3 of 3 lost   ->  1 row,  1 unread, 92%     <- the defect
#
# The elseif's own comment already states the rule the branch above it breaks: "Discovering less of
# the estate must never improve the headline." It was fixed for the partial case and missed for the
# total one - the same shape as every other defect found in this campaign.
#
# After the fix the total-loss score falls monotonically as more is lost (92 -> 86 -> 81 -> 72) and a
# 3-of-3 total loss costs exactly what three unverified servers cost by any other route.
#
# The two total-loss shapes that have NO accounts to name are deliberately unchanged and are pinned
# below as controls: a directory enumeration that FAILED, and accounts that parsed cleanly but name
# computers the directory says do not exist (a decommissioned host, which must not be charged).
#
# End-to-end score evidence: MDI-AB\live\w89-ecsync.ps1. Root cause: MDI-AB\hunt\w92-entrascore.

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$parsable = 'Account created by Microsoft Entra Connect with installation identifier 8f2 running on {0} configured to synchronize to tenant contoso.onmicrosoft.com'
$germanUnparsable = 'Konto erstellt von Microsoft Entra Connect mit der Installations-ID 8f2 zur Synchronisierung des Verzeichnisses'

$script:syncAccounts = @()
$script:knownComputers = @()
$script:enumThrows = $false

Set-Item -Path function:script:Get-ADUser -Value {
    param($LDAPFilter, $Properties, $Server, $ErrorAction)
    if ($script:enumThrows) { throw 'Access is denied' }
    $script:syncAccounts
}
Set-Item -Path function:script:Get-ADComputer -Value {
    param($Identity, $Server, $Properties, $ErrorAction)
    if ($script:knownComputers -contains [string] $Identity) {
        return [PSCustomObject]@{ distinguishedName = ('CN={0},CN=Computers,DC=contoso,DC=com' -f $Identity) }
    }
    throw ('Cannot find an object with identity: {0}' -f $Identity)
}
Set-Item -Path function:script:Test-mdiServerReachable -Value { param($ComputerName) [PSCustomObject]@{ Reachable = $false; Method = 'stubbed' } }
Set-Item -Path function:script:Get-mdiComputerAddress -Value { param($ComputerName, $KnownAddress) @('10.0.0.5') }

function New-SyncAccount { param([string] $Sam, [string] $Description) [PSCustomObject]@{ sAMAccountName = $Sam; description = $Description } }

# Returns the PLACEHOLDER rows only - the rows that stand for a server nobody was able to look at.
function Get-Placeholders {
    param([object[]] $Accounts, [string[]] $Known = @(), [switch] $EnumThrows)
    $script:syncAccounts = $Accounts
    $script:knownComputers = $Known
    $script:enumThrows = [bool] $EnumThrows
    $rows = @(Get-mdiEntraConnectReadiness -Domain 'contoso.com' 3>$null 4>$null 6>$null)
    @($rows | Where-Object { Test-mdiServerIsPlaceholder -Server $_ })
}
function New-LostSet { param([int] $Count) @(1..$Count | ForEach-Object { New-SyncAccount ('AAD_lost{0}' -f $_) $germanUnparsable }) }

'[w92] a TOTAL loss is charged one row per lost sync account'
foreach ($n in 1, 2, 3, 5) {
    $rows = @(Get-Placeholders -Accounts (New-LostSet -Count $n))
    Assert-That "  $n unreadable account(s) produce $n placeholder row(s)" ($rows.Count -eq $n) "(got $($rows.Count))"
}

'[w92] and each row NAMES the account it could not read'
$named = @(Get-Placeholders -Accounts (New-LostSet -Count 3))
foreach ($i in 1, 2, 3) {
    $want = 'AAD_lost{0}' -f $i
    Assert-That "  the row for $want names it" (@($named | Where-Object { [string] $_.FQDN -match [regex]::Escape($want) }).Count -eq 1) `
        "(rows: $((@($named | ForEach-Object { [string] $_.FQDN })) -join ' | '))"
}

'[w92] THE INVARIANT - losing more never produces fewer gaps'
# The decisive assertion. Before the fix a 3-of-3 loss produced ONE row while a 2-of-3 loss produced
# three, so the count went DOWN as the loss went UP.
$counts = @{}
foreach ($n in 1, 2, 3, 5) { $counts[$n] = @(Get-Placeholders -Accounts (New-LostSet -Count $n)).Count }
Assert-That 'the gap count never decreases as more is lost' `
    (($counts[1] -le $counts[2]) -and ($counts[2] -le $counts[3]) -and ($counts[3] -le $counts[5])) `
    "(1->$($counts[1]) 2->$($counts[2]) 3->$($counts[3]) 5->$($counts[5]))"

'[w92] a TOTAL loss costs the same as the equivalent PARTIAL loss'
# 3 accounts all lost must cost what 3 servers unverified by any other route cost. The partial case
# is the one that was already correct, so it is the reference.
$totalThree = @(Get-Placeholders -Accounts (New-LostSet -Count 3)).Count
$partialTwo = @(Get-Placeholders -Accounts @(
        (New-SyncAccount 'AAD_ok' ($parsable -f 'AADC01')),
        (New-SyncAccount 'AAD_lost1' $germanUnparsable),
        (New-SyncAccount 'AAD_lost2' $germanUnparsable)
    ) -Known @('AADC01')).Count
Assert-That 'a partial loss of 2 still charges 2' ($partialTwo -eq 2) "(got $partialTwo)"
Assert-That 'a total loss of 3 charges 3, not 1' ($totalThree -eq 3) "(got $totalThree)"
Assert-That '  ...so the total-loss path is no cheaper than the partial one' ($totalThree -gt $partialTwo) `
    "(total3=$totalThree partial2=$partialTwo)"

'[w92] CONTROL - a FAILED enumeration still emits exactly one whole-domain row'
# Nothing was read, so there is no account to name and nothing to charge per server.
$enum = @(Get-Placeholders -Accounts @() -EnumThrows)
Assert-That 'exactly one placeholder' ($enum.Count -eq 1) "(got $($enum.Count))"
Assert-That '  ...and it says NOT ENUMERATED' ([string] $enum[0].FQDN -match 'not enumerated') "(got '$([string] $enum[0].FQDN)')"

'[w92] CONTROL - accounts naming ABSENT computers are still one row, still not per-account'
# The directory positively answered "no such computer" - a decommissioned host. Charging one per
# account would fabricate a permanently unclearable failure.
$absent = @(Get-Placeholders -Accounts @(
        (New-SyncAccount 'AAD_a' ($parsable -f 'GONE01')),
        (New-SyncAccount 'AAD_b' ($parsable -f 'GONE02')),
        (New-SyncAccount 'AAD_c' ($parsable -f 'GONE03'))
    ) -Known @())
Assert-That 'exactly one placeholder for three absent computers' ($absent.Count -eq 1) "(got $($absent.Count))"
Assert-That '  ...and it does not name an account' ([string] $absent[0].FQDN -eq 'Entra Connect (not identified) - contoso.com') `
    "(got '$([string] $absent[0].FQDN)')"

'[w92] CONTROL - a domain with no Entra Connect at all stays silent'
$none = @(Get-Placeholders -Accounts @())
Assert-That 'no placeholder rows' ($none.Count -eq 0) "(got $($none.Count))"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
