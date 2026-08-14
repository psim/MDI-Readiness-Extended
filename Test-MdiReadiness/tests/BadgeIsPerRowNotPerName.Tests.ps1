# [w97] A badge belongs to a ROW, not to a name.
#
# The per-row "not reachable" / "partial results" badges are applied by rewriting the generated table
# with -replace, keyed on the FQDN cell. -replace rewrites EVERY match. The FQDN does not identify a
# row: a multi-homed domain controller appears in the inventory once per address, so two rows can
# legitimately carry the same name.
#
# Measured on the shipped renderer with one multi-homed DC - two entries, same FQDN, only the entry
# for the address that did not answer marked Unreachable:
#
#   rows rendered 2, entries unreachable 1, rows badged 2
#
# Both rows were painted class="unreachable" with the badge and with the DEAD ADDRESS's error as the
# row tooltip - including the row carrying real measured findings (class="red">False), whose genuine
# failures were then presented as data from a server nobody had reached. An operator reading that row
# is being told to discount findings that are valid. The same shape hit PartialFailure.
#
# It went unseen because the obvious control passes: two DIFFERENT domain controllers, one
# unreachable, badges exactly one row. Only a repeated FQDN exposes it.
#
# The fix matches positionally - one occurrence consumed per row, in the order the rows were rendered
# - so the badge lands on the entry that actually earned it.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Entry {
    param([string] $Fqdn, [bool] $Unreachable = $false, [bool] $Partial = $false, [string] $Comment = '')
    $o = [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $Unreachable; PartialFailure = $Partial
        OperatingSystem = 'Windows Server 2022'
        Details = [PSCustomObject]@{ }
    }
    if ($Comment) { $o | Add-Member -NotePropertyName Comment -NotePropertyValue $Comment }
    if (-not $Unreachable) {
        $o | Add-Member -NotePropertyName NtlmAuditing -NotePropertyValue $false
        $o | Add-Member -NotePropertyName PowerSettings -NotePropertyValue $false
    }
    $o
}

function Get-DcRows {
    param([object[]] $DomainControllers)
    $report = [PSCustomObject]@{
        DomainsInScope = @('contoso.com')
        DomainControllers = $DomainControllers
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $dir = Join-Path $env:TEMP ('w97test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    try {
        Set-MdiReadinessReport -Domain 'contoso.com' -ReportData $report -Path $dir -SkipTrend | Out-Null
        $htmlFile = @(Get-ChildItem -LiteralPath $dir -Filter '*.html' | Select-Object -First 1)
        if ($htmlFile.Count -eq 0) { throw 'no HTML report was written' }
        $html = [IO.File]::ReadAllText($htmlFile[0].FullName)
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    # The whole <tr> is captured. A pattern that stops at the first </td> would cut off the cells the
    # assertions below actually read.
    @([regex]::Matches($html, '<tr[^>]*>\s*<td class="mono">.*?</tr>') | ForEach-Object { $_.Value })
}

# ---------------------------------------------------------------------------------------------
'[w97] control: two DIFFERENT servers, one unreachable'
$control = Get-DcRows -DomainControllers @(
    (New-Entry -Fqdn 'dc1.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable'),
    (New-Entry -Fqdn 'dc2.contoso.com'))
$controlBadged = @($control | Where-Object { $_ -match 'badge-warn' })
Assert-That 'two rows are rendered' (@($control | Where-Object { $_ -match 'dc[12]\.contoso\.com' }).Count -eq 2) `
    "($(@($control | Where-Object { $_ -match 'dc[12]\.contoso\.com' }).Count) row(s) for the two servers)"
Assert-That 'exactly one is badged' ($controlBadged.Count -eq 1) "($($controlBadged.Count) badged)"
Assert-That 'and it is the unreachable one' (($controlBadged -join '') -match 'dc1\.contoso\.com') "($($controlBadged -join ' | '))"

# ---------------------------------------------------------------------------------------------
'[w97] the defect: ONE multi-homed server, two entries, same FQDN'
$multiHomed = Get-DcRows -DomainControllers @(
    (New-Entry -Fqdn 'dc1.contoso.com' -Unreachable $true -Comment 'The RPC server is unavailable (10.0.0.2)'),
    (New-Entry -Fqdn 'dc1.contoso.com'))
$mhBadged = @($multiHomed | Where-Object { $_ -match 'badge-warn' })
Assert-That 'two rows are rendered for the two entries' `
    (@($multiHomed | Where-Object { $_ -match 'dc1\.contoso\.com' }).Count -eq 2) `
    "($(@($multiHomed | Where-Object { $_ -match 'dc1\.contoso\.com' }).Count) row(s) carry the name)"
Assert-That 'only ONE row is badged, not both' ($mhBadged.Count -eq 1) `
    "($($mhBadged.Count) badged - the badge is keyed on the name, so it painted every row carrying it)"
Assert-That 'only one row carries the unreachable class' `
    (@($multiHomed | Where-Object { $_ -match 'class="unreachable"' }).Count -eq 1) `
    "($(@($multiHomed | Where-Object { $_ -match 'class="unreachable"' }).Count))"
Assert-That "the dead address's error is not attached to both rows" `
    (@($multiHomed | Where-Object { $_ -match '10\.0\.0\.2' }).Count -le 1) `
    "($(@($multiHomed | Where-Object { $_ -match '10\.0\.0\.2' }).Count) row(s) carry it)"

# The row that holds real measured findings must not be labelled unreachable - that tells the reader
# to discount findings that are valid.
$measuredRow = @($multiHomed | Where-Object { $_ -match 'class="red"' })
Assert-That 'the row with measured findings still exists' ($measuredRow.Count -ge 1) `
    "(no row carries a measured False - the fixture stopped testing anything)"
Assert-That 'and it is NOT painted unreachable' `
    (@($measuredRow | Where-Object { $_ -match 'class="unreachable"' }).Count -eq 0) `
    "($($measuredRow -join ' | '))"

# ---------------------------------------------------------------------------------------------
'[w97] the same shape for PartialFailure'
$partial = Get-DcRows -DomainControllers @(
    (New-Entry -Fqdn 'dc9.contoso.com' -Partial $true -Comment 'Remote registry read failed'),
    (New-Entry -Fqdn 'dc9.contoso.com'))
$partialBadged = @($partial | Where-Object { $_ -match 'badge-warn' })
Assert-That 'only one row is badged "partial results"' ($partialBadged.Count -eq 1) "($($partialBadged.Count) badged)"
Assert-That 'and only one row carries the partial class' `
    (@($partial | Where-Object { $_ -match 'class="partial"' }).Count -eq 1) `
    "($(@($partial | Where-Object { $_ -match 'class="partial"' }).Count))"

# ---------------------------------------------------------------------------------------------
'[w97] control: three entries of one name, two of them unreachable'
$three = Get-DcRows -DomainControllers @(
    (New-Entry -Fqdn 'dc5.contoso.com' -Unreachable $true -Comment 'unavailable A'),
    (New-Entry -Fqdn 'dc5.contoso.com' -Unreachable $true -Comment 'unavailable B'),
    (New-Entry -Fqdn 'dc5.contoso.com'))
Assert-That 'exactly two of the three rows are badged' `
    (@($three | Where-Object { $_ -match 'badge-warn' }).Count -eq 2) `
    "($(@($three | Where-Object { $_ -match 'badge-warn' }).Count) of $($three.Count))"

# ---------------------------------------------------------------------------------------------
'[w97] control: an error message containing regex substitution syntax survives intact'
# The replacement used to be a regex substitution string, where $_ and ${x} are meaningful; an OS
# error legitimately contains them. The evaluator returns its string literally, so this must render
# as typed rather than being rewritten.
$dollar = Get-DcRows -DomainControllers @(
    (New-Entry -Fqdn 'dc7.contoso.com' -Unreachable $true -Comment 'Access denied to C:\$Recycle.Bin (see $_ for details)'))
Assert-That 'the $ sequences in the reason are preserved' `
    (($dollar -join '') -match '\$Recycle\.Bin' -and ($dollar -join '') -match '\$_') `
    "($($dollar -join ' | '))"

''
"BadgeIsPerRowNotPerName: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
