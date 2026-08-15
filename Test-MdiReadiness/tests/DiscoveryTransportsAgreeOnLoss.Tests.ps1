<#
    The two domain-controller discovery transports must report the SAME loss for the SAME directory.

    Discovery has two paths. Resolve-mdiDomainController first asks Active Directory Web Services
    (Get-ADDomainController); if ADWS is stopped, faulted, firewalled on TCP 9389, or refuses a
    restricted caller, it falls back to raw LDAP on 389.

    The ADWS branch counts every DC record that carries neither dNSHostName nor name in $blankName,
    warns about it, and returns that count as Unnamed - which Get-mdiDomainControllerReadiness turns
    into an unmeasured placeholder row, an unread check, an issue, and a NOT-READY verdict.

    The LDAP branch did `if ([string]::IsNullOrWhiteSpace($hostName)) { continue }` and then returned
    `Unnamed = 0` unconditionally. The lost controller left the NUMERATOR and the DENOMINATOR, so on
    one and the same directory:

        ADWS  ->  2 servers + 1 placeholder,  20/21,  95%,  1 unread,  1 issue,  NOT READY
        LDAP  ->  2 servers,                  20/20, 100%,  0 unread,  0 issues, READY

    Losing a domain controller RAISED the score and flipped the verdict. Which transport answered is
    not something the customer chose - it depends on whether an optional Windows service happened to
    be reachable - so the same forest could be certified ready or not ready by accident.

    This file runs the REAL Resolve-mdiDomainController and the REAL Get-mdiDomainControllerFromLdap.
    Only the System.DirectoryServices boundary is faked (RootDSE, the search root and the searcher),
    so every branch, filter and calculation under test is the shipped code. Nothing is rewritten from
    source text, so this test cannot silently pass by failing to find an anchor.
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

$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }
Set-Item -Path function:script:Get-mdiComputerAddress -Value { param($ComputerName, $KnownAddress) @('10.0.0.9') }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# --- the directory content, used identically by BOTH transports -------------------------------------
# Two named controllers and one record whose dNSHostName and name are both unreadable.
$script:directory = @(
    @{ Host = 'dc1.contoso.com'; Name = 'DC1' },
    @{ Host = 'dc2.contoso.com'; Name = 'DC2' },
    @{ Host = '';                Name = '' }
)

# --- the System.DirectoryServices boundary, faked ---------------------------------------------------
function New-FakeProps {
    # A plain hashtable: the walker indexes it as $entry.Properties['dnshostname'], and a hashtable
    # answers [] directly. A missing or empty attribute must present as an EMPTY COLLECTION, because
    # the shipped code decides on .Count - that is precisely the "no readable name" condition.
    #
    # The assignment below is deliberately a plain if/else with the assignment INSIDE each branch,
    # not `$store[$k] = if (...) { @($v) } else { @() }`. An if-STATEMENT writes through the output
    # pipeline, which unwraps a single-element array to a scalar - so the fake would hand the walker
    # the STRING 'dc1.contoso.com' instead of a one-element collection. [string]$s.Count is 1, so the
    # guard still passed, and $s[0] then returned the first CHARACTER 'd'. Both servers came back
    # named 'd', merged into one row by FQDN, and halved the denominator - a fixture bug that looked
    # exactly like a product defect.
    param([hashtable] $Values)
    $store = @{}
    foreach ($k in $Values.Keys) {
        $v = [string] $Values[$k]
        $key = $k.ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($v)) { $store[$key] = @() } else { $store[$key] = @($v) }
    }
    $store
}

function New-FakeRootDse {
    $o = New-Object PSObject
    $o | Add-Member -MemberType NoteProperty -Name 'Properties' -Value (New-FakeProps @{ 'defaultNamingContext' = 'DC=contoso,DC=com' }) -Force
    $o | Add-Member -MemberType ScriptMethod -Name Dispose -Value { } -Force
    $o
}
function New-FakeSearchRoot {
    $o = New-Object PSObject
    $o | Add-Member -MemberType ScriptMethod -Name Dispose -Value { } -Force
    $o
}
function New-FakeSearcher {
    $entries = @(foreach ($d in $script:directory) {
            [PSCustomObject]@{ Properties = (New-FakeProps @{ 'dnshostname' = $d.Host; 'name' = $d.Name }) }
        })
    $o = [PSCustomObject]@{
        SearchRoot = $null; Filter = $null; PageSize = 0
        PropertiesToLoad = (New-Object System.Collections.ArrayList)
    }
    $o | Add-Member -MemberType NoteProperty -Name '_entries' -Value $entries -Force
    $o | Add-Member -MemberType ScriptMethod -Name FindAll -Value { $this._entries } -Force
    $o | Add-Member -MemberType ScriptMethod -Name Dispose -Value { } -Force
    $o
}

# The three New-Object calls inside the walker are the only things it touches outside this process.
# They are intercepted by shadowing New-Object itself, so the walker's own source is untouched.
Set-Item -Path function:script:New-Object -Value {
    param(
        [Parameter(Position = 0)] $TypeName,
        [Parameter(Position = 1)] $ArgumentList,
        $ComObject, $Property, $Strict, $TypeNameParameterSetName
    )
    $t = [string] $TypeName
    if ($t -eq 'System.DirectoryServices.DirectoryEntry') {
        $path = [string] (@($ArgumentList)[0])
        if ($path -match 'RootDSE$') { return New-FakeRootDse }
        return New-FakeSearchRoot
    }
    if ($t -eq 'System.DirectoryServices.DirectorySearcher') { return New-FakeSearcher }
    # Everything else goes to the real cmdlet, so ArrayList/HashSet/etc still work.
    if ($PSBoundParameters.ContainsKey('ArgumentList')) {
        Microsoft.PowerShell.Utility\New-Object -TypeName $t -ArgumentList $ArgumentList
    } else {
        Microsoft.PowerShell.Utility\New-Object -TypeName $t
    }
}

# ADWS transport. 'fail' forces the documented fallback to LDAP.
$script:adwsMode = 'ok'
Set-Item -Path function:script:Get-ADDomainController -Value {
    param($Server, $Filter, $ErrorAction)
    if ($script:adwsMode -eq 'fail') { throw 'The operation failed because of a bad parameter' }
    @($script:directory | ForEach-Object {
            [PSCustomObject]@{ HostName = $_.Host; Name = $_.Name; IPv4Address = '10.0.0.9' }
        })
}

function New-PassingDcRow {
    param([string] $Fqdn)
    $o = [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
        Comment = $null; Details = [ordered]@{}
    }
    foreach ($n in 'NtlmAuditing', 'AdvancedAuditing', 'PowerSettings', 'TimeSync', 'SensorHealth', 'RootCertificates', 'CapacitySufficient') {
        $o | Add-Member -NotePropertyName $n -NotePropertyValue $true -Force
    }
    $o
}

function Get-Facts {
    param([string] $Transport)
    $script:adwsMode = if ($Transport -eq 'LDAP') { 'fail' } else { 'ok' }
    $script:warnings = New-Object System.Collections.ArrayList

    $resolved = Resolve-mdiDomainController -Domain 'contoso.com' 3>$null 4>$null

    # Build the report exactly as the readiness pass does: one row per named server, plus one
    # unmeasured placeholder per lost record.
    $rows = New-Object System.Collections.ArrayList
    foreach ($s in @($resolved.Servers)) { [void] $rows.Add((New-PassingDcRow -Fqdn ([string] $s.Name))) }
    for ($i = 0; $i -lt [int] $resolved.Unnamed; $i++) {
        [void] $rows.Add([PSCustomObject]@{
                FQDN = 'A domain controller of contoso.com (name not readable)'
                Domain = 'contoso.com'; SensorHealth = 'N/A'
                Comment = 'This domain controller record carries no name, so it was NOT checked.'
                Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true
                Details = [ordered]@{}
            })
    }
    $report = [PSCustomObject]@{
        DomainControllers   = @($rows)
        CAServers           = @()
        EntraConnectServers = @()
        DomainsInScope      = @('contoso.com')
        ForestDiscovery     = [PSCustomObject]@{ Complete = $true }
    }
    $st = Get-mdiReportStatistics -ReportData $report
    [PSCustomObject]@{
        Method      = [string] $resolved.Method
        Discovered  = @($resolved.Servers).Count
        Unnamed     = [int] $resolved.Unnamed
        Placeholders = @($rows | Where-Object { Test-mdiServerIsPlaceholder -Server $_ }).Count
        Warned      = @($script:warnings | Where-Object { $_ -like '*neither a DNS host name nor a name*' }).Count
        Unread      = [int] $st.ChecksUnread
        Denominator = [int] (Get-mdiCoverageDenominator -Measured $st.ChecksTotal -Unread $st.ChecksUnread)
        Percent     = [int] [math]::Floor((Get-mdiCoveragePercent -Passed $st.ChecksPassed -Measured $st.ChecksTotal -Unread $st.ChecksUnread))
        Verdict     = (Test-mdiReadinessResult -ReportData $report 3>$null)
        Issues      = @(Get-mdiIssueList -Statistics $st -ReportData $report).Count
    }
}

Write-Host 'Both discovery transports must report the same loss for the same directory' -ForegroundColor Cyan

$adws = Get-Facts -Transport 'ADWS'
$ldap = Get-Facts -Transport 'LDAP'

Write-Host ("  ADWS  method={0} discovered={1} unnamed={2} {3}% den={4} unread={5} issues={6} ready={7}" -f
    $adws.Method, $adws.Discovered, $adws.Unnamed, $adws.Percent, $adws.Denominator, $adws.Unread, $adws.Issues, $adws.Verdict)
Write-Host ("  LDAP  method={0} discovered={1} unnamed={2} {3}% den={4} unread={5} issues={6} ready={7}" -f
    $ldap.Method, $ldap.Discovered, $ldap.Unnamed, $ldap.Percent, $ldap.Denominator, $ldap.Unread, $ldap.Issues, $ldap.Verdict)

# Both transports really were exercised - otherwise the comparison below is vacuous.
Assert-That 'the ADWS transport was used' ($adws.Method -eq 'ADWS') ("method=$($adws.Method)")
Assert-That 'the LDAP fallback was used' ($ldap.Method -eq 'LDAP') ("method=$($ldap.Method)")
Assert-That 'both transports found the same two named controllers' (
    $adws.Discovered -eq 2 -and $ldap.Discovered -eq 2
) ("adws=$($adws.Discovered) ldap=$($ldap.Discovered)")

# --- The defect -------------------------------------------------------------------------------------
Assert-That 'the LDAP fallback COUNTS the nameless record' ($ldap.Unnamed -eq 1) ("got $($ldap.Unnamed)")
Assert-That 'the LDAP fallback WARNS about the nameless record' ($ldap.Warned -ge 1) ("got $($ldap.Warned)")
Assert-That 'the LDAP fallback charges the lost controller as unread' ($ldap.Unread -ge 1) ("unread=$($ldap.Unread)")
Assert-That 'the LDAP fallback refuses READY' (-not $ldap.Verdict) "verdict=$($ldap.Verdict)"
Assert-That 'the LDAP fallback raises an issue' ($ldap.Issues -ge 1) ("issues=$($ldap.Issues)")

# THE INVARIANT: losing a domain controller must never improve the headline.
Assert-That 'losing a controller does not RAISE the score' ($ldap.Percent -le $adws.Percent) (
    "adws=$($adws.Percent)% ldap=$($ldap.Percent)%")
Assert-That 'losing a controller does not SHRINK the denominator' ($ldap.Denominator -ge $adws.Denominator) (
    "adws=$($adws.Denominator) ldap=$($ldap.Denominator)")

# THE CROSS-TRANSPORT INVARIANT: the same directory must produce the same answer either way.
Assert-That 'both transports agree on the number of lost records' ($ldap.Unnamed -eq $adws.Unnamed) (
    "adws=$($adws.Unnamed) ldap=$($ldap.Unnamed)")
Assert-That 'both transports agree on the score' ($ldap.Percent -eq $adws.Percent) (
    "adws=$($adws.Percent)% ldap=$($ldap.Percent)%")
Assert-That 'both transports agree on the denominator' ($ldap.Denominator -eq $adws.Denominator) (
    "adws=$($adws.Denominator) ldap=$($ldap.Denominator)")
Assert-That 'both transports agree on the verdict' ($ldap.Verdict -eq $adws.Verdict) (
    "adws=$($adws.Verdict) ldap=$($ldap.Verdict)")
Assert-That 'both transports emit the same number of placeholder rows' (
    $ldap.Placeholders -eq $adws.Placeholders
) ("adws=$($adws.Placeholders) ldap=$($ldap.Placeholders)")

# --- The controls that must NOT be broken ------------------------------------------------------------
# The ADWS behaviour is the reference and must be untouched by the LDAP fix.
Assert-That 'CONTROL: ADWS still counts the nameless record' ($adws.Unnamed -eq 1) ("got $($adws.Unnamed)")
Assert-That 'CONTROL: ADWS still refuses READY' (-not $adws.Verdict) "verdict=$($adws.Verdict)"

# A clean directory must be completely unaffected on BOTH transports: no phantom loss, still READY.
$script:directory = @(
    @{ Host = 'dc1.contoso.com'; Name = 'DC1' },
    @{ Host = 'dc2.contoso.com'; Name = 'DC2' }
)
$cleanAdws = Get-Facts -Transport 'ADWS'
$cleanLdap = Get-Facts -Transport 'LDAP'
Assert-That 'CONTROL: a clean directory reports no loss over ADWS' (
    $cleanAdws.Unnamed -eq 0 -and $cleanAdws.Warned -eq 0 -and $cleanAdws.Percent -eq 100 -and $cleanAdws.Verdict
) ("unnamed=$($cleanAdws.Unnamed) warned=$($cleanAdws.Warned) pct=$($cleanAdws.Percent) ready=$($cleanAdws.Verdict)")
Assert-That 'CONTROL: a clean directory reports no loss over LDAP' (
    $cleanLdap.Unnamed -eq 0 -and $cleanLdap.Warned -eq 0 -and $cleanLdap.Percent -eq 100 -and $cleanLdap.Verdict
) ("unnamed=$($cleanLdap.Unnamed) warned=$($cleanLdap.Warned) pct=$($cleanLdap.Percent) ready=$($cleanLdap.Verdict)")
Assert-That 'CONTROL: a clean directory scores identically on both transports' (
    $cleanLdap.Percent -eq $cleanAdws.Percent -and $cleanLdap.Denominator -eq $cleanAdws.Denominator
) ("adws=$($cleanAdws.Percent)%/den$($cleanAdws.Denominator) ldap=$($cleanLdap.Percent)%/den$($cleanLdap.Denominator)")

# A directory in which EVERY record is nameless must not look like a domain with no domain
# controllers - that would score as nothing to check rather than as everything unchecked.
$script:directory = @( @{ Host = ''; Name = '' }, @{ Host = ''; Name = '' } )
$allLost = Get-Facts -Transport 'LDAP'
Assert-That 'CONTROL: a wholly nameless directory still reports the loss' (
    $allLost.Unnamed -eq 2
) ("unnamed=$($allLost.Unnamed)")
Assert-That 'CONTROL: a wholly nameless directory refuses READY' (-not $allLost.Verdict) (
    "verdict=$($allLost.Verdict)")

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
