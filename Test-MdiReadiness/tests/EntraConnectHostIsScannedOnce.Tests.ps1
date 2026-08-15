<#
    ONE ENTRA CONNECT HOST WAS SCANNED TWICE AND REPORTED TWICE.

    Entra Connect servers are discovered from the directory-synchronization accounts in each domain.
    Two such accounts can name the SAME physical host - an account left behind by a re-installation, a
    staging-mode server promoted in place, or simply two descriptions that resolve to one DNSHostName.

    Measured on the shipped producer with two accounts naming one host:

        CONTROL_ONE_ACCOUNT  raw_entra_rows=1 power_check_invocations=1  json_entra_rows=1 html_entra_rows=1
        DEFECT_TWO_ACCOUNTS  raw_entra_rows=2 power_check_invocations=2  json_entra_rows=2 html_entra_rows=2
        downstream_score_identical=True

    The host was contacted TWICE - every remote check run a second time against one machine - and
    rendered as TWO rows in both the JSON and the HTML, describing a server that does not exist.

    The score was already right, because Merge-mdiServerByFqdn collapses the rows before they are
    counted. That is precisely why this stayed invisible: the number everyone checks was correct while
    the remote work was doubled and the per-role tables lied about the estate.

    De-duplication happens AFTER resolution, because that is where identity becomes knowable - two
    accounts naming "AADC01" and "aadc01.contoso.com" are the same host only once both have resolved
    to a DNSHostName. It uses Get-mdiServerIdentityKey, the same rule the merge and the coverage
    counters use, so all three agree about what one machine is.
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# Every remote reader is counted, so "was this machine contacted twice?" is measured rather than
# inferred. Only the outermost boundaries are replaced.
$script:contacted = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName)
    [void] $script:contacted.Add([string] $ComputerName)
    [PSCustomObject]@{ Reachable = $false; Method = 'fixture'; Detail = 'not reachable in this fixture' }
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param($ComputerName, $KnownAddress)
    @('10.0.0.5')
}
Set-Item -Path function:script:Get-ADComputer -Value {
    param($Identity, $Server, $Properties, $ErrorAction)
    # Whatever spelling is asked for, the directory answers with the one canonical DNSHostName - which
    # is exactly how two sync accounts come to name one host.
    [PSCustomObject]@{
        DNSHostName = 'aadc01.contoso.com'
        IPv4Address = '10.0.0.5'
        OperatingSystem = 'Windows Server 2022'
        distinguishedName = 'CN=AADC01,OU=Servers,DC=contoso,DC=com'
    }
}

function Invoke-Discovery {
    param([string[]] $Named)
    $script:contacted.Clear()
    $rows = @(Get-mdiEntraConnectReadiness -Domain 'contoso.com' -EntraConnectServer $Named 3>$null 4>$null)
    [PSCustomObject]@{
        Rows      = @($rows | Where-Object { $_ })
        Contacted = @($script:contacted)
    }
}

# The control has to behave, or nothing below means anything.
$one = Invoke-Discovery -Named @('aadc01.contoso.com')
if (@($one.Rows).Count -ne 1) {
    throw "the single-account control produced $(@($one.Rows).Count) row(s) - the harness is not reaching the producer"
}

Write-Host 'Two sync accounts naming one host produce ONE server' -ForegroundColor Cyan
$two = Invoke-Discovery -Named @('aadc01.contoso.com', 'aadc01.contoso.com')
Assert-That 'only one server row is produced' (
    @($two.Rows).Count -eq 1) "rows=$(@($two.Rows).Count)"
# The half the merge could never fix: the machine itself.
Assert-That 'and the host is contacted only once' (
    @($two.Contacted | Where-Object { $_ -match 'aadc01' }).Count -eq 1) (
    "contacted=[$($two.Contacted -join '; ')]")

Write-Host ''
Write-Host 'The same host under two different spellings is still one server' -ForegroundColor Cyan
# The reason de-duplication happens AFTER resolution: these two are only knowably the same host once
# the directory has answered with one canonical name for both.
$spellings = Invoke-Discovery -Named @('AADC01', 'aadc01.contoso.com')
Assert-That 'a short name and its FQDN collapse to one server' (
    @($spellings.Rows).Count -eq 1) "rows=$(@($spellings.Rows).Count)"
Assert-That 'and that host is contacted only once' (
    @($spellings.Contacted | Where-Object { $_ -match 'aadc01' }).Count -eq 1) (
    "contacted=[$($spellings.Contacted -join '; ')]")

Write-Host ''
Write-Host 'CONTROLS - genuinely distinct servers must all survive' -ForegroundColor Cyan
Set-Item -Path function:script:Get-ADComputer -Value {
    param($Identity, $Server, $Properties, $ErrorAction)
    # Each name resolves to its own host, which is the ordinary multi-server deployment.
    $short = ([string] $Identity) -replace '\..*$', ''
    [PSCustomObject]@{
        DNSHostName = ('{0}.contoso.com' -f $short.ToLowerInvariant())
        IPv4Address = '10.0.0.5'
        OperatingSystem = 'Windows Server 2022'
        distinguishedName = ('CN={0},OU=Servers,DC=contoso,DC=com' -f $short)
    }
}
$distinct = Invoke-Discovery -Named @('aadc01.contoso.com', 'aadc02.contoso.com')
Assert-That 'CONTROL: two different hosts remain two servers' (
    @($distinct.Rows).Count -eq 2) "rows=$(@($distinct.Rows).Count)"
Assert-That 'CONTROL: and both are contacted' (
    @($distinct.Contacted | Where-Object { $_ -match 'aadc01' }).Count -eq 1 -and
    @($distinct.Contacted | Where-Object { $_ -match 'aadc02' }).Count -eq 1) (
    "contacted=[$($distinct.Contacted -join '; ')]")
$single = Invoke-Discovery -Named @('aadc01.contoso.com')
Assert-That 'CONTROL: one host is still one server' (
    @($single.Rows).Count -eq 1) "rows=$(@($single.Rows).Count)"

Write-Host ''
Write-Host 'The surviving row must still be usable by the code that follows' -ForegroundColor Cyan
# The rows are hashtables and the loop after discovery mutates them ($ec['Domain'] = ...). A
# de-duplication that returned PSCustomObjects instead would break that silently.
$survivor = @($two.Rows)[0]
Assert-That 'the row still carries an FQDN' (
    -not [string]::IsNullOrWhiteSpace([string] $survivor.FQDN)) "fqdn=$($survivor.FQDN)"
Assert-That 'and a Domain, assigned by the loop after discovery' (
    -not [string]::IsNullOrWhiteSpace([string] $survivor.Domain)) "domain=$($survivor.Domain)"

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
