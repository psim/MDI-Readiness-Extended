<#
    A WMI or registry field that came back absent, blank or non-numeric is NOT a measurement.

    Win32_OperatingSystem exists on every running Windows machine, so `$null -ne $osInfo` was taken as
    proof that the properties inside the answer were populated. They were then converted with a bare
    `[int]` cast, which fails in two ways that both destroy the distinction between "read" and
    "not read":

      * `[int] $null` and `[int] ''` are a clean ZERO. A domain controller whose ProductType was not
        carried compared `0 -eq 2` and was reported as a MEASURED fact: "Not a domain controller - the
        v3.x sensor only supports domain controllers, keep using the v2.x sensor on this server". That
        verdict is architectural rather than remediable, so it also emptied the server's
        ActionableBlockers and the generated remediation script closed "No remediation is required:
        every automatically fixable check passed." The same zero made an unread BuildNumber fail
        "Windows Server 2019 or later" outright.
      * A non-numeric value THROWS. 'Server 2022' in BuildNumber, or any text in ProductType, aborted
        Get-mdiSensorV3Readiness entirely, so every remaining v3 check on that domain controller - the
        CU level, MDE onboarding, the sensor version - was never evaluated at all.

    The tests assert BEHAVIOUR: the tri-state Status, the Measured flag, membership of UnknownChecks,
    and that the operator-facing Detail never asserts a fact nobody measured. They never inspect the
    script's source text, so restoring the [int] casts turns them red.
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
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'Get-mdiMeasuredInteger separates a value from the absence of one' -ForegroundColor Cyan
Assert-That 'a plain integer reads' ((Get-mdiMeasuredInteger 17763) -eq 17763) "got '$(Get-mdiMeasuredInteger 17763)'"
Assert-That 'an integer as text reads' ((Get-mdiMeasuredInteger '17763') -eq 17763) "got '$(Get-mdiMeasuredInteger '17763')'"
Assert-That 'surrounding whitespace is tolerated' ((Get-mdiMeasuredInteger ' 17763 ') -eq 17763) "got '$(Get-mdiMeasuredInteger ' 17763 ')'"
# Zero is a real reading and must survive - it is only the ABSENCE of a reading that becomes $null.
Assert-That 'a genuine zero is a reading' ((Get-mdiMeasuredInteger 0) -eq 0) "got '$(Get-mdiMeasuredInteger 0)'"
Assert-That '  ...and is distinguishable from no reading' ($null -ne (Get-mdiMeasuredInteger 0)) 'zero must not collapse to $null'
foreach ($bad in @($null, '', '   ', 'N/A', 'Unknown', 'Server 2022', '17763.1', '99999999999999')) {
    $shown = if ($null -eq $bad) { '<null>' } else { "'$bad'" }
    Assert-That "  $shown is not a measurement" ($null -eq (Get-mdiMeasuredInteger $bad)) "got '$(Get-mdiMeasuredInteger $bad)'"
}

# The v3 readiness probe is driven entirely through WMI and the remote registry, both shadowed here.
$script:osProps = @{ Caption = 'Microsoft Windows Server 2022 Standard'; Version = '10.0.20348'; ProductType = 2; BuildNumber = '20348' }
$script:wmiThrows = $false
function global:Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    if ($script:wmiThrows) { throw 'The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)' }
    if ($Class -eq 'Win32_OperatingSystem') { return [PSCustomObject] $script:osProps }
    [PSCustomObject]@{ Name = 'x' }
}
Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
    param($ComputerName, $Key, $Value)
    [PSCustomObject]@{ Value = 99999999; Readable = $true; Error = $null }
}
Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
    param($ComputerName, $ServiceName)
    [PSCustomObject]@{ Readable = $true; Installed = $true; State = 'Running'; StartMode = 'Auto'; Error = $null }
}
Set-Item -Path function:script:Get-mdiSensorVersion -Value {
    param($ComputerName) [PSCustomObject]@{ Installed = $false; Version = $null; Readable = $true }
}

function Get-V3 {
    param($ProductType = 2, $BuildNumber = '20348')
    $script:osProps = @{ Caption = 'Microsoft Windows Server 2022 Standard'; Version = '10.0.20348'; ProductType = $ProductType; BuildNumber = $BuildNumber }
    Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com'
}
function Get-Check {
    param($Result, [string] $Name)
    @($Result.details.Checks | Where-Object { $_.Name -eq $Name })[0]
}

Write-Host 'The controls still behave exactly as before' -ForegroundColor Cyan
$dc = Get-V3 -ProductType 2 -BuildNumber '20348'
$roleDc = Get-Check $dc 'Server is a domain controller'
Assert-That 'a real domain controller passes the role check' ($roleDc.Status -eq $true) "got '$($roleDc.Status)'"
Assert-That '  ...as a measured fact' ($roleDc.Measured -eq $true) "got '$($roleDc.Measured)'"

$member = Get-V3 -ProductType 3 -BuildNumber '20348'
$roleMember = Get-Check $member 'Server is a domain controller'
Assert-That 'a real member server still FAILS the role check' ($roleMember.Status -eq $false) "got '$($roleMember.Status)'"
Assert-That '  ...as a measured fact' ($roleMember.Measured -eq $true) "got '$($roleMember.Measured)'"
Assert-That '  ...and is still told to keep the v2.x sensor' ($roleMember.Detail -like '*keep using the v2.x sensor*') "got '$($roleMember.Detail)'"

$old = Get-V3 -ProductType 2 -BuildNumber '14393'
$osOld = Get-Check $old 'Windows Server 2019 or later'
Assert-That 'a genuinely old build still FAILS the OS check' ($osOld.Status -eq $false) "got '$($osOld.Status)'"
Assert-That '  ...as a measured fact' ($osOld.Measured -eq $true) "got '$($osOld.Measured)'"

Write-Host 'A ProductType that was not carried is unknown, never "not a domain controller"' -ForegroundColor Cyan
foreach ($pt in @($null, '', '   ', 'Server', 'N/A')) {
    $shown = if ($null -eq $pt) { '<null>' } else { "'$pt'" }
    $r = $null
    $threw = $null
    try { $r = Get-V3 -ProductType $pt -BuildNumber '20348' } catch { $threw = $_.Exception.Message }
    # A throw here aborted every remaining check on the server, which is worse than any wrong verdict.
    Assert-That "ProductType $shown does not abort the whole v3 evaluation" ($null -eq $threw) "threw: $threw"
    if ($null -eq $threw) {
        $c = Get-Check $r 'Server is a domain controller'
        Assert-That "  ...and the role check is unmeasured" ($c.Measured -eq $false) "Measured=$($c.Measured)"
        Assert-That "  ...and its status is the tri-state N/A" ([string] $c.Status -eq 'N/A') "got '$($c.Status)'"
        Assert-That "  ...and it never asserts 'Not a domain controller'" ($c.Detail -notlike '*Not a domain controller*') "got '$($c.Detail)'"
        Assert-That "  ...and it is listed as an unknown check" (@($r.details.UnknownChecks) -contains 'Server is a domain controller') "UnknownChecks=$($r.details.UnknownChecks -join ', ')"
    }
}

Write-Host 'A BuildNumber that was not carried is unknown, never "requires Windows Server 2019 or later"' -ForegroundColor Cyan
foreach ($b in @($null, '', '   ', 'Unknown', 'N/A', 'Server 2022', '99999999999999')) {
    $shown = if ($null -eq $b) { '<null>' } else { "'$b'" }
    $r = $null
    $threw = $null
    try { $r = Get-V3 -ProductType 2 -BuildNumber $b } catch { $threw = $_.Exception.Message }
    Assert-That "BuildNumber $shown does not abort the whole v3 evaluation" ($null -eq $threw) "threw: $threw"
    if ($null -eq $threw) {
        $c = Get-Check $r 'Windows Server 2019 or later'
        Assert-That "  ...and the OS check is unmeasured" ($c.Measured -eq $false) "Measured=$($c.Measured)"
        Assert-That "  ...and its status is the tri-state N/A" ([string] $c.Status -eq 'N/A') "got '$($c.Status)'"
        Assert-That "  ...and it never claims the OS is too old" ($c.Detail -notlike '*requires Windows Server 2019 or later*') "got '$($c.Detail)'"
        # The CU check is derived from the OS check, so an unknown build must not produce a measured
        # patch-level verdict either.
        $cu = Get-Check $r 'July 2026 or later cumulative update'
        Assert-That "  ...and the derived CU check is unmeasured too" ($cu.Measured -eq $false) "Measured=$($cu.Measured)"
    }
}

Write-Host 'A UBR the registry did not carry is unknown, never an out-of-date update level' -ForegroundColor Cyan
foreach ($u in @($null, '', 'N/A', 'not-a-number')) {
    $shown = if ($null -eq $u) { '<null>' } else { "'$u'" }
    Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value ([scriptblock]::Create("
        param(`$ComputerName, `$Key, `$Value)
        [PSCustomObject]@{ Value = $(if ($null -eq $u) { '$null' } else { "'$u'" }); Readable = `$true; Error = `$null }
    "))
    $r = Get-V3 -ProductType 2 -BuildNumber '20348'
    $cu = Get-Check $r 'July 2026 or later cumulative update'
    Assert-That "UBR $shown is not a measured failure" ($cu.Status -ne $false) "got '$($cu.Status)'"
    Assert-That "  ...and never tells the operator to install a CU" ($cu.Detail -notlike '*is older than the July 2026 cumulative update*') "got '$($cu.Detail)'"
}
# A REAL revision below the required level must still fail, or the fix has hidden a genuine gap.
Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
    param($ComputerName, $Key, $Value)
    [PSCustomObject]@{ Value = 1; Readable = $true; Error = $null }
}
$stale = Get-V3 -ProductType 2 -BuildNumber '20348'
$staleCu = Get-Check $stale 'July 2026 or later cumulative update'
Assert-That 'a genuinely old UBR still FAILS' ($staleCu.Status -eq $false) "got '$($staleCu.Status)'"
Assert-That '  ...as a measured fact' ($staleCu.Measured -eq $true) "got '$($staleCu.Measured)'"

Write-Host 'An OnboardingState that is present but not a number is unknown, not "not onboarded"' -ForegroundColor Cyan
function Set-Registry {
    param($Value, $Readable = $true)
    $literal = if ($null -eq $Value) { '$null' } else { "'$Value'" }
    Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value ([scriptblock]::Create("
        param(`$ComputerName, `$Key, `$Value)
        if (`$Value -eq 'UBR') { return [PSCustomObject]@{ Value = 99999999; Readable = `$true; Error = `$null } }
        [PSCustomObject]@{ Value = $literal; Readable = `$$Readable; Error = `$null }
    "))
}
foreach ($o in @('N/A', 'Unknown', 'not-a-number', '')) {
    Set-Registry -Value $o
    $r = $null
    $threw = $null
    try { $r = Get-V3 -ProductType 2 -BuildNumber '20348' } catch { $threw = $_.Exception.Message }
    # A throw here aborted the rest of the server's v3 evaluation, which is the worst outcome.
    Assert-That "OnboardingState '$o' does not abort the whole v3 evaluation" ($null -eq $threw) "threw: $threw"
    if ($null -eq $threw) {
        $c = Get-Check $r 'Defender for Endpoint is onboarded'
        Assert-That "  ...and the onboarding check is unmeasured" ($c.Measured -eq $false) "Measured=$($c.Measured) Status=$($c.Status) Detail=$($c.Detail)"
        Assert-That "  ...and its status is the tri-state N/A" ([string] $c.Status -eq 'N/A') "got '$($c.Status)'"
        Assert-That "  ...and it never asserts the server is not onboarded" ($c.Detail -notlike '*is not onboarded to Defender for Endpoint*') "got '$($c.Detail)'"
    }
}

Write-Host '  ...while the real onboarding states are unchanged' -ForegroundColor Cyan
Set-Registry -Value 1
$on = Get-Check (Get-V3 -ProductType 2 -BuildNumber '20348') 'Defender for Endpoint is onboarded'
Assert-That 'OnboardingState = 1 still passes' ($on.Status -eq $true) "got '$($on.Status)' Detail=$($on.Detail)"
Assert-That '  ...as a measured fact' ($on.Measured -eq $true) "got '$($on.Measured)'"

Set-Registry -Value 0
$off = Get-Check (Get-V3 -ProductType 2 -BuildNumber '20348') 'Defender for Endpoint is onboarded'
Assert-That 'OnboardingState = 0 still FAILS' ($off.Status -eq $false) "got '$($off.Status)' Detail=$($off.Detail)"
Assert-That '  ...as a measured fact' ($off.Measured -eq $true) "got '$($off.Measured)'"
Assert-That '  ...and still says the server is not onboarded' ($off.Detail -like '*is not onboarded*') "got '$($off.Detail)'"

Set-Registry -Value $null
$absent = Get-Check (Get-V3 -ProductType 2 -BuildNumber '20348') 'Defender for Endpoint is onboarded'
Assert-That 'an ABSENT OnboardingState is still a measured "not onboarded"' ($absent.Status -eq $false) "got '$($absent.Status)' Detail=$($absent.Detail)"
Assert-That '  ...because absence of the value is itself the answer' ($absent.Detail -like '*is not present under*') "got '$($absent.Detail)'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
