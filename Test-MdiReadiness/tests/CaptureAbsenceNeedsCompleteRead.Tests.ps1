<#
    ABSENCE WAS CLAIMED OVER PRODUCTS THAT WERE NEVER READ.

    Get-mdiCaptureComponent decides whether Npcap or WinPcap is installed by enumerating the
    Uninstall registry key in both registry views. It returns the marker 'N/A' when the registry
    could not be read, and the sensor v3 check turns that into "Not tested" rather than a pass -
    because "no driver is installed" and "the registry could not be read" are different facts with
    the same shape.

    The readable flag was set by opening the Uninstall ROOT. Opening the root says nothing about the
    products underneath it. Access denied on each enumerated product was swallowed into
    Write-Verbose - a stream a default run never shows - and the resulting EMPTY list was returned
    as a measurement. The v3 check then reported:

        Status = True, Measured = True, "No packet capture driver installed"

    green, measured, and absent from UnknownChecks, over a registry where nothing was examined at
    all. Access denied on those subkeys is the ORDINARY case for the non-admin caller this tool is
    documented to support, and this check gates an in-place sensor v3 migration: the one product
    that could not be read is exactly the one that might be Npcap.

    A denied ENUMERATION reached the same false pass through the outer per-view catch.

    A POSITIVE detection is deliberately still reported even when another product could not be read:
    finding Npcap does not become less true because something else was unreadable. Only the claim of
    ABSENCE requires a complete read. The controls below pin both halves of that.
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

$script:uninstallPath = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
$script:mode = 'clean'
$script:productOpens = 0
$script:rootOpens = 0

function New-FakeProductKey {
    param([string] $DisplayName, [string] $Version)
    $k = Microsoft.PowerShell.Utility\New-Object PSObject
    $k | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param($n)
        if ($n -eq 'DisplayName') { return $this.MdiName }
        if ($n -eq 'DisplayVersion') { return $this.MdiVersion }
        $null
    } -Force
    $k | Add-Member -MemberType NoteProperty -Name MdiName -Value $DisplayName -Force
    $k | Add-Member -MemberType NoteProperty -Name MdiVersion -Value $Version -Force
    $k | Add-Member -MemberType ScriptMethod -Name Close -Value { } -Force
    $k
}

try {
    Update-TypeData -TypeName Microsoft.Win32.RegistryKey -MemberType ScriptMethod -MemberName OpenSubKey -Value {
        param($name)
        if ([string] $name -eq $script:uninstallPath) {
            $script:rootOpens++
            if ($script:mode -eq 'denyRoot') { throw [UnauthorizedAccessException]::new('TEST: uninstall root') }
            return $this.PSBase.OpenSubKey($name)
        }
        if ([string] $name -like ($script:uninstallPath + '\*')) {
            $script:productOpens++
            $leaf = ([string] $name).Split('\')[-1]
            switch ($script:mode) {
                'denyProducts'     { throw [UnauthorizedAccessException]::new('TEST: product subkey') }
                'foundWithFailure' {
                    if ($leaf -eq 'UNREADABLE') { throw [UnauthorizedAccessException]::new('TEST: product subkey') }
                    return (New-FakeProductKey -DisplayName 'Npcap' -Version '1.79')
                }
                default            { return (New-FakeProductKey -DisplayName 'Contoso Agent' -Version '2.1') }
            }
        }
        $this.PSBase.OpenSubKey($name)
    } -Force

    Update-TypeData -TypeName Microsoft.Win32.RegistryKey -MemberType ScriptMethod -MemberName GetSubKeyNames -Value {
        if ([string] $this.Name -like '*\Uninstall') {
            if ($script:mode -eq 'denyEnum') { throw [UnauthorizedAccessException]::new('TEST: enumeration') }
            if ($script:mode -eq 'foundWithFailure') { return @('UNREADABLE', 'PRESENT') }
            if ($script:mode -eq 'empty') { return @() }
            return @('TEST_PRODUCT_A', 'TEST_PRODUCT_B')
        }
        $this.PSBase.GetSubKeyNames()
    } -Force

    # Enough of the surrounding v3 collection to reach the Npcap check without a live estate.
    Set-Item -Path function:script:Get-WmiObject -Value {
        param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
        [PSCustomObject]@{ Version = '10.0.20348'; Caption = 'Windows Server 2022'; ProductType = 2; BuildNumber = '20348' }
    }
    Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
        param($ComputerName, $Key, $Value)
        [PSCustomObject]@{ Readable = $true; Value = 99999; Error = $null }
    }
    Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
        param($ComputerName, $ServiceName)
        $svc = if ($ServiceName -eq 'Sense') { [PSCustomObject]@{ State = 'Running'; StartMode = 'Auto' } } else { $null }
        [PSCustomObject]@{ Readable = $true; Service = $svc; Error = $null }
    }
    # The stubs must actually be in force, or every conclusion below is drawn from the real machine.
    if ((Get-WmiObject -ComputerName x -Class x).ProductType -ne 2) { throw 'Get-WmiObject stub did not take effect' }
    if ((Get-mdiServiceStateResult -ComputerName x -ServiceName Sense).Service.State -ne 'Running') { throw 'service stub did not take effect' }

    function Get-CaptureCheck {
        $r = Get-mdiSensorV3Readiness -ComputerName $env:COMPUTERNAME
        @($r.details.Checks | Where-Object { $_.Name -eq 'Npcap / WinPcap removed' })[0]
    }

    # ==============================================================================================
    Write-Host 'A denied product subkey must not become a measured "nothing installed"' -ForegroundColor Cyan
    $script:mode = 'denyProducts'; $script:rootOpens = 0; $script:productOpens = 0
    $denied = [string] (Get-mdiCaptureComponent -ComputerName $env:COMPUTERNAME)
    Assert-That 'the denial boundary actually executed' ($script:rootOpens -gt 0 -and $script:productOpens -gt 0) (
        "rootOpens=$($script:rootOpens) productOpens=$($script:productOpens)")
    Assert-That 'a denied product read is reported as unmeasured' ($denied -eq 'N/A') "capture='$denied'"

    $script:mode = 'denyProducts'
    $chk = Get-CaptureCheck
    Assert-That 'the v3 check is not a pass' ($chk.Status -ne $true) "status=$($chk.Status)"
    Assert-That 'the v3 check reports N/A' ([string] $chk.Status -eq 'N/A') "status=$($chk.Status)"
    Assert-That 'the v3 check is not marked measured' ($chk.Measured -ne $true) "measured=$($chk.Measured)"
    Assert-That 'the detail says it was not tested' ([string] $chk.Detail -like 'Not tested*') "detail=$($chk.Detail)"
    Assert-That 'the detail does not claim nothing is installed' (
        [string] $chk.Detail -ne 'No packet capture driver installed'
    ) "detail=$($chk.Detail)"

    Write-Host ''
    Write-Host 'A denied enumeration must not become a measured "nothing installed"' -ForegroundColor Cyan
    $script:mode = 'denyEnum'
    $enumDenied = [string] (Get-mdiCaptureComponent -ComputerName $env:COMPUTERNAME)
    Assert-That 'a denied enumeration is reported as unmeasured' ($enumDenied -eq 'N/A') "capture='$enumDenied'"

    Write-Host ''
    Write-Host 'CONTROLS - a complete read must still measure, and a detection must still stand' -ForegroundColor Cyan

    # CONTROL: a fully readable registry with no capture driver is a REAL measurement and must pass.
    $script:mode = 'clean'
    $clean = [string] (Get-mdiCaptureComponent -ComputerName $env:COMPUTERNAME)
    Assert-That 'CONTROL: a complete read with no driver returns an empty result' ($clean -eq '') "capture='$clean'"
    $script:mode = 'clean'
    $cleanChk = Get-CaptureCheck
    Assert-That 'CONTROL: a complete read is a measured pass' (
        $cleanChk.Status -eq $true -and $cleanChk.Measured -eq $true
    ) "status=$($cleanChk.Status) measured=$($cleanChk.Measured)"
    Assert-That 'CONTROL: a complete read still says no driver is installed' (
        [string] $cleanChk.Detail -eq 'No packet capture driver installed'
    ) "detail=$($cleanChk.Detail)"

    # CONTROL: an empty Uninstall key is a real measurement too - nothing failed, nothing is there.
    $script:mode = 'empty'
    $empty = [string] (Get-mdiCaptureComponent -ComputerName $env:COMPUTERNAME)
    Assert-That 'CONTROL: an empty product list is a measurement, not an unknown' ($empty -eq '') "capture='$empty'"

    # CONTROL: a POSITIVE detection survives an unreadable sibling - absence needs a complete read,
    # presence does not.
    $script:mode = 'foundWithFailure'
    $found = [string] (Get-mdiCaptureComponent -ComputerName $env:COMPUTERNAME)
    Assert-That 'CONTROL: Npcap is still reported when another product is unreadable' (
        $found -like '*Npcap*'
    ) "capture='$found'"
    Assert-That 'CONTROL: a detection is not downgraded to unknown' ($found -ne 'N/A') "capture='$found'"
    $script:mode = 'foundWithFailure'
    $foundChk = Get-CaptureCheck
    Assert-That 'CONTROL: a detected driver is a measured failure' (
        $foundChk.Status -eq $false -and $foundChk.Measured -eq $true
    ) "status=$($foundChk.Status) measured=$($foundChk.Measured)"

    # CONTROL: the pre-existing "neither view would open" path is unchanged.
    $script:mode = 'denyRoot'
    $rootDenied = [string] (Get-mdiCaptureComponent -ComputerName $env:COMPUTERNAME)
    Assert-That 'CONTROL: an unreadable root is still unmeasured' ($rootDenied -eq 'N/A') "capture='$rootDenied'"

} finally {
    Remove-TypeData -TypeName Microsoft.Win32.RegistryKey -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
