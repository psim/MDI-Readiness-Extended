<#
    A REGISTRY VALUE'S TYPE LEAKED INTO THE REPORT AS A .NET TYPE NAME.

    Get-mdiCaptureComponent reads DisplayName and DisplayVersion out of the Uninstall key with
    RegistryKey.GetValue, which returns [object]. The runtime type follows the value's KIND:
    REG_SZ and REG_EXPAND_SZ arrive as [string], REG_DWORD as [int], REG_QWORD as [long] - but
    REG_MULTI_SZ arrives as [string[]] and REG_BINARY as [byte[]].

    Both values were then interpolated straight into '{0} ({1})'. PowerShell's format operator
    renders an ARRAY operand as its type name rather than its contents, so the evidence string
    became 'System.String[] (1.79)' or 'Npcap (System.Byte[])'.

    That string is not decoration. Get-mdiSensorV3Readiness puts it into the detail of the
    'Npcap / WinPcap removed' check, so the operator was told:

        "System.String[] (1.79) is installed. It was used by the v2.x sensor and is not required
         by v3.x - remove it after the migration completes"

    The verdict either side of it was correct - a driver IS installed and the check DID fail -
    which is exactly why this survives: nothing goes red, and the one field that says WHICH
    driver to remove has been replaced by a .NET type name. Measured against this project's
    standing rule that a report must never present something it did not read as though it had,
    a type name in place of a product name is the same failure wearing different clothes.

    Behavioural, not textual: every assertion calls the shipped function with a registry whose
    values carry the awkward TYPES and inspects what comes back, so the test still holds if the
    formatting is rewritten in any way that keeps the data.

    The multi-element case is pinned deliberately. The tempting one-line repair - take [0], or
    cast the operand with [string] - passes a single-element REG_MULTI_SZ and silently discards
    every value after the first. Data the registry carried and the reader successfully read must
    not be dropped on the way to the page, so both elements are required to survive.
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
$script:productOpens = 0
# Get-mdiCaptureComponent deliberately scans BOTH registry views, so a fake product offered to
# every view would be found twice and the exact-string controls below would be measuring the
# harness rather than the code. It is listed in the first view only.
$script:productListed = $false

<#
    The fake product key is a COMPILED class, not a PSObject with a ScriptMethod, and that is
    load-bearing rather than a style choice.

    A PowerShell ScriptMethod re-types its return value: handed a [string[]] it hands back a
    [System.Object[]], and the format operator renders those two types DIFFERENTLY - an
    [object[]] joins its elements, a [string[]] prints as 'System.String[]'. A ScriptMethod fake
    therefore reports a clean result for a registry that the real API would have rendered as a
    type name, and the whole defect this file exists for becomes invisible. Measured directly
    against a real REG_MULTI_SZ value written into HKCU:

        RegistryKey.GetValue      -> System.String[]   '{0} ({1})' -f ... -> 'System.String[] (1.79)'
        PSObject ScriptMethod     -> System.Object[]   '{0} ({1})' -f ... -> 'Npcap OEM edition (1.79)'

    Microsoft.Win32.RegistryKey.GetValue is declared to return [object], so only a compiled
    method with that same signature reproduces the boundary faithfully.
#>
if (-not ('MdiCaptureFakeProductKey' -as [type])) {
    Add-Type -TypeDefinition @'
public class MdiCaptureFakeProductKey {
    public static object NameValue;
    public static object VersionValue;
    public object GetValue(string name) {
        if (name == "DisplayName") { return NameValue; }
        if (name == "DisplayVersion") { return VersionValue; }
        return null;
    }
    public void Close() { }
}
'@
}

# The value pair the fake Uninstall product hands back. Set per case, so one harness covers
# every registry KIND without changing the code under test. A plain variable preserves the
# exact runtime type; it is pushed into the compiled fake at the start of each measurement.
$script:fakeName = 'Npcap'
$script:fakeVersion = '1.79'

# The fake must hand back the EXACT runtime type it was given, or every conclusion drawn below
# is drawn from the harness rather than from the shipped reader.
[MdiCaptureFakeProductKey]::NameValue = [string[]]@('a', 'b')
[MdiCaptureFakeProductKey]::VersionValue = [byte[]]@(1)
$probe = (New-Object MdiCaptureFakeProductKey)
if ($probe.GetValue('DisplayName').GetType().FullName -ne 'System.String[]') {
    throw ('the fake key re-typed REG_MULTI_SZ to {0} - it cannot reproduce the registry boundary' -f $probe.GetValue('DisplayName').GetType().FullName)
}
if ($probe.GetValue('DisplayVersion').GetType().FullName -ne 'System.Byte[]') {
    throw 'the fake key re-typed REG_BINARY - it cannot reproduce the registry boundary'
}

function New-FakeProductKey {
    New-Object MdiCaptureFakeProductKey
}

function Get-Capture {
    $script:productOpens = 0
    $script:productListed = $false
    [MdiCaptureFakeProductKey]::NameValue = $script:fakeName
    [MdiCaptureFakeProductKey]::VersionValue = $script:fakeVersion
    $r = [string] (Get-mdiCaptureComponent -ComputerName $env:COMPUTERNAME)
    if ($script:productOpens -ne 1) { throw "the fake Uninstall product was opened $($script:productOpens) time(s), expected exactly 1 - the probe measured nothing" }
    $r
}

try {
    Update-TypeData -TypeName Microsoft.Win32.RegistryKey -MemberType ScriptMethod -MemberName OpenSubKey -Value {
        param($name)
        if ([string] $name -eq $script:uninstallPath) { return $this.PSBase.OpenSubKey($name) }
        if ([string] $name -like ($script:uninstallPath + '\*')) {
            $script:productOpens++
            return (New-FakeProductKey)
        }
        $this.PSBase.OpenSubKey($name)
    } -Force

    Update-TypeData -TypeName Microsoft.Win32.RegistryKey -MemberType ScriptMethod -MemberName GetSubKeyNames -Value {
        if ([string] $this.Name -like '*\Uninstall') {
            if ($script:productListed) { return @() }
            $script:productListed = $true
            return @('TEST_PRODUCT')
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

    function Get-CaptureDetail {
        $script:productOpens = 0
        $script:productListed = $false
        [MdiCaptureFakeProductKey]::NameValue = $script:fakeName
        [MdiCaptureFakeProductKey]::VersionValue = $script:fakeVersion
        $r = Get-mdiSensorV3Readiness -ComputerName $env:COMPUTERNAME
        if ($script:productOpens -ne 1) { throw "the fake Uninstall product was opened $($script:productOpens) time(s), expected exactly 1" }
        [string] (@($r.details.Checks | Where-Object { $_.Name -eq 'Npcap / WinPcap removed' })[0].Detail)
    }

    # ==============================================================================================
    Write-Host 'A REG_MULTI_SZ DisplayName must reach the report as data, not as a type name' -ForegroundColor Cyan
    $script:fakeName = [string[]]@('Npcap', 'OEM edition')
    $script:fakeVersion = '1.79'
    $multi = Get-Capture
    Assert-That 'the driver is still detected' ($multi -like '*Npcap*') "capture='$multi'"
    Assert-That 'no .NET type name reaches the result' ($multi -notmatch 'System\.\w+\[\]') "capture='$multi'"
    Assert-That 'the version that was read is still present' ($multi -like '*1.79*') "capture='$multi'"
    # The multi-argument trap: a fix that takes only the first element passes every assertion above.
    Assert-That 'EVERY element the registry carried survives, not just the first' (
        $multi -like '*OEM edition*'
    ) "capture='$multi'"

    Write-Host ''
    Write-Host 'A REG_BINARY / REG_MULTI_SZ DisplayVersion must not become a type name either' -ForegroundColor Cyan
    $script:fakeName = 'WinPcap'
    $script:fakeVersion = [byte[]]@(4, 1, 3)
    $binVer = Get-Capture
    Assert-That 'a REG_BINARY version leaves no type name' ($binVer -notmatch 'System\.\w+\[\]') "capture='$binVer'"
    Assert-That 'the product is still named' ($binVer -like '*WinPcap*') "capture='$binVer'"

    $script:fakeName = 'Npcap'
    $script:fakeVersion = [string[]]@('1.79', 'x64')
    $multiVer = Get-Capture
    Assert-That 'a REG_MULTI_SZ version leaves no type name' ($multiVer -notmatch 'System\.\w+\[\]') "capture='$multiVer'"
    Assert-That 'both version elements survive' (
        $multiVer -like '*1.79*' -and $multiVer -like '*x64*'
    ) "capture='$multiVer'"

    # An EMPTY REG_MULTI_SZ is the degenerate end of the same class: an array with nothing in it.
    $script:fakeName = 'Npcap'
    $script:fakeVersion = [string[]]@()
    $emptyVer = Get-Capture
    Assert-That 'an empty REG_MULTI_SZ version leaves no type name' (
        $emptyVer -notmatch 'System\.\w+\[\]'
    ) "capture='$emptyVer'"
    Assert-That 'an empty version does not lose the detection' ($emptyVer -like '*Npcap*') "capture='$emptyVer'"
    Assert-That 'an empty version is not downgraded to unmeasured' ($emptyVer -ne 'N/A') "capture='$emptyVer'"

    Write-Host ''
    Write-Host 'The operator-facing remediation detail must not carry a type name' -ForegroundColor Cyan
    $script:fakeName = [string[]]@('Npcap', 'OEM edition')
    $script:fakeVersion = [byte[]]@(4, 1, 3)
    $detail = Get-CaptureDetail
    Assert-That 'the v3 detail still reports the driver' ($detail -like '*Npcap*') "detail='$detail'"
    Assert-That 'the v3 detail contains no .NET type name' (
        $detail -notmatch 'System\.\w+\[\]'
    ) "detail='$detail'"
    Assert-That 'the v3 detail still tells the operator to remove it' (
        $detail -like '*remove it after the migration completes*'
    ) "detail='$detail'"

    Write-Host ''
    Write-Host 'CONTROLS - the ordinary registry types must be completely unchanged' -ForegroundColor Cyan

    # CONTROL: the overwhelmingly common case. Two REG_SZ values, rendered exactly as before.
    $script:fakeName = 'Npcap'
    $script:fakeVersion = '1.79'
    $plain = Get-Capture
    Assert-That 'CONTROL: two REG_SZ values render unchanged' ($plain -eq 'Npcap (1.79)') "capture='$plain'"

    # CONTROL: REG_DWORD and REG_QWORD are scalars and must not be mangled into a list.
    $script:fakeVersion = [int] 179
    $dword = Get-Capture
    Assert-That 'CONTROL: a REG_DWORD version renders as its number' ($dword -eq 'Npcap (179)') "capture='$dword'"
    $script:fakeVersion = [long] 4294967296
    $qword = Get-Capture
    Assert-That 'CONTROL: a REG_QWORD version renders as its number' ($qword -eq 'Npcap (4294967296)') "capture='$qword'"

    # CONTROL: an absent DisplayVersion is not an error and must not invent one.
    $script:fakeVersion = $null
    $noVer = Get-Capture
    Assert-That 'CONTROL: an absent version still names the product' ($noVer -like 'Npcap*') "capture='$noVer'"
    Assert-That 'CONTROL: an absent version prints no type name' ($noVer -notmatch 'System\.') "capture='$noVer'"

    # CONTROL: a non-capture product must still not be reported, whatever its value types are.
    $script:fakeName = [string[]]@('Contoso Agent', 'Standard')
    $script:fakeVersion = '2.1'
    $other = Get-Capture
    Assert-That 'CONTROL: an unrelated product is still not reported' ($other -eq '') "capture='$other'"

    # CONTROL: the match is still case-insensitive across a multi-valued name.
    $script:fakeName = [string[]]@('Contoso', 'NPCAP OEM')
    $script:fakeVersion = '9'
    $late = Get-Capture
    Assert-That 'CONTROL: a match in a later element is still detected' ($late -like '*NPCAP*') "capture='$late'"

    Write-Host ''
    Write-Host 'The converter itself, exercised directly across every registry KIND' -ForegroundColor Cyan
    Assert-That 'REG_SZ round-trips'            ((ConvertTo-mdiRegistryValueText -Value 'Npcap') -eq 'Npcap')
    Assert-That 'a null value becomes empty'    ((ConvertTo-mdiRegistryValueText -Value $null) -eq '')
    Assert-That 'REG_DWORD becomes its number'  ((ConvertTo-mdiRegistryValueText -Value ([int] 179)) -eq '179')
    Assert-That 'REG_MULTI_SZ keeps every element' (
        (ConvertTo-mdiRegistryValueText -Value ([string[]]@('a', 'b', 'c'))) -match 'a.*b.*c'
    ) ("got='{0}'" -f (ConvertTo-mdiRegistryValueText -Value ([string[]]@('a', 'b', 'c'))))
    # A string is IEnumerable in .NET; splitting it into characters would be the obvious way to
    # get this wrong, so the single-value case is pinned explicitly.
    Assert-That 'a string is one value, not a sequence of characters' (
        (ConvertTo-mdiRegistryValueText -Value 'abc') -eq 'abc'
    ) ("got='{0}'" -f (ConvertTo-mdiRegistryValueText -Value 'abc'))

} finally {
    Remove-TypeData -TypeName Microsoft.Win32.RegistryKey -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
