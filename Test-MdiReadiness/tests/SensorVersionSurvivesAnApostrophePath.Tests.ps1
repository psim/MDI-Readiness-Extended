<#
    AN APOSTROPHE IN THE INSTALL PATH ERASED THE SENSOR VERSION.

    Get-mdiSensorVersion asks WMI for the version of the sensor executable:

        select Version from CIM_DataFile where Name='<path>'

    A backslash escapes in WQL, so the separators are doubled. An APOSTROPHE also closes that
    single-quoted literal early, and that escape was missing. The v2 installer explicitly supports a
    caller-chosen InstallationPath, so a company- or person-named folder such as O'Brien is a legal
    place for the sensor to live.

    Measured against the REAL Windows WMI provider with two byte-identical copies of one executable:

        ordinary-custom-path                FUNCTION_RESULT=10.0.26100.8875   PROVIDER_ERRORS=
        supported-custom-path-with-apostrophe
                                            FUNCTION_RESULT=N/A
                                            PROVIDER_ERRORS=Invalid query "select Version from
                                              CIM_DataFile where Name='...\O'Brien\...exe'"
        same path, apostrophe escaped       DIRECT_ESCAPED_QUERY_VERSION=10.0.26100.8875

    Because that call uses SilentlyContinue, the provider's rejection is swallowed and an ordinary run
    simply reports the version as 'N/A'. The server table renders that as "Not tested" and the v3
    migration check loses the measurement - on a server whose sensor is installed, running, and
    carrying a perfectly readable version.

    These assertions build the filter the shipped function builds and hand it to the REAL provider,
    because a claim about escaping is worth nothing as an argument about quoting rules.
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

# A real, versioned executable to point at. Copied rather than invented so the provider has something
# genuine to return a version for.
$source = Join-Path $env:SystemRoot 'System32\notepad.exe'
if (-not (Test-Path $source)) { $source = Join-Path $env:SystemRoot 'explorer.exe' }
if (-not (Test-Path $source)) { throw 'no versioned system executable was available to copy' }
$expectedVersion = [string] (Get-Item $source).VersionInfo.ProductVersion
if ([string]::IsNullOrWhiteSpace($expectedVersion)) {
    $expectedVersion = [string] (Get-Item $source).VersionInfo.FileVersion
}
if ([string]::IsNullOrWhiteSpace($expectedVersion)) { throw 'the source executable carries no readable version' }

$root = Join-Path ([IO.Path]::GetTempPath()) ('mdi-wql-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$plainDir = Join-Path $root 'plain'
$quoteDir = Join-Path $root "O'Brien"
[void] (New-Item -ItemType Directory -Path $plainDir -Force)
[void] (New-Item -ItemType Directory -Path $quoteDir -Force)

try {
    $plainExe = Join-Path $plainDir 'sensor-fixture.exe'
    $quoteExe = Join-Path $quoteDir 'sensor-fixture.exe'
    Copy-Item -LiteralPath $source -Destination $plainExe -Force
    Copy-Item -LiteralPath $source -Destination $quoteExe -Force

    # The shipped function is driven end to end; only the service lookup that tells it WHERE the
    # sensor lives is replaced. The CIM_DataFile query underneath is the real provider.
    $script:servicePath = $null
    Set-Item -Path function:script:Get-WmiObject -Value {
        param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
        if ($Class -eq 'Win32_Service') {
            return [PSCustomObject]@{ Name = 'AATPSensor'; PathName = ('"{0}" -k netsvcs' -f $script:servicePath); State = 'Running' }
        }
        # Everything else - the CIM_DataFile version query - goes to the real provider, with the
        # filter exactly as the shipped function built it.
        $splat = @{ Namespace = $Namespace; Class = $Class; ErrorAction = 'SilentlyContinue' }
        if ($Property) { $splat['Property'] = $Property }
        if ($Filter) { $splat['Filter'] = $Filter }
        Microsoft.PowerShell.Management\Get-WmiObject @splat
    }

    function Get-Version {
        param([string] $ExecutablePath)
        $script:servicePath = $ExecutablePath
        Get-mdiSensorVersion -ComputerName $env:COMPUTERNAME 3>$null
    }

    # The control must genuinely work, or every assertion below is measuring a broken harness.
    $plainResult = [string] (Get-Version -ExecutablePath $plainExe)
    if ([string]::IsNullOrWhiteSpace($plainResult) -or $plainResult -eq 'N/A') {
        throw "the ordinary-path control returned '$plainResult' - the harness is not reaching the real provider"
    }

    Write-Host 'A legal install path containing an apostrophe must still yield the version' -ForegroundColor Cyan
    $quoteResult = [string] (Get-Version -ExecutablePath $quoteExe)
    Assert-That 'the apostrophe path returns a version rather than N/A' (
        $quoteResult -ne 'N/A' -and -not [string]::IsNullOrWhiteSpace($quoteResult)) "result=$quoteResult"
    Assert-That 'and it is the SAME version as the identical copy in a plain path' (
        $quoteResult -eq $plainResult) "apostrophe=$quoteResult plain=$plainResult"

    Write-Host ''
    Write-Host 'CONTROL - the ordinary path still works' -ForegroundColor Cyan
    Assert-That 'CONTROL: a path with no apostrophe returns the version' (
        $plainResult -ne 'N/A' -and -not [string]::IsNullOrWhiteSpace($plainResult)) "result=$plainResult"

    Write-Host ''
    Write-Host 'The escaping itself, against the real provider' -ForegroundColor Cyan
    # Both escapes are needed and their ORDER matters: escaping the apostrophe first would introduce a
    # backslash that the backslash pass would then double, breaking the escape it had just added.
    $escaped = ($quoteExe -replace '\\', '\\') -replace "'", "\'"
    $direct = Microsoft.PowerShell.Management\Get-WmiObject -Namespace 'root\cimv2' -Class 'CIM_DataFile' `
        -Property 'Version' -Filter ("Name='{0}'" -f $escaped) -ErrorAction SilentlyContinue
    Assert-That 'the escaped filter is accepted by the provider' (
        $null -ne $direct) "filter=Name='$escaped'"

    # And the unescaped form must genuinely be rejected, or the fix is guarding against nothing.
    $unescaped = $quoteExe -replace '\\', '\\'
    $rejected = $false
    try {
        $null = Microsoft.PowerShell.Management\Get-WmiObject -Namespace 'root\cimv2' -Class 'CIM_DataFile' `
            -Property 'Version' -Filter ("Name='{0}'" -f $unescaped) -ErrorAction Stop
    } catch { $rejected = $true }
    Assert-That 'CONTROL: the unescaped filter IS rejected, so the escape is load-bearing' $rejected (
        "filter=Name='$unescaped' was accepted")

    # A backslash must still be doubled - the escape that was already there must not be lost.
    Assert-That 'backslashes are still doubled' (
        $escaped -match '\\\\') "escaped=$escaped"
    Assert-That 'and the apostrophe is escaped rather than doubled' (
        $escaped -match "\\'" -and $escaped -notmatch "''") "escaped=$escaped"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
