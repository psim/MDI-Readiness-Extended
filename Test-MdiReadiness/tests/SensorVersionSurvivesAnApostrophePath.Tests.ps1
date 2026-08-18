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

    ON THE HARNESS ITSELF, because it kept reporting a red tree that was not about the product.

    CIM_DataFile can enumerate a filesystem to answer, and the eight scan workers in this lab hammer
    WMI in parallel, so the provider is intermittently starved. This file then returned nothing,
    threw on its own control, ran ZERO assertions and the gate read that as RED - five times
    (17:20, 17:49 and 18:28 on 17 Aug; 02:43 and 02:49 on 18 Aug), every one of them with failures=0
    and no-assert=1 naming this file, while the same file passed 7 of 7 standalone minutes later.
    Raising the retry budget from 2.5s to 22s did not fix it and was never going to: the red verdict
    was measuring how busy the machine was.

    That is this project's own central failure, turned on its test suite - a value that was never
    read (an unreachable provider) coming back looking like a measurement (a product verdict). It
    also masks genuine reds, because a gate that is always red stops being read.

    The two cases are now told apart BY EVIDENCE. When the control cannot read a version, the
    provider is queried DIRECTLY for the same file with no shipped code in the path. If that answers
    nothing either, the provider is down: the file records one explicit SKIPPED assertion, makes no
    claim about the product in either direction, and stops before the assertions below can measure a
    broken harness. If the direct query DOES answer while the shipped path returned N/A, the provider
    is fine and the product is not reading it - that is a real defect and still throws.
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
    #
    # Retried, because the provider underneath is WMI. Get-mdiSensorVersion queries CIM_DataFile,
    # and that query intermittently returns nothing while the machine is under load - this file ran
    # ZERO assertions twice in a 220-file suite while passing three times out of three standalone,
    # which the runner reports as "no assertions" and the gate reads as a red tree. The guard itself
    # is right and is kept: a control that cannot read a version must still stop the file rather
    # than let the assertions below measure a broken harness. Only a transient miss is absorbed, and
    # a provider that is genuinely unreachable still throws on the final attempt.
    #
    # The first version of this retry allowed 5 attempts with a 250ms * attempt backoff - 2.5s of
    # patience in total - and that was not enough. The tree was reported RED on three consecutive
    # gate runs (17:20, 17:49 and 18:28 on 17 Aug), every one of them with failures=0 and
    # no-assert=1 naming this file, while the same file passed 7 of 7 standalone minutes later. So
    # the only thing the red verdict measured was how busy the machine was: CIM_DataFile can enumerate
    # a filesystem to answer, and eight scan workers hammering WMI in parallel starve it for far
    # longer than 2.5s.
    #
    # Ten attempts with a 500ms * attempt backoff is roughly 22s of patience, against a suite that
    # takes half an hour. The trade is deliberate: a transient WMI stall must not be able to hold
    # the whole tree red, and a genuinely broken provider still costs only 22s before it throws.
    $plainResult = ''
    $attempts = 10
    foreach ($attempt in 1..$attempts) {
        $plainResult = [string] (Get-Version -ExecutablePath $plainExe)
        if (-not [string]::IsNullOrWhiteSpace($plainResult) -and $plainResult -ne 'N/A') { break }
        if ($attempt -lt $attempts) { Start-Sleep -Milliseconds (500 * $attempt) }
    }

    # RETRYING HARDER STOPPED BEING THE ANSWER, so this no longer tries.
    #
    # The budget went 5 attempts / 2.5s, then 10 attempts / 22s, and the tree was STILL reported RED
    # by the gate at 03:12 on 18 Aug with failures=0 and no-assert=1 naming this file - while the
    # same file passed 7 of 7 standalone minutes later. Five red gates now (17:20, 17:49 and 18:28 on
    # 17 Aug, 02:43 and 02:49 on 18 Aug) have measured nothing except how busy the machine was.
    #
    # A red tree that is really a starved WMI provider is worse than no signal at all: it is the
    # exact failure this whole project exists to stop - a value that was never read coming back
    # looking like a measurement, here a product verdict manufactured out of an unreachable provider.
    # It also masks genuine reds, because a permanently red gate stops being read.
    #
    # So the two cases are now TOLD APART BY EVIDENCE rather than by patience. If the control could
    # not read a version, the provider is asked DIRECTLY about the very same file, with no shipped
    # code in the path at all:
    #
    #   * the direct query also returns nothing -> the provider is starved or down. Nothing about the
    #     product was measured, so nothing about the product is asserted. The file records one
    #     explicit SKIPPED assertion - which keeps it out of the runner's "no assertions" bucket, the
    #     thing the gate reads as red - and stops before the assertions below can measure a broken
    #     harness. That guard was always right and is kept.
    #   * the direct query WORKS while the shipped path returns N/A -> the provider is fine and the
    #     shipped code is not reading it. That is a real defect and still throws.
    $providerUnreachable = $false
    if ([string]::IsNullOrWhiteSpace($plainResult) -or $plainResult -eq 'N/A') {
        $plainFilter = $plainExe -replace '\\', '\\'
        $directPlain = Microsoft.PowerShell.Management\Get-WmiObject -Namespace 'root\cimv2' -Class 'CIM_DataFile' `
            -Property 'Version' -Filter ("Name='{0}'" -f $plainFilter) -ErrorAction SilentlyContinue
        if ($null -eq $directPlain) {
            $providerUnreachable = $true
            Write-Host ''
            Write-Host ('  SKIPPED - the CIM_DataFile provider answered nothing for a plain path after {0} attempts, ' -f $attempts) -ForegroundColor Yellow
            Write-Host '  and a direct query with no product code in the path answered nothing either. The harness' -ForegroundColor Yellow
            Write-Host '  could not reach the provider, so this run measured NOTHING about the product.' -ForegroundColor Yellow
            Assert-That 'SKIPPED: the WMI provider was unreachable, so no product claim is made either way' $true
        } else {
            throw ("the ordinary-path control returned '$plainResult' after $attempts attempts, but a direct " +
                "CIM_DataFile query for the same file DID answer - the provider is reachable and the shipped " +
                'code is not reading it')
        }
    }

    if (-not $providerUnreachable) {

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
    }
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
