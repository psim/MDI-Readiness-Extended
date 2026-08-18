<#
    Output read back from a server must reach the JSON document as TEXT.

    Invoke-mdiRemoteCommand reads the redirected output file with Get-Content, and every line
    Get-Content returns is a System.String DECORATED with the provider note properties PSPath,
    PSParentPath, PSChildName, PSDrive, PSProvider, ReadCount and Length. ConvertTo-Json serialises
    note properties, and PSProvider is a ProviderInfo whose Drives -> PSDriveInfo -> Provider ->
    Drives graph is cyclic. Callers store that value verbatim as a check's `details` -
    Get-mdiPowerScheme does, on both of its measured branches - so it went straight into the -AsJson
    document and into mdi-<domain>.json.

    Measured on the shipped code, ONE line of powercfg /getactivescheme output at the nesting the
    report actually uses (report.DomainControllers[0].Details.PowerSettingsDetails, -Depth 7):

        359,045 characters of JSON for one check on one server, opening
        {"PowerSettingsDetails":{"value":"Power Scheme GUID: 8c5e7fda-...","PSPath":
         "Microsoft.PowerShell.Core\FileSystem::\\<DC>\C$\WINDOWS\TEMP\mdi-<guid>.tmp",...

    and in isolation 44,738,380 characters at -Depth 6, then OutOfMemoryException at -Depth 7 - so
    the same value one level shallower kills the run outright after every check has succeeded, with
    no document written.

    Three things break for a machine consumer:

      * TYPE DRIFT. `details` is a JSON string when the check could not be read (the not-measured
        branches build their text with -f) and a JSON OBJECT when it was read. The same field has a
        different type on a healthy server than on a broken one, and the text hides under `.value`.
      * SIZE. ~350 KB of noise per affected check per server.
      * DISCLOSURE. The payload is the scanning host's own provider and drive metadata, including the
        admin-share path and temp file name used on the domain controller.

    These tests drive the REAL Invoke-mdiRemoteCommand down its REAL SMB read path - only the WMI
    process start is stubbed - then serialise with the shipped -Depth 7 and assert on the PARSED
    values, because that is what a consumer sees. Reverting the normalisation turns them red.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

# The file actually loaded is identified, never assumed. A stale shadow copy beside the tests once
# produced results that did not describe the shipped script at all; a NOTE is printed rather than a
# throw so the run still reports what it measured.
$loaded = (Resolve-Path -LiteralPath $target).ProviderPath
$canonical = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
Write-Host ("  LOADED  {0}" -f $loaded) -ForegroundColor DarkGray
Write-Host ("  SHA256  {0}" -f (Get-FileHash -LiteralPath $loaded -Algorithm SHA256).Hash) -ForegroundColor DarkGray
# Run-Suite.ps1 - and the publisher's release gate - copy every test into a FLAT isolated directory
# whose PARENT holds no product script. Resolving the canonical path unconditionally threw there and
# killed this file before a single assertion ran, which the runner reports as "no assertions": a dead
# test that reads exactly like a quiet one. The canonical copy is optional context for the drift
# NOTE below, never a precondition for measuring anything.
if ((Test-Path -LiteralPath $canonical) -and (Resolve-Path -LiteralPath $canonical).ProviderPath -ne $loaded) {
    $a = (Get-FileHash -LiteralPath $loaded -Algorithm SHA256).Hash
    $b = (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash
    if ($a -ne $b) { Write-Host "  NOTE  the loaded file differs from $canonical ($a vs $b)" -ForegroundColor Yellow }
}

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# --- harness -------------------------------------------------------------------------------------
# The real function is exercised, not a copy. Only the WMI process start is replaced: the stub writes
# the payload to exactly the path the shipped ArgumentList redirects to, and the real Get-Content read
# at the SMB path then runs against it. The UNC rewrite in the shipped code fires only for a path
# shaped "<letter>:...", so a PROVIDER-QUALIFIED folder is passed through unchanged and the read
# happens locally - nothing on the network is touched.
$script:scratch = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remoteout-{0}' -f ([guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $script:scratch -Force | Out-Null
$script:providerFolder = 'FileSystem::' + $script:scratch
$script:payload = ''
$script:startSucceeds = $true

Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) $script:providerFolder }
Set-Item -Path function:script:Invoke-WmiMethod -Value {
    param($ComputerName, $Namespace, $Class, $Name, $ArgumentList, $ErrorAction)
    if (-not $script:startSucceeds) { return [PSCustomObject]@{ ReturnValue = 2; ProcessId = 0 } }
    $m = [regex]::Match([string] $ArgumentList, '>\s*(?<f>.+?)\s+2>&1\s*$')
    if ($m.Success) {
        $physical = ([string] $m.Groups['f'].Value) -replace '^FileSystem::', ''
        [IO.File]::WriteAllText($physical, $script:payload)
    }
    [PSCustomObject]@{ ReturnValue = 0; ProcessId = 4242 }
}
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    $null
}

function Get-EtsPropertyNames {
    param($Value)
    if ($null -eq $Value) { return @() }
    # Length is the intrinsic String property; every other name here is provider decoration.
    @($Value.PSObject.Properties.Name | Where-Object { $_ -ne 'Length' })
}

# ConvertTo-Json against a decorated value can throw OutOfMemoryException outright - that is one of
# the outcomes under test - so every serialisation here reports the failure as a value instead of
# letting it abort the run.
function ConvertTo-SafeJson {
    param($Value, [int] $Depth = 7)
    try { @{ v = $Value } | ConvertTo-Json -Depth $Depth -Compress } catch { '<<ConvertTo-Json threw {0}>>' -f $_.Exception.GetType().Name }
}

try {

    Write-Host 'A single line of remote output is a JSON string, not an object' -ForegroundColor Cyan
    $script:payload = "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)`r`n"
    $one = Invoke-mdiRemoteCommand -ComputerName 'dc1.contoso.com' -CommandLine 'cmd.exe /c powercfg.exe /getactivescheme'
    Assert-That 'the read succeeded' ($null -ne $one) 'got $null'
    Assert-That '  ...and carries no provider decoration' ((Get-EtsPropertyNames $one).Count -eq 0) `
        "got [$((Get-EtsPropertyNames $one) -join ',')]"
    # -Depth 4, not 7: with the decoration present the bare value at -Depth 7 does not merely grow, it
    # throws OutOfMemoryException after several minutes. -Depth 4 already renders the whole difference
    # (a JSON string of 83 characters against an object of 359,005) and does so in milliseconds either
    # way. The shipped -Depth 7 is covered below at the nesting the report actually uses.
    $json = ConvertTo-SafeJson -Value $one -Depth 4
    Assert-That '  ...and serialises as a JSON string' ($json -match '^\{"v":"') "got: $($json.Substring(0, [Math]::Min(200, $json.Length)))"
    Assert-That '  ...with no PSPath / PSProvider anywhere in the document' `
        (($json -notmatch 'PSPath|PSProvider|PSParentPath|PSDrive') -and ($json -notmatch 'ConvertTo-Json threw')) `
        "document length $($json.Length): $($json.Substring(0, [Math]::Min(120, $json.Length)))"
    $revived = try { ($json | ConvertFrom-Json).v } catch { $null }
    Assert-That '  ...and revives as a string' ($revived -is [string]) `
        "got $(if ($null -eq $revived) { '<null>' } else { $revived.GetType().FullName })"
    Assert-That '  ...with the text unchanged' ($revived -ceq 'Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)') "got '$revived'"

    Write-Host 'The document does not explode in size' -ForegroundColor Cyan
    # Serialised where the report actually puts it - report.DomainControllers[i].Details.<Check>Details -
    # so the depth budget is the real one. The decorated form measured 359,045 characters here for this
    # same single line, and 383,361 at -Depth 4 with the value one level below the root. An
    # OutOfMemoryException is caught and recorded as a failure rather than being allowed to abort the
    # run, because "ConvertTo-Json died" is the worst outcome this guards against, not an excuse to
    # stop testing.
    function Measure-PublishedLength {
        param($Value, [int] $Depth)
        $nested = @{
            DomainControllers = @(
                [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Details = [PSCustomObject]@{ PowerSettingsDetails = $Value } }
            )
        }
        try { ($nested | ConvertTo-Json -Depth $Depth -Compress).Length } catch { -1 }
    }
    foreach ($d in 4, 5, 6, 7) {
        $len = Measure-PublishedLength -Value $one -Depth $d
        Assert-That "  one line published at -Depth $d stays under 4 KB" ($len -ge 0 -and $len -lt 4096) `
            $(if ($len -lt 0) { 'ConvertTo-Json threw' } else { "got $len characters" })
    }
    $shallow = try { (@{ v = $one } | ConvertTo-Json -Depth 4 -Compress).Length } catch { -1 }
    Assert-That '  the bare value at -Depth 4 stays under 1 KB' ($shallow -ge 0 -and $shallow -lt 1024) `
        $(if ($shallow -lt 0) { 'ConvertTo-Json threw' } else { "got $shallow characters" })

    Write-Host 'The array-of-lines shape callers parse is preserved' -ForegroundColor Cyan
    # Get-mdiPowerScheme iterates the lines and Get-mdiAdvancedAuditing tests $output.Count -gt 1, so
    # collapsing the array would break both.
    $script:payload = "line one`r`nline two`r`nline three`r`n"
    $many = Invoke-mdiRemoteCommand -ComputerName 'dc1.contoso.com' -CommandLine 'cmd.exe /c something'
    Assert-That 'three lines come back as three items' (@($many).Count -eq 3) "got $(@($many).Count)"
    Assert-That '  ...each of them a plain string' (@($many | Where-Object { (Get-EtsPropertyNames $_).Count -ne 0 }).Count -eq 0) `
        "decorated: $(@($many | Where-Object { (Get-EtsPropertyNames $_).Count -ne 0 }).Count)"
    $manyJson = ConvertTo-SafeJson -Value $many -Depth 4
    Assert-That '  ...serialising as an array of strings' ($manyJson -eq '{"v":["line one","line two","line three"]}') "got: $($manyJson.Substring(0, [Math]::Min(200, $manyJson.Length)))"

    Write-Host 'An empty read is still empty, and a failed start is still $null' -ForegroundColor Cyan
    $script:payload = ''
    $empty = Invoke-mdiRemoteCommand -ComputerName 'dc1.contoso.com' -CommandLine 'cmd.exe /c nothing'
    Assert-That 'no output does not become a decorated object' ((Get-EtsPropertyNames $empty).Count -eq 0) `
        "got [$((Get-EtsPropertyNames $empty) -join ',')]"
    $script:startSucceeds = $false
    $failed = Invoke-mdiRemoteCommand -ComputerName 'dc1.contoso.com' -CommandLine 'cmd.exe /c nothing'
    Assert-That 'a refused process start still returns $null' ($null -eq $failed) "got '$failed'"
    $script:startSucceeds = $true

    Write-Host 'End to end: Details.PowerSettingsDetails is the same JSON type on every estate' -ForegroundColor Cyan
    # Both branches of the real Get-mdiPowerScheme, serialised at the nesting and depth the shipped
    # -AsJson path uses, then parsed back - which is exactly what a consumer does.
    function Get-PublishedDetail {
        param([string] $Payload)
        $script:payload = $Payload
        $check = Get-mdiPowerScheme -ComputerName 'dc1.contoso.com'
        $report = @{
            DomainControllers = @(
                [PSCustomObject]@{
                    FQDN    = 'dc1.contoso.com'
                    Details = [PSCustomObject]@{ PowerSettingsDetails = $check.details }
                }
            )
        }
        $doc = $report | ConvertTo-Json -Depth 7
        [PSCustomObject]@{
            Status = $check.isPowerSchemeOk
            Json   = $doc
            Value  = ($doc | ConvertFrom-Json).DomainControllers[0].Details.PowerSettingsDetails
        }
    }

    $read = Get-PublishedDetail "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)`r`n"
    $unread = Get-PublishedDetail ''

    Assert-That 'a readable server measures the scheme' ($read.Status -eq $true) "got '$($read.Status)'"
    Assert-That 'an unreadable server reports N/A' ([string] $unread.Status -eq 'N/A') "got '$($unread.Status)'"

    Assert-That 'the measured detail revives as a string' ($read.Value -is [string]) `
        "got $(if ($null -eq $read.Value) { '<null>' } else { $read.Value.GetType().FullName })"
    Assert-That 'the unread detail revives as a string' ($unread.Value -is [string]) `
        "got $(if ($null -eq $unread.Value) { '<null>' } else { $unread.Value.GetType().FullName })"
    Assert-That '  ...so the field does not change type with the estate' `
        (($read.Value -is [string]) -and ($unread.Value -is [string])) `
        "measured=$(if ($null -eq $read.Value) { '<null>' } else { $read.Value.GetType().Name }) unread=$(if ($null -eq $unread.Value) { '<null>' } else { $unread.Value.GetType().Name })"

    Assert-That 'the measured detail is the powercfg text itself, not an object wrapping it' `
        ($read.Value -like 'Power Scheme GUID:*') "got '$($read.Value)'"
    Assert-That '  ...and is not hidden under a .value property' `
        ($read.Json -notmatch '"PowerSettingsDetails"\s*:\s*\{') "got: $($read.Json.Substring(0, [Math]::Min(300, $read.Json.Length)))"

    Assert-That 'the published document leaks no provider metadata' `
        ($read.Json -notmatch 'PSPath|PSProvider|PSParentPath|PSChildName|PSDrive') "document length $($read.Json.Length)"
    Assert-That '  ...nor the admin-share path of the temp file' `
        ($read.Json -notmatch 'FileSystem::') "document length $($read.Json.Length)"
    # One server, one check. The decorated form measured 359,045 characters here.
    Assert-That '  ...and one check on one server stays under 4 KB' ($read.Json.Length -lt 4096) `
        "got $($read.Json.Length) characters"

} finally {
    Remove-Item -LiteralPath $script:scratch -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
