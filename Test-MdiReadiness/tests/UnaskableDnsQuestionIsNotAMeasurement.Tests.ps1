<#
    A DNS QUESTION THAT COULD NOT BE ASKED MUST NOT COME BACK AS A MEASUREMENT - OR TAKE THE
    WHOLE PORT-PROBE PASS WITH IT.

    New-mdiDnsQueryPacket wrote each label's length with a bare cast:

        $packet.Add([byte] $labelBytes.Length)

    RFC 1035 caps a DNS label at 63 bytes and the whole encoded QNAME at 255. Neither was enforced,
    so the same operator input broke in two different ways depending only on its length:

      * 64..255 BYTES - the length byte was written with its TOP BITS SET. 0xC0 is the DNS
        COMPRESSION POINTER marker, so a label of 192..255 did not encode an over-long name, it
        encoded a different structure. Measured on the shipped function, a label of 192 'a's
        produced length byte 0xC0 and one of 255 produced 0xFF, silently, with no warning - and
        Invoke-mdiPortProbePlan then recorded a DnsUdp RESULT for that malformed question. A query
        that asked the server nothing, reported as a measurement.

      * 256+ BYTES - the [byte] cast THREW "Cannot convert value \"256\" to type \"System.Byte\".
        Value was either too large or too small for an unsigned byte", and the throw ESCAPED
        Invoke-mdiPortProbePlan. Measured on the shipped functions with one identical plan:

            -Domain <63-byte label>.local    plan returned results
            -Domain <256-byte label>.local   PLAN THREW - no results at all
            -Domain <300-byte label>.local   PLAN THREW - no results at all

        Not a failed probe: an ABSENT one. Every other probe in the pass lost its record too, and a
        probe with no record cannot be counted as missing by anything downstream, so the denominator
        itself shrank - the same shape this script already removes elsewhere.

    Both are reachable from ordinary operator input. -Domain is a plain [string] with no length
    validation, and New-mdiPortProbePlan carries it into the plan verbatim as DnsProbeName
    (measured: plan.DnsProbeName was the -Domain string byte for byte at 306 characters). Both
    New-mdiDnsQueryPacket and Invoke-mdiPortProbePlan are in Get-mdiPortProbeScriptText's shipped
    function list and the shipped text carries DnsProbeName, so the throw happened on EVERY scanned
    server inside the remote command line, not only on the scanning host.

    The fix refuses explicitly rather than truncating - a question this encoder cannot represent
    must not be sent as something else, and a shorter name would ask about a host nobody named -
    and the caller records the refusal as NOT TESTED, which is the route the DnsServer scope already
    uses when the DNS server list cannot be read.

    Reverting either half turns these tests red: dropping the label/name guard restores the 0xC0
    length byte and the escaping throw; dropping the try/catch at the call site restores the plan
    that returns nothing.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$loaded = (Resolve-Path -LiteralPath $target).ProviderPath
Write-Host ("  LOADED  {0}" -f $loaded) -ForegroundColor DarkGray
Write-Host ("  SHA256  {0}" -f (Get-FileHash -LiteralPath $loaded -Algorithm SHA256).Hash) -ForegroundColor DarkGray

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:failures = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
    } else {
        $script:failures++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " - $Detail" } else { '' })) -ForegroundColor Red
    }
}

# The QNAME is everything between the 12-byte header and the 4 trailing type/class bytes.
function Get-QnameLengthByte {
    param([byte[]] $Packet)
    $Packet[12]
}

Write-Host 'A legal name still encodes exactly as before' -ForegroundColor Cyan

foreach ($name in 'mdilab.local', 'fabrikam.local', 'FABCORP', 'emea.mdilab.local', 'dcfab01.fabrikam.local') {
    $packet = $null
    try { $packet = New-mdiDnsQueryPacket -Name $name } catch { }
    Assert-True ("'{0}' encodes" -f $name) ($null -ne $packet)
    if ($null -ne $packet) {
        $labels = @($name -split '\.' | Where-Object { $_ })
        Assert-True ("'{0}' first length byte is its first label's length" -f $name) `
        ((Get-QnameLengthByte -Packet $packet) -eq $labels[0].Length) `
            ("got {0}, expected {1}" -f (Get-QnameLengthByte -Packet $packet), $labels[0].Length)
    }
}

# 63 is the largest legal label and must keep working: the guard must not move the boundary.
$packet63 = $null
try { $packet63 = New-mdiDnsQueryPacket -Name (('a' * 63) + '.local') } catch { }
Assert-True 'a 63-byte label (the RFC maximum) still encodes' ($null -ne $packet63)
if ($null -ne $packet63) {
    Assert-True 'a 63-byte label writes length byte 63' ((Get-QnameLengthByte -Packet $packet63) -eq 63)
}

# The largest legal NAME: 255 bytes of encoded QNAME must still be accepted.
$maxName = ((1..4 | ForEach-Object { 'a' * 49 }) -join '.') + '.' + ('a' * 50)
$packetMax = $null
try { $packetMax = New-mdiDnsQueryPacket -Name $maxName } catch { }
Assert-True 'a name at the 255-byte QNAME ceiling still encodes' ($null -ne $packetMax) `
    ("name is {0} chars" -f $maxName.Length)

Write-Host ''
Write-Host 'An over-long label is REFUSED, never encoded with the pointer bits set' -ForegroundColor Cyan

foreach ($len in 64, 65, 128, 191, 192, 255) {
    $packet = $null
    $threw = $false
    try { $packet = New-mdiDnsQueryPacket -Name (('a' * $len) + '.local') } catch { $threw = $true }
    Assert-True ("a {0}-byte label is refused" -f $len) $threw `
        ("it encoded, length byte 0x{0:X2}" -f $(if ($null -ne $packet) { Get-QnameLengthByte -Packet $packet } else { 0 }))
    # The specific corruption: 192..255 sets both pointer bits, so the server reads a pointer.
    if ($null -ne $packet) {
        Assert-True ("a {0}-byte label did not write pointer bits" -f $len) `
        (((Get-QnameLengthByte -Packet $packet) -band 0xC0) -eq 0)
    }
}

foreach ($len in 256, 300, 1000) {
    $threw = $false
    try { $null = New-mdiDnsQueryPacket -Name (('a' * $len) + '.local') } catch { $threw = $true }
    Assert-True ("a {0}-byte label is refused" -f $len) $threw
}

# A name whose every label is legal but whose total exceeds 255 must also be refused.
$overLongName = (1..20 | ForEach-Object { 'b' * 60 }) -join '.'
$threwName = $false
try { $null = New-mdiDnsQueryPacket -Name $overLongName } catch { $threwName = $true }
Assert-True 'a name over the 255-byte QNAME ceiling is refused, even with legal labels' $threwName

# The refusal must be readable, not a raw cast error, so the "Not tested" reason means something.
$message = ''
try { $null = New-mdiDnsQueryPacket -Name (('a' * 300) + '.local') } catch { $message = $_.Exception.Message }
Assert-True 'the refusal names RFC 1035 rather than reporting a byte cast' `
($message -match 'RFC 1035') ("message was: $message")
Assert-True 'the refusal is not the raw System.Byte conversion error' `
($message -notmatch 'System\.Byte') ("message was: $message")

Write-Host ''
Write-Host 'An unencodable name costs ONE probe, not the whole pass' -ForegroundColor Cyan

Set-Item -Path function:script:Get-mdiConfiguredDnsServer -Value {
    [PSCustomObject]@{ Measured = $true; Servers = @('10.10.1.10'); Detail = 'stub' }
}
Set-Item -Path function:script:Test-mdiTcpPort -Value {
    param($ComputerName, $Port, $TimeoutMs)
    [PSCustomObject]@{ Success = $true; Detail = 'Connected'; LatencyMs = 1 }
}
Set-Item -Path function:script:Test-mdiUdpPort -Value {
    param($ComputerName, $Port, $Payload, $TimeoutMs, $ExpectedTransactionId, $ResponseValidator, [switch] $IsRetry)
    [PSCustomObject]@{ Success = $true; Detail = 'Replied'; LatencyMs = 1; Response = [byte[]] (1..64) }
}
Set-Item -Path function:script:Get-mdiLocalProbeAddress -Value { @() }
Set-Item -Path function:script:Test-mdiLocalTcpListener -Value { param($Port) $false }
Set-Item -Path function:script:Test-mdiLocalUdpListener -Value { param($Port) $false }
Set-Item -Path function:script:Test-mdiCloudConnectivity -Value {
    param($Url, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'ok'; LatencyMs = 1 }
}
Set-Item -Path function:script:Test-mdiNnrNetBios -Value {
    param($ComputerName, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'Resolved to: X'; LatencyMs = 1 }
}
Set-Item -Path function:script:Test-mdiReverseDns -Value {
    param($IPAddress, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'Resolved'; LatencyMs = 1 }
}

$dcs = @([PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50'; Domain = 'fabrikam.local' })

function Invoke-PlanFor {
    param([string] $DomainValue)
    $plan = New-mdiPortProbePlan -Domain $DomainValue -DomainController $dcs -NnrTarget $dcs -TimeoutMs 200
    try {
        # Invoke-mdiPortProbePlan returns `, $results.ToArray()`, so its output is ONE object that IS
        # the row array. Assigning it first and wrapping afterwards unwraps it; wrapping the call
        # inline would produce a one-element array holding the array, and every row property would
        # read back as Object[].
        $raw = Invoke-mdiPortProbePlan -Plan $plan
        [PSCustomObject]@{ Threw = $false; Results = @($raw) }
    } catch {
        [PSCustomObject]@{ Threw = $true; Results = @() }
    }
}

$control = Invoke-PlanFor -DomainValue 'fabrikam.local'
Assert-True 'a legal domain produces a plan that does not throw' (-not $control.Threw)
Assert-True 'a legal domain produces at least one probe result' ($control.Results.Count -gt 0)

foreach ($len in 256, 300) {
    $bad = Invoke-PlanFor -DomainValue ((('a' * $len)) + '.local')
    Assert-True ("a {0}-byte label does not end the plan" -f $len) (-not $bad.Threw)
    Assert-True ("a {0}-byte label leaves the other probes' records intact" -f $len) `
    ($bad.Results.Count -eq $control.Results.Count) `
        ("got {0} result(s), the control produced {1}" -f $bad.Results.Count, $control.Results.Count)

    # The DNS probe itself must still be RECORDED, and recorded as not measured rather than as a pass.
    $dnsRows = @($bad.Results | Where-Object { $_.Id -eq 'DnsUdp' })
    Assert-True ("a {0}-byte label still records the DnsUdp probe" -f $len) ($dnsRows.Count -gt 0)
    foreach ($row in $dnsRows) {
        Assert-True ("a {0}-byte label records DnsUdp as not tested" -f $len) `
        (([string] $row.Detail) -match 'Not tested') ("detail was: {0}" -f $row.Detail)
        Assert-True ("a {0}-byte label does not record DnsUdp as a success" -f $len) `
        ($row.Success -ne $true)
    }
}

# The 192..255 range is the silent one: it used to produce a RESULT for a corrupt question.
foreach ($len in 192, 255) {
    $bad = Invoke-PlanFor -DomainValue ((('a' * $len)) + '.local')
    Assert-True ("a {0}-byte label does not end the plan" -f $len) (-not $bad.Threw)
    $dnsRows = @($bad.Results | Where-Object { $_.Id -eq 'DnsUdp' })
    Assert-True ("a {0}-byte label still records the DnsUdp probe" -f $len) ($dnsRows.Count -gt 0)
    foreach ($row in $dnsRows) {
        Assert-True ("a {0}-byte label is not reported as a successful DNS probe" -f $len) `
        ($row.Success -ne $true) ("detail was: {0}" -f $row.Detail)
    }
}

Write-Host ''
Write-Host 'The encoder that refuses is the one shipped to every scanned server' -ForegroundColor Cyan

$plan = New-mdiPortProbePlan -Domain 'fabrikam.local' -DomainController $dcs -NnrTarget $dcs -TimeoutMs 200
$shipped = Get-mdiPortProbeScriptText -Plan $plan -OutputFile 'C:\Windows\Temp\x.json'
Assert-True 'New-mdiDnsQueryPacket is shipped to the server' ($shipped -match 'function New-mdiDnsQueryPacket')
Assert-True 'Invoke-mdiPortProbePlan is shipped to the server' ($shipped -match 'function Invoke-mdiPortProbePlan')
Assert-True 'the shipped encoder carries the RFC 1035 guard' ($shipped -match 'RFC 1035')
Assert-True 'the shipped call site carries the guard, not a bare build' `
($shipped -notmatch '\$dnsPayload = New-mdiDnsQueryPacket -Name \$Plan\.DnsProbeName\s*\r?\n\s*Test-mdiUdpPort')

Write-Host ''
if ($script:failures -gt 0) {
    Write-Host ("FAILED: {0} assertion(s)" -f $script:failures) -ForegroundColor Red
    exit 1
}
Write-Host 'All assertions passed.' -ForegroundColor Green
exit 0
