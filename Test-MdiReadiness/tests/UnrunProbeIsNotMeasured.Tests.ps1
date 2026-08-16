<#
    A probe that never left this machine is not a measurement of a remote port.

    Test-mdiIsNotRunError already recognised access-denied and the two "no route" codes. It did not
    recognise the LOCAL-side failures, where the call fails here before a packet can be sent:

        WSAEMFILE (10024)        too many open sockets - the socket was never created
        WSAEAFNOSUPPORT (10047)  the address family cannot be used
        WSAEADDRNOTAVAIL (10049) the address is not valid in its context
        WSAENETDOWN (10050)      the local network subsystem has failed
        WSAENOBUFS (10055)       no buffer space - the send never happened
        WSAENOTCONN (10057)      a send on a socket that was never connected

    Every one was recorded as a MEASURED blocked required port. The issue list read, literally,
    "A required network probe was measured as blocked: TCP/53 to ::1", the verdict went NOT READY,
    and the remediation generator was willing to open a firewall for it.

    A dual-stack domain controller reaches this the ordinary way: Windows puts ::1 in
    DNSServerSearchOrder, an IPv4 probe socket cannot use that address, and a healthy estate is told
    a required port is shut. That mismatch surfaces in three different shapes depending on the API -
    a SocketException 10047, a System.NotSupportedException, or a bare System.ArgumentException with
    no error code at all - so the port probers key on the ABSENCE of a socket error rather than on a
    list of exception types or on any localised message.

    The line these tests hold: an outcome that carries a real socket answer - refused, reset,
    timed out - is a MEASUREMENT and must keep failing the verdict. Everything else is "not tested",
    which still refuses to call the run ready, but points the operator at the real problem instead of
    at a firewall.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$loadedHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
$canonicalPath = $(if ($env:MDI_CANONICAL) { $env:MDI_CANONICAL } else { $c = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1'; if (Test-Path -LiteralPath $c) { $c } else { Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1' } })
$canonicalHash = $(if (Test-Path -LiteralPath $canonicalPath) { (Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256).Hash } else { '<canonical not found>' })
"LOADED_PATH=$target"
"LOADED_SHA256=$loadedHash"
"CANONICAL_SHA256=$canonicalHash"
"HASH_MATCH=$($loadedHash -eq $canonicalHash)"
# Enforced only when the test IS running against the canonical file. Run-Suite.ps1 deliberately
# executes from an ISOLATED COPY so that the canonical can be edited mid-run without corrupting the
# result - its own header says "a result gathered from a directory that can change underneath the run
# is not evidence of anything". Comparing the copy against the LIVE canonical re-read at test time
# therefore measured a race, not the product: this file threw before a single assertion ran whenever
# another edit landed during the suite, and the run was reported as "no-assertions" rather than as a
# pass or a failure. The hashes are still printed above, so a stale copy remains visible.
# NOT fatal. Run-Suite.ps1 deliberately executes from an ISOLATED COPY so the canonical can be edited
# mid-run without corrupting the result - its own header says "a result gathered from a directory that
# can change underneath the run is not evidence of anything". Re-reading the LIVE canonical here and
# throwing on any difference measured that race instead of the product: this file aborted before a
# single assertion ran whenever another edit landed during the suite, and was reported as
# "no-assertions" rather than as a pass or a failure - a test silently not running at all. The hashes
# are printed above, so a genuinely stale copy is still visible to anyone reading the output.
if ($loadedHash -ne $canonicalHash) { Write-Host 'NOTE: running against an isolated copy that differs from the current canonical file.' -ForegroundColor DarkYellow }
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

Write-Host 'Local-side socket failures are not measurements' -ForegroundColor Cyan
# Driven with GENUINE SocketException objects, so the numeric mapping is the real one.
foreach ($case in @(
        @{ Code = 10024; Name = 'WSAEMFILE too many open sockets' },
        @{ Code = 10047; Name = 'WSAEAFNOSUPPORT address family unusable' },
        @{ Code = 10049; Name = 'WSAEADDRNOTAVAIL address not valid here' },
        @{ Code = 10050; Name = 'WSAENETDOWN local network subsystem failed' },
        @{ Code = 10055; Name = 'WSAENOBUFS no buffer space' },
        @{ Code = 10057; Name = 'WSAENOTCONN send on an unconnected socket' }
    )) {
    $ex = New-Object System.Net.Sockets.SocketException ([int] $case.Code)
    Assert-That "$($case.Name) never ran" ((Test-mdiIsNotRunError $ex) -eq $true) "code $($case.Code)"
}

Write-Host 'The access and routing failures already recognised must stay recognised' -ForegroundColor Cyan
foreach ($case in @(
        @{ Code = 10013; Name = 'WSAEACCES socket access forbidden' },
        @{ Code = 10051; Name = 'WSAENETUNREACH no route to network' },
        @{ Code = 10065; Name = 'WSAEHOSTUNREACH no route to host' }
    )) {
    $ex = New-Object System.Net.Sockets.SocketException ([int] $case.Code)
    Assert-That "$($case.Name) never ran" ((Test-mdiIsNotRunError $ex) -eq $true) "code $($case.Code)"
}

Write-Host 'CONTROLS - a real answer from the far end is still a MEASUREMENT' -ForegroundColor Cyan
# These two are what a firewall and a closed port actually look like. If either were excused as
# "not tested" the tool would stop reporting the failures it exists to find.
foreach ($case in @(
        @{ Code = 10060; Name = 'WSAETIMEDOUT silence consistent with a firewall' },
        @{ Code = 10061; Name = 'WSAECONNREFUSED actively refused' },
        @{ Code = 10054; Name = 'WSAECONNRESET reset by peer' }
    )) {
    $ex = New-Object System.Net.Sockets.SocketException ([int] $case.Code)
    Assert-That "$($case.Name) IS a measurement" ((Test-mdiIsNotRunError $ex) -eq $false) "code $($case.Code)"
}

Write-Host 'CONTROLS - ordinary errors are not excused as "never ran"' -ForegroundColor Cyan
Assert-That 'a plain ArgumentException is not excused' ((Test-mdiIsNotRunError (New-Object System.ArgumentException 'bad arg')) -eq $false)
Assert-That 'a plain InvalidOperationException is not excused' ((Test-mdiIsNotRunError (New-Object System.InvalidOperationException 'nope')) -eq $false)
Assert-That 'a FormatException is not excused' ((Test-mdiIsNotRunError (New-Object System.FormatException 'bad format')) -eq $false)
Assert-That 'a null error is not excused' ((Test-mdiIsNotRunError $null) -eq $false)

Write-Host 'An operation the stack refuses to attempt at all never ran' -ForegroundColor Cyan
# A pre-wire local failure can carry no SocketException. Rather than list broad exception types in
# the shared classifier - which would ship to every DC and excuse ordinary bad arguments - the
# probers classify that outcome at the socket boundary. A plain exception must remain unrecognised by
# the numeric code classifier itself...
Assert-That 'a NotSupportedException is not matched by error code' `
((Test-mdiIsNotRunError (New-Object System.NotSupportedException 'This protocol version is not supported.')) -eq $false)
# ...while the PROBER still reports the same situation as not tested. That is asserted end to end
# against the real Test-mdiTcpPort below.

Write-Host 'The REAL prober: an unresolvable name is not a measured port failure' -ForegroundColor Cyan
# The reserved .invalid name deterministically resolves to nothing, so no packet can leave this machine.
$tcp = Test-mdiTcpPort -ComputerName 'never-resolves.invalid' -Port 53 -TimeoutMs 700
Assert-That 'the unresolved-name probe does not report success' ($tcp.Success -eq $false)
Assert-That '  ...and marks the result Not tested' ([string] $tcp.Detail -like 'Not tested*') "got '$($tcp.Detail)'"
Assert-That '  ...and never calls it Closed or Blocked' `
([string] $tcp.Detail -notlike '*Closed -*' -and [string] $tcp.Detail -notlike '*Blocked -*') "got '$($tcp.Detail)'"

Write-Host 'CONTROL - the REAL prober against IPv4 loopback still MEASURES' -ForegroundColor Cyan
# Port 1 on 127.0.0.1: nothing listens, so the stack refuses. That is a genuine measurement and it
# must NOT acquire the "Not tested" marker.
$ctl = Test-mdiTcpPort -ComputerName '127.0.0.1' -Port 1 -TimeoutMs 1500
Assert-That 'the control probe does not report success' ($ctl.Success -eq $false)
Assert-That '  ...and is NOT marked Not tested' ([string] $ctl.Detail -notlike 'Not tested*') "got '$($ctl.Detail)'"

Write-Host 'The marker is what every downstream reader keys on' -ForegroundColor Cyan
# Test-mdiProbeWasMeasured is the shared reader used by the score, the issue list and the verdict.
# It takes the whole RECORD: Success must be a real boolean and Applicable must be $true before the
# detail is even consulted.
$untested = [PSCustomObject]@{ Success = $false; Applicable = $true
    Detail = 'Not tested - NetworkDown - a socket operation encountered a dead network'
}
$measured = [PSCustomObject]@{ Success = $false; Applicable = $true
    Detail = 'Closed - connection refused (actively refused)'
}
Assert-That 'an unrun probe is not counted as measured' ((Test-mdiProbeWasMeasured -Record $untested) -eq $false) "got '$($untested.Detail)'"
Assert-That '  ...while a refused probe is' ((Test-mdiProbeWasMeasured -Record $measured) -eq $true) "got '$($measured.Detail)'"

# End to end through the real prober: the record the IPv6 probe produces must not be counted either.
$tcpRecord = [PSCustomObject]@{ Success = [bool] $tcp.Success; Applicable = $true; Detail = [string] $tcp.Detail }
Assert-That '  ...and the real unresolved-name probe record is not counted as measured' `
((Test-mdiProbeWasMeasured -Record $tcpRecord) -eq $false) "got '$($tcp.Detail)'"
$ctlRecord = [PSCustomObject]@{ Success = [bool] $ctl.Success; Applicable = $true; Detail = [string] $ctl.Detail }
Assert-That '  ...while the real IPv4 control record IS counted as measured' `
((Test-mdiProbeWasMeasured -Record $ctlRecord) -eq $true) "got '$($ctl.Detail)'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
