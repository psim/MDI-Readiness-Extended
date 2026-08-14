# A missing route was reported as a measured closed port.
#
#  w55-F3  Test-mdiTcpPort classified anything that was neither a name-resolution failure nor a
#          Test-mdiIsNotRunError as an immediate RST, so WSAENETUNREACH (10051) and WSAEHOSTUNREACH
#          (10065) fell into the connection-refused catch-all and produced the self-contradictory
#
#              Closed - connection refused (A socket operation was attempted to an unreachable network)
#
#          With no route the packet never reached the host, so nothing at all was learned about the
#          port. Worse than the wording: that Detail carries no "Not tested" marker, and every
#          downstream classifier keys on that marker - so Test-mdiProbeWasMeasured returned $true,
#          the probe counted as a measurement, and a required port on an unroutable host was
#          reported as measured and blocking. The remediation for a missing route is routing; for a
#          closed port it is starting a service; and the report sent operators to the wrong one.
#
#          Test-mdiUdpPort had the same gap: both codes fell to its default switch arm and emitted a
#          bare "NetworkUnreachable - ..." detail, equally unmarked.
#
#          Note this is NOT the same as WSAEACCES or an unresolvable name - those were already
#          handled - and it must NOT swallow a genuine RST (10061) or an ICMP port-unreachable
#          (ConnectionReset), which are real measurements of a closed port and must stay measured.
#
# These tests are BEHAVIOURAL: the real classification statements are extracted from the shipped
# file with the parser and EXECUTED against real SocketExceptions, then the resulting Detail is put
# through the real Test-mdiProbeWasMeasured. No network is touched.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$ast = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref] $null, [ref] $null)
function Get-FunctionAst {
    param([string] $Name)
    $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name
        }, $true) | Select-Object -First 1
}

# The TCP EndConnect classification, extracted whole. The innermost if-statement that mentions both
# the resolution codes and the refused wording is the one that decides how a failed connect reads.
#
# The outer "if ($async.AsyncWaitHandle.WaitOne(...))" block also contains both strings, and when the
# classification was refactored that outer block became the shortest match - so this harness silently
# started executing a fragment that depends on $async, $client and $TimeoutMs, none of which it
# supplies, and every case died on "You cannot call a method on a null-valued expression". The
# fragment wanted is the one that CLASSIFIES an error it has already caught, so candidates that set
# up the connection are excluded, and the shape is asserted before it is used rather than failing
# obscurely inside Invoke-Expression.
$tcp = Get-FunctionAst 'Test-mdiTcpPort'
$tcpIf = $tcp.Body.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.IfStatementAst] -and
        $n.Extent.Text -match 'could not be resolved' -and $n.Extent.Text -match 'connection refused' -and
        $n.Extent.Text -notmatch 'AsyncWaitHandle'
    }, $true) | Sort-Object { $_.Extent.Text.Length } | Select-Object -First 1
Assert-That 'the TCP connect classification was found' ($null -ne $tcpIf)
Assert-That '  ...and it is a classification, not the connect set-up' `
($null -ne $tcpIf -and $tcpIf.Extent.Text -notmatch 'AsyncWaitHandle|BeginConnect') `
    'the extracted fragment sets up the connection, so it is the wrong statement'
$script:tcpSource = if ($tcpIf) { $tcpIf.Extent.Text } else { '[PSCustomObject]@{ Detail = "" }' }

# The UDP switch, extracted whole.
$udp = Get-FunctionAst 'Test-mdiUdpPort'
$udpSwitch = $udp.Body.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.SwitchStatementAst] -and
        $n.Extent.Text -match 'ConnectionReset'
    }, $true) | Select-Object -First 1
Assert-That 'the UDP classification was found' ($null -ne $udpSwitch)
$script:udpSource = if ($udpSwitch) { '$detail = ' + $udpSwitch.Extent.Text } else { '$detail = ""' }

function New-SocketError {
    param([int] $Code)
    $sock = New-Object System.Net.Sockets.SocketException($Code)
    # PowerShell wraps a .NET method exception in a MethodInvocationException, which is exactly the
    # shape EndConnect produces at runtime.
    $outer = New-Object System.Management.Automation.MethodInvocationException(
        ('Exception calling "EndConnect" with "1" argument(s): "{0}"' -f $sock.Message), $sock)
    New-Object System.Management.Automation.ErrorRecord($outer, 'X', 'NotSpecified', $null)
}
function Invoke-TcpBranch {
    param($ErrorRecord, [string] $ComputerName)
    $_ = $ErrorRecord
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $socketError = $null
    $candidate = $ErrorRecord.Exception
    $d = 0
    while ($candidate -and $null -eq $socketError -and $d -lt 16) {
        if ($candidate -is [System.Net.Sockets.SocketException]) { $socketError = $candidate.SocketErrorCode }
        $candidate = $candidate.InnerException
        $d++
    }
    Invoke-Expression $script:tcpSource
}
function Invoke-UdpBranch {
    param([string] $Code, [int] $Number, [string] $ComputerName, [int] $TimeoutMs = 1500)
    # A REAL SocketException as the error record's OWN Exception, which is the shape the UDP path
    # sees (its switch reads $socketError.Exception.SocketErrorCode directly). A PSCustomObject
    # stand-in would not be recognised by Test-mdiIsNotRunError and the default arm would be tested
    # against a shape that never occurs at runtime.
    $sock = New-Object System.Net.Sockets.SocketException($Number)
    $socketError = New-Object System.Management.Automation.ErrorRecord($sock, 'X', 'NotSpecified', $null)
    Invoke-Expression $script:udpSource
    $detail
}
function Test-Measured {
    param([string] $Detail, [string] $Protocol = 'TCP')
    Test-mdiProbeWasMeasured -Record ([PSCustomObject]@{
            Protocol = $Protocol; Port = 3389; Target = 'dc1.contoso.com'; Requirement = 'Required'
            Success = $false; Applicable = $true; Detail = $Detail; Group = 'Ports'
        })
}

'[tcp] an unreachable network is not a measured port state'
$net = Invoke-TcpBranch -ErrorRecord (New-SocketError -Code 10051) -ComputerName 'dc1.contoso.com'
Assert-That 'it is not called connection refused' ([string] $net.Detail -notmatch 'connection refused') "(got '$($net.Detail)')"
Assert-That 'it is marked Not tested' ([string] $net.Detail -match '^Not tested') "(got '$($net.Detail)')"
Assert-That '  ...and says the host was unreachable' ([string] $net.Detail -match '(?i)unreachable') "(got '$($net.Detail)')"
Assert-That 'it does NOT count as a measurement' (-not (Test-Measured ([string] $net.Detail))) "(got '$($net.Detail)')"

'[tcp] an unreachable host is not a measured port state'
$host1 = Invoke-TcpBranch -ErrorRecord (New-SocketError -Code 10065) -ComputerName 'dc1.contoso.com'
Assert-That 'it is not called connection refused' ([string] $host1.Detail -notmatch 'connection refused') "(got '$($host1.Detail)')"
Assert-That 'it is marked Not tested' ([string] $host1.Detail -match '^Not tested') "(got '$($host1.Detail)')"
Assert-That 'it does NOT count as a measurement' (-not (Test-Measured ([string] $host1.Detail))) "(got '$($host1.Detail)')"

'[tcp] a genuine RST is still a real measurement'
# The fix must not swallow the case the branch exists for: the host answered, nothing is listening.
$rst = Invoke-TcpBranch -ErrorRecord (New-SocketError -Code 10061) -ComputerName 'dc1.contoso.com'
Assert-That 'a refused connection still reads Closed' ([string] $rst.Detail -match 'Closed - connection refused') "(got '$($rst.Detail)')"
Assert-That '  ...and is NOT marked Not tested' ([string] $rst.Detail -notmatch 'Not tested') "(got '$($rst.Detail)')"
Assert-That '  ...and counts as a measurement' (Test-Measured ([string] $rst.Detail)) "(got '$($rst.Detail)')"

'[tcp] the pre-existing classifications are unchanged'
$denied = Invoke-TcpBranch -ErrorRecord (New-SocketError -Code 10013) -ComputerName 'dc1.contoso.com'
Assert-That 'access denied is still Not tested' ([string] $denied.Detail -match '^Not tested') "(got '$($denied.Detail)')"
Assert-That '  ...and unmeasured' (-not (Test-Measured ([string] $denied.Detail)))
$dns = Invoke-TcpBranch -ErrorRecord (New-SocketError -Code 11001) -ComputerName 'dc1.contoso.com'
Assert-That 'an unresolvable name is still Not tested' ([string] $dns.Detail -match '^Not tested') "(got '$($dns.Detail)')"
Assert-That '  ...and still says it could not be resolved' ([string] $dns.Detail -match 'could not be resolved') "(got '$($dns.Detail)')"
Assert-That '  ...and unmeasured' (-not (Test-Measured ([string] $dns.Detail)))

'[udp] the same two conditions are unmeasured there too'
$udpNet = Invoke-UdpBranch -Code 'NetworkUnreachable' -Number 10051 -ComputerName 'dc1.contoso.com'
Assert-That 'UDP NetworkUnreachable is Not tested' ([string] $udpNet -match '^Not tested') "(got '$udpNet')"
Assert-That '  ...and unmeasured' (-not (Test-Measured ([string] $udpNet) 'UDP')) "(got '$udpNet')"
$udpHost = Invoke-UdpBranch -Code 'HostUnreachable' -Number 10065 -ComputerName 'dc1.contoso.com'
Assert-That 'UDP HostUnreachable is Not tested' ([string] $udpHost -match '^Not tested') "(got '$udpHost')"
Assert-That '  ...and unmeasured' (-not (Test-Measured ([string] $udpHost) 'UDP')) "(got '$udpHost')"

'[udp] a real ICMP port-unreachable and a real timeout stay measured'
$udpReset = Invoke-UdpBranch -Code 'ConnectionReset' -Number 10054 -ComputerName 'dc1.contoso.com'
Assert-That 'ConnectionReset still reads Closed' ([string] $udpReset -match 'Closed') "(got '$udpReset')"
Assert-That '  ...and counts as a measurement' (Test-Measured ([string] $udpReset) 'UDP') "(got '$udpReset')"
$udpTimeout = Invoke-UdpBranch -Code 'TimedOut' -Number 10060 -ComputerName 'dc1.contoso.com'
Assert-That 'TimedOut still reads Blocked' ([string] $udpTimeout -match 'Blocked') "(got '$udpTimeout')"
Assert-That '  ...and counts as a measurement' (Test-Measured ([string] $udpTimeout) 'UDP') "(got '$udpTimeout')"

'[blocking] an unroutable required port raises no blocking failure'
# The consequence that made this worth fixing: a required port on an unroutable host was reported
# as a measured blocking failure, sending the operator to change a firewall.
$blocking = @(Get-mdiBlockingPortFailure -Record @(
        [PSCustomObject]@{
            Protocol = 'TCP'; Port = 3389; Target = 'dc1.contoso.com'; Requirement = 'Required'
            Success = $false; Applicable = $true; Detail = [string] $net.Detail; Group = 'Ports'
        }
    ))
Assert-That 'no blocking failure is raised for an unroutable host' ($blocking.Count -eq 0) "(got $($blocking.Count))"
# ...while a genuinely refused required port still does raise one.
$blockingRst = @(Get-mdiBlockingPortFailure -Record @(
        [PSCustomObject]@{
            Protocol = 'TCP'; Port = 3389; Target = 'dc1.contoso.com'; Requirement = 'Required'
            Success = $false; Applicable = $true; Detail = [string] $rst.Detail; Group = 'Ports'
        }
    ))
Assert-That 'a refused required port still raises one' ($blockingRst.Count -ge 1) "(got $($blockingRst.Count))"

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
