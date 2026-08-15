<#
    A NetBIOS node status reply must not be called a resolution unless it actually carries a name.

    A NetBIOS name field is 15 bytes of printable ASCII padded with spaces or NULs. The parser
    trimmed NUL and whitespace - the two padding bytes that had been SEEN - and let every other byte
    through. A reply padded with 0x01, 0x7F, 0x80 or 0xFF trimmed to a non-empty string, satisfied
    the blank-name guard, and the function returned Success with "Resolved to:" followed by junk.

    Measured end to end on the shipped parser before the fix, with a structurally perfect reply whose
    only hostile feature was the pad byte:

        pad 0xFF -> Success=True  Detail=[Resolved to: ???????????????]
                    NnrTargetCount=1  NnrResolvable=1
                    KPI "NNR resolvable targets  1/1"   sub-label "Every target resolvable"
                    tone ok (GREEN)   0 blocking records   0 issues

    An address that resolved to nothing at all, reported as fully resolved, in green, with no issue
    raised - the exact false green this tool exists to prevent.

    THE TRAP, and why this test asserts on bytes: [Text.Encoding]::ASCII.GetString maps every byte
    above 0x7F to a literal question mark, so 15 bytes of 0xFF decode to "???????????????" - which is
    printable, non-empty, and passes any check made on the decoded TEXT. The junk is only visible
    before decoding, so the guard must inspect the raw bytes.

    The controls carry equal weight. Rejecting harder would also "fix" this and would break every
    real scan, so a genuine name must still resolve, a name padded with spaces must still resolve,
    and a name padded with NULs must still resolve.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = (Resolve-Path -LiteralPath $target).ProviderPath

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$raw = [IO.File]::ReadAllText($target)
$i = $raw.IndexOf('#region Main')
if ($i -lt 0) { throw 'no #region Main in the canonical script' }
$pre = $raw.Substring(0, $i)
$pre = $pre -replace '(?m)^\s*#Requires.*$', ''
$pre = $pre -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
Invoke-Expression $pre

if (-not (Get-Command Test-mdiNnrNetBios -ErrorAction SilentlyContinue)) {
    throw 'Test-mdiNnrNetBios was not defined by the canonical script'
}

# Set-Item function:script: is REQUIRED. `function global:` does NOT override the script's own
# function, and the test would then silently exercise the real UDP path and prove nothing.
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

<#
    A structurally VALID node status reply, so the only thing under test is the name field:
      byte 2       QR set (not our own request reflected back)
      bytes 6-7    ANCOUNT = 1
      bytes 46-47  record type 0x0021 (NBSTAT)
      byte 56      number of names
      57 + n*18    each 15-byte name field
#>
function New-NbstatReply {
    param([byte[]] $NameBytes, [int] $NameCount = 1)
    $b = New-Object System.Collections.ArrayList
    $header = New-Object byte[] 56
    $header[2] = 0x84          # QR + authoritative
    $header[6] = 0x00
    $header[7] = 0x01          # ANCOUNT = 1
    $header[46] = 0x00
    $header[47] = 0x21         # NBSTAT
    [void] $b.AddRange($header)
    [void] $b.Add([byte] $NameCount)
    for ($n = 0; $n -lt $NameCount; $n++) {
        $entry = New-Object byte[] 18
        for ($k = 0; $k -lt 15; $k++) { $entry[$k] = $NameBytes[$k] }
        $entry[15] = 0x20      # NetBIOS suffix
        [void] $b.AddRange($entry)
    }
    , $b.ToArray()
}

function Set-Reply {
    param([byte[]] $Bytes)
    $script:mdiTestReply = $Bytes
    Set-Item -Path function:script:Test-mdiUdpPort -Value {
        [PSCustomObject]@{ Success = $true; Detail = 'Replied'; Response = $script:mdiTestReply; LatencyMs = 4 }
    }
}

function New-PaddedName {
    param([byte] $Pad)
    $a = New-Object byte[] 15
    for ($k = 0; $k -lt 15; $k++) { $a[$k] = $Pad }
    , $a
}

function New-RealName {
    param([string] $Name, [byte] $Pad = 0x20)
    $a = New-Object byte[] 15
    for ($k = 0; $k -lt 15; $k++) { $a[$k] = $Pad }
    $ascii = [Text.Encoding]::ASCII.GetBytes($Name)
    for ($k = 0; $k -lt $ascii.Length -and $k -lt 15; $k++) { $a[$k] = $ascii[$k] }
    , $a
}

# --- the defect: junk padding must never be reported as a resolved name ---
foreach ($pad in @(0x01, 0x02, 0x1F, 0x7F, 0x80, 0xFE, 0xFF)) {
    Set-Reply (New-NbstatReply -NameBytes (New-PaddedName ([byte] $pad)))
    $r = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 100
    Assert-That ('a name field of 0x{0:X2} padding is NOT a resolution' -f $pad) (-not $r.Success) ("detail=$($r.Detail)")
    # The wrong answer is not merely "unsuccessful": it must not claim a name either.
    Assert-That ('  ...and 0x{0:X2} does not appear as a resolved name' -f $pad) ("$($r.Detail)" -notmatch 'Resolved to') ("detail=$($r.Detail)")
}

# --- controls: real names must STILL resolve, or every genuine scan breaks ---
Set-Reply (New-NbstatReply -NameBytes (New-RealName -Name 'DC01' -Pad 0x20))
$r = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 100
Assert-That 'a real name padded with SPACES still resolves' ($r.Success) ("detail=$($r.Detail)")
Assert-That '  ...and the name is reported' ("$($r.Detail)" -match 'DC01') ("detail=$($r.Detail)")

Set-Reply (New-NbstatReply -NameBytes (New-RealName -Name 'DC02' -Pad 0x00))
$r = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 100
Assert-That 'a real name padded with NULs still resolves' ($r.Success) ("detail=$($r.Detail)")
Assert-That '  ...and the name is reported' ("$($r.Detail)" -match 'DC02') ("detail=$($r.Detail)")

# A name using the full printable range must survive - the guard is about non-printable bytes, not
# about being conservative with punctuation that appears in real NetBIOS names.
Set-Reply (New-NbstatReply -NameBytes (New-RealName -Name 'DC-01_A$' -Pad 0x20))
$r = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 100
Assert-That 'a name with punctuation still resolves' ($r.Success) ("detail=$($r.Detail)")

# --- previously fixed behaviour that must stay fixed ---
Set-Reply (New-NbstatReply -NameBytes (New-PaddedName 0x20))
$r = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 100
Assert-That 'an all-blank name field is still not a resolution' (-not $r.Success) ("detail=$($r.Detail)")

Set-Reply (New-NbstatReply -NameBytes (New-PaddedName 0x00))
$r = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 100
Assert-That 'an all-NUL name field is still not a resolution' (-not $r.Success) ("detail=$($r.Detail)")

# One good name alongside a junk one is still a resolution - the good name is real.
$two = New-NbstatReply -NameBytes (New-RealName -Name 'DC03' -Pad 0x20) -NameCount 2
# overwrite the SECOND entry with junk
for ($k = 0; $k -lt 15; $k++) { $two[57 + 18 + $k] = 0xFF }
Set-Reply $two
$r = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 100
Assert-That 'a good name alongside a junk name still resolves' ($r.Success) ("detail=$($r.Detail)")
Assert-That '  ...and only the good name is reported' ("$($r.Detail)" -match 'DC03' -and "$($r.Detail)" -notmatch '\?') ("detail=$($r.Detail)")

""
"  $($script:pass) passed, $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
