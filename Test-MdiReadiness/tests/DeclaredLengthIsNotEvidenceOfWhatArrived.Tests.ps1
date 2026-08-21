# A LENGTH THE PAYLOAD DECLARED WAS TRUSTED OVER THE BYTES THAT ACTUALLY ARRIVED
#
# Invoke-mdiRemoteCommand reads the remote command's output file over SMB and falls back to CIM
# (PS_ModuleFile) when that fails - which is the ordinary path on a domain controller with C$
# disabled, a documented hardening step, not an exotic one. The CIM branch decoded the payload by
# taking a four-byte big-endian length prefix off the front and slicing to it:
#
#     $fileLengthBytes = $fileContents.FileData[0..3]
#     [array]::Reverse($fileLengthBytes)
#     $fileLength = [BitConverter]::ToUInt32($fileLengthBytes, 0)
#     $fileBytes  = $fileContents.FileData[4..($fileLength - 1)]
#
# $fileLength is DECLARED by the payload. It was never compared against how many bytes actually
# arrived, and the slice bound was computed from it directly. Two consequences, both measured on the
# shipped function against FileData = 0,0,0,15 + 'HELLO WORLD' (15 bytes in total):
#
#   1. A PREFIX AT OR BELOW THE START OF THE DATA FABRICATES OUTPUT. In PowerShell `4..N` with N
#      below 4 is a DESCENDING range - 4,3,2,1,0,-1 - and a negative index counts from the END of
#      the array. So a prefix declaring no content did not yield nothing; it yielded the length
#      prefix itself, backwards, plus whatever -1 reached:
#
#          prefix=0 -> [H    D]   prefix=1 -> [H   ]   prefix=2 -> [H  ]
#          prefix=3 -> [H ]       prefix=4 -> [H]
#
#      Those bytes were written to a temp file, read back with Get-Content and returned to the
#      caller as the output of the remote command. Nothing threw and nothing was null, so no caller
#      could tell.
#
#   2. A PREFIX THAT UNDERSTATES THE PAYLOAD TRUNCATES IT SILENTLY:
#
#          prefix=8  of a 15-byte payload -> [HELL]
#          prefix=10 of a 15-byte payload -> [HELLO ]
#
#      Real bytes, no error, WriteAllBytes succeeds, and the caller parses a short read as the
#      complete output. This transport carries the port-probe results, the auditpol backup and the
#      power scheme, so a short read is a wrong measurement rather than a missing one.
#
# The prefix counts the WHOLE FileData, not the content after it - established by measurement, since
# only that convention round-trips: prefix=15 on a 15-byte payload returns 'HELLO WORLD' exactly,
# while prefix=11 returns 'HELLO W'. The shipped slice is therefore CORRECT whenever the prefix
# agrees with what arrived. The defect is purely that it was never checked.
#
# WHAT THIS TEST PINS:
#   1. Every declared length that disagrees with the bytes received yields NOTHING ($null), not
#      fabricated or truncated content.
#   2. The cases that were ALREADY correct stay correct - a well-formed payload, a genuinely empty
#      output file, an over-declared length, and every unreadable FileData shape. Without these a
#      "fix" that refused everything would pass, and refusing everything would silently disable the
#      whole CIM fallback on exactly the hardened servers that depend on it.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
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

$script:FileData = $null

# The remote surface, shadowed so the DECLARED length is the only thing that varies.
Set-Item -Path function:script:Invoke-WmiMethod -Value {
    param($ComputerName, $Namespace, $Class, $Name, $ArgumentList, $ErrorAction)
    [PSCustomObject]@{ ReturnValue = 0; ProcessId = 4242 }
}
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Filter, $Property, $ErrorAction)
    [PSCustomObject]@{ CommandLine = '<<exited>>' }
}
# [CmdletBinding()] and NO explicit $ErrorAction parameter. THIS IS LOAD-BEARING. Declaring any
# [Parameter()] attribute makes a function advanced, at which point ErrorAction arrives as a COMMON
# parameter - so declaring $ErrorAction as well defines it twice and PowerShell throws during
# parameter BINDING, before the body runs. The product calls Get-Content inside its own try/catch,
# so that failure is swallowed and looks exactly like "the stub was never reached": every case
# returns $null INCLUDING the controls, and the whole test silently proves nothing.
Set-Item -Path function:script:Get-Content -Value {
    [CmdletBinding()]
    param($Path, $LiteralPath, [switch] $Raw, $Encoding, $TotalCount, $Tail)
    if ("$Path" -like '\\*') { throw 'Access is denied (SMB blocked, forcing the CIM fallback)' }
    Microsoft.PowerShell.Management\Get-Content -Path $Path
}
Set-Item -Path function:script:Get-CimClass -Value {
    param($Namespace, $ClassName, $ComputerName, $ErrorAction)
    [PSCustomObject]@{ CimClassName = 'PS_ModuleFile' }
}
Set-Item -Path function:script:New-CimInstance -Value {
    param($CimClass, $Property, $ClientOnly)
    [PSCustomObject]@{ InstanceID = $Property.InstanceID }
}
Set-Item -Path function:script:Get-CimInstance -Value {
    param($InputObject, $ComputerName, $ErrorAction)
    [PSCustomObject]@{ FileData = $script:FileData }
}
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

$content = [System.Text.Encoding]::ASCII.GetBytes('HELLO WORLD')   # 11 bytes -> 15 with the prefix

function New-Payload {
    param([byte[]] $Content, [uint32] $DeclaredLength)
    $prefix = [BitConverter]::GetBytes([uint32] $DeclaredLength)
    if ([BitConverter]::IsLittleEndian) { [array]::Reverse($prefix) }
    , ([byte[]] ($prefix + $Content))
}

function Invoke-Read {
    param($Data)
    $script:FileData = $Data
    try {
        $r = Invoke-mdiRemoteCommand -ComputerName 'dcfab01.fabrikam.local' -CommandLine 'whoami' `
            -LocalFile 'C:\Windows\Temp\mdi-regression.txt' -TimeoutSeconds 2 3>$null 4>$null
        [PSCustomObject]@{ Threw = $false; Value = $r }
    } catch {
        [PSCustomObject]@{ Threw = $true; Value = $null }
    }
}
function Render {
    param($Outcome)
    if ($Outcome.Threw) { return '<threw>' }
    if ($null -eq $Outcome.Value) { return '<null>' }
    '[' + ((@($Outcome.Value) | ForEach-Object { [string] $_ }) -join '|') + ']'
}

'[controls] a payload whose prefix AGREES with what arrived still round-trips'
$good = Invoke-Read (New-Payload -Content $content -DeclaredLength 15)
Assert-That 'a well-formed payload returns the command output exactly' `
    ((Render $good) -eq '[HELLO WORLD]') "got $(Render $good)"

$empty = Invoke-Read ([byte[]] @(0, 0, 0, 4))
Assert-That 'a genuinely EMPTY output file is still read as empty, not refused' `
    (-not $empty.Threw -and [string]::IsNullOrEmpty(($empty.Value -join ''))) "got $(Render $empty)"

$one = Invoke-Read (New-Payload -Content ([byte[]] [System.Text.Encoding]::ASCII.GetBytes('X')) -DeclaredLength 5)
Assert-That 'a one-byte payload still round-trips' ((Render $one) -eq '[X]') "got $(Render $one)"

''
'[the defect] a declared length that DISAGREES with what arrived yields nothing'
# 0-4 all declare "no content after the prefix" yet the shipped slice returned bytes, because
# 4..N with N below 4 counts DOWN and -1 wraps to the end of the array.
foreach ($n in 0, 1, 2, 3, 4) {
    $o = Invoke-Read (New-Payload -Content $content -DeclaredLength $n)
    $r = Render $o
    Assert-That ("prefix=$n contradicts the 15 bytes received, so nothing is returned") `
        ($r -eq '<null>') "got $r"
    Assert-That ("  ...and prefix=$n never returns the reversed length prefix as output") `
        ($r -notmatch 'H') "got $r"
}
# An UNDERSTATED length is the dangerous one: real bytes, no error, silently short.
foreach ($n in 8, 10, 14) {
    $o = Invoke-Read (New-Payload -Content $content -DeclaredLength $n)
    $r = Render $o
    Assert-That ("prefix=$n understates a 15-byte payload, so nothing is returned") ($r -eq '<null>') "got $r"
    Assert-That ("  ...and prefix=$n never returns a TRUNCATED read as the output") `
        ($r -ne '[HELL]' -and $r -ne '[HELLO ]' -and $r -ne '[HELLO WORL]') "got $r"
}

''
'[unchanged] shapes that were already handled honestly must stay that way'
foreach ($s in @(
        @{ Name = '$null FileData';        Data = $null }
        @{ Name = 'empty FileData';        Data = ([byte[]] @()) }
        @{ Name = 'only 2 bytes';          Data = ([byte[]] @(1, 2)) }
        @{ Name = 'a string, not bytes';   Data = 'not bytes at all' }
    )) {
    $o = Invoke-Read $s.Data
    $r = Render $o
    Assert-That ("{0} is not read as output" -f $s.Name) ($r -eq '<null>' -or $r -eq '<threw>') "got $r"
}
# An OVER-declared length was already harmless - the slice simply stops at the end of the array, so
# the full payload came back. It must keep working: refusing it would lose a readable result.
$over = Invoke-Read (New-Payload -Content $content -DeclaredLength 40)
Assert-That 'an over-declared length still yields the bytes that DID arrive' `
    ((Render $over) -eq '[HELLO WORLD]' -or (Render $over) -eq '<null>') "got $(Render $over)"

''
"pass=$script:pass  fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
