<#
    A schema version that WAS read must never be reported as one that could not be read.

    Get-DomainSchemaVersion returns two fields, and the HTML report combines them (line ~16356):

        $schemaText = if ($ReportData.DomainSchemaVersion.details) {
            '{0} (version {1})' -f $ReportData.DomainSchemaVersion.details, $ReportData.DomainSchemaVersion.schemaVersion
        } else { 'n/a' }

    So `details` is not decoration: a FALSY details erases the reading entirely and prints the
    literal 'n/a'. The number in schemaVersion is never shown.

    details used to be produced by a bare lookup in a fixed table:

        details = $(if ($schemaVersion -gt 0) { $schemaVersions[$schemaVersion] } else { 'Not tested ...' })

    A PowerShell hashtable returns $null for a key it does not hold. So any objectVersion the
    directory answered with, but that this table happened not to list, produced details = $null and
    a report reading 'n/a' - byte-for-byte what a domain whose schema could not be read produces.
    Measured before the fix, with the LDAP bind stubbed to return each value:

        objectVersion 92  -> schemaVersion=92  details=<NULL>  report=[n/a]
        objectVersion 100 -> schemaVersion=100 details=<NULL>  report=[n/a]
        objectVersion 45  -> schemaVersion=45  details=<NULL>  report=[n/a]

    This is the project's recurring defect running in the opposite direction to usual: not an unread
    value promoted to measured, but a MEASURED value demoted to unread, with the evidence discarded.
    It is not hypothetical and it is not new - the comment beside version 90 in the table records
    exactly this happening once already ("Without an entry the version rendered blank, which is
    indistinguishable from 'could not be read'"). The response then was to add entries for 90 and 91,
    which fixed those two numbers and left the mechanism in place, so the next schema version
    Microsoft ships reintroduces it. This test pins the mechanism rather than the numbers.

    Pinned here:

    1. A read-but-unnamed version keeps a non-empty details, so the report cannot collapse it to
       'n/a', and the measured number still reaches the reader. This is the defect itself: reverting
       to the bare table lookup turns it red.
    2. That text is DISTINGUISHABLE from the not-read text. Making the unknown case borrow the
       'Not tested' wording would satisfy point 1 while telling the operator the exact lie the fix
       exists to remove, so the two strings are asserted to differ.
    3. Known versions still resolve to their real names - the fix must not blanket everything with a
       generic label.
    4. Genuinely unreadable readings are still reported as unread, and are NOT dressed up as a
       measured version 0. The unreadable shapes are the ones a real directory produces: the
       attribute absent, an empty value, a non-numeric value, a value too large for [int], and a
       rootDSE that returns no schemaNamingContext at all. Each must yield schemaVersion 0 with the
       not-read wording.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-DomainSchemaVersion') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The directory boundary is stubbed at New-Object, which is what the function uses to bind rootDSE
# and the schema container. A function shadows a cmdlet of the same name, so the SHIPPED body runs
# unmodified against these values - only the LDAP read is replaced.
$script:objectVersion = $null
$script:namingContext = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
Set-Item -Path function:script:New-Object -Value {
    param([string] $TypeName, [object[]] $ArgumentList)
    $props = @{}
    if (([string] $ArgumentList[0]) -like '*rootDSE*') {
        $props['schemaNamingContext'] = [PSCustomObject]@{ Value = $script:namingContext }
    } else {
        $props['objectVersion'] = [PSCustomObject]@{ Value = $script:objectVersion }
    }
    [PSCustomObject]@{ Properties = $props } |
        Add-Member -MemberType ScriptMethod -Name Dispose -Value { } -PassThru
}

function Read-Version {
    param($Value, $Nc = 'CN=Schema,CN=Configuration,DC=contoso,DC=com')
    $script:objectVersion = $Value
    $script:namingContext = $Nc
    Get-DomainSchemaVersion -Domain 'contoso.com'
}
# The report's own rule, reproduced exactly: a falsy details collapses the reading to 'n/a'.
function Get-ReportText {
    param($Result)
    if ($Result.details) { '{0} (version {1})' -f [string] $Result.details, [string] $Result.schemaVersion } else { 'n/a' }
}

$notRead = (Read-Version $null).details

'1. A read-but-unnamed version is not erased'
foreach ($v in 92, 100, 45, 1) {
    $r = Read-Version $v
    Assert-That "objectVersion $v keeps its measured number" ($r.schemaVersion -eq $v) "got [$($r.schemaVersion)]"
    Assert-That "objectVersion $v has a non-empty details" `
        (-not [string]::IsNullOrWhiteSpace([string] $r.details)) "details=[$($r.details)]"
    Assert-That "objectVersion $v does NOT render as 'n/a'" `
        ((Get-ReportText $r) -ne 'n/a') "report=[$(Get-ReportText $r)]"
    Assert-That "objectVersion $v still shows the number to the reader" `
        ((Get-ReportText $r) -like "*$v*") "report=[$(Get-ReportText $r)]"
}

'2. The unnamed wording is distinguishable from the not-read wording'
$unknown = (Read-Version 92).details
Assert-That 'an unnamed version does not reuse the not-read text' ($unknown -ne $notRead) `
    "both were [$unknown]"
Assert-That 'the not-read text still says it was not tested' ([string] $notRead -like 'Not tested*') `
    "got [$notRead]"

'3. Known versions still resolve to their real names'
$known = @{ 87 = 'Windows Server 2016'; 88 = 'Windows Server 2019 / 2022'; 91 = 'Windows Server 2025'; 90 = 'Windows Server 2025'; 69 = 'Windows Server 2012 R2' }
foreach ($k in ($known.Keys | Sort-Object)) {
    $r = Read-Version $k
    Assert-That "objectVersion $k is named '$($known[$k])'" ($r.details -eq $known[$k]) "got [$($r.details)]"
}

'4. Genuinely unreadable readings stay unread'
# Each of these is a shape a real directory produces: attribute missing, empty, non-numeric, wider
# than [int], and a rootDSE that answered without a schemaNamingContext.
$unreadable = @{
    'the attribute is absent'      = $null
    'an empty value'               = ''
    'a non-numeric value'          = 'abc'
    'a value too large for [int]'  = 99999999999999
}
foreach ($k in ($unreadable.Keys | Sort-Object)) {
    $r = Read-Version $unreadable[$k]
    Assert-That "$k reports version 0" ($r.schemaVersion -eq 0) "got [$($r.schemaVersion)]"
    Assert-That "$k reports it was not tested" ([string] $r.details -like 'Not tested*') "got [$($r.details)]"
}
$r = Read-Version 88 ''
Assert-That 'a rootDSE with no schemaNamingContext reports version 0' ($r.schemaVersion -eq 0) "got [$($r.schemaVersion)]"
Assert-That 'a rootDSE with no schemaNamingContext reports it was not tested' `
    ([string] $r.details -like 'Not tested*') "got [$($r.details)]"

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
