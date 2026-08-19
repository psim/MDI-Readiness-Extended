<#
    A server row written as a DICTIONARY must not lose its readiness checks and gain the dictionary's
    own .NET members as failed ones.

    THE DEFECT THIS PINS. Get-mdiCheckProperty is the single definition of "the boolean readiness
    checks on a server object". It used to begin:

        @(foreach ($prop in $Server.PSObject.Properties) {
            if ($prop.Name -in $script:mdiStatusFlag) { continue }
            if ($prop.Value -is [bool]) { $prop; continue }
            ...

    PSObject.Properties over an IDictionary enumerates the DICTIONARY'S OWN .NET MEMBERS, not its
    entries - Count, Keys, Values, IsReadOnly, IsFixedSize, IsSynchronized - and three of those are
    real booleans. The boolean branch accepts a boolean from ANY property name by design, so all
    three were admitted as readiness checks, and every real check the row carried was invisible.

    Measured on the shipped function, ONE server written the two ways a report can carry it:

        PSCustomObject row   4 checks   isAdvancedAuditingOk=False  isNtlmAuditingOk=True
                                        isPowerSchemeOk=False       isSensorVersionOk=True
        Hashtable row        3 checks   IsReadOnly=False  IsFixedSize=False  IsSynchronized=False

    So the same server lost every real check - including its two genuine FAILURES, which is a false
    green - and gained three that cannot exist, which is a false red. Both at once, from the shape the
    row happened to be written in.

    It does not stop at the counters. Get-mdiEffectiveCheckProperty wraps this function and feeds the
    per-server score, the per-check pass rates, the issue list, the HTML check matrix and the
    remediation generator. Measured end to end through the real New-mdiRemediationScript, one real
    domain controller plus one dictionary row:

        control            1 finding needing manual attention
        + dictionary row   4 findings, the generated script gaining
                             Write-Host '    [High] : Is Read Only check failed'
                             Write-Host '    [High] : Is Fixed Size check failed'
                             Write-Host '    [High] : Is Synchronized check failed'

    That is a script an operator runs against production domain controllers, listing three failures
    that were never measured and name nothing that exists.

    This is the same false red the STRING branch of the same function already guards against, one
    line below, and its comment states the rule: "Promoting ANY string that reads 'True' or 'False'
    turned a descriptive field into a readiness check: a server carrying SiteName='False' was
    reported as failing a 'Site Name check' that does not exist, which is a false red invented out of
    nothing." The boolean branch had no equivalent protection and did not need one until the row
    itself arrived in a shape whose plumbing is boolean.

    WHY IT SURVIVED. A live scan writes PSCustomObject rows, and ConvertFrom-Json in Windows
    PowerShell 5.1 produces objects too, so the shape never appears on the ordinary path. It arrives
    from another tool's JSON handling, a hand-edited report, or an older version - which is precisely
    why ConvertTo-mdiRecordObject exists in this script already, applied to the PORT records for the
    identical reason, its own comment naming IsReadOnly among the members that get read instead of
    the entries. The server rows never got the same treatment.

    THE FIX. Get-mdiCheckProperty normalises its argument through ConvertTo-mdiRecordObject before
    enumerating, so a dictionary row's ENTRIES are read. Get-mdiEffectiveCheckProperty does the same,
    because it reads the RequiredPorts summary through PSObject.Properties independently.

    Pinned here:

    1. A dictionary row and an object row carrying the same fields yield the SAME set of checks.
    2. IsReadOnly, IsFixedSize, IsSynchronized and Count never appear as a readiness check.
    3. An EMPTY dictionary row yields NO checks - not three failing ones.
    4. A dictionary row's genuine FAILURES survive, so the false green half cannot come back either.
    5. Every IDictionary shape is covered, not just Hashtable: an ordered dictionary and a
       Generic.Dictionary[string,object] behave the same, because a [PSCustomObject] cast only
       special-cases the first two and the report's shape is not this script's choice.
    6. The generated remediation script contains no "Is Read Only / Is Fixed Size / Is Synchronized
       check failed" line when a dictionary row is present - the surface an operator executes.
    7. The RequiredPorts summary on a dictionary row is still read by Get-mdiEffectiveCheckProperty.
    8. Ordinary object rows are unchanged, so the normalisation cannot have cost anything.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiCheckProperty') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# The dictionary's own boolean members. These are the three that were admitted as readiness checks,
# plus Count, which is not boolean but must not appear either.
$plumbing = @('IsReadOnly', 'IsFixedSize', 'IsSynchronized', 'Count', 'Keys', 'Values', 'SyncRoot')

# A cross-forest domain controller, because that is the estate the extended lab now has and the
# reports most likely to be handed between tools are the ones covering more than one forest.
$fields = [ordered]@{
    FQDN                 = 'dcfab01.fabrikam.local'
    Domain               = 'fabrikam.local'
    Unreachable          = $false
    isAdvancedAuditingOk = $false
    isNtlmAuditingOk     = $true
    isPowerSchemeOk      = $false
    isSensorVersionOk    = $true
}

function New-ObjectRow { $o = [ordered]@{}; foreach ($k in $fields.Keys) { $o[$k] = $fields[$k] }; [PSCustomObject] $o }
function New-HashRow { $h = @{}; foreach ($k in $fields.Keys) { $h[$k] = $fields[$k] }; $h }
function New-OrderedRow { $o = [ordered]@{}; foreach ($k in $fields.Keys) { $o[$k] = $fields[$k] }; $o }
function New-GenericRow {
    $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    foreach ($k in $fields.Keys) { $d[[string] $k] = $fields[$k] }
    $d
}

function Get-CheckNames { param($Row) @(@(Get-mdiCheckProperty -Server $Row) | ForEach-Object { [string] $_.Name } | Sort-Object) }

$objectNames = Get-CheckNames (New-ObjectRow)

''
'--- 1/2/4/5  the same server, every shape a report can carry it in ---'
foreach ($shape in @(
        @{ Name = 'Hashtable'; Row = (New-HashRow) }
        @{ Name = 'OrderedDictionary'; Row = (New-OrderedRow) }
        @{ Name = 'Generic.Dictionary'; Row = (New-GenericRow) }
    )) {
    $names = Get-CheckNames $shape.Row
    Assert-That "$($shape.Name) row yields the same checks as the object row" `
    ((@($names) -join ',') -eq (@($objectNames) -join ',')) "got [$($names -join ', ')] want [$($objectNames -join ', ')]"

    $leaked = @($names | Where-Object { $_ -in $plumbing })
    Assert-That "$($shape.Name) row exposes no dictionary member as a check" ($leaked.Count -eq 0) "leaked [$($leaked -join ', ')]"

    # The false-green half: a genuine failure must not be deleted by the row's shape.
    $props = @(Get-mdiCheckProperty -Server $shape.Row)
    $failing = @($props | Where-Object { $_.Value -eq $false } | ForEach-Object { [string] $_.Name } | Sort-Object)
    Assert-That "$($shape.Name) row keeps its two genuine failures" `
    ((@($failing) -join ',') -eq 'isAdvancedAuditingOk,isPowerSchemeOk') "got [$($failing -join ', ')]"
}

''
'--- 3  an empty dictionary row is not three failing checks ---'
foreach ($empty in @(
        @{ Name = 'empty Hashtable'; Row = @{} }
        @{ Name = 'empty OrderedDictionary'; Row = ([ordered]@{}) }
        @{ Name = 'empty Generic.Dictionary'; Row = (New-Object 'System.Collections.Generic.Dictionary[string,object]') }
    )) {
    $names = Get-CheckNames $empty.Row
    Assert-That "$($empty.Name) yields no readiness check at all" ($names.Count -eq 0) "got [$($names -join ', ')]"
}

''
'--- 8  ordinary object rows are unchanged ---'
Assert-That 'the object row still yields its four checks' ($objectNames.Count -eq 4) "got [$($objectNames -join ', ')]"
Assert-That 'the object row exposes no dictionary member' (@($objectNames | Where-Object { $_ -in $plumbing }).Count -eq 0) "got [$($objectNames -join ', ')]"
$statusKept = @($objectNames | Where-Object { $_ -in @('Unreachable', 'PartialFailure') })
Assert-That 'the status flags are still excluded from the checks' ($statusKept.Count -eq 0) "got [$($statusKept -join ', ')]"

''
'--- 7  the RequiredPorts summary survives on a dictionary row ---'
# Get-mdiEffectiveCheckProperty reads the summary through PSObject.Properties independently of
# Get-mdiCheckProperty, so it needs the same normalisation or a dictionary row's summary is invisible.
$portsName = $script:mdiRequiredPortsCheckName
$withSummary = @{}
foreach ($k in $fields.Keys) { $withSummary[$k] = $fields[$k] }
$withSummary[$portsName] = $false
$effective = @(Get-mdiEffectiveCheckProperty -Server $withSummary)
$summaryPair = @($effective | Where-Object { $_.Name -eq $portsName })
Assert-That 'the RequiredPorts summary is read from a dictionary row' ($summaryPair.Count -eq 1) "got $($summaryPair.Count) entr(y/ies)"
Assert-That 'and it keeps the failing value it was stored with' (@($summaryPair)[0].Value -eq $false) "got [$(@($summaryPair)[0].Value)]"
$effLeaked = @($effective | ForEach-Object { [string] $_.Name } | Where-Object { $_ -in $plumbing })
Assert-That 'Get-mdiEffectiveCheckProperty exposes no dictionary member either' ($effLeaked.Count -eq 0) "leaked [$($effLeaked -join ', ')]"

''
'--- 6  the generated remediation script names no invented check ---'
$realServer = [PSCustomObject]@{
    FQDN          = 'dc2022.mdilab.local'
    Domain        = 'mdilab.local'
    SensorVersion = '2.244.0.0'
    Unreachable   = $false
    Addresses     = @('10.0.0.10')
    IP            = '10.0.0.10'
    Details       = [PSCustomObject]@{
        SensorHealthDetails  = [PSCustomObject]@{ Installed = $true }
        RequiredPortsDetails = [PSCustomObject]@{
            Results = @(
                [PSCustomObject]@{ Id = 'LdapsTcp'; Name = 'Secure LDAP (LDAPS)'; Protocol = 'TCP'; Port = 636
                    Scope = 'DomainController'; Group = $null; Requirement = 'Required'
                    Target = 'dcfab01.fabrikam.local'; TargetIP = '10.10.1.50'
                    Applicable = $true; Success = $false; Detail = 'connection refused'
                }
            )
        }
    }
}
$reportData = [PSCustomObject]@{
    Domain              = 'mdilab.local'
    Forest              = 'mdilab.local'
    DomainsInScope      = @('mdilab.local')
    DomainControllers   = @($realServer, (New-HashRow))
    CAServers           = @()
    EntraConnectServers = @()
    DomainAuditing      = @()
    ScriptVersion       = '1.1.5'
}
$scriptPath = Join-Path ([System.IO.Path]::GetTempPath()) ('mdi-dictrow-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
try {
    [void] (New-mdiRemediationScript -ReportData $reportData -FilePath $scriptPath)
    $generated = if (Test-Path -LiteralPath $scriptPath) { Get-Content -LiteralPath $scriptPath -Raw } else { '' }
} finally {
    Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
}
Assert-That 'the remediation script was generated' ($generated.Length -gt 0) "length $($generated.Length)"
foreach ($invented in @('Is Read Only check failed', 'Is Fixed Size check failed', 'Is Synchronized check failed', 'Count check failed')) {
    Assert-That "the remediation script does not say '$invented'" ($generated -notmatch [regex]::Escape($invented))
}

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
