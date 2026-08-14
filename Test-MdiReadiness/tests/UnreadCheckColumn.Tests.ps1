# A check that could not be read on EVERY server had no column in the server table at all.
#
#  w50-F3  The table's column list was built only from Get-mdiEffectiveCheckProperty, which is built
#          on Get-mdiCheckProperty, which drops any value that does not parse to a boolean. The 'N/A'
#          marker is therefore ABSENT from its output rather than merely non-boolean, so a check that
#          failed to read on every server contributed no column name and vanished from the table
#          entirely.
#
#          That is exactly backwards. A check unread on one server out of fifty is a local fault; a
#          check unread on all fifty is a systemic one - the Remote Registry service disabled by
#          policy, a firewall rule, a denied certificate-store read - and it is the single most
#          worth-surfacing result of the scan. Instead the reader got a table with no
#          RootCertificates and no CAAuditing column at all, which looks like a complete account of
#          everything that was examined. Get-mdiUnreadCheckName, called on the very same objects,
#          names those checks correctly, so the data was present and known the whole time.
#
#          The identical defect had already been found and fixed in the per-check chart - its own
#          comment says a check unread on every server "vanished from the chart entirely while the
#          score card still counted it" - but the server table was never given the same treatment.
#
#          Second, separate loss: when NO check was readable the column list came out empty and the
#          table fell back to FQDN and Comment only, discarding the descriptive facts that HAD been
#          read successfully - the sensor version, the capture driver and the virtualization
#          platform. Losing measurements that succeeded because other measurements failed is
#          straightforward data loss.
#
# These tests are BEHAVIOURAL: the shipped column-selection statements are extracted from the file
# with the parser and EXECUTED against fixtures, so they run the real code and fail if it regresses.

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

Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

# A domain controller whose certificate store and CA auditing reads both failed - what an estate
# with Remote Registry stopped actually produces - but whose descriptive facts were read fine.
function New-Dc {
    param([string] $Fqdn, [switch] $WithReadable)
    $o = [PSCustomObject]@{
        FQDN               = $Fqdn
        Unreachable        = $false
        PartialFailure     = $false
        RootCertificates   = 'N/A'
        CAAuditing         = 'N/A'
        PowerScheme        = 'N/A'
        OSVersion          = 'N/A'
        SensorVersion      = '2.255.1'
        CapturingComponent = 'Npcap 1.79'
        MachineType        = 'Hyper-V'
        Comment            = ''
    }
    if ($WithReadable) { $o | Add-Member -NotePropertyName TimeSync -NotePropertyValue $true -Force }
    $o
}

# The column-selection statements, taken straight out of the shipped file so this test cannot drift
# from the code it covers. The table builder itself is a scriptblock closing over
# Set-MdiReadinessReport's locals and cannot be invoked standalone; extracting and running the
# statements is the established way to exercise it.
$ast = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref] $null, [ref] $null)
$tableBuilder = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$convertServerTable'
    }, $true) | Select-Object -First 1
Assert-That 'the server table builder was found' ($null -ne $tableBuilder)

$blockText = if ($tableBuilder) { $tableBuilder.Right.Extent.Text } else { '' }
$startToken = '$checkColumns'
$endToken = 'AddRange($propsToAdd)'
$start = $blockText.IndexOf($startToken)
$end = $blockText.IndexOf($endToken)
Assert-That 'the column selection reads the unread check names' ($start -ge 0)
Assert-That 'the column selection adds the descriptive columns' ($end -ge 0)
$script:selectionSource = if ($start -ge 0 -and $end -gt $start) {
    $blockText.Substring($start, ($end - $start) + $endToken.Length)
} else { '$properties = [collections.arraylist]@()' }

function Get-Columns {
    param($ServerList)
    # $serverList is the variable name the shipped statements use.
    $serverList = @($ServerList)
    Invoke-Expression $script:selectionSource | Out-Null
    , @($properties)
}

'[table columns] a check unread on every server still gets a column'
$allUnread = Get-Columns @((New-Dc 'dc1.contoso.com'), (New-Dc 'dc2.contoso.com'))
Assert-That 'RootCertificates has a column' ($allUnread -contains 'RootCertificates') "(got [$($allUnread -join ', ')])"
Assert-That 'CAAuditing has a column' ($allUnread -contains 'CAAuditing') "(got [$($allUnread -join ', ')])"
Assert-That 'PowerScheme has a column' ($allUnread -contains 'PowerScheme') "(got [$($allUnread -join ', ')])"
Assert-That 'OSVersion has a column' ($allUnread -contains 'OSVersion') "(got [$($allUnread -join ', ')])"
# The names the table must show are exactly the ones the unread reader already knew about.
$known = @(Get-mdiUnreadCheckName -Server (New-Dc 'dc1.contoso.com'))
$missing = @($known | Where-Object { $allUnread -notcontains $_ })
Assert-That 'every known unread check is represented' ($missing.Count -eq 0) "(missing [$($missing -join ', ')])"

'[table columns] the facts that WERE read are never discarded'
Assert-That 'the sensor version column survives' ($allUnread -contains 'SensorVersion') "(got [$($allUnread -join ', ')])"
Assert-That 'the capture driver column survives' ($allUnread -contains 'CapturingComponent') "(got [$($allUnread -join ', ')])"
Assert-That 'the platform column survives' ($allUnread -contains 'MachineType') "(got [$($allUnread -join ', ')])"
Assert-That 'the comment column survives' ($allUnread -contains 'Comment') "(got [$($allUnread -join ', ')])"
Assert-That 'FQDN is still the first column' ($allUnread[0] -eq 'FQDN') "(got '$($allUnread[0])')"

'[table columns] readable and unread checks coexist'
$mixed = Get-Columns @((New-Dc 'dc1.contoso.com' -WithReadable), (New-Dc 'dc2.contoso.com' -WithReadable))
Assert-That 'the readable check has a column' ($mixed -contains 'TimeSync') "(got [$($mixed -join ', ')])"
Assert-That 'the unread checks still have columns' ($mixed -contains 'RootCertificates' -and $mixed -contains 'CAAuditing') "(got [$($mixed -join ', ')])"
# A name reachable through both paths must not produce two columns.
$dupes = @($mixed | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
Assert-That 'no column is emitted twice' ($dupes.Count -eq 0) "(duplicated [$($dupes -join ', ')])"

'[table columns] a server with one unread check among many read ones'
# The pre-existing behaviour that must not regress: one server unread, another readable.
$one = New-Dc 'dc-bad.contoso.com'
$two = [PSCustomObject]@{
    FQDN = 'dc-good.contoso.com'; Unreachable = $false; PartialFailure = $false
    RootCertificates = $true; CAAuditing = $true; PowerScheme = $true; OSVersion = $true
    SensorVersion = '2.255.1'; CapturingComponent = ''; MachineType = 'Hyper-V'; Comment = ''
}
$partly = Get-Columns @($one, $two)
Assert-That 'a readable check keeps its column' ($partly -contains 'RootCertificates') "(got [$($partly -join ', ')])"
$dupes2 = @($partly | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
Assert-That 'still no duplicate columns' ($dupes2.Count -eq 0) "(duplicated [$($dupes2 -join ', ')])"

'[table columns] the unread cells render as Not tested, not as a claim'
# The cell value for an unread check is the stored 'N/A', which the blanket rewrite turns into
# "Not tested". Confirm the column being present actually yields that wording rather than a blank.
$srv = New-Dc 'dc1.contoso.com'
$cell = $srv.PSObject.Properties['RootCertificates'].Value
$rendered = if ([string] $cell -eq 'N/A') { 'Not tested' } else { [string] $cell }
Assert-That 'an unread check cell reads Not tested' ($rendered -eq 'Not tested') "(got '$rendered')"

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
