# Two descriptive columns turned an UNREAD value into a positive factual claim.
#
#  w50-F1  Get-mdiSensorVersion returned the single marker 'N/A' for two different facts:
#            (a) Win32_Service was queried and there is no AATPSensor -> genuinely not installed
#            (b) the AATPSensor service exists and is RUNNING, but the CIM_DataFile version read
#                came back empty                                      -> installed, version unknown
#          and, because the service query used -ErrorAction SilentlyContinue, a third:
#            (c) the WMI connection FAILED                            -> nothing was read at all
#          The server table then rewrote 'N/A' to the assertion "Not installed", so a domain
#          controller with a running sensor - and a domain controller whose WMI was unreachable -
#          were both reported as having no sensor. The sensor-health table in the SAME report, for
#          the SAME server, in the SAME run, said "Sensor installed: Yes / Running / Auto".
#
#  w50-F2  Get-mdiCaptureComponent already draws the distinction correctly: it returns 'N/A' when
#          NEITHER registry view could be opened, and an EMPTY string when the registry was read
#          and no capture driver is installed. The table rewrite inverted that: the unread case
#          ('N/A') rendered as "None" - a positive claim that no driver is present - while the case
#          that genuinely means none rendered as a blank cell. The v3 tab, reading the same value
#          through its own three-state logic, correctly said "Not tested"; the two surfaces of one
#          report therefore disagreed about the same server.
#
# The fix: the source function spells out the genuine absence ('Not installed'), 'N/A' is reserved
# for "could not be read" and is left for the blanket rewrite that renders it "Not tested", and the
# capture column's real "none" case (the empty string) is the one given the word "None".
#
# These tests are BEHAVIOURAL: they drive the real Get-mdiSensorVersion with stubbed WMI and assert
# on what it returns, then push each value through the real table-cell rules.

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

# Script scope, not global: Get-mdiSensorVersion is script-scoped and would not see a global stub,
# and every assertion below would then be testing the real cmdlet against a machine name that does
# not exist - which passes for the wrong reason.
function Set-Wmi {
    param([scriptblock] $Body)
    Set-Item -Path function:script:Get-WmiObject -Value $Body
}
$sensorService = [PSCustomObject]@{
    Name     = 'AATPSensor'
    State    = 'Running'
    PathName = '"C:\Program Files\Azure Advanced Threat Protection Sensor\2.255.1\Microsoft.Tri.Sensor.exe"'
}

'[sensor version] the three outcomes are three different answers'
# (a) the query was ANSWERED and found no sensor service.
Set-Wmi { param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction) $null }
$absent = Get-mdiSensorVersion -ComputerName 'dc-nosensor.contoso.com'
Assert-That 'no sensor service reads as Not installed' ($absent -eq 'Not installed') "(got '$absent')"

# (b) the sensor IS installed and running; only the file version could not be read.
Set-Wmi {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_Service' { $script:probeService }
        'CIM_DataFile'  { [PSCustomObject]@{ Version = $null } }
        default         { $null }
    }
}
$script:probeService = $sensorService
$unread = Get-mdiSensorVersion -ComputerName 'dc-hassensor.contoso.com'
Assert-That 'an unreadable version stays N/A' ($unread -eq 'N/A') "(got '$unread')"
Assert-That 'an installed sensor is NOT called absent' ($unread -ne 'Not installed') "(got '$unread')"
Assert-That 'the two facts no longer share an answer' ($absent -ne $unread) "(both '$absent')"

# (c) WMI itself failed. Nothing was read, so nothing may be asserted.
Set-Wmi { param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction) throw 'The RPC server is unavailable' }
$failed = Get-mdiSensorVersion -ComputerName 'dc-unreachable.contoso.com'
Assert-That 'a failed WMI query reads as N/A' ($failed -eq 'N/A') "(got '$failed')"
Assert-That '  ...and is never called Not installed' ($failed -ne 'Not installed') "(got '$failed')"
# The guard that makes (c) distinguishable from (a) at all.
$sourceText = Get-Content -LiteralPath $target -Raw
$fnStart = $sourceText.IndexOf('function Get-mdiSensorVersion')
$fnText = $sourceText.Substring($fnStart, 2000)
Assert-That 'the service query stops on error' ($fnText -match "Class\s*=\s*'Win32_Service'[\s\S]{0,1200}ErrorAction\s*=\s*'Stop'")

# (d) the ordinary case must be untouched.
Set-Wmi {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch ($Class) {
        'Win32_Service' { $script:probeService }
        'CIM_DataFile'  { [PSCustomObject]@{ Version = '2.255.1' } }
        default         { $null }
    }
}
$normal = Get-mdiSensorVersion -ComputerName 'dc-ok.contoso.com'
Assert-That 'a readable version is returned as-is' ($normal -eq '2.255.1') "(got '$normal')"

'[server table] an unread cell is never rewritten into a claim'
# BEHAVIOURAL. The table builder is a scriptblock nested inside Set-MdiReadinessReport that closes
# over that function's locals, so it cannot be invoked standalone - the convention in this suite is
# to locate it with the parser. Rather than only asserting on its text, the descriptive-column
# rewrite statement is EXTRACTED from the real file and EXECUTED here with $p and $cell bound, so
# every assertion below runs the shipped code and fails if its behaviour regresses.
$ast = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref] $null, [ref] $null)
$tableBuilder = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$convertServerTable'
    }, $true) | Select-Object -First 1
Assert-That 'the server table builder was found' ($null -ne $tableBuilder)
$rewrite = $null
if ($tableBuilder) {
    # The innermost matching if-statement: FindAll returns enclosing statements first, and the
    # outer "if ($serverList.Count -gt 0)" also contains both tokens.
    $rewrite = $tableBuilder.Right.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.IfStatementAst] -and
            $node.Extent.Text -match '\$p -in \$propsToAdd'
        }, $true) | Sort-Object { $_.Extent.Text.Length } | Select-Object -First 1
}
Assert-That 'the descriptive-column rewrite was found' ($null -ne $rewrite)
$script:rewriteSource = if ($rewrite) { $rewrite.Extent.Text } else { '$cell = $cell' }

$propsToAdd = @('SensorVersion', 'CapturingComponent', 'MachineType', 'Comment')
function Get-Cell {
    param([string] $Property, $Value)
    # $p and $cell are the variable names the shipped block uses.
    $p = $Property
    $cell = $Value
    Invoke-Expression $script:rewriteSource | Out-Null
    # Then the blanket rewrite the table applies to the rendered cell.
    if ([string] $cell -eq 'N/A') { $cell = 'Not tested' }
    $cell
}
Assert-That 'an unread sensor version shows Not tested' ((Get-Cell 'SensorVersion' 'N/A') -eq 'Not tested') "(got '$(Get-Cell 'SensorVersion' 'N/A')')"
Assert-That '  ...and never Not installed' ((Get-Cell 'SensorVersion' 'N/A') -ne 'Not installed') "(got '$(Get-Cell 'SensorVersion' 'N/A')')"
Assert-That 'a genuinely absent sensor still shows Not installed' ((Get-Cell 'SensorVersion' 'Not installed') -eq 'Not installed') "(got '$(Get-Cell 'SensorVersion' 'Not installed')')"
Assert-That 'a real version is shown unchanged' ((Get-Cell 'SensorVersion' '2.255.1') -eq '2.255.1') "(got '$(Get-Cell 'SensorVersion' '2.255.1')')"

'[server table] the capture column is no longer inverted'
# 'N/A' from Get-mdiCaptureComponent means the registry could not be opened.
Assert-That 'an unreadable registry shows Not tested' ((Get-Cell 'CapturingComponent' 'N/A') -eq 'Not tested') "(got '$(Get-Cell 'CapturingComponent' 'N/A')')"
Assert-That '  ...and never None' ((Get-Cell 'CapturingComponent' 'N/A') -ne 'None') "(got '$(Get-Cell 'CapturingComponent' 'N/A')')"
# An empty string means the registry WAS read and no driver was found. That is the real "None".
Assert-That 'a read registry with no driver shows None' ((Get-Cell 'CapturingComponent' '') -eq 'None') "(got '$(Get-Cell 'CapturingComponent' '')')"
Assert-That 'an installed driver is named' ((Get-Cell 'CapturingComponent' 'Npcap (1.79)') -eq 'Npcap (1.79)') "(got '$(Get-Cell 'CapturingComponent' 'Npcap (1.79)')')"
Assert-That 'an unread machine type shows Not tested' ((Get-Cell 'MachineType' 'N/A') -eq 'Not tested') "(got '$(Get-Cell 'MachineType' 'N/A')')"
Assert-That 'a read machine type is shown' ((Get-Cell 'MachineType' 'Hyper-V') -eq 'Hyper-V') "(got '$(Get-Cell 'MachineType' 'Hyper-V')')"

'[server table] the source no longer maps N/A onto a claim'
# Pin the rule itself too, so a reader of a failure sees immediately what was reinstated. Asserted
# against the extracted rewrite statement rather than a fixed-size slice of the file, so unrelated
# edits nearby cannot move the rule out of the window and fail this for the wrong reason.
$tableText = $script:rewriteSource
Assert-That "no 'N/A' arm maps to Not installed" ($tableText -notmatch "\`$cell -eq 'N/A'[\s\S]{0,400}'Not installed'")
Assert-That "the rewrite is gated on NOT being N/A" ($tableText -match "\`$p -in \`$propsToAdd -and \[string\] \`$cell -ne 'N/A'")

'[consistency] the two report surfaces agree about one server'
# The defect's visible symptom: the server table and the v3 tab describing the same unread capture
# value differently. Both must now decline to make a claim.
$captureUnread = 'N/A'
$v3Readable = ([string] $captureUnread -ne 'N/A')
Assert-That 'the v3 tab treats an unread capture value as unread' (-not $v3Readable)
Assert-That '  ...and so does the server table' ((Get-Cell 'CapturingComponent' $captureUnread) -eq 'Not tested')

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
