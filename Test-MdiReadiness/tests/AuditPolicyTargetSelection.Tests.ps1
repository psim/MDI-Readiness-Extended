# A per-user audit policy was read as the system audit policy.
#
#  w56-F1  auditpol /backup exports PER-USER audit policy alongside the system policy, and a
#          per-user row carries the same Subcategory GUID as the system row for that subcategory.
#          The rows therefore have to be separated, and the separation could not use the literal
#          word "System" because Policy Target is localised.
#
#          The heuristic chosen instead - "the system policy is whichever target covers the most
#          distinct subcategories" - inverts on exactly the case that matters:
#            * a per-user policy configured across EVERY subcategory TIES with the system policy,
#              and the tie was broken alphabetically, so 'CONTOSO\alice' beat 'System';
#            * a per-user target covering MORE subcategories won outright.
#
#          Measured on the shipped function: a domain controller whose SYSTEM policy was 0 - which
#          means MDI is blind for that subcategory - was reported as correctly configured, because
#          alice's per-user row for the same subcategory read 3. That is a false green on detection
#          coverage the customer does not have, and nothing else in the report contradicts it. The
#          mirror case is a false red: a correctly configured machine reported as misconfigured,
#          whose remediation rewrites the audit policy of a machine that was already right.
#
#          The fix identifies a per-user target by its SHAPE, which is locale-neutral: per-user
#          policy is always recorded against a user principal - DOMAIN\user, user@domain, or a raw
#          SID S-1-5-21-... - while the system target is a single translated word carrying none of
#          those markers. The subcategory count survives only as a tiebreak.
#
# These tests are BEHAVIOURAL: the shipped selection statements are extracted from the file with the
# parser and EXECUTED against synthetic auditpol rows.

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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

# The real policy-target selection, taken straight out of the shipped file.
$ast = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref] $null, [ref] $null)
$fn = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-mdiAdvancedAuditing'
    }, $true) | Select-Object -First 1
Assert-That 'Get-mdiAdvancedAuditing was found' ($null -ne $fn)
$body = if ($fn) { $fn.Body.Extent.Text } else { '' }
$start = $body.IndexOf('$rows = $allRows')
$end = $body.IndexOf('$actual = @($rows', $start)
Assert-That 'the policy-target selection was found' ($start -ge 0 -and $end -gt $start)
$script:selection = if ($start -ge 0 -and $end -gt $start) { $body.Substring($start, $end - $start) } else { '$rows = $allRows' }

function Get-ChosenTarget {
    param($AllRows, [int] $ColumnCount = 7)
    $allRows = @($AllRows)
    $columnCount = $ColumnCount
    Invoke-Expression $script:selection | Out-Null
    @(@($rows) | Select-Object -ExpandProperty 'Policy Target' -Unique)
}
function Get-SettingFor {
    param($AllRows, [string] $Guid, [int] $ColumnCount = 7)
    $allRows = @($AllRows)
    $columnCount = $ColumnCount
    Invoke-Expression $script:selection | Out-Null
    @(@($rows) | Where-Object { $_.'Subcategory GUID' -eq $Guid } | Select-Object -ExpandProperty 'Setting Value')
}

$guids = @(for ($n = 1; $n -le 64; $n++) { '{{0cce92{0:x2}-69ae-11d9-bed3-505054503030}}' -f $n })
$requiredGuid = $guids[0]
function New-Rows {
    param([string] $PolicyTarget, [int] $Setting, [int] $Count)
    @(for ($n = 0; $n -lt $Count; $n++) {
            [PSCustomObject]@{
                'Machine Name' = 'DC1'; 'Policy Target' = $PolicyTarget
                'Subcategory' = "Sub$n"; 'Subcategory GUID' = $guids[$n]
                'Inclusion Setting' = 'Success and Failure'; 'Exclusion Setting' = ''
                'Setting Value' = $Setting
            }
        })
}

'[auditpol] a per-user policy never displaces the system policy'
# The dangerous case: the system policy is 0 - MDI is blind - while alice's per-user policy reads 3
# across the same 64 subcategories. Reading alice reports full coverage the customer does not have.
$blind = @(New-Rows -PolicyTarget 'System' -Setting 0 -Count 64) + @(New-Rows -PolicyTarget 'CONTOSO\alice' -Setting 3 -Count 64)
$chosen = Get-ChosenTarget -AllRows $blind
Assert-That 'the system target is chosen over a DOMAIN\user target' (($chosen -join ',') -eq 'System') "(got '$($chosen -join ',')')"
$value = Get-SettingFor -AllRows $blind -Guid $requiredGuid
Assert-That 'the SYSTEM setting value is what gets read' (($value -join ',') -eq '0') "(got '$($value -join ',')')"

# The mirror case: system correct, per-user weaker. Reading alice reports a false failure and its
# remediation rewrites audit policy on a machine that was already right.
$good = @(New-Rows -PolicyTarget 'System' -Setting 3 -Count 64) + @(New-Rows -PolicyTarget 'CONTOSO\alice' -Setting 1 -Count 64)
Assert-That 'a tie does not hand the choice to the user target' (((Get-ChosenTarget -AllRows $good) -join ',') -eq 'System') "(got '$((Get-ChosenTarget -AllRows $good) -join ',')')"
$goodValue = Get-SettingFor -AllRows $good -Guid $requiredGuid
Assert-That 'a correctly configured system policy still reads 3' (($goodValue -join ',') -eq '3') "(got '$($goodValue -join ',')')"

'[auditpol] the per-user shape is recognised in every form it takes'
foreach ($form in @('CONTOSO\alice', 'alice@contoso.com', 'S-1-5-21-1111111111-2222222222-3333333333-1105')) {
    # Each covers MORE subcategories than the system policy, so a count-based rule would pick it.
    $rows = @(New-Rows -PolicyTarget 'System' -Setting 0 -Count 40) + @(New-Rows -PolicyTarget $form -Setting 3 -Count 64)
    $t = Get-ChosenTarget -AllRows $rows
    Assert-That "a '$form' target is not read as the system policy" (($t -join ',') -eq 'System') "(got '$($t -join ',')')"
}

'[auditpol] a localised system target still works'
# The whole reason the literal word cannot be matched. A translated system target carries none of
# the user-principal markers, so it is still selected.
foreach ($word in @('Système', 'システム', 'Sistema')) {
    $rows = @(New-Rows -PolicyTarget $word -Setting 3 -Count 64) + @(New-Rows -PolicyTarget 'CONTOSO\alice' -Setting 1 -Count 64)
    $t = Get-ChosenTarget -AllRows $rows
    Assert-That "a '$word' system target is selected" (($t -join ',') -eq $word) "(got '$($t -join ',')')"
}

'[auditpol] the ordinary and degenerate shapes are unchanged'
# One target only: nothing to filter, every row is the system policy.
$single = @(New-Rows -PolicyTarget 'System' -Setting 3 -Count 64)
Assert-That 'a single-target backup is left alone' (((Get-ChosenTarget -AllRows $single) -join ',') -eq 'System')
# The common real case: per-user policy configured for a handful of subcategories.
$typical = @(New-Rows -PolicyTarget 'System' -Setting 3 -Count 64) + @(New-Rows -PolicyTarget 'CONTOSO\alice' -Setting 1 -Count 2)
Assert-That 'the ordinary per-user case still resolves to System' (((Get-ChosenTarget -AllRows $typical) -join ',') -eq 'System')
# An export with no Policy Target column at all must not be filtered to nothing.
$noTarget = @(New-Rows -PolicyTarget 'System' -Setting 3 -Count 8)
$allRows = @($noTarget); $columnCount = 3
Invoke-Expression $script:selection | Out-Null
Assert-That 'a backup without the target column keeps its rows' (@($rows).Count -eq 8) "(got $(@($rows).Count))"

'[auditpol] a backup whose targets are ALL user-shaped is still readable'
# Defensive: if the filter would remove everything, it must not - an unusual export should stay
# readable rather than being reduced to nothing, which would report every subcategory as unread.
$allUser = @(New-Rows -PolicyTarget 'CONTOSO\alice' -Setting 3 -Count 64) + @(New-Rows -PolicyTarget 'CONTOSO\bob' -Setting 1 -Count 8)
$t = Get-ChosenTarget -AllRows $allUser
Assert-That 'some target is still selected' ($t.Count -eq 1) "(got '$($t -join ',')')"
$v = Get-SettingFor -AllRows $allUser -Guid $requiredGuid
Assert-That '  ...and its rows are readable' ($v.Count -ge 1) "(got '$($v -join ',')')"

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
