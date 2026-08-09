$sp = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($sp,[ref]$t,[ref]$e)
if($e){ "PARSE ERRORS:"; $e | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Message)" }; exit 1 }
"PARSE OK"
# The raw text, for the rules that look for a calling idiom rather than a syntax shape. Rule 14 read
# this before it was ever assigned, so its test was "$null -match ..." and the rule could not fire:
# a deliberate comma-operator return with an @()-wrapping caller passed it cleanly.
$source = Get-Content $sp -Raw
# Find method invocations whose argument list contains a bare (unparenthesized) -f binary expression.
# PowerShell parses the commas of `-f a, b` as *method* argument separators, silently breaking the format.
$bad = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
  Where-Object {
    $_.Arguments -and @($_.Arguments).Count -gt 1 -and
    @($_.Arguments | Where-Object { $_ -is [System.Management.Automation.Language.BinaryExpressionAst] -and $_.Operator -eq 'Format' }).Count -gt 0
  }
if ($bad) {
  "FOUND $(@($bad).Count) unparenthesized -f inside method call(s):"
  $bad | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text.Substring(0,[Math]::Min(110,$_.Extent.Text.Length)) -replace '\r?\n',' ')" }
  exit 1
} else { "No unparenthesized -f inside method calls" }
# Also verify every -f format string has enough arguments for its highest placeholder index
$fmts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -eq 'Format' }, $true)
$mismatch = 0
foreach ($f in $fmts) {
  if ($f.Left -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
  $s = $f.Left.Value
  $idx = ([regex]::Matches($s,'(?<!\{)\{(\d+)[^}]*\}') | ForEach-Object { [int]$_.Groups[1].Value })
  if (-not $idx) { continue }
  $need = ($idx | Measure-Object -Maximum).Maximum + 1
  $have = if ($f.Right -is [System.Management.Automation.Language.ArrayLiteralAst]) { @($f.Right.Elements).Count } else { 1 }
  if ($have -lt $need) { "  L$($f.Extent.StartLineNumber): needs $need args, has $have -> $($s.Substring(0,[Math]::Min(70,$s.Length)))"; $mismatch++ }
}
if ($mismatch) { "FOUND $mismatch format/arg mismatches"; exit 1 } else { "All -f format strings have enough arguments ($($fmts.Count) checked)" }
# Numeric-cast followed by string concatenation: '[int]$x + "/"' evaluates left to right and throws
# "Cannot convert value ... to type System.Int32". Flag any cast-to-number immediately followed by + '...'.
$castConcat = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -eq 'Plus' -and
    $n.Left -is [System.Management.Automation.Language.ConvertExpressionAst] -and
    $n.Left.Type.TypeName.Name -match '^(int|long|double|decimal|single|float)$' -and
    $n.Right -is [System.Management.Automation.Language.StringConstantExpressionAst]
  }, $true)
if ($castConcat) {
  "FOUND $(@($castConcat).Count) numeric-cast + string concatenation:"
  $castConcat | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text)" }
  exit 1
} else { "No numeric-cast followed by string concatenation" }
# @(... | ConvertFrom-Json) nests the result: Windows PowerShell emits a JSON array as a SINGLE pipeline object,
# so the array subexpression wraps the whole array into one element. Assign first, then wrap.
$jsonNest = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.ArrayExpressionAst] -and
    $n.Extent.Text -match 'ConvertFrom-Json'
  }, $true)
if ($jsonNest) {
  "FOUND $(@($jsonNest).Count) @(...) wrapping a ConvertFrom-Json pipeline:"
  $jsonNest | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text)" }
  exit 1
} else { "No @() wrapping a ConvertFrom-Json pipeline" }
# The format operator binds tighter than +, so `'a {0}' + 'b {1}' -f $x, $y` parses as
# `'a {0}' + ('b {1}' -f $x, $y)`: only the LAST fragment is formatted and every placeholder in the
# earlier fragments renders literally as {0}, {1}.
# The resulting AST is therefore rooted at the +, with the -f on its RIGHT side, so the rule looks
# for a Plus whose right operand is a Format and whose left operand still carries placeholders.
$concatFormat = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -eq 'Plus' -and
    $n.Right -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Right.Operator -eq 'Format' -and
    $n.Left.Extent.Text -match '\{\d+[^}]*\}'
  }, $true)
if ($concatFormat) {
  "FOUND $(@($concatFormat).Count) -f applied to a string concatenation (only the last fragment is formatted):"
  $concatFormat | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text.Substring(0,[Math]::Min(110,$_.Extent.Text.Length)) -replace '\r?\n',' ')" }
  exit 1
} else { "No -f applied to an unparenthesized string concatenation" }
# A command whose name begins with '-' is a broken line continuation: PowerShell parses the parameter
# as a command name, so the script parses cleanly and then fails at run time with
# "The term '-Filter' is not recognized". Cheap to detect, and invisible to a parse check.
$dashCommands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
  Where-Object { $_.GetCommandName() -and $_.GetCommandName().StartsWith('-') }
if ($dashCommands) {
  "FOUND $(@($dashCommands).Count) command(s) whose name starts with '-' (broken line continuation):"
  $dashCommands | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text -replace '\r?\n',' ')" }
  exit 1
} else { "No commands with a parameter as the command name" }
# Comparing a value that may be $true/$false against the string 'N/A' silently coerces: PowerShell casts
# the RIGHT operand to the type of the LEFT, and [bool]'N/A' is $true, so `$true -ne 'N/A'` is FALSE.
# A tri-state value must be cast to [string] before it is compared against 'N/A'.
$naCompare = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and
    $n.Operator -in @('Ine', 'Ieq', 'Cne', 'Ceq') -and
    $n.Right.Extent.Text -match "^'N/A'$" -and
    $n.Left.Extent.Text -notmatch '^\[string\]' -and
    # A literal string on the left is safe. Anything else may be tri-state: a variable holding $true
    # compared against 'N/A' is TRUE, because PowerShell casts the right operand to the left's type and
    # [bool]'N/A' is $true. Property access and plain variables are both caught.
    $n.Left -isnot [System.Management.Automation.Language.StringConstantExpressionAst]
  }, $true) | Where-Object {
    # An explicit `-is [string]` test on the same value in the same expression already proves the type,
    # so the comparison cannot be tri-state. Without this the rule flags its own remedy.
    $enclosing = $_.Parent
    $guarded = $false
    while ($enclosing -and -not $guarded) {
      if ($enclosing.Extent.Text -match [regex]::Escape($_.Left.Extent.Text) + '\s+-is\s+\[string\]') { $guarded = $true }
      if ($enclosing -is [System.Management.Automation.Language.StatementAst]) { break }
      $enclosing = $enclosing.Parent
    }
    -not $guarded
  }
if ($naCompare) {
  "FOUND $(@($naCompare).Count) comparison(s) against 'N/A' without a [string] cast:"
  $naCompare | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text)" }
  exit 1
} else { "No unguarded comparisons against 'N/A'" }
# Concatenating report collections with + breaks when a domain has exactly one server: the property is
# then a bare PSObject rather than an array, and PSObject + PSObject throws "does not contain a method
# named op_Addition". Every operand must be wrapped in @() first. This fired in four places at once
# (readiness verdict, remediation generator, statistics, HTML report) and is invisible in a multi-DC lab.
$bareConcat = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -eq 'Plus' -and
    $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and
    $n.Right -is [System.Management.Automation.Language.MemberExpressionAst] -and
    $n.Left.Extent.Text -match '\.(DomainControllers|CAServers|EntraConnectServers)$'
  }, $true)
if ($bareConcat) {
  "FOUND $(@($bareConcat).Count) unwrapped collection concatenation(s) (breaks with a single server):"
  $bareConcat | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text -replace '\r?\n',' ')" }
  exit 1
} else { "No unwrapped report collection concatenations" }
# Assigning to an automatic variable shadows engine state. $error is the error history, $host the host
# object, $input the pipeline: writing to them inside a function produces effects far from the
# assignment and is very hard to trace back.
$autoVars = 'error','host','input','matches','args','this','true','false','psitem','_'
$shadowed = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
    $n.Left.VariablePath.UserPath.ToLower() -in $autoVars
  }, $true)
if ($shadowed) {
  "FOUND $(@($shadowed).Count) assignment(s) to a PowerShell automatic variable:"
  $shadowed | ForEach-Object { "  L$($_.Extent.StartLineNumber): $($_.Extent.Text -replace '\r?\n',' ')" }
  exit 1
} else { "No assignments to automatic variables" }
# A remote-facing .NET call outside a try aborts the entire run. These fail for ordinary reasons: the
# server is off, a service is stopped, a firewall blocks the port, or rights were revoked.
$remoteCalls = 'Open','OpenRemoteBaseKey','OpenSubKey','GetSubKeyNames','GetValue'
$unguarded = @()
foreach ($n in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
  if ($n.Member.Extent.Text -notin $remoteCalls) { continue }
  $p = $n.Parent; $inTry = $false
  while ($p) { if ($p -is [System.Management.Automation.Language.TryStatementAst]) { $inTry = $true; break }; $p = $p.Parent }
  if (-not $inTry) { $unguarded += "  L$($n.Extent.StartLineNumber): $($n.Extent.Text -replace '\r?\n',' ')" }
}
if ($unguarded) {
  "FOUND $(@($unguarded).Count) unguarded remote .NET call(s):"
  $unguarded
  exit 1
} else { "No unguarded remote .NET calls" }
# A throw inside a finally REPLACES the original exception and unwinds the caller, so a failure to
# release a handle turns a recoverable error into a lost run. Found live: disposing a lazily bound
# DirectoryEntry raised "There is no such object on the server" from a finally and discarded the whole
# forest scan after it had completed. Cleanup must never throw.
$unguardedCleanup = @()
foreach ($try in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] -and $n.Finally }, $true)) {
  $fin = $try.Finally
  foreach ($call in $fin.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
    if ($call.Member.Extent.Text -notin @('Close','Dispose')) { continue }
    $p = $call.Parent; $guarded = $false
    while ($p -and $p -ne $fin) {
      if ($p -is [System.Management.Automation.Language.TryStatementAst]) { $guarded = $true; break }
      $p = $p.Parent
    }
    if (-not $guarded) { $unguardedCleanup += "  L$($call.Extent.StartLineNumber): $($call.Extent.Text)" }
  }
}
if ($unguardedCleanup) {
  "FOUND $(@($unguardedCleanup).Count) unguarded cleanup call(s) inside a finally block:"
  $unguardedCleanup
  exit 1
} else { "No unguarded cleanup inside finally blocks" }

# Rule 13: a function must not read a variable that is only assigned inside a DIFFERENT function.
# Found live: the port matrix was changed to filter on $portNotTestedPattern, which is a local of
# Get-mdiReportStatistics. In Get-mdiRequiredPortsHtml it is $null, and "-notmatch $null" matches
# nothing, so every measurable probe would have been reclassified as "Not tested" - the whole port
# table would have gone blank while the KPI still reported numbers. Shared values must be script
# scoped so this cannot happen silently.
$functionAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$crossFunction = @()
foreach ($fn in $functionAsts) {
  # Names assigned anywhere in this function, plus its parameters, are legitimately local.
  # The left side of "$a, $b, $c = ..." is an ArrayLiteralAst, not a VariableExpressionAst, so every
  # target of a multi-variable assignment has to be walked or the rule reports its own blind spot as
  # a bug in the script.
  $assigned = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
      ForEach-Object { $_.Left.FindAll({ param($x) $x -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) } |
      ForEach-Object { $_.VariablePath.UserPath })
  $params = @($fn.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
  foreach ($p in $fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)) {
    $params += $p.Name.VariablePath.UserPath
  }
  # Names bound by foreach and by scriptblock parameters are local too.
  foreach ($fe in $fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
    $assigned += $fe.Variable.VariablePath.UserPath
  }
  foreach ($use in $fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    $name = $use.VariablePath.UserPath
    if ($use.VariablePath.IsGlobal -or $use.VariablePath.IsScript -or $name -like '*:*') { continue }
    if ($name -in $assigned -or $name -in $params) { continue }
    if ($name -in @('_','PSItem','args','input','true','false','null','PSCmdlet','PSBoundParameters','PSScriptRoot','MyInvocation','Host','settings','ErrorActionPreference','ProgressPreference','PSVersionTable','LASTEXITCODE','env','matches','Matches','error','PWD','home','pid')) { continue }
    if ($name -match '^(env|using|script|global|local|private):') { continue }
    # Only flag names that ARE assigned in some other function - an unknown name is a different bug
    # and would drown this rule in noise from automatic variables.
    $ownedElsewhere = $false
    foreach ($other in $functionAsts) {
      if ($other -eq $fn) { continue }
      $otherAssigned = @($other.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
          ForEach-Object { $_.Left.FindAll({ param($x) $x -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) } |
          ForEach-Object { $_.VariablePath.UserPath })
      if ($name -in $otherAssigned) { $ownedElsewhere = $true; break }
    }
    if ($ownedElsewhere) {
      $crossFunction += "  L$($use.Extent.StartLineNumber): `$$name read in $($fn.Name) but only assigned in another function"
    }
  }
}
if ($crossFunction) {
  "FOUND $(@($crossFunction).Count) cross-function variable read(s):"
  $crossFunction | Select-Object -Unique
  exit 1
} else { "No function reads another function's local variable" }

# Rule 14: a function must not return through the comma operator when any caller wraps the call in @().
# ", $x" stops PowerShell unrolling a single-element result, but it turns an EMPTY result into one
# element that IS the empty array - so @(Get-Thing) counts 1 where there are 0. This has now shipped
# THREE times in this file (Get-mdiIssueList, Merge-mdiServerByFqdn, Resolve-mdiLdapTarget), each time
# producing a count that was wrong in the direction of "something is there when nothing is".
# Functions returning a byte[] or a jagged array legitimately need the comma; those are listed.
$commaReturnAllowed = @('New-mdiNetBiosNodeStatusPacket', 'New-mdiDnsQueryPacket', 'New-mdiCldapPingPacket',
  'Invoke-mdiPortProbePlan', 'Get-mdiTrafficSampleSet', 'Get-mdiPortResultRecord')
$commaReturns = @()
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($fn.Name -in $commaReturnAllowed) { continue }
  # The last statement of the body, which is what a PowerShell function returns.
  $stmts = @($fn.Body.EndBlock.Statements)
  if ($stmts.Count -eq 0) { continue }
  $last = $stmts[-1]
  if ($last.Extent.Text -match '^\s*,\s*') {
    # Only a problem if some caller wraps the call in @(), which is the idiom used throughout.
    # The character class after the name has to include ')' and '|': a no-argument call written
    # "@(Get-Thing)" is the commonest form and was missed when only whitespace and '-' were allowed,
    # so the rule stayed silent on exactly the shape it exists to catch.
    if ($source -match ('@\(' + [regex]::Escape($fn.Name) + '\s*[\s\-\)\|]')) {
      $commaReturns += "  L$($last.Extent.StartLineNumber): $($fn.Name) returns with the comma operator but a caller wraps it in @()"
    }
  }
}
if ($commaReturns) {
  "FOUND $(@($commaReturns).Count) comma-operator return(s) with an @()-wrapping caller:"
  $commaReturns
  exit 1
} else { "No comma-operator return is wrapped in @() by a caller" }
