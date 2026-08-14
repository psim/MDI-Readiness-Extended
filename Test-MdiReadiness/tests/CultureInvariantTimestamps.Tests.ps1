# Every timestamp the script renders was formatted in the OPERATOR'S culture.
#
#  w73-F1  A date format string carries no culture of its own. `.ToString('yyyy-MM-dd HH:mm:ss')`
#          formats through CurrentCulture, and that brings the culture's CALENDAR with it. The same
#          instant renders:
#
#              en-US   2026-08-13 19:32:26
#              th-TH   2569-08-13 19:32:26     (Buddhist era)
#              ar-SA   1448-02-30 19:32:26     (Umm al-Qura)
#              fa-IR   1405-05-22 19:32:26     (Persian)
#              fi-FI   2026-08-13 19.32.26     (':' is a PLACEHOLDER for TimeSeparator)
#              oc-FR   2026-08-13 19h32h26
#
#          Measured across every installed culture on this machine: 40 of 915 render the script's own
#          stamp wrongly; 0 of 915 do with InvariantCulture.
#
#          This is not cosmetic, and two of the sites prove why:
#
#          - Get-mdiTimeSync is the CLOCK check. RemoteUtc/ReferenceUtc are the evidence it offers
#            that a domain controller's clock is correct, and under th-TH that evidence was an
#            impossible date. The one check whose entire subject is time got the time wrong.
#          - A stamp is re-read. '2026-08-13 19.32.26' is REFUSED by [datetime]::TryParse, and
#            Get-mdiRunTimestamp returns $null for it - so on 22 cultures the run silently vanishes
#            from the trend. '2569-08-13 19:32:26' parses cleanly to the year 2569 and sorts ahead of
#            every real run forever. Unparseable is bad; parseable-and-wrong is worse.
#
#          The certificate renewal warning had the same fault through the -f operator, which also
#          formats in CurrentCulture: "Root certificate ... expires on 2569-08-23", in a sentence
#          whose only purpose is to convey urgency.
#
# These tests are BEHAVIOURAL, and deliberately so in a specific way: rather than re-implementing the
# formatting (which would pass while the script itself reverted), each rendering expression is LIFTED
# OUT OF THE PARSED SCRIPT and EXECUTED under a hostile culture. The assertion is on the string the
# script's own code produces. Reintroduce the defect anywhere and the lifted expression is the
# defective one, so these fail - which is exactly what the mutation run confirms.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
function Use-Culture {
    param([string] $Name)
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($Name)
}

function Get-ScriptExpression {
    <#
        Every .ToString(...) call in the script whose format string looks like a date, returned as
        source text ready to execute. Taken from the PARSED script, so a decoy inside a comment or a
        string cannot satisfy the test, and returned verbatim so that executing it runs the script's
        OWN rendering rather than a copy of it.
    #>
    param([Parameter(Mandatory = $true)] [string] $ScriptText)

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref] $null, [ref] $null)
    $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Member.Extent.Text -eq 'ToString' -and
            $n.Arguments -and $n.Arguments.Count -ge 1 -and
            $n.Arguments[0].Extent.Text -match "(yyyy|HH:mm|MM-dd)"
        }, $true) | ForEach-Object { $_.Extent.Text }
}

# th-TH shifts the CALENDAR (2026 -> 2569); fi-FI shifts the TIME SEPARATOR (':' -> '.'). Between them
# they cover both ways a format string picks up the ambient culture. ar-SA and fa-IR are the other two
# non-Gregorian calendars present on a default install.
$hostile = @('th-TH', 'fi-FI', 'ar-SA', 'fa-IR')

try {
    '[w73] every date the script renders is invariant, under every hostile culture'
    # The script's own expressions, executed. $remoteTime / $reference / $cert are bound to a known
    # instant so the expected output is exact and the same for all of them.
    $instant = [datetime]::new(2026, 8, 13, 19, 32, 26, [System.DateTimeKind]::Utc)
    $expressions = @(Get-ScriptExpression -ScriptText $full)
    Assert-That 'the script still renders dates somewhere' ($expressions.Count -ge 4) "(found $($expressions.Count))"

    # The expected date is DERIVED, never hard-coded. An expression that reads the live clock
    # ([datetime]::Now / [datetimeoffset]::Now) cannot be bound to $instant, so its correct output is
    # today's date, not $instant's. Hard-coding the author's date made this test pass only on the day
    # it was written and fail from the next midnight onwards.
    $boundDay = $instant.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)

    foreach ($c in $hostile) {
        Use-Culture $c
        $bad = @()
        foreach ($e in $expressions) {
            # Bind the names the script's expressions use.
            $remoteTime = $instant
            $reference = $instant
            $cert = [PSCustomObject]@{ NotAfter = $instant }

            # Straddle the evaluation so a midnight tick mid-run cannot flake the assertion. Read the
            # clock the same way the expression does, and in the ambient (hostile) culture - so a
            # culture leak still cannot be papered over by the expectation.
            $isLiveClock = $e -match '::(Now|UtcNow)'
            $isUtc = $e -match '::UtcNow'
            $before = if ($isUtc) { [datetime]::UtcNow } else { [datetime]::Now }
            $rendered = [string] (Invoke-Expression $e)
            $after = if ($isUtc) { [datetime]::UtcNow } else { [datetime]::Now }

            $allowedDays = if ($isLiveClock) {
                @($before.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture),
                  $after.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)) | Select-Object -Unique
            }
            else { @($boundDay) }

            # Gregorian year, ':' as the time separator, '-' as the date separator. Any culture that
            # leaked in changes at least one of the three: th-TH renders the year as 2569, fi-FI
            # renders the time as 00.43.16.
            $dayOk = @($allowedDays | Where-Object { $rendered.StartsWith($_, [System.StringComparison]::Ordinal) }).Count -gt 0
            if (-not $dayOk) { $bad += "$c -> '$rendered' (expected day one of $($allowedDays -join '/'))  [$e]" }
            elseif ($rendered -match '\d\d[.h]\d\d[.h]\d\d') { $bad += "$c -> '$rendered'  [$e]" }
        }
        Assert-That "  all $($expressions.Count) rendered dates are correct under $c" ($bad.Count -eq 0) `
            "($($bad.Count) wrong: $(($bad | Select-Object -First 2) -join ' | '))"
    }
    Use-Culture 'en-US'

    # Positive control: the same renderings WITHOUT InvariantCulture must be rejected by the checks
    # above. Without this, a rewrite that loosened the checks would still show green.
    Use-Culture 'th-TH'
    $leakThai = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    Use-Culture 'fi-FI'
    $leakFinnish = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    Use-Culture 'en-US'
    $todayInvariant = [datetime]::Now.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    Assert-That '  a th-TH culture leak would still be caught (Buddhist year)' `
        (-not $leakThai.StartsWith($todayInvariant, [System.StringComparison]::Ordinal)) "(leaked: '$leakThai')"
    Assert-That '  a fi-FI culture leak would still be caught (dot time separator)' `
        ($leakFinnish -match '\d\d[.h]\d\d[.h]\d\d') "(leaked: '$leakFinnish')"

    '[w73] the certificate renewal warning states a real date'
    # The -f operator formats in CurrentCulture too, so the warning sentence is lifted and executed
    # the same way. Located by its own text so a rewrite that keeps the sentence keeps the test.
    $warnLine = @($full -split "`r?`n" | Where-Object { $_ -match 'renew it before it lapses' -and $_ -notmatch '^\s*#' })
    Assert-That 'the renewal warning still exists' ($warnLine.Count -ge 1)
    foreach ($c in $hostile) {
        Use-Culture $c
        $cert = [PSCustomObject]@{ Thumbprint = 'ABC123'; Subject = 'CN=Contoso Root'; NotAfter = $instant }
        $joined = ($warnLine -join ' ')
        $exprText = [regex]::Match($joined, "\('Root certificate.*lapses\.'\s*-f[^)]*\)").Value
        if (-not $exprText) {
            # Wrapped across lines: rebuild from the parsed script instead.
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($full, [ref] $null, [ref] $null)
            $node = $ast.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and
                    $n.Operator -eq 'Format' -and $n.Extent.Text -match 'renew it before it lapses'
                }, $true) | Select-Object -First 1
            $exprText = $node.Extent.Text
        }
        $rendered = [string] (Invoke-Expression $exprText)
        Assert-That "  renewal warning is dated invariantly under $c" (
            $rendered -match 'expires on 2026-08-13;') "(got '$rendered')"
    }
    Use-Culture 'en-US'

    '[w73] every stamp the script writes survives being read back'
    # The property that actually matters: a stamp written under ANY culture must be re-readable by the
    # trend reader, and must come back as the SAME instant. This catches both failure modes at once -
    # unparseable (the run is dropped) and parseable-but-wrong (the year 2569 sorts ahead forever).
    $stampExpr = @($expressions | Where-Object { $_ -match "yyyy-MM-dd HH:mm:ss" }) | Select-Object -First 1
    Assert-That 'the script writes a full timestamp somewhere' ($null -ne $stampExpr) "(none found)"
    foreach ($c in @('en-US') + $hostile) {
        Use-Culture $c
        $remoteTime = $instant; $reference = $instant
        $stamp = [string] (Invoke-Expression $stampExpr)
        Use-Culture 'en-US'
        $back = Get-mdiRunTimestamp -Value $stamp
        Assert-That "  a stamp written under $c is still readable" ($null -ne $back) "(stamp '$stamp')"
        Assert-That "    ...and is the same instant under $c" (
            $null -ne $back -and ([datetime] $back).Year -eq 2026 -and
            ([datetime] $back).Month -eq 8 -and ([datetime] $back).Day -eq 13) "(stamp '$stamp' -> $back)"
    }
    Use-Culture 'en-US'

    '[w73] no date is rendered through the ambient culture anywhere in the script'
    # The CLASS, not the five instances. A date format string with no explicit culture is the defect;
    # this fails on the next one added, wherever it is added.
    $lines = $full -split "`r?`n"
    $offenders = @()
    for ($n = 0; $n -lt $lines.Count; $n++) {
        $l = $lines[$n]
        if ($l -match '^\s*#') { continue }
        if ($l -match "ToString\('[^']*(yyyy|MM|dd|HH|mm|ss)[^']*'\s*\)" -and $l -notmatch 'InvariantCulture|CultureInfo') {
            $offenders += "L$($n + 1): $($l.Trim())"
        } elseif ($l -match "\{\d+:(yyyy|HH|MM|dd)[^}]*\}" -and $l -notmatch 'InvariantCulture') {
            $offenders += "L$($n + 1): $($l.Trim())"
        }
    }
    Assert-That 'every date rendering names its culture' ($offenders.Count -eq 0) `
        "($($offenders.Count) site(s): $(($offenders | Select-Object -First 3) -join ' | '))"

    '[w73] the invariant form is correct on EVERY installed culture'
    # The measurement that decided the fix: not a sample of cultures, all of them.
    $all = [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::AllCultures)
    $expected = '2026-08-13 19:32:26'
    $wrong = 0
    foreach ($ci in $all) {
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
            if ($instant.ToString('yyyy-MM-dd HH:mm:ss', [cultureinfo]::InvariantCulture) -ne $expected) { $wrong++ }
        } catch { }
    }
    Use-Culture 'en-US'
    Assert-That "the invariant stamp is identical across all $($all.Count) installed cultures" ($wrong -eq 0) "($wrong wrong)"
} finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
}

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
