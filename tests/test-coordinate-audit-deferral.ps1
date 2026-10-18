# Exercise the actual build-all routing block while mocking its audit process.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$coordinateProject = Split-Path -Parent $PSScriptRoot
$coordinateScriptPath = Join-Path $coordinateProject 'scripts/build-all.ps1'
$coordinateParseTokens = $null
$coordinateParseErrors = $null
$coordinateAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $coordinateScriptPath, [ref]$coordinateParseTokens, [ref]$coordinateParseErrors)
if ($coordinateParseErrors.Count) { throw ($coordinateParseErrors | Out-String) }
$coordinateRoute = $coordinateAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
    $node.Extent.Text.StartsWith('foreach ($deferredBand in $deferredCoordinatesAudits)')
}, $true)
if (-not $coordinateRoute) { throw 'Coordinate audit deferral block missing.' }
$coordinateAuditCall = '& (Join-Path $PSScriptRoot ''audit-build.ps1'') -Bands @($deferredBand)'
$coordinateMockedRoute = $coordinateRoute.Extent.Text.Replace(
    $coordinateAuditCall, '[void]$coordinateAuditResults.Add($deferredBand)')
if ($coordinateMockedRoute -eq $coordinateRoute.Extent.Text) { throw 'Audit process mock did not bind.' }
$coordinateRouteBlock = [scriptblock]::Create($coordinateMockedRoute)
$coordinateCases = @(
    @{ Name='Fresh full B00: B28 waits for B33 bracketing after zero transport'; Band='B28';
       NeedsBracketing=$true; BracketingBuilt=$false; NeedsZero=$true; ZeroBuilt=$false;
       Bracket='B28'; Zero=''; Audit='' },
    @{ Name='Pending zero transport without pending bracketing'; Band='B28';
       NeedsBracketing=$false; BracketingBuilt=$false; NeedsZero=$true; ZeroBuilt=$false;
       Bracket=''; Zero='B28'; Audit='' },
    @{ Name='Partial range with all B28 companions already built'; Band='B28';
       NeedsBracketing=$true; BracketingBuilt=$true; NeedsZero=$true; ZeroBuilt=$true;
       Bracket=''; Zero=''; Audit='B28' },
    @{ Name='B31 can be audited after its own coordinate editions'; Band='B31';
       NeedsBracketing=$true; BracketingBuilt=$false; NeedsZero=$true; ZeroBuilt=$false;
       Bracket=''; Zero=''; Audit='B31' }
)
foreach ($coordinateCase in $coordinateCases) {
    $deferredCoordinatesAudits = [System.Collections.Generic.List[string]]::new()
    $deferredCoordinatesAudits.Add($coordinateCase.Band)
    $deferredBracketingAudits = [System.Collections.Generic.List[string]]::new()
    $deferredZeroTransportAudits = [System.Collections.Generic.List[string]]::new()
    $coordinateAuditResults = [System.Collections.Generic.List[string]]::new()
    $needsBracketing = $coordinateCase.NeedsBracketing
    $bracketingBuilt = $coordinateCase.BracketingBuilt
    $needsZeroTransport = $coordinateCase.NeedsZero
    $zeroTransportBuilt = $coordinateCase.ZeroBuilt
    & $coordinateRouteBlock
    if (($deferredBracketingAudits -join ',') -ne $coordinateCase.Bracket -or
        ($deferredZeroTransportAudits -join ',') -ne $coordinateCase.Zero -or
        ($coordinateAuditResults -join ',') -ne $coordinateCase.Audit) {
        throw "Incorrect coordinate audit routing: $($coordinateCase.Name)"
    }
    Write-Output "Passed: $($coordinateCase.Name)"
}
