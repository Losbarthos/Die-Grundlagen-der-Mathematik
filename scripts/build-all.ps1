[CmdletBinding()]
param(
    [ValidatePattern('^B[0-9]{2}$')][string]$From = 'B00',
    [ValidatePattern('^B[0-9]{2}$')][string]$To = 'B48',
    [switch]$SkipMain,
    [switch]$SkipPublish,
    [string]$Python = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command 'latexmk'
Assert-Command 'lualatex'
Assert-Command 'pdftotext'
$graph = Read-BandDependencyGraph -Path $dependencyFile
if (-not $graph.ContainsKey($From) -or -not $graph.ContainsKey($To) -or $From -gt $To) {
    throw "Invalid build range: $From through $To"
}
New-Item -ItemType Directory -Force -Path $registryDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/build-all') | Out-Null
$selected = @($graph.Keys | Sort-Object | Where-Object { $_ -ge $From -and $_ -le $To })
# Resuming a publishing build must also refresh the overview's printed references.
if (-not $SkipPublish -and 'B00' -notin $selected -and $graph.ContainsKey('B00')) {
    $selected += 'B00'
}
# The overview is printed first but imports the results of the subject volumes.
$buildOrder = [System.Collections.Generic.List[string]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new()
foreach ($target in $selected) {
    foreach ($candidate in @((Get-TopologicalPredecessors -Band $target -Graph $graph)) + @($target)) {
        if ($candidate -in $selected -and $seen.Add($candidate)) { $buildOrder.Add($candidate) }
    }
}
$bands = @($buildOrder)
# The pilot editions read canonical B08/B11 results, while those volumes link
# back to the editions. Build the editions after the last selected source
# volume or required predecessor, then audit the source volumes' remote links.
# A partial range ending at B08 requires existing B11 artifacts for the pilot's
# application section; the pilot builder checks this without extending the range.
$needsCsbPilot = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B08', 'B11') }).Count -gt 0)
$pilotTriggerBand = $null
if ($needsCsbPilot) {
    $pilotDependencies = @('B08', 'B11') + @($graph['B08'].Predecessors) + @($graph['B11'].Predecessors)
    $pilotTriggerBand = $bands | Where-Object { $_ -in $pilotDependencies } | Select-Object -Last 1
}
$deferredPilotAudits = [System.Collections.Generic.List[string]]::new()
$pilotsBuilt = $false

function Invoke-LoggedBuild {
    param([string]$Source, [string]$JobName, [string]$OutDir = 'registry')
    $consoleLog = Join-Path $repoRoot "tmp/build-all/$JobName.console.log"
    Write-Host "Building $Source (console log: $consoleLog)"
    $arguments = @('-norc', '-gg', '-lualatex', '-interaction=nonstopmode',
        '-halt-on-error', '-file-line-error', "-jobname=$JobName", "-outdir=$OutDir", $Source)
    & latexmk @arguments *> $consoleLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $consoleLog -Tail 60 | Write-Host
        throw "latexmk failed for $Source; see $consoleLog"
    }
}

Push-Location $repoRoot
try {
    if ($needsCsbPilot -and -not $pilotTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-csb-pilot.ps1') -EditionsOnly -Python $Python
        $pilotsBuilt = $true
    }
    foreach ($band in $bands) {
        # Each volume is rebuilt once. A resumed range uses already audited
        # predecessors and never recursively rebuilds the same prefix.
        $record = $graph[$band]
        foreach ($predecessor in $record.Predecessors) {
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
        $started = Get-Date
        Invoke-LoggedBuild -Source $record.Source -JobName "_$band"
        $stage = New-BuildStage -Record $record -Started $started
        Assert-BuildStageArtifacts -Stage $stage
        if ($band -eq $pilotTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-csb-pilot.ps1') -EditionsOnly -Python $Python
            $pilotsBuilt = $true
            foreach ($deferredBand in $deferredPilotAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -in @('B08', 'B11') -and -not $pilotsBuilt) {
            $deferredPilotAudits.Add($band)
        } else {
            & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($band)
        }
    }
    if (-not $SkipMain) {
        Invoke-LoggedBuild -Source 'main.tex' -JobName 'main' -OutDir '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands $bands -IncludeMain
    }
    if (-not $SkipPublish) {
        $publishArguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'))
        if ($SkipMain) { $publishArguments += '--skip-main' }
        & $Python @publishArguments
        if ($LASTEXITCODE -ne 0) { throw 'PDF publication or link audit failed.' }
    }
    Write-Host "Build completed: $From through $To"
}
finally { Pop-Location }
