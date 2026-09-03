[CmdletBinding()]
param(
    [ValidatePattern('^B[0-9]{2}$')][string]$From = 'B01',
    [ValidatePattern('^B[0-9]{2}$')][string]$To = 'B43',
    [switch]$SkipMain,
    [switch]$SkipRemarkable,
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
$bands = @($graph.Keys | Sort-Object | Where-Object { $_ -ge $From -and $_ -le $To })

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
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($band)
    }
    if (-not $SkipRemarkable) {
        Invoke-LoggedBuild -Source 'Bd. 37 - Endliche Halbgruppen - reMarkable.tex' -JobName '_B37-remarkable'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B37') -IncludeRemarkable
    }
    if (-not $SkipMain) {
        Invoke-LoggedBuild -Source 'main.tex' -JobName 'main' -OutDir '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands $bands -IncludeMain
    }
    if (-not $SkipPublish) {
        $publishArguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'))
        if ($SkipMain) { $publishArguments += '--skip-main' }
        if ($SkipRemarkable) { $publishArguments += '--skip-remarkable' }
        & $Python @publishArguments
        if ($LASTEXITCODE -ne 0) { throw 'PDF publication or link audit failed.' }
    }
    Write-Host "Build completed: $From through $To"
}
finally { Pop-Location }
