[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipVolumeBuild,
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command 'latexmk'
Assert-Command 'lualatex'
Assert-Command 'pdftotext'
Assert-Command $Python

function Invoke-ECoordinatesLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/e-coordinates-edition/$Job.console.log"
    Write-Host "Building $Job (log: $log)"
    & latexmk -norc -g -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$Job" "-outdir=$Directory" $Source *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $log -Tail 55 | Write-Host
        throw "Build failed for $Job"
    }
}

Push-Location $repoRoot
try {
    $graph = Read-BandDependencyGraph -Path $dependencyFile
    foreach ($predecessor in $graph['B28'].Predecessors) {
        foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
            Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
        }
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/e-coordinates') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/e-coordinates-edition') | Out-Null
    if (-not $SkipVolumeBuild) {
        Invoke-ECoordinatesLatexmk -Source $graph['B28'].Source -Job '_B28'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B28')
    }
    foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
        Assert-Artifact -RelativePath "$($graph['B28'].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
    }
    & $Python -B (Join-Path $PSScriptRoot 'e-coordinates-edition.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'E-coordinate source extraction or import preparation failed.' }

    $started = Get-Date
    Invoke-ECoordinatesLatexmk -Source 'editions/b28-e-coordinates.tex' -Job '_B28-e-coordinates' -Directory 'registry/e-coordinates'
    $base = 'registry/e-coordinates/_B28-e-coordinates'
    foreach ($extension in @('aux', 'pdf', 'log')) {
        Assert-Artifact -RelativePath "$base.$extension" -NotBefore $started
    }
    Assert-Artifact -RelativePath "$base.registry.tsv" -NotBefore $started -AllowEmpty
    Assert-CleanLog -RelativePath "$base.log"
    Assert-CleanDebugLog -RelativePath "$base.debug.log"
    Assert-CleanPdfText -RelativePath "$base.pdf"
    & $Python -B (Join-Path $PSScriptRoot 'e-coordinates-edition.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'E-coordinate source, identity or PDF audit failed.' }

    # The canonical section has no reverse links to this extract. No overview
    # or main rebuild is needed; publish B28 only if it was rebuilt here.
    if (-not $SkipPublish) {
        $publishArguments = @('-B', (Join-Path $PSScriptRoot 'publish-pdfs.py'))
        if ($SkipVolumeBuild) {
            $publishArguments += '--e-coordinates-only'
        } else {
            $publishArguments += @('--bands', 'B28', '--skip-main', '--e-coordinates')
        }
        & $Python @publishArguments
        if ($LASTEXITCODE -ne 0) { throw 'E-coordinate publication or link audit failed.' }
    }
    Write-Host 'E-coordinate companion build and audits completed.'
} finally { Pop-Location }
