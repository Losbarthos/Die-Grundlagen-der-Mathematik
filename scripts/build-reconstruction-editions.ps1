[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$EditionsOnly,
    [switch]$SkipVolumeBuild,
    [switch]$SkipMain,
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($EditionsOnly) {
    $SkipVolumeBuild = $true
    $SkipMain = $true
    $SkipPublish = $true
}
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command 'latexmk'
Assert-Command 'lualatex'
Assert-Command 'pdftotext'
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/reconstruction') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/reconstruction-editions') | Out-Null

function Invoke-ReconstructionLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/reconstruction-editions/$Job.console.log"
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
    # build-all invokes -EditionsOnly after building the canonical dependencies.
    $requiredBands = if ($EditionsOnly) { @('B40') } else { @('B40', 'B00') }
    foreach ($band in $requiredBands) {
        foreach ($predecessor in $graph[$band].Predecessors) {
            if (-not $SkipVolumeBuild -and $predecessor -eq 'B40') { continue }
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-ReconstructionLatexmk -Source $graph['B40'].Source -Job '_B40'
    }
    & $Python (Join-Path $PSScriptRoot 'reconstruction-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Reconstruction import preparation failed.' }
    foreach ($edition in @('proofs', 'reading')) {
        Invoke-ReconstructionLatexmk -Source "editions/b40-reconstruction-$edition.tex" -Job "_B40-reconstruction-$edition" -Directory 'registry/reconstruction'
    }
    & $Python (Join-Path $PSScriptRoot 'reconstruction-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Reconstruction source, identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-ReconstructionLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/reconstruction/_B40-reconstruction-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
    }
    if (-not $SkipMain) {
        Invoke-ReconstructionLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B40') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B40')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B40', '--reconstruction')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Reconstruction publication or link audit failed.' }
    }
    Write-Host 'Reconstruction companion build and audits completed.'
} finally { Pop-Location }
