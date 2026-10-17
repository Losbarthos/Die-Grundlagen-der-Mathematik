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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/power') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/power-editions') | Out-Null

function Invoke-PowerLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/power-editions/$Job.console.log"
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
    $requiredBands = if ($EditionsOnly) { @('B28') } else { @('B28', 'B00') }
    foreach ($band in $requiredBands) {
        foreach ($predecessor in $graph[$band].Predecessors) {
            if (-not $SkipVolumeBuild -and $predecessor -eq 'B28') { continue }
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-PowerLatexmk -Source $graph['B28'].Source -Job '_B28'
    }
    & $Python (Join-Path $PSScriptRoot 'power-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Power-semigroup import preparation failed.' }
    foreach ($edition in @('proofs', 'reading')) {
        Invoke-PowerLatexmk -Source "editions/b28-power-$edition.tex" -Job "_B28-power-$edition" -Directory 'registry/power'
    }
    & $Python (Join-Path $PSScriptRoot 'power-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Power-semigroup source, identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-PowerLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/power/_B28-power-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
    }
    if (-not $SkipMain) {
        Invoke-PowerLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B28') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B28')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B28', '--power')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Power-semigroup publication or link audit failed.' }
    }
    Write-Host 'Power-semigroup companion build and audits completed.'
} finally { Pop-Location }
