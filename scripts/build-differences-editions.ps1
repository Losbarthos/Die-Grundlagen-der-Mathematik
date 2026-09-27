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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/differences') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/differences-editions') | Out-Null

function Invoke-DifferencesLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/differences-editions/$Job.console.log"
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
    foreach ($predecessor in $graph['B41'].Predecessors) {
        foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
            Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-DifferencesLatexmk -Source $graph['B41'].Source -Job '_B41'
    }
    & $Python (Join-Path $PSScriptRoot 'differences-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Differences import preparation failed.' }
    Invoke-DifferencesLatexmk -Source 'editions/b41-differences-proofs.tex' -Job '_B41-differences-proofs' -Directory 'registry/differences'
    & $Python (Join-Path $PSScriptRoot 'differences-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'Differences proof-reference preparation failed.' }
    Invoke-DifferencesLatexmk -Source 'editions/b41-differences-reading.tex' -Job '_B41-differences-reading' -Directory 'registry/differences'
    & $Python (Join-Path $PSScriptRoot 'differences-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Differences identity or PDF audit failed.' }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/differences/_B41-differences-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        if ($edition -eq 'proofs') {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '41E'
        } else {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux"
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-DifferencesLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    if (-not $SkipMain) {
        Invoke-DifferencesLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B41', 'B00') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B41', 'B00')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B41', '--differences')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Differences publication or link audit failed.' }
    }
    Write-Host 'Formal-difference companion build and audits completed.'
} finally { Pop-Location }
