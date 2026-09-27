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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/compactness') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/compactness-editions') | Out-Null

function Invoke-CompactnessLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/compactness-editions/$Job.console.log"
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
    $requiredBands = if ($EditionsOnly) { @('B47') } else { @('B47', 'B00') }
    foreach ($band in $requiredBands) {
        foreach ($predecessor in $graph[$band].Predecessors) {
            if (-not $SkipVolumeBuild -and $predecessor -eq 'B47') { continue }
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
    }
    & $Python (Join-Path $PSScriptRoot 'compactness-editions.py') audit-sources
    if ($LASTEXITCODE -ne 0) { throw 'Compactness source audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-CompactnessLatexmk -Source $graph['B47'].Source -Job '_B47'
    }
    & $Python (Join-Path $PSScriptRoot 'compactness-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Compactness import preparation failed.' }
    Invoke-CompactnessLatexmk -Source 'editions/b47-compactness-proofs.tex' -Job '_B47-compactness-proofs' -Directory 'registry/compactness'
    & $Python (Join-Path $PSScriptRoot 'compactness-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'Compactness reading import preparation failed.' }
    Invoke-CompactnessLatexmk -Source 'editions/b47-compactness-reading.tex' -Job '_B47-compactness-reading' -Directory 'registry/compactness'
    & $Python (Join-Path $PSScriptRoot 'compactness-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Compactness source, identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-CompactnessLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/compactness/_B47-compactness-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
    }
    if (-not $SkipMain) {
        Invoke-CompactnessLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B47') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B47')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B47', '--compactness')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Compactness publication or link audit failed.' }
    }
    Write-Host 'Compactness companion build and audits completed.'
} finally { Pop-Location }
