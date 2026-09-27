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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/nullproducts') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/nullproducts-editions') | Out-Null

function Invoke-NullproductsLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/nullproducts-editions/$Job.console.log"
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
    $requiredBands = if ($EditionsOnly) { @('B37') } else { @('B37', 'B00') }
    foreach ($band in $requiredBands) {
        foreach ($predecessor in $graph[$band].Predecessors) {
            if (-not $SkipVolumeBuild -and $predecessor -eq 'B37') { continue }
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-NullproductsLatexmk -Source $graph['B37'].Source -Job '_B37'
    }
    & $Python (Join-Path $PSScriptRoot 'nullproducts-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Nullproducts import preparation failed.' }
    Invoke-NullproductsLatexmk -Source 'editions/b37-nullproducts-proofs.tex' -Job '_B37-nullproducts-proofs' -Directory 'registry/nullproducts'
    & $Python (Join-Path $PSScriptRoot 'nullproducts-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'Null-product reading import preparation failed.' }
    Invoke-NullproductsLatexmk -Source 'editions/b37-nullproducts-reading.tex' -Job '_B37-nullproducts-reading' -Directory 'registry/nullproducts'
    & $Python (Join-Path $PSScriptRoot 'nullproducts-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Nullproducts source, identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-NullproductsLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/nullproducts/_B37-nullproducts-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
    }
    if (-not $SkipMain) {
        Invoke-NullproductsLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B37') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B37')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B37', '--nullproducts')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Nullproducts publication or link audit failed.' }
    }
    Write-Host 'Nullproducts companion build and audits completed.'
} finally { Pop-Location }
