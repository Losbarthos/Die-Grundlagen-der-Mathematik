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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/mogiljanskaja') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/mogiljanskaja-editions') | Out-Null

function Invoke-MogiljanskajaLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/mogiljanskaja-editions/$Job.console.log"
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
    # A targeted build reuses already built predecessors. build-all.ps1 builds
    # the full dependency graph in order, then calls this with -EditionsOnly.
    $requiredBands = @('B21', 'B28')
    if (-not $EditionsOnly) { $requiredBands += @('B37', 'B00') }
    foreach ($band in $requiredBands) {
        foreach ($predecessor in $graph[$band].Predecessors) {
            if (-not $SkipVolumeBuild -and $predecessor -in @('B21', 'B28', 'B37')) { continue }
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-MogiljanskajaLatexmk -Source $graph['B21'].Source -Job '_B21'
        Invoke-MogiljanskajaLatexmk -Source $graph['B28'].Source -Job '_B28'
    }
    & $Python (Join-Path $PSScriptRoot 'mogiljanskaja-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Mogiljanskaja import preparation failed.' }
    Invoke-MogiljanskajaLatexmk -Source 'editions/b28-mog-proofs.tex' -Job '_B28-mog-proofs' -Directory 'registry/mogiljanskaja'
    & $Python (Join-Path $PSScriptRoot 'mogiljanskaja-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'Mogiljanskaja proof-reference preparation failed.' }
    Invoke-MogiljanskajaLatexmk -Source 'editions/b28-mog-reading.tex' -Job '_B28-mog-reading' -Directory 'registry/mogiljanskaja'
    & $Python (Join-Path $PSScriptRoot 'mogiljanskaja-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Mogiljanskaja identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-MogiljanskajaLatexmk -Source $graph['B37'].Source -Job '_B37'
        Invoke-MogiljanskajaLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/mogiljanskaja/_B28-mog-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        if ($edition -eq 'proofs') {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '28E'
        } else {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux"
        }
    }
    if (-not $SkipMain) {
        Invoke-MogiljanskajaLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B21', 'B28', 'B37') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B21', 'B28', 'B37')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B21', 'B28', 'B37', '--mogiljanskaja')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Mogiljanskaja publication or link audit failed.' }
    }
    Write-Host 'Mogiljanskaja companion build and audits completed.'
} finally { Pop-Location }
