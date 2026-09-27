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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/bracketing') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/bracketing-editions') | Out-Null

function Invoke-BracketingLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/bracketing-editions/$Job.console.log"
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
    # Reuse existing predecessor artifacts; build-all invokes -EditionsOnly
    # after building the dependency graph in its canonical order.
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
        Invoke-BracketingLatexmk -Source $graph['B28'].Source -Job '_B28'
    }
    & $Python (Join-Path $PSScriptRoot 'bracketing-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Bracketing import preparation failed.' }
    Invoke-BracketingLatexmk -Source 'editions/b28-bracketing-proofs.tex' -Job '_B28-bracketing-proofs' -Directory 'registry/bracketing'
    & $Python (Join-Path $PSScriptRoot 'bracketing-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'Bracketing proof-reference preparation failed.' }
    Invoke-BracketingLatexmk -Source 'editions/b28-bracketing-reading.tex' -Job '_B28-bracketing-reading' -Directory 'registry/bracketing'
    & $Python (Join-Path $PSScriptRoot 'bracketing-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Bracketing identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-BracketingLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/bracketing/_B28-bracketing-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '28'
    }
    if (-not $SkipMain) {
        Invoke-BracketingLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B28') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B28')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B28', '--bracketing-editions')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Bracketing publication or link audit failed.' }
    }
    Write-Host 'Bracketing companion build and audits completed.'
} finally { Pop-Location }
