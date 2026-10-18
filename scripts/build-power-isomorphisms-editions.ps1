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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/power-isomorphisms') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/power-isomorphisms-editions') | Out-Null

function Invoke-PowerIsomorphismsLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/power-isomorphisms-editions/$Job.console.log"
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
    & $Python (Join-Path $PSScriptRoot 'power-isomorphisms-editions.py') prepare-main
    if ($LASTEXITCODE -ne 0) { throw 'Power-isomorphism B28 import preparation failed.' }
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
        Invoke-PowerIsomorphismsLatexmk -Source $graph['B28'].Source -Job '_B28'
    }
    & $Python (Join-Path $PSScriptRoot 'power-isomorphisms-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'PowerIsomorphisms import preparation failed.' }
    Invoke-PowerIsomorphismsLatexmk -Source 'editions/b28-power-isomorphisms-proofs.tex' -Job '_B28-power-isomorphisms-proofs' -Directory 'registry/power-isomorphisms'
    & $Python (Join-Path $PSScriptRoot 'power-isomorphisms-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'PowerIsomorphisms proof-reference preparation failed.' }
    Invoke-PowerIsomorphismsLatexmk -Source 'editions/b28-power-isomorphisms-reading.tex' -Job '_B28-power-isomorphisms-reading' -Directory 'registry/power-isomorphisms'
    & $Python (Join-Path $PSScriptRoot 'power-isomorphisms-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'PowerIsomorphisms identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-PowerIsomorphismsLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/power-isomorphisms/_B28-power-isomorphisms-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '28'
    }
    if (-not $SkipMain) {
        Invoke-PowerIsomorphismsLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B28') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B28')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B28', '--power-isomorphisms-editions')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'PowerIsomorphisms publication or link audit failed.' }
    }
    Write-Host 'PowerIsomorphisms companion build and audits completed.'
} finally { Pop-Location }
