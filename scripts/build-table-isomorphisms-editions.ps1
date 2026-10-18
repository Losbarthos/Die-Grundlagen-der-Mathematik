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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/table-isomorphisms') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/table-isomorphisms-editions') | Out-Null

function Invoke-TableIsomorphismsLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/table-isomorphisms-editions/$Job.console.log"
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
    & $Python (Join-Path $PSScriptRoot 'table-isomorphisms-editions.py') prepare-main
    if ($LASTEXITCODE -ne 0) { throw 'Table-isomorphism B37 import preparation failed.' }
    # Reuse existing predecessor artifacts; build-all invokes -EditionsOnly
    # after building the dependency graph in its canonical order.
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
        Invoke-TableIsomorphismsLatexmk -Source $graph['B37'].Source -Job '_B37'
    }
    & $Python (Join-Path $PSScriptRoot 'table-isomorphisms-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'TableIsomorphisms import preparation failed.' }
    Invoke-TableIsomorphismsLatexmk -Source 'editions/b37-table-isomorphisms-proofs.tex' -Job '_B37-table-isomorphisms-proofs' -Directory 'registry/table-isomorphisms'
    & $Python (Join-Path $PSScriptRoot 'table-isomorphisms-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'TableIsomorphisms proof-reference preparation failed.' }
    Invoke-TableIsomorphismsLatexmk -Source 'editions/b37-table-isomorphisms-reading.tex' -Job '_B37-table-isomorphisms-reading' -Directory 'registry/table-isomorphisms'
    & $Python (Join-Path $PSScriptRoot 'table-isomorphisms-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'TableIsomorphisms identity or PDF audit failed.' }
    if (-not $EditionsOnly) {
        # The B37 registry and the overview reading changed together.
        & (Join-Path $PSScriptRoot 'build-nullproducts-editions.ps1') -EditionsOnly -SkipTableIsomorphismsBuild -Python $Python
    }
    if (-not $SkipVolumeBuild) {
        Invoke-TableIsomorphismsLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/table-isomorphisms/_B37-table-isomorphisms-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '37'
    }
    if (-not $SkipMain) {
        Invoke-TableIsomorphismsLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B37') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B37')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B37', '--table-isomorphisms-editions', '--nullproducts', '--zero-transport', '--finite-semigroups')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'TableIsomorphisms publication or link audit failed.' }
    }
    Write-Host 'TableIsomorphisms companion build and audits completed.'
} finally { Pop-Location }
