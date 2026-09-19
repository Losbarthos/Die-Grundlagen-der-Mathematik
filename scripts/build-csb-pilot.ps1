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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/csb') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/csb-pilot') | Out-Null

function Invoke-CsbLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/csb-pilot/$Job.console.log"
    Write-Host "Building $Job (log: $log)"
    & latexmk -norc -gg -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$Job" "-outdir=$Directory" $Source *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $log -Tail 55 | Write-Host
        throw "Build failed for $Job"
    }
}

Push-Location $repoRoot
try {
    $graph = Read-BandDependencyGraph -Path $dependencyFile
    # This targeted build uses existing predecessors. build-all.ps1 prepares
    # them in dependency order on a completely clean repository.
    $requiredBands = @('B08', 'B11')
    if (-not $EditionsOnly) { $requiredBands += 'B00' }
    foreach ($band in $requiredBands) {
        foreach ($predecessor in $graph[$band].Predecessors) {
            if (-not $SkipVolumeBuild -and $predecessor -in @('B08', 'B11')) { continue }
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-CsbLatexmk -Source $graph['B08'].Source -Job '_B08'
        Invoke-CsbLatexmk -Source $graph['B11'].Source -Job '_B11'
    }
    & $Python (Join-Path $PSScriptRoot 'csb-pilot.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'CSB import preparation failed.' }
    foreach ($edition in @('reading', 'proofs')) {
        Invoke-CsbLatexmk -Source "editions/b08-csb-$edition.tex" -Job "_B08-csb-$edition" -Directory 'registry/csb'
    }
    & $Python (Join-Path $PSScriptRoot 'csb-pilot.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'CSB identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        Invoke-CsbLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/csb/_B08-csb-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux"
    }
    if (-not $SkipMain) {
        Invoke-CsbLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B08', 'B11') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B00', 'B08', 'B11')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B08', 'B11', '--csb-pilot')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'CSB publication or link audit failed.' }
    }
    Write-Host 'CSB pilot build and audits completed.'
} finally { Pop-Location }
