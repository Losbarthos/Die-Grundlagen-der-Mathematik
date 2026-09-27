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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/integers') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/integers-editions') | Out-Null

function Invoke-IntegersLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/integers-editions/$Job.console.log"
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
    foreach ($predecessor in $graph['B17'].Predecessors) {
        foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
            Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-IntegersLatexmk -Source $graph['B17'].Source -Job '_B17'
    }
    & $Python (Join-Path $PSScriptRoot 'integers-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Integer import preparation failed.' }
    Invoke-IntegersLatexmk -Source 'editions/b17-integers-proofs.tex' -Job '_B17-integers-proofs' -Directory 'registry/integers'
    & $Python (Join-Path $PSScriptRoot 'integers-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'Integer proof-reference preparation failed.' }
    Invoke-IntegersLatexmk -Source 'editions/b17-integers-reading.tex' -Job '_B17-integers-reading' -Directory 'registry/integers'
    # B41 is refreshed below (or later by build-all). Check its return links
    # only after that stage so a stale reading cannot block its own rebuild.
    & $Python (Join-Path $PSScriptRoot 'integers-editions.py') audit --skip-group-navigation
    if ($LASTEXITCODE -ne 0) { throw 'Integer identity or PDF audit failed.' }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/integers/_B17-integers-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        if ($edition -eq 'proofs') {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '17E'
        } else {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux"
        }
    }
    if (-not $EditionsOnly) {
        # Its reading now uses the completed integer construction as a
        # prerequisite. Reuse B41 while refreshing both of its companions.
        & (Join-Path $PSScriptRoot 'build-differences-editions.ps1') -EditionsOnly -Python $Python
        & $Python (Join-Path $PSScriptRoot 'integers-editions.py') audit
        if ($LASTEXITCODE -ne 0) { throw 'Integer reciprocal-navigation audit failed.' }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-IntegersLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    if (-not $SkipMain) {
        Invoke-IntegersLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B17', 'B00') -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @('B17', 'B00')
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands', 'B00', 'B17', '--integers', '--differences')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Integer publication or link audit failed.' }
    }
    Write-Host 'Integer companion build and audits completed.'
} finally { Pop-Location }
