[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$EditionsOnly,
    [switch]$SkipVolumeBuild,
    [switch]$SkipMain,
    [switch]$SkipPublish,
    [ValidatePattern('^B[0-9]{2}$')][string[]]$AffectedBands = @(
        'B15', 'B16', 'B17', 'B19', 'B20', 'B21', 'B22', 'B26', 'B27', 'B28',
        'B29', 'B33', 'B34', 'B35', 'B37', 'B38', 'B39', 'B43', 'B47', 'B48'
    )
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
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/dedekind') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/dedekind-editions') | Out-Null

function Invoke-DedekindLatexmk {
    param([string]$Source, [string]$Job, [string]$Directory = 'registry')
    $log = Join-Path $repoRoot "tmp/dedekind-editions/$Job.console.log"
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
    $followingBands = @($AffectedBands | Where-Object { $_ -notin @('B00', 'B10') } | Sort-Object -Unique)
    $auditedBands = @('B10') + $followingBands + @('B00')
    $requiredBands = if ($EditionsOnly) { @('B10') } else { $auditedBands }
    foreach ($band in $requiredBands) {
        if (-not $graph.ContainsKey($band)) { throw "Unknown affected volume: $band" }
        foreach ($predecessor in $graph[$band].Predecessors) {
            if (-not $SkipVolumeBuild -and $predecessor -in $auditedBands) { continue }
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
    }
    if (-not $SkipVolumeBuild) {
        Invoke-DedekindLatexmk -Source $graph['B10'].Source -Job '_B10'
    }
    & $Python (Join-Path $PSScriptRoot 'dedekind-editions.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'Dedekind import preparation failed.' }
    Invoke-DedekindLatexmk -Source 'editions/b10-dedekind-proofs.tex' -Job '_B10-dedekind-proofs' -Directory 'registry/dedekind'
    & $Python (Join-Path $PSScriptRoot 'dedekind-editions.py') prepare-reading
    if ($LASTEXITCODE -ne 0) { throw 'Dedekind proof-reference preparation failed.' }
    Invoke-DedekindLatexmk -Source 'editions/b10-dedekind-reading.tex' -Job '_B10-dedekind-reading' -Directory 'registry/dedekind'
    & $Python (Join-Path $PSScriptRoot 'dedekind-editions.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Dedekind identity or PDF audit failed.' }
    if (-not $SkipVolumeBuild) {
        foreach ($band in $followingBands) {
            Invoke-DedekindLatexmk -Source $graph[$band].Source -Job "_$band"
        }
        # The Mogiljanskaja proof edition also imports affected B10 results.
        & (Join-Path $PSScriptRoot 'build-mogiljanskaja-editions.ps1') -EditionsOnly -Python $Python
        Invoke-DedekindLatexmk -Source $graph['B00'].Source -Job '_B00'
    }
    foreach ($edition in @('reading', 'proofs')) {
        $base = "registry/dedekind/_B10-dedekind-$edition"
        Assert-CleanLog -RelativePath "$base.log"
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-CleanPdfText -RelativePath "$base.pdf"
        if ($edition -eq 'proofs') {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '10E'
        } else {
            Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux"
        }
    }
    if (-not $SkipMain) {
        Invoke-DedekindLatexmk -Source 'main.tex' -Job 'main' -Directory '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands $auditedBands -IncludeMain
    } elseif (-not $EditionsOnly) {
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands $auditedBands
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'), '--bands') + $auditedBands + @('--dedekind', '--mogiljanskaja')
        if ($SkipMain) { $arguments += '--skip-main' }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Dedekind publication or link audit failed.' }
    }
    Write-Host 'Dedekind companion build and audits completed.'
} finally { Pop-Location }
