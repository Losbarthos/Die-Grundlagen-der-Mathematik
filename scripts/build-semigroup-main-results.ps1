[CmdletBinding()]
param([switch]$SkipPublish)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$artifactDirectory = 'registry/main-results'
$job = '_B28-main-results'
$source = 'editions/b28-main-results.tex'
$logDirectory = Join-Path $repoRoot 'tmp/main-results'
$publicationDirectory = Join-Path $repoRoot 'output/07 Halbgruppen und Monoide/Ergänzungen/Bd. 28 Halbgruppen/Leitfaden der Hauptresultate'
$publicationName = 'Bd. 28 - Halbgruppen - Leitfaden der Hauptresultate.pdf'

foreach ($command in @('latexmk', 'lualatex')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' was not found on PATH."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $source) -PathType Leaf)) {
    throw "Missing guide source: $source"
}
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $artifactDirectory) | Out-Null
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

Push-Location $repoRoot
try {
    $buildLog = Join-Path $logDirectory "$job.console.log"
    Write-Host "Building B28 main-results guide (log: $buildLog)"
    # Native locale warnings must not become terminating errors in Windows PowerShell 5.
    $nativeErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & latexmk -norc -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$job" "-outdir=$artifactDirectory" $source *> $buildLog
        $buildExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $nativeErrorPreference }
    if ($buildExitCode -ne 0) {
        Get-Content -LiteralPath $buildLog -Tail 55 | Write-Host
        throw 'B28 main-results guide build failed.'
    }
    $artifactBase = Join-Path $repoRoot "$artifactDirectory/$job"
    foreach ($extension in @('pdf', 'log')) {
        if (-not (Test-Path -LiteralPath "$artifactBase.$extension" -PathType Leaf)) {
            throw "Missing build artifact: $artifactBase.$extension"
        }
    }
    $diagnostics = (Get-Content -LiteralPath "$artifactBase.log" -Raw) -replace '\s+', ' '
    if ($diagnostics -match 'There were undefined references|There were multiply-defined labels|Rerun to get cross-references right|LaTeX Warning:\s*(Reference|Hyper reference).{0,1000}?undefined') {
        throw "Unresolved references in $artifactBase.log"
    }
    if (-not $SkipPublish) {
        # This self-contained guide has no links to external PDF destinations.
        New-Item -ItemType Directory -Force -Path $publicationDirectory | Out-Null
        $destination = Join-Path $publicationDirectory $publicationName
        Copy-Item -LiteralPath "$artifactBase.pdf" -Destination $destination -Force
        Write-Host "Published: $destination"
    } else {
        Write-Host 'B28 main-results guide built; LaTeX reference checks passed.'
    }
} finally { Pop-Location }
