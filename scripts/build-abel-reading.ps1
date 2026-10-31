[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
$artifactDirectory = 'registry/abel'
$logDirectory = Join-Path $repoRoot 'tmp/abel-reading'
$job = '_B21-abel-reading'
$source = 'editions/b21-abel-reading.tex'

foreach ($command in @('latexmk', 'lualatex', 'pdftotext')) {
    Assert-Command $command
}
if (-not $SkipPublish) { Assert-Command $Python }
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $source) -PathType Leaf)) {
    throw "Missing Abel reading source: $source"
}
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $artifactDirectory) | Out-Null
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

Push-Location $repoRoot
try {
    # Refresh the guide and its link to this reading; the main volume is unchanged.
    & (Join-Path $PSScriptRoot 'build-sequences-main-results.ps1') -SkipPublish
    $buildLog = Join-Path $logDirectory "$job.console.log"
    Write-Host "Building $job (log: $buildLog)"
    $nativeErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & latexmk -norc -g -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$job" "-outdir=$artifactDirectory" $source *> $buildLog
        $buildExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $nativeErrorPreference }
    if ($buildExitCode -ne 0) {
        Get-Content -LiteralPath $buildLog -Tail 55 | Write-Host
        throw 'Abel reading build failed.'
    }
    $base = "$artifactDirectory/$job"
    foreach ($extension in @('pdf', 'log')) {
        if (-not (Test-Path -LiteralPath (Join-Path $repoRoot "$base.$extension") -PathType Leaf)) {
            throw "Missing build artifact: $base.$extension"
        }
    }
    Assert-CleanLog -RelativePath "$base.log"
    $logContent = [System.IO.File]::ReadAllText((Join-Path $repoRoot "$base.log"))
    if ($logContent -match 'Overfull \\[hv]box') {
        throw "Overfull boxes in $base.log"
    }
    Assert-CleanPdfText -RelativePath "$base.pdf"
    if (-not $SkipPublish) {
        $publishLog = Join-Path $logDirectory 'abel-reading.publish.log'
        try {
            $ErrorActionPreference = 'Continue'
            & $Python (Join-Path $PSScriptRoot 'publish-pdfs.py') --abel-only *> $publishLog
            $publishExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $nativeErrorPreference }
        if ($publishExitCode -ne 0) {
            Get-Content -LiteralPath $publishLog -Tail 55 | Write-Host
            throw 'Abel reading publication or complete PDF link audit failed.'
        }
        Write-Host 'Abel reading and guide published; complete PDF link audit passed.'
    } else {
        Write-Host 'Abel reading and guide built; reference, layout and PDF text checks passed.'
    }
} finally { Pop-Location }
