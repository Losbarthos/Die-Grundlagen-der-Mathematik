[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$artifactDirectory = 'registry/context-profiles'
$job = '_B37-context-profiles-reading'
$source = 'editions/b37-context-profiles-reading.tex'
$logDirectory = Join-Path $repoRoot 'tmp/context-profiles-reading'

foreach ($command in @('latexmk', 'lualatex')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' was not found on PATH."
    }
}
if (-not $SkipPublish -and -not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Required Python command '$Python' was not found."
}
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $source) -PathType Leaf)) {
    throw "Missing reading source: $source"
}
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $artifactDirectory) | Out-Null
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

Push-Location $repoRoot
try {
    $buildLog = Join-Path $logDirectory "$job.console.log"
    Write-Host "Building context-profile reading (log: $buildLog)"
    # Windows PowerShell 5 turns native stderr into error records. Locale
    # warnings are harmless; the native exit code decides whether a build failed.
    $nativeErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & latexmk -norc -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$job" "-outdir=$artifactDirectory" $source *> $buildLog
        $buildExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $nativeErrorPreference }
    if ($buildExitCode -ne 0) {
        Get-Content -LiteralPath $buildLog -Tail 55 | Write-Host
        throw 'Context-profile reading build failed.'
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
        $publishLog = Join-Path $logDirectory "$job.publish.log"
        try {
            $ErrorActionPreference = 'Continue'
            & $Python (Join-Path $PSScriptRoot 'publish-pdfs.py') --context-profiles-only *> $publishLog
            $publishExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $nativeErrorPreference }
        if ($publishExitCode -ne 0) {
            Get-Content -LiteralPath $publishLog -Tail 55 | Write-Host
            throw 'Context-profile reading publication or complete PDF link audit failed.'
        }
        Write-Host 'Context-profile reading built and published; complete PDF link audit passed.'
    } else {
        Write-Host 'Context-profile reading built; LaTeX reference checks passed.'
    }
} finally { Pop-Location }
