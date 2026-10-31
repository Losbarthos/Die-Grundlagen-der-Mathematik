[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
$artifactDirectory = 'registry/newton'
$logDirectory = Join-Path $repoRoot 'tmp/newton-editions'

foreach ($command in @('latexmk', 'lualatex', 'pdftotext')) {
    Assert-Command $command
}
if (-not $SkipPublish) { Assert-Command $Python }
foreach ($edition in @('proofs', 'reading')) {
    $source = Join-Path $repoRoot "editions/b21-newton-$edition.tex"
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing Newton source: $source"
    }
}
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $artifactDirectory) | Out-Null
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

function Invoke-NewtonEditionBuild {
    param([string]$Edition)
    $job = "_B21-newton-$Edition"
    $source = "editions/b21-newton-$Edition.tex"
    $buildLog = Join-Path $logDirectory "$job.console.log"
    Write-Host "Building $job (log: $buildLog)"
    $nativeErrorPreference = $ErrorActionPreference
    try {
        # The Lua registry inputs are not all recorded in LaTeX's FLS file.
        # One fresh engine pass also refreshes imported theorem references.
        $ErrorActionPreference = 'Continue'
        & latexmk -norc -g -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$job" "-outdir=$artifactDirectory" $source *> $buildLog
        $buildExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $nativeErrorPreference }
    if ($buildExitCode -ne 0) {
        Get-Content -LiteralPath $buildLog -Tail 55 | Write-Host
        throw "Newton $Edition build failed."
    }
    $base = "$artifactDirectory/$job"
    $extensions = @('pdf', 'log')
    if ($Edition -eq 'proofs') { $extensions += @('aux', 'debug.log', 'registry.tsv') }
    foreach ($extension in $extensions) {
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
    if ($Edition -eq 'proofs') {
        Assert-CleanDebugLog -RelativePath "$base.debug.log"
        Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '21N'
    }
}

Push-Location $repoRoot
try {
    # The guide keeps only the theorem statement and the companion links.
    # No main volume or complete-manuscript build is needed here.
    & (Join-Path $PSScriptRoot 'build-sequences-main-results.ps1') -SkipPublish
    Invoke-NewtonEditionBuild -Edition 'proofs'
    Invoke-NewtonEditionBuild -Edition 'reading'
    if (-not $SkipPublish) {
        $publishLog = Join-Path $logDirectory 'newton-editions.publish.log'
        $nativeErrorPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $Python (Join-Path $PSScriptRoot 'publish-pdfs.py') --newton-only *> $publishLog
            $publishExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $nativeErrorPreference }
        if ($publishExitCode -ne 0) {
            Get-Content -LiteralPath $publishLog -Tail 55 | Write-Host
            throw 'Newton companion publication or complete PDF link audit failed.'
        }
        Write-Host 'Newton companions and guide published; complete PDF link audit passed.'
    } else {
        Write-Host 'Newton companions and guide built; reference, registry and PDF text checks passed.'
    }
} finally { Pop-Location }
