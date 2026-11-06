[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
$artifactDirectory = 'registry/binomial'
$logDirectory = Join-Path $repoRoot 'tmp/binomial-reading'
$editions = @(
    @{ Name = 'reading'; Job = '_B10-binomial-reading'; Source = 'editions/b10-binomial-reading.tex'; Booklet = '_B10-binomial-booklet' },
    @{ Name = 'exercises'; Job = '_B10-binomial-exercises'; Source = 'editions/b10-binomial-exercises.tex'; Booklet = '_B10-binomial-exercises-booklet' }
)

foreach ($command in @('latexmk', 'lualatex', 'pdftotext')) {
    Assert-Command $command
}
Assert-Command $Python
foreach ($edition in $editions) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $edition.Source) -PathType Leaf)) {
        throw "Missing Binomial source: $($edition.Source)"
    }
}
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $artifactDirectory) | Out-Null
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

Push-Location $repoRoot
try {
    # Refresh the guide and its link to this reading; the main volume is unchanged.
    & (Join-Path $PSScriptRoot 'build-natural-numbers-main-results.ps1') -SkipPublish
    $nativeErrorPreference = $ErrorActionPreference
    foreach ($edition in $editions) {
        $job = $edition.Job
        $source = $edition.Source
        $buildLog = Join-Path $logDirectory "$job.console.log"
        Write-Host "Building $job (log: $buildLog)"
        try {
            $ErrorActionPreference = 'Continue'
            & latexmk -norc -g -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$job" "-outdir=$artifactDirectory" $source *> $buildLog
            $buildExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $nativeErrorPreference }
        if ($buildExitCode -ne 0) {
            Get-Content -LiteralPath $buildLog -Tail 55 | Write-Host
            throw "Binomial build failed: $job"
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
        $impositionLog = Join-Path $logDirectory "$($edition.Booklet).console.log"
        try {
            $ErrorActionPreference = 'Continue'
            & $Python (Join-Path $PSScriptRoot 'impose-binomial-booklet.py') --edition $edition.Name *> $impositionLog
            $impositionExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $nativeErrorPreference }
        if ($impositionExitCode -ne 0) {
            Get-Content -LiteralPath $impositionLog -Tail 55 | Write-Host
            throw "Binomial booklet imposition failed: $($edition.Name)"
        }
        Assert-CleanPdfText -RelativePath "$artifactDirectory/$($edition.Booklet).pdf"
    }
    if (-not $SkipPublish) {
        $publishLog = Join-Path $logDirectory 'binomial-reading.publish.log'
        try {
            $ErrorActionPreference = 'Continue'
            & $Python (Join-Path $PSScriptRoot 'publish-pdfs.py') --binomial-only *> $publishLog
            $publishExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $nativeErrorPreference }
        if ($publishExitCode -ne 0) {
            Get-Content -LiteralPath $publishLog -Tail 55 | Write-Host
            throw 'Binomial publication or complete PDF link audit failed.'
        }
        Write-Host 'Binomial reading, exercises, both print booklets and guide published; complete PDF link audit passed.'
    } else {
        Write-Host 'Binomial reading, exercises, both print booklets and guide built; reference, layout and PDF text checks passed.'
    }
} finally { Pop-Location }
