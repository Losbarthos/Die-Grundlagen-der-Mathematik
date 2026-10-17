[CmdletBinding()]
param([string]$Python = 'python')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command 'latexmk'
Assert-Command 'lualatex'
Assert-Command 'pdftotext'
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/finite') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/finite-semigroups') | Out-Null
Push-Location $repoRoot
try {
    & $Python (Join-Path $PSScriptRoot 'finite-semigroups-edition.py') prepare
    if ($LASTEXITCODE -ne 0) { throw 'B37 reading import failed.' }
    $log = Join-Path $repoRoot 'tmp/finite-semigroups/reading.console.log'
    & latexmk -norc -g -lualatex -interaction=nonstopmode -halt-on-error -file-line-error '-jobname=_B37-finite-reading' '-outdir=registry/finite' 'editions/b37-finite-reading.tex' *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $log -Tail 45 | Write-Host
        throw 'B37 reading build failed.'
    }
    & $Python (Join-Path $PSScriptRoot 'finite-semigroups-edition.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'B37 reading audit failed.' }
} finally { Pop-Location }
