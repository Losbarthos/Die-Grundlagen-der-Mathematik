[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command 'lualatex'
Assert-Command 'pdftotext'
$coordinateDirectory = Join-Path $repoRoot 'registry/coordinates'
$coordinateLogs = Join-Path $repoRoot 'tmp/coordinates-editions'
New-Item -ItemType Directory -Force -Path $coordinateDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $coordinateLogs | Out-Null

function Get-CoordinateBuildState {
    param([string]$Edition)
    $coordinateHashes = foreach ($extension in @('aux', 'out', 'registry.tsv', 'proof-references.tsv')) {
        $coordinateArtifact = Join-Path $coordinateDirectory "_B31-coordinates-$Edition.$extension"
        if (Test-Path -LiteralPath $coordinateArtifact) {
            "$extension=$((Get-FileHash -LiteralPath $coordinateArtifact -Algorithm SHA256).Hash)"
        } else { "$extension=missing" }
    }
    return $coordinateHashes -join ';'
}

Push-Location $repoRoot
try {
    # Reuse current canonical B31/predecessor artifacts. This isolated builder
    # does not rebuild subject volumes or the main PDF.
    & $Python (Join-Path $PSScriptRoot 'coordinates-proofs.py') source
    if ($LASTEXITCODE -ne 0) { throw 'Coordinate source/artifact preflight failed.' }
    foreach ($coordinateEdition in @('proofs', 'reading')) {
        $coordinatePriorState = Get-CoordinateBuildState -Edition $coordinateEdition
        $coordinateStable = $false
        for ($coordinatePass = 1; $coordinatePass -le 5; $coordinatePass++) {
            $coordinateConsole = Join-Path $coordinateLogs "$coordinateEdition-pass-$coordinatePass.console.log"
            Write-Host "Building coordinate $coordinateEdition, pass $coordinatePass (log: $coordinateConsole)"
            & lualatex --disable-installer --disable-write18 -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=_B31-coordinates-$coordinateEdition" '-output-directory=registry/coordinates' "editions/b31-coordinates-$coordinateEdition.tex" *> $coordinateConsole
            if ($LASTEXITCODE -ne 0) {
                Get-Content -LiteralPath $coordinateConsole -Tail 60 | Write-Host
                throw "Coordinate $coordinateEdition build failed."
            }
            $coordinateState = Get-CoordinateBuildState -Edition $coordinateEdition
            $coordinateLog = Get-Content -LiteralPath (Join-Path $coordinateDirectory "_B31-coordinates-$coordinateEdition.log") -Raw
            $coordinateNeedsRerun = $coordinateLog -match 'Rerun to get cross-references right|Label\(s\) may have changed|Table widths have changed|Rerun to get outlines right'
            if ($coordinatePass -ge 2 -and $coordinateState -eq $coordinatePriorState -and -not $coordinateNeedsRerun) {
                $coordinateStable = $true
                break
            }
            $coordinatePriorState = $coordinateState
        }
        if (-not $coordinateStable) { throw "Coordinate $coordinateEdition references did not stabilize within five passes." }
    }
    & $Python (Join-Path $PSScriptRoot 'coordinates-proofs.py') audit
    if ($LASTEXITCODE -ne 0) { throw 'Coordinate source/reference/PDF audit failed.' }
    # Run the marked-content geometry audit separately with a Python that has
    # pdfplumber: see BUILDING.md. It is not silently skipped or substituted.
    if (-not $SkipPublish) {
        & $Python (Join-Path $PSScriptRoot 'publish-pdfs.py') --coordinates-only
        if ($LASTEXITCODE -ne 0) { throw 'Coordinate publication or PDF link audit failed.' }
    }
    Write-Host 'Both B31 coordinate editions: 397 proof rows, sixteen reference overviews, stable PDFs and links checked.'
} finally { Pop-Location }
