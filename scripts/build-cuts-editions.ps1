[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$EditionsOnly,
    [switch]$SkipMain,
    [switch]$SkipPublish
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
$artifactDirectory = 'registry/cuts'
$logDirectory = Join-Path $repoRoot 'tmp/cuts-editions'
foreach ($command in @('latexmk', 'lualatex', 'pdftotext', $Python)) { Assert-Command $command }
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $artifactDirectory), $logDirectory | Out-Null
function Invoke-CutsBuild {
    param([string]$Source, [string]$Job, [string]$OutDir, [switch]$StrictLayout)
    $consoleLog = Join-Path $logDirectory "$Job.console.log"
    Write-Host "Building $Job (log: $consoleLog)"
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & latexmk -norc -g -lualatex -interaction=nonstopmode -halt-on-error -file-line-error "-jobname=$Job" "-outdir=$OutDir" $Source *> $consoleLog
        $buildCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($buildCode -ne 0) {
        Get-Content -LiteralPath $consoleLog -Tail 55 | Write-Host
        throw "Build failed: $Job"
    }
    $base = "$OutDir/$Job"
    Assert-CleanLog -RelativePath "$base.log"
    Assert-CleanPdfText -RelativePath "$base.pdf"
    if ($StrictLayout -and ([IO.File]::ReadAllText((Join-Path $repoRoot "$base.log")) -match 'Overfull \\[hv]box')) {
        throw "Overfull boxes in $base.log"
    }
}
Push-Location $repoRoot
try {
    if (-not $EditionsOnly) {
        Invoke-CutsBuild -Source 'Bd. 19 - Reelle Zahlen.tex' -Job '_B19' -OutDir 'registry'
    }
    & $Python (Join-Path $PSScriptRoot 'check-cuts-editions.py') --registry-only
    if ($LASTEXITCODE -ne 0) { throw 'Canonical B19 registry audit failed.' }
    foreach ($edition in @('proofs', 'reading', 'exercises')) {
        Invoke-CutsBuild -Source "editions/b19-cuts-$edition.tex" -Job "_B19-cuts-$edition" -OutDir $artifactDirectory -StrictLayout
    }
    Assert-CleanDebugLog -RelativePath "$artifactDirectory/_B19-cuts-proofs.debug.log"
    & $Python (Join-Path $PSScriptRoot 'impose-cuts-booklets.py')
    if ($LASTEXITCODE -ne 0) { throw 'Cuts booklet imposition failed.' }
    & $Python (Join-Path $PSScriptRoot 'check-cuts-editions.py')
    if ($LASTEXITCODE -ne 0) { throw 'Cuts edition audit failed.' }
    if (-not $EditionsOnly -and -not $SkipMain) {
        Invoke-CutsBuild -Source 'main.tex' -Job 'main' -OutDir '.'
        & $Python (Join-Path $PSScriptRoot 'check-cuts-editions.py') --include-main
        if ($LASTEXITCODE -ne 0) { throw 'Main/standalone statement audit failed.' }
    }
    if (-not $SkipPublish) {
        $arguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'))
        if ($EditionsOnly) { $arguments += '--cuts-only' }
        else {
            $arguments += @('--bands', 'B19', '--cuts-editions')
            if ($SkipMain) { $arguments += '--skip-main' }
        }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Cuts publication or PDF link audit failed.' }
    }
    Write-Host 'Cuts reading, exercises, proof companion and both print booklets completed.'
} finally { Pop-Location }
