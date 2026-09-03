[CmdletBinding()]
param(
    [ValidatePattern('^B[0-9]{2}$')][string[]]$Bands = @(),
    [switch]$IncludeMain,
    [switch]$IncludeRemarkable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command 'pdftotext'
$graph = Read-BandDependencyGraph -Path $dependencyFile
if ($Bands.Count -eq 0) { $Bands = @($graph.Keys | Sort-Object) }
$pdfAsciiCache = @{}

foreach ($band in $Bands) {
    if (-not $graph.ContainsKey($band)) { throw "Unknown volume: $band" }
    $stage = New-BuildStage -Record $graph[$band] -Started ([datetime]::MinValue)
    Assert-BuildStageArtifacts -Stage $stage
    Assert-CleanLog -RelativePath $stage.Log
    Assert-CleanDebugLog -RelativePath $stage.Debug
    Assert-CleanPdfText -RelativePath $stage.Pdf
    $allowedExternalPdfs = @($graph[$band].Predecessors | ForEach-Object { "$($graph[$_].ArtifactBase).pdf" })
    Assert-ExternalPdfTargets -RelativePath $stage.Pdf -PdfAsciiCache $pdfAsciiCache -AllowedExternalPdfs $allowedExternalPdfs
    Write-Host "Reference audit passed: $band"
}

if ($IncludeRemarkable) {
    $base = 'registry/_B37-remarkable'
    foreach ($extension in @('aux', 'log', 'pdf', 'registry.tsv')) {
        Assert-Artifact -RelativePath "$base.$extension" -NotBefore ([datetime]::MinValue)
    }
    Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux"
    Assert-CleanLog -RelativePath "$base.log"
    Assert-CleanDebugLog -RelativePath "$base.debug.log"
    Assert-CleanPdfText -RelativePath "$base.pdf"
    Assert-ExternalPdfTargets -RelativePath "$base.pdf" -PdfAsciiCache $pdfAsciiCache
    Write-Host 'Reference audit passed: B37 reMarkable'
}

if ($IncludeMain) {
    Assert-CleanLog -RelativePath 'main.log'
    Assert-CleanPdfText -RelativePath 'main.pdf'
    $mainAuxNumbers = @{}
    foreach ($match in [regex]::Matches([System.IO.File]::ReadAllText((Join-Path $repoRoot 'main.aux')), '(?m)^\\newlabel\{([^}]*)\}\{\{([^}]*)\}')) {
        $mainAuxNumbers[$match.Groups[1].Value] = $match.Groups[2].Value.Trim()
    }
    foreach ($band in @($graph.Keys | Sort-Object)) {
        $registry = "registry/main/_$band.registry.tsv"
        Assert-RegistryLabelsInAux -RegistryPath $registry -AuxPath 'main.aux'
        Assert-CleanDebugLog -RelativePath "registry/main/_$band.debug.log"
        $standaloneIndex = @([System.IO.File]::ReadLines((Join-Path $repoRoot "registry/_$band.registry.tsv")) |
            ForEach-Object { ($_.Split("`t") | Select-Object -First 4) -join "`t" } |
            Sort-Object -Unique)
        $mainIndex = @([System.IO.File]::ReadLines((Join-Path $repoRoot $registry)) |
            ForEach-Object { ($_.Split("`t") | Select-Object -First 4) -join "`t" } |
            Sort-Object -Unique)
        if (@(Compare-Object -ReferenceObject $standaloneIndex -DifferenceObject $mainIndex).Count -gt 0) {
            throw "The main and standalone result indices differ for $band."
        }
        $standaloneAuxNumbers = @{}
        foreach ($match in [regex]::Matches([System.IO.File]::ReadAllText((Join-Path $repoRoot "$($graph[$band].ArtifactBase).aux")), '(?m)^\\newlabel\{([^}]*)\}\{\{([^}]*)\}')) {
            $standaloneAuxNumbers[$match.Groups[1].Value] = $match.Groups[2].Value.Trim()
        }
        foreach ($row in $standaloneIndex) {
            $columns = $row.Split("`t")
            $label = if ($columns[0] -eq 'ID') { $columns[3] } else { $columns[1] }
            if (-not $mainAuxNumbers.ContainsKey($label) -or
                -not $standaloneAuxNumbers.ContainsKey($label) -or
                $mainAuxNumbers[$label] -ne $standaloneAuxNumbers[$label]) {
                throw "The main and standalone AUX numbers differ for $label."
            }
        }
    }
    Assert-ExternalPdfTargets -RelativePath 'main.pdf' -PdfAsciiCache $pdfAsciiCache
    Write-Host 'Reference audit passed: main'
}
