[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('B03', 'B04', 'B05', 'B06')]
    [string]$Target = 'B03'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dependencyFile = Join-Path $repoRoot 'band-dependencies.tsv'
$registryDir = Join-Path $repoRoot 'registry'

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found on PATH."
    }
}

function ConvertTo-RepoRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    return ($Path -replace '\\', '/').TrimStart('./')
}

function Assert-WorkspaceRelativePath {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw "$Description must not be empty."
    }
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        throw "$Description must be relative to the repository: $RelativePath"
    }

    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath))
    $rootWithSeparator = $repoRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith(
        $rootWithSeparator,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description escapes the repository: $RelativePath"
    }
}

function Read-BandDependencyGraph {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Dependency graph is missing: $Path"
    }

    $graph = @{}
    $headerSeen = $false
    $lineNumber = 0

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) {
            continue
        }

        $columns = [regex]::Split($line, "`t")
        if (-not $headerSeen) {
            $expectedHeader = @('band', 'source', 'artifact_base', 'predecessors')
            if ($columns.Count -ne $expectedHeader.Count) {
                throw "Malformed dependency header in ${Path}: expected four TSV columns."
            }
            for ($index = 0; $index -lt $expectedHeader.Count; $index++) {
                if ($columns[$index].Trim().ToLowerInvariant() -ne $expectedHeader[$index]) {
                    throw "Malformed dependency header in ${Path}: expected '$($expectedHeader -join "`t")'."
                }
            }
            $headerSeen = $true
            continue
        }

        if ($columns.Count -ne 4) {
            throw "Malformed dependency row at ${Path}:${lineNumber}: expected four TSV columns."
        }

        $band = $columns[0].Trim()
        $source = ConvertTo-RepoRelativePath $columns[1].Trim()
        $artifactBase = ConvertTo-RepoRelativePath $columns[2].Trim()
        $predecessors = @()
        if (-not [string]::IsNullOrWhiteSpace($columns[3])) {
            $predecessors = @(
                $columns[3] -split '[, ]+' |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }

        if ($band -notmatch '^B[0-9]{2}$') {
            throw "Invalid band '$band' at ${Path}:${lineNumber}."
        }
        if ($graph.ContainsKey($band)) {
            throw "Duplicate band '$band' in dependency graph."
        }
        if ([System.IO.Path]::GetExtension($source) -ne '.tex') {
            throw "Source for $band must be a .tex file: $source"
        }

        Assert-WorkspaceRelativePath -RelativePath $source -Description "Source for $band"
        Assert-WorkspaceRelativePath -RelativePath $artifactBase -Description "Artifact base for $band"

        $expectedArtifactBase = "registry/_$band"
        if ($artifactBase -ne $expectedArtifactBase) {
            throw "Artifact base for $band must be '$expectedArtifactBase', got '$artifactBase'."
        }
        if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $source) -PathType Leaf)) {
            throw "Source for $band is missing: $source"
        }

        foreach ($predecessor in $predecessors) {
            if ($predecessor -notmatch '^B[0-9]{2}$') {
                throw "Invalid predecessor '$predecessor' for $band at ${Path}:${lineNumber}."
            }
            if ($predecessor -eq $band) {
                throw "$band cannot depend on itself."
            }
        }

        $graph[$band] = [pscustomobject]@{
            Band = $band
            Source = $source
            ArtifactBase = $artifactBase
            Predecessors = @($predecessors)
        }
    }

    if (-not $headerSeen) {
        throw "Dependency graph has no header: $Path"
    }
    return $graph
}

function Get-TopologicalPredecessors {
    param(
        [Parameter(Mandatory)][string]$Band,
        [Parameter(Mandatory)][hashtable]$Graph
    )

    $states = @{}
    $ordered = [System.Collections.Generic.List[string]]::new()
    $visit = $null
    $visit = {
        param([string]$CurrentBand)

        if (-not $Graph.ContainsKey($CurrentBand)) {
            throw "Dependency graph has no row for predecessor $CurrentBand."
        }

        $state = 0
        if ($states.ContainsKey($CurrentBand)) {
            $state = $states[$CurrentBand]
        }
        if ($state -eq 1) {
            throw "Dependency graph contains a cycle at $CurrentBand."
        }
        if ($state -eq 2) {
            return
        }

        $states[$CurrentBand] = 1
        foreach ($predecessor in $Graph[$CurrentBand].Predecessors) {
            & $visit $predecessor
        }
        $states[$CurrentBand] = 2
        [void]$ordered.Add($CurrentBand)
    }

    & $visit $Band
    return @($ordered | Where-Object { $_ -ne $Band })
}

function Remove-FileIfPresent {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $repoRoot $RelativePath
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer) {
            throw "Refusing to remove directory while cleaning artifacts: $RelativePath"
        }
        Write-Host "Removing $RelativePath"
        Remove-Item -LiteralPath $path -Force
    }
    if (Test-Path -LiteralPath $path) {
        throw "Failed to remove stale artifact: $RelativePath"
    }
}

function Remove-ArtifactFamily {
    param([Parameter(Mandatory)][string]$RelativeBase)

    $extensions = @(
        'aux', 'bbl', 'bcf', 'blg', 'debug.log', 'fdb_latexmk', 'fls',
        'lof', 'log', 'lot', 'nav', 'out', 'pdf', 'registry.tsv', 'run.xml',
        'snm', 'synctex.gz', 'toc', 'vrb', 'xdv'
    )
    foreach ($extension in $extensions) {
        Remove-FileIfPresent "$RelativeBase.$extension"
    }
}

function Get-SourceBase {
    param([Parameter(Mandatory)][string]$Source)

    $directory = [System.IO.Path]::GetDirectoryName($Source)
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($Source)
    if ([string]::IsNullOrWhiteSpace($directory)) {
        return $leaf
    }
    return ConvertTo-RepoRelativePath (Join-Path $directory $leaf)
}

function Remove-BandArtifacts {
    param([Parameter(Mandatory)]$Record)

    $sourceBase = Get-SourceBase $Record.Source

    # The fixed registry build, any root build, and legacy thmlookup defaults
    # are all removed so no previous run can satisfy an import accidentally.
    Remove-ArtifactFamily $Record.ArtifactBase
    Remove-ArtifactFamily $sourceBase
    Remove-ArtifactFamily "_$($Record.Band)"
    Remove-ArtifactFamily "thmlookup.$($Record.Band)"
    Remove-ArtifactFamily "thmlookup._$($Record.Band)"
}

function Invoke-Latexmk {
    param(
        [Parameter(Mandatory)][string]$Source,
        [string[]]$ExtraArguments = @()
    )

    # -norc is intentional: this script already owns the complete topological
    # build and must not recursively trigger the root latexmkrc rule.
    $arguments = @(
        '-norc'
        '-gg'
        '-lualatex'
        '-interaction=nonstopmode'
        '-halt-on-error'
        '-file-line-error'
    ) + $ExtraArguments + @($Source)

    Write-Host "`n==> latexmk $($arguments -join ' ')"
    & latexmk @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "latexmk failed for $Source (exit code $LASTEXITCODE)."
    }
}

function Assert-Artifact {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][datetime]$NotBefore,
        [switch]$AllowEmpty
    )

    $path = Join-Path $repoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Expected build artifact is missing: $RelativePath"
    }

    $item = Get-Item -LiteralPath $path
    if (-not $AllowEmpty -and $item.Length -eq 0) {
        throw "Expected build artifact is empty: $RelativePath"
    }
    if ($item.LastWriteTimeUtc -lt $NotBefore.ToUniversalTime().AddSeconds(-2)) {
        throw "Build artifact was not freshly generated: $RelativePath"
    }
}

function Assert-RegistryLabelsInAux {
    param(
        [Parameter(Mandatory)][string]$RegistryPath,
        [Parameter(Mandatory)][string]$AuxPath
    )

    $registry = Join-Path $repoRoot $RegistryPath
    $aux = Join-Path $repoRoot $AuxPath
    $auxLabels = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $auxContent = [System.IO.File]::ReadAllText($aux)
    foreach ($match in [regex]::Matches($auxContent, '(?m)^\\newlabel\{([^}]*)\}')) {
        [void]$auxLabels.Add($match.Groups[1].Value)
    }

    $missingLabels = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($line in [System.IO.File]::ReadLines($registry)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $columns = $line -split "`t"
        if ($columns[0] -eq 'ID') {
            if ($columns.Count -lt 4) {
                throw "Malformed ID row in ${RegistryPath}: $line"
            }
            $label = $columns[3]
        }
        else {
            if ($columns.Count -lt 2) {
                throw "Malformed theorem row in ${RegistryPath}: $line"
            }
            $label = $columns[1]
        }

        if ($label -and -not $auxLabels.Contains($label)) {
            [void]$missingLabels.Add($label)
        }
    }

    if ($missingLabels.Count -gt 0) {
        $sample = ($missingLabels | Sort-Object | Select-Object -First 20) -join ', '
        throw "$RegistryPath contains labels missing from ${AuxPath}: $sample"
    }
}

function Assert-CleanLog {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $repoRoot $RelativePath
    $content = [System.IO.File]::ReadAllText($path)
    $normalized = [regex]::Replace($content, '\s+', ' ')
    $patterns = @(
        'LaTeX Warning:\s*(?:Reference|Hyper reference).{0,1000}?undefined',
        'There were undefined references',
        'There were multiply-defined labels',
        'multiply defined',
        'LABELS NOT IMPORTED',
        'No file\s+registry[/\\]_B[0-9]{2}\.aux',
        'referenced but does not exist',
        'Invalid page number',
        'ignoring duplicate destination',
        'destination with the same identifier',
        'Suppressing (?:empty link|link with empty target)',
        'thmlookup:\s*cannot open registry file',
        'thmlookup:\s*cannot open file for append',
        'thmlookup WARNING:\s*duplicate',
        'band-dependencies ERROR',
        'Rerun to get cross-references right'
    )

    $matchedPatterns = @($patterns | Where-Object {
        [regex]::IsMatch(
            $normalized,
            $_,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    })
    if ($matchedPatterns.Count -gt 0) {
        throw "$RelativePath contains unresolved, ambiguous, duplicate, or missing-import diagnostics:`n$($matchedPatterns -join "`n")"
    }
}

function Assert-CleanDebugLog {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $repoRoot $RelativePath
    $content = [System.IO.File]::ReadAllText($path)
    $pattern = '(?im)^status:\s*(?:none|ambiguous[^\r\n]*|duplicate-register)\s*$'
    $matches = [regex]::Matches($content, $pattern)
    if ($matches.Count -gt 0) {
        $sample = @($matches | Select-Object -First 20 | ForEach-Object { $_.Value.Trim() })
        throw "$RelativePath contains failed or ambiguous lookups: $($sample -join ', ')"
    }
}

function Assert-CleanPdfText {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $repoRoot $RelativePath
    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) (
        'Die-Grundlagen-der-Mathematik-{0}-{1}.txt' -f
            ([System.IO.Path]::GetFileNameWithoutExtension($RelativePath)),
            [Guid]::NewGuid().ToString('N')
    )

    try {
        & pdftotext -layout $path $tempPath
        if ($LASTEXITCODE -ne 0) {
            throw "pdftotext failed for $RelativePath (exit code $LASTEXITCODE)."
        }

        $normalized = [regex]::Replace(
            [System.IO.File]::ReadAllText($tempPath),
            '\s+',
            ' '
        )
        $markers = @(
            'Theorem nicht gefunden',
            'Definition nicht gefunden',
            'Axiom nicht gefunden',
            'Regel nicht gefunden',
            'Referenz nicht gefunden',
            'Mehrdeutige Theorem-Referenz',
            'Mehrdeutige Definition-Referenz',
            'Mehrdeutige Axiom-Referenz',
            'Mehrdeutige Regel-Referenz',
            'Mehrdeutig: bitte',
            'Th. ?',
            'Def. ?',
            'Ax. ?',
            'Ref. ?',
            '??'
        )
        $found = @($markers | Where-Object {
            $normalized.IndexOf(
                $_,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -ge 0
        })
        if ($found.Count -gt 0) {
            throw "$RelativePath contains unresolved theorem/reference markers: $($found -join ', ')"
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
    }
}

function ConvertFrom-PdfLiteralString {
    param([Parameter(Mandatory)][string]$Value)

    $result = $Value.Replace('\(', '(').Replace('\)', ')')
    $result = $result.Replace('\\', '\')
    return $result
}

function Get-PdfAscii {
    param(
        [Parameter(Mandatory)][string]$FullPath,
        [Parameter(Mandatory)][hashtable]$Cache
    )

    if (-not $Cache.ContainsKey($FullPath)) {
        $Cache[$FullPath] = [System.Text.Encoding]::ASCII.GetString(
            [System.IO.File]::ReadAllBytes($FullPath)
        )
    }
    return $Cache[$FullPath]
}

function Assert-ExternalPdfTargets {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][hashtable]$PdfAsciiCache,
        [string]$RequiredExternalPdf
    )

    $pdfPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath))
    $pdfDirectory = Split-Path -Parent $pdfPath
    $content = Get-PdfAscii -FullPath $pdfPath -Cache $PdfAsciiCache
    $goToRCount = [regex]::Matches($content, '/S\s*/GoToR').Count
    $actionPattern = '/F\s*\((?<file>(?:\\.|[^\\)])*)\)\s*/S\s*/GoToR\s*/D\s*\((?<destination>(?:\\.|[^\\)])*)\)'
    $actions = [regex]::Matches(
        $content,
        $actionPattern,
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    if ($actions.Count -ne $goToRCount) {
        throw "$RelativePath contains $goToRCount GoToR actions, but only $($actions.Count) could be audited."
    }

    $uniqueTargets = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $targetCounts = @{}
    $rootWithSeparator = $repoRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

    foreach ($action in $actions) {
        $externalFile = ConvertFrom-PdfLiteralString $action.Groups['file'].Value
        $rawDestination = $action.Groups['destination'].Value
        $destination = ConvertFrom-PdfLiteralString $rawDestination
        if ([string]::IsNullOrWhiteSpace($externalFile) -or
            [string]::IsNullOrWhiteSpace($destination)) {
            throw "$RelativePath contains a GoToR action with an empty file or destination."
        }

        $externalFileForPlatform = $externalFile.Replace(
            '/',
            [System.IO.Path]::DirectorySeparatorChar
        )
        $externalPath = [System.IO.Path]::GetFullPath(
            (Join-Path $pdfDirectory $externalFileForPlatform)
        )
        if (-not $externalPath.StartsWith(
            $rootWithSeparator,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "$RelativePath contains a GoToR file outside the repository: $externalFile"
        }
        if (-not (Test-Path -LiteralPath $externalPath -PathType Leaf)) {
            throw "$RelativePath links to a missing external PDF: $externalFile"
        }

        if (-not $targetCounts.ContainsKey($externalPath)) {
            $targetCounts[$externalPath] = 0
        }
        $targetCounts[$externalPath]++

        $uniqueKey = "$externalPath`n$rawDestination"
        if ($uniqueTargets.Add($uniqueKey)) {
            $externalContent = Get-PdfAscii -FullPath $externalPath -Cache $PdfAsciiCache
            $rawNeedle = "($rawDestination)"
            $decodedNeedle = "($destination)"
            if ($externalContent.IndexOf(
                $rawNeedle,
                [System.StringComparison]::Ordinal
            ) -lt 0 -and $externalContent.IndexOf(
                $decodedNeedle,
                [System.StringComparison]::Ordinal
            ) -lt 0) {
                throw "$RelativePath links to missing destination '$destination' in $externalFile."
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($RequiredExternalPdf)) {
        $requiredPath = [System.IO.Path]::GetFullPath(
            (Join-Path $repoRoot $RequiredExternalPdf)
        )
        if (-not $targetCounts.ContainsKey($requiredPath) -or
            $targetCounts[$requiredPath] -lt 1) {
            throw "$RelativePath must contain at least one GoToR link to $RequiredExternalPdf."
        }
    }

    Write-Host "GoToR audit: $RelativePath -> $goToRCount external links, $($uniqueTargets.Count) unique targets."
}

function New-BuildStage {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][datetime]$Started,
        [switch]$RootTarget
    )

    $registryPath = "$($Record.ArtifactBase).registry.tsv"
    $debugPath = "$($Record.ArtifactBase).debug.log"
    if ($RootTarget) {
        $rootBase = Get-SourceBase $Record.Source
        return [pscustomobject]@{
            Band = $Record.Band
            Aux = "$rootBase.aux"
            Log = "$rootBase.log"
            Pdf = "$rootBase.pdf"
            Registry = $registryPath
            Debug = $debugPath
            Started = $Started
            RootTarget = $true
        }
    }

    return [pscustomobject]@{
        Band = $Record.Band
        Aux = "$($Record.ArtifactBase).aux"
        Log = "$($Record.ArtifactBase).log"
        Pdf = "$($Record.ArtifactBase).pdf"
        Registry = $registryPath
        Debug = $debugPath
        Started = $Started
        RootTarget = $false
    }
}

function Assert-BuildStageArtifacts {
    param([Parameter(Mandatory)]$Stage)

    Assert-Artifact -RelativePath $Stage.Aux -NotBefore $Stage.Started
    Assert-Artifact -RelativePath $Stage.Log -NotBefore $Stage.Started
    Assert-Artifact -RelativePath $Stage.Pdf -NotBefore $Stage.Started
    Assert-Artifact -RelativePath $Stage.Registry -NotBefore $Stage.Started
    Assert-Artifact -RelativePath $Stage.Debug -NotBefore $Stage.Started -AllowEmpty
    Assert-RegistryLabelsInAux -RegistryPath $Stage.Registry -AuxPath $Stage.Aux
}

Assert-Command 'latexmk'
Assert-Command 'lualatex'
Assert-Command 'pdftotext'

$graph = Read-BandDependencyGraph -Path $dependencyFile
if (-not $graph.ContainsKey($Target)) {
    throw "Dependency graph has no row for target $Target."
}
$predecessors = @(Get-TopologicalPredecessors -Band $Target -Graph $graph)
$bandsForRun = @($predecessors + @($Target))

Write-Host "Target: $Target"
Write-Host "Topological predecessors: $(if ($predecessors.Count) { $predecessors -join ', ' } else { '(none)' })"

New-Item -ItemType Directory -Force -Path $registryDir | Out-Null

Push-Location $repoRoot
try {
    Write-Host "`n==> Cleaning all known artifacts for $($bandsForRun -join ', ')"
    foreach ($band in $bandsForRun) {
        Remove-BandArtifacts -Record $graph[$band]
    }

    $stages = [System.Collections.Generic.List[object]]::new()

    foreach ($band in $predecessors) {
        $record = $graph[$band]
        $artifactDirectory = [System.IO.Path]::GetDirectoryName($record.ArtifactBase)
        $artifactJobName = [System.IO.Path]::GetFileName($record.ArtifactBase)
        $started = Get-Date
        Invoke-Latexmk -Source $record.Source -ExtraArguments @(
            "-outdir=$artifactDirectory",
            "-jobname=$artifactJobName"
        )
        $stage = New-BuildStage -Record $record -Started $started
        Assert-BuildStageArtifacts -Stage $stage
        [void]$stages.Add($stage)
    }

    $targetRecord = $graph[$Target]
    $targetStarted = Get-Date
    Invoke-Latexmk -Source $targetRecord.Source
    $targetStage = New-BuildStage -Record $targetRecord -Started $targetStarted -RootTarget
    Assert-BuildStageArtifacts -Stage $targetStage
    [void]$stages.Add($targetStage)

    $pdfAsciiCache = @{}
    foreach ($stage in $stages) {
        Assert-CleanLog -RelativePath $stage.Log
        Assert-CleanDebugLog -RelativePath $stage.Debug
        Assert-CleanPdfText -RelativePath $stage.Pdf

        $requiredExternalPdf = $null
        $directPredecessors = @($graph[$stage.Band].Predecessors)
        if ($stage.RootTarget -and $directPredecessors.Count -gt 0) {
            $lastPredecessor = $directPredecessors[-1]
            $requiredExternalPdf = "$($graph[$lastPredecessor].ArtifactBase).pdf"
        }
        Assert-ExternalPdfTargets `
            -RelativePath $stage.Pdf `
            -PdfAsciiCache $pdfAsciiCache `
            -RequiredExternalPdf $requiredExternalPdf
    }

    Write-Host "`n$Target standalone build and reference audit completed successfully."
    Write-Host "Built predecessors: $(if ($predecessors.Count) { $predecessors -join ', ' } else { '(none)' })"
    Write-Host "Output: $(Join-Path $repoRoot $targetStage.Pdf)"
}
finally {
    Pop-Location
}
