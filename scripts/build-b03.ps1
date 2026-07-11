[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$registryDir = Join-Path $repoRoot 'registry'
$buildStarted = Get-Date

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found on PATH."
    }
}

function Invoke-Latexmk {
    param(
        [Parameter(Mandatory)][string]$Source,
        [string[]]$ExtraArguments = @()
    )

    $arguments = @(
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
    if ($item.LastWriteTime -lt $buildStarted.AddSeconds(-2)) {
        throw "Build artifact was not freshly generated: $RelativePath"
    }
}

function Assert-NoMatches {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string[]]$Patterns,
        [Parameter(Mandatory)][string]$Description,
        [switch]$SimpleMatch
    )

    $path = Join-Path $repoRoot $RelativePath
    $arguments = @{
        LiteralPath = $path
        Pattern = $Patterns
    }
    if ($SimpleMatch) {
        $arguments.SimpleMatch = $true
    }

    $matches = Select-String @arguments
    if ($matches) {
        $sample = ($matches | Select-Object -First 20 | ForEach-Object {
            "{0}:{1}: {2}" -f $RelativePath, $_.LineNumber, $_.Line.Trim()
        }) -join [Environment]::NewLine
        throw "$Description`n$sample"
    }
}

function Assert-NoNormalizedMatches {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string[]]$Patterns,
        [Parameter(Mandatory)][string]$Description
    )

    $path = Join-Path $repoRoot $RelativePath
    $content = [System.IO.File]::ReadAllText($path)
    $normalized = [regex]::Replace($content, '\s+', ' ')
    $matchedPatterns = @($Patterns | Where-Object {
        [regex]::IsMatch(
            $normalized,
            $_,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    })

    if ($matchedPatterns.Count -gt 0) {
        throw "$Description`nMatched patterns: $($matchedPatterns -join ', ')"
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

Assert-Command 'latexmk'
Assert-Command 'lualatex'
Assert-Command 'pdftotext'
New-Item -ItemType Directory -Force -Path $registryDir | Out-Null

Push-Location $repoRoot
$pdfTextPath = $null
try {
    # latexmk does not track the files written directly by thmlookup.lua.
    # Remove them explicitly so no previous self-registry can mask a miss.
    $luaArtifacts = @(
        'registry/_B01.registry.tsv',
        'registry/_B01.debug.log',
        'registry/_B02.registry.tsv',
        'registry/_B02.debug.log',
        'registry/_B03.registry.tsv',
        'registry/_B03.debug.log',
        'thmlookup._B01.registry.tsv',
        'thmlookup._B01.debug.log',
        'thmlookup._B02.registry.tsv',
        'thmlookup._B02.debug.log',
        'thmlookup.B03.registry.tsv',
        'thmlookup.B03.debug.log'
    )
    foreach ($relativePath in $luaArtifacts) {
        $path = Join-Path $repoRoot $relativePath
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }

    Invoke-Latexmk -Source 'B01.tex' -ExtraArguments @(
        '-outdir=registry',
        '-jobname=_B01'
    )
    Assert-Artifact 'registry/_B01.aux'
    Assert-Artifact 'registry/_B01.log'
    Assert-Artifact 'registry/_B01.pdf'
    Assert-Artifact 'registry/_B01.registry.tsv'
    Assert-Artifact 'registry/_B01.debug.log' -AllowEmpty
    Assert-RegistryLabelsInAux 'registry/_B01.registry.tsv' 'registry/_B01.aux'

    Invoke-Latexmk -Source 'B02.tex' -ExtraArguments @(
        '-outdir=registry',
        '-jobname=_B02'
    )
    Assert-Artifact 'registry/_B02.aux'
    Assert-Artifact 'registry/_B02.log'
    Assert-Artifact 'registry/_B02.pdf'
    Assert-Artifact 'registry/_B02.registry.tsv'
    Assert-Artifact 'registry/_B02.debug.log' -AllowEmpty
    Assert-RegistryLabelsInAux 'registry/_B02.registry.tsv' 'registry/_B02.aux'

    Invoke-Latexmk -Source 'B03.tex'
    Assert-Artifact 'B03.aux'
    Assert-Artifact 'B03.log'
    Assert-Artifact 'B03.pdf'
    Assert-Artifact 'registry/_B03.registry.tsv'
    Assert-Artifact 'registry/_B03.debug.log' -AllowEmpty
    Assert-RegistryLabelsInAux 'registry/_B03.registry.tsv' 'B03.aux'

    Assert-NoNormalizedMatches -RelativePath 'B03.log' -Description 'B03.log contains unresolved or ambiguous reference diagnostics:' -Patterns @(
        'LaTeX Warning:\s*(?:Reference|Hyper reference).{0,500}?undefined',
        'There were undefined references',
        'multiply defined',
        'LABELS NOT IMPORTED',
        'referenced but does not exist',
        'Invalid page number',
        'ignoring duplicate destination',
        'destination with the same identifier',
        'Suppressing (?:empty link|link with empty target)',
        'thmlookup WARNING:\s*duplicate'
    )

    foreach ($debugPath in @(
        'registry/_B01.debug.log',
        'registry/_B02.debug.log',
        'registry/_B03.debug.log'
    )) {
        Assert-NoMatches -RelativePath $debugPath -Description "$debugPath contains failed or ambiguous lookups:" -Patterns @(
            '^status:\s*(?:none|ambiguous.*|duplicate-register)\s*$'
        )
    }

    foreach ($dependencyLog in @('registry/_B01.log', 'registry/_B02.log')) {
        Assert-NoNormalizedMatches -RelativePath $dependencyLog -Description "$dependencyLog contains duplicate theorem-registry IDs:" -Patterns @(
            'thmlookup WARNING:\s*duplicate'
        )
    }

    $pdfTextPath = Join-Path ([System.IO.Path]::GetTempPath()) (
        'Die-Grundlagen-der-Mathematik-B03-{0}.txt' -f [Guid]::NewGuid().ToString('N')
    )
    & pdftotext -layout 'B03.pdf' $pdfTextPath
    if ($LASTEXITCODE -ne 0) {
        throw "pdftotext failed for B03.pdf (exit code $LASTEXITCODE)."
    }

    $normalizedPdfText = [regex]::Replace(
        [System.IO.File]::ReadAllText($pdfTextPath),
        '\s+',
        ' '
    )
    $pdfMarkerPatterns = @(
        'Theorem nicht gefunden',
        'Mehrdeutige Theorem-Referenz',
        'Mehrdeutig: bitte',
        'Th. ?',
        'Def. ?',
        'Ax. ?',
        'Ref. ?',
        '??'
    )
    $pdfMarkers = @($pdfMarkerPatterns | Where-Object {
        $normalizedPdfText.IndexOf(
            $_,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -ge 0
    })
    if ($pdfMarkers.Count -gt 0) {
        throw "B03.pdf contains unresolved theorem/reference markers: $($pdfMarkers -join ', ')"
    }

    Write-Host "`nB03 standalone build and reference audit completed successfully."
    Write-Host "Output: $(Join-Path $repoRoot 'B03.pdf')"
}
finally {
    if ($pdfTextPath -and (Test-Path -LiteralPath $pdfTextPath)) {
        Remove-Item -LiteralPath $pdfTextPath -Force
    }
    Pop-Location
}
