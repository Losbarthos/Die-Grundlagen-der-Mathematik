[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Pack', 'Verify', 'Restore')]
    [string]$Mode = 'Verify',

    [Parameter()]
    [switch]$RequireToolMatch,

    [Parameter()]
    [switch]$SkipBuildForTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$cacheRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $repoRoot 'registry-cache')
)
$cacheInputFile = Join-Path $repoRoot 'cache-inputs.tsv'
$manifestName = 'manifest.tsv'
$manifestVersion = '1'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false, $true)
$requiredToolNames = @('PowerShell', 'latexmk', 'lualatex', 'pdftotext')

function ConvertTo-NormalizedRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    return $Path -replace '\\', '/'
}

function Get-SafeChildPath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Description
    )

    $normalized = ConvertTo-NormalizedRelativePath $RelativePath
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw "$Description must not be empty."
    }
    if ([System.IO.Path]::IsPathRooted($RelativePath) -or
        $normalized.StartsWith('/') -or
        $normalized -notmatch '^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$') {
        throw "$Description is not a safe relative path: $RelativePath"
    }

    $segments = @($normalized -split '/')
    if ($segments -contains '.' -or $segments -contains '..') {
        throw "$Description contains a traversal segment: $RelativePath"
    }

    $platformPath = $normalized.Replace(
        '/',
        [System.IO.Path]::DirectorySeparatorChar
    )
    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $Root $platformPath))
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $rootPrefix = $rootFull.TrimEnd([char[]]@([char]92, [char]47)) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith(
        $rootPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description escapes its allowed root: $RelativePath"
    }
    Assert-ExistingChildChainNotReparsePoint `
        -Root $rootFull `
        -FullPath $fullPath `
        -Description $Description
    return $fullPath
}

function Assert-NotReparsePoint {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Description must not be a symbolic link or reparse point: $Path"
        }
    }
}

function Assert-ExistingChildChainNotReparsePoint {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$FullPath,
        [Parameter(Mandatory)][string]$Description
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $full = [System.IO.Path]::GetFullPath($FullPath)
    $rootPrefix = $rootFull.TrimEnd([char[]]@([char]92, [char]47)) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith(
        $rootPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description escapes its allowed root: $FullPath"
    }

    Assert-NotReparsePoint -Path $rootFull -Description "$Description root"
    $relative = $full.Substring($rootPrefix.Length)
    $current = $rootFull
    foreach ($segment in $relative -split '[\\/]') {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        Assert-NotReparsePoint -Path $current -Description $Description
    }
}

function Assert-FixedCacheRoot {
    param([Parameter(Mandatory)][string]$Path)

    $expected = [System.IO.Path]::GetFullPath(
        (Join-Path $repoRoot 'registry-cache')
    )
    $actual = [System.IO.Path]::GetFullPath($Path)
    if (-not $actual.Equals(
        $expected,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing cache operation outside the fixed workspace cache: $actual"
    }
    [void](Get-SafeChildPath `
        -Root $repoRoot `
        -RelativePath 'registry-cache/.safety-check' `
        -Description 'Cache root')
    Assert-NotReparsePoint -Path $actual -Description 'Cache root'
}

function Assert-SafeGeneratedDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Parent,
        [Parameter(Mandatory)][string]$LeafPattern,
        [Parameter(Mandatory)][string]$Description
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullParent = [System.IO.Path]::GetFullPath($Parent)
    $actualParent = [System.IO.Path]::GetFullPath(
        (Split-Path -Parent $fullPath)
    )
    if (-not $actualParent.Equals(
        $fullParent,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description is not a direct child of its allowed directory: $fullPath"
    }
    if ((Split-Path -Leaf $fullPath) -notmatch $LeafPattern) {
        throw "$Description has an unsafe name: $fullPath"
    }
    Assert-NotReparsePoint -Path $fullParent -Description "$Description parent"
    Assert-NotReparsePoint -Path $fullPath -Description $Description
}

function Assert-DirectoryTreeNoReparsePoints {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Description is not a directory: $Path"
    }
    Assert-NotReparsePoint -Path $Path -Description $Description
    foreach ($member in Get-ChildItem -LiteralPath $Path -Recurse -Force) {
        Assert-NotReparsePoint `
            -Path $member.FullName `
            -Description "$Description member"
    }
}

function Remove-SafeGeneratedDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Parent,
        [Parameter(Mandatory)][string]$LeafPattern,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    Assert-SafeGeneratedDirectory `
        -Path $Path `
        -Parent $Parent `
        -LeafPattern $LeafPattern `
        -Description $Description
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Description is not a directory: $Path"
    }
    Assert-DirectoryTreeNoReparsePoints -Path $Path -Description $Description
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Remove-FixedCacheRoot {
    if (-not (Test-Path -LiteralPath $cacheRoot)) {
        return
    }
    Assert-FixedCacheRoot -Path $cacheRoot
    if (-not (Test-Path -LiteralPath $cacheRoot -PathType Container)) {
        throw "Cache root is not a directory: $cacheRoot"
    }
    Assert-DirectoryTreeNoReparsePoints `
        -Path $cacheRoot `
        -Description 'Cache root'
    Remove-Item -LiteralPath $cacheRoot -Recurse -Force
}

function Get-RepoRelativePath {
    param([Parameter(Mandatory)][string]$FullPath)

    $full = [System.IO.Path]::GetFullPath($FullPath)
    $rootPrefix = $repoRoot.TrimEnd([char[]]@([char]92, [char]47)) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith(
        $rootPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Path is outside the repository: $FullPath"
    }
    return ConvertTo-NormalizedRelativePath $full.Substring($rootPrefix.Length)
}

function Get-FileSignature {
    param(
        [Parameter(Mandatory)][string]$FullPath,
        [Parameter(Mandatory)][string]$Description,
        [switch]$AllowEmpty
    )

    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        throw "$Description is missing: $FullPath"
    }
    Assert-NotReparsePoint -Path $FullPath -Description $Description
    $item = Get-Item -LiteralPath $FullPath -Force
    if (-not $AllowEmpty -and $item.Length -eq 0) {
        throw "$Description is empty: $FullPath"
    }
    $hash = (Get-FileHash -LiteralPath $FullPath -Algorithm SHA256).Hash
    return [pscustomobject]@{
        Size = [long]$item.Length
        Sha256 = $hash.ToLowerInvariant()
        LastWriteTimeUtc = $item.LastWriteTimeUtc
    }
}

function New-ManifestRow {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Path,
        [string]$CachePath = '',
        [string]$Size = '',
        [string]$Sha256 = '',
        [string]$Value = ''
    )

    foreach ($field in @($Kind, $Path, $CachePath, $Size, $Sha256, $Value)) {
        if ($field -match "[`t`r`n]") {
            throw 'A manifest field contains a tab or newline.'
        }
    }
    return [pscustomobject]@{
        Kind = $Kind
        Path = $Path
        CachePath = $CachePath
        Size = $Size
        Sha256 = $Sha256
        Value = $Value
    }
}

function Read-BandDependencyGraph {
    $graphPath = Get-SafeChildPath `
        -Root $repoRoot `
        -RelativePath 'band-dependencies.tsv' `
        -Description 'Dependency graph'
    if (-not (Test-Path -LiteralPath $graphPath -PathType Leaf)) {
        throw "Dependency graph is missing: $graphPath"
    }

    $lines = [System.IO.File]::ReadAllLines($graphPath, $utf8NoBom)
    if ($lines.Count -lt 2) {
        throw "Dependency graph is empty: $graphPath"
    }
    $lines[0] = $lines[0].TrimStart([char]0xFEFF)
    $expectedHeader = "band`tsource`tartifact_base`tpredecessors"
    if ($lines[0] -ne $expectedHeader) {
        throw "Dependency graph has an invalid header: $graphPath"
    }

    $graph = @{}
    for ($lineIndex = 1; $lineIndex -lt $lines.Count; $lineIndex++) {
        $line = $lines[$lineIndex]
        if ([string]::IsNullOrWhiteSpace($line) -or
            $line.TrimStart().StartsWith('#')) {
            continue
        }
        $columns = [regex]::Split($line, "`t")
        if ($columns.Count -ne 4) {
            throw "Malformed dependency row at ${graphPath}:$($lineIndex + 1)."
        }

        $band = $columns[0].Trim()
        $source = ConvertTo-NormalizedRelativePath $columns[1].Trim()
        $artifactBase = ConvertTo-NormalizedRelativePath $columns[2].Trim()
        if ($band -notmatch '^B[0-9]{2}$' -or $graph.ContainsKey($band)) {
            throw "Invalid or duplicate band '$band' in $graphPath."
        }
        [void](Get-SafeChildPath `
            -Root $repoRoot `
            -RelativePath $source `
            -Description "Source for $band")
        [void](Get-SafeChildPath `
            -Root $repoRoot `
            -RelativePath "$artifactBase.aux" `
            -Description "Artifact base for $band")
        $expectedArtifactBase = "registry/_$band"
        if ($artifactBase -ne $expectedArtifactBase) {
            throw "Artifact base for $band must be '$expectedArtifactBase', got '$artifactBase'."
        }

        $predecessors = @()
        if (-not [string]::IsNullOrWhiteSpace($columns[3]) -and
            $columns[3].Trim() -ne '-') {
            $predecessors = @(
                $columns[3] -split ',' |
                    ForEach-Object { $_.Trim() }
            )
        }
        $graph[$band] = [pscustomobject]@{
            Band = $band
            Source = $source
            ArtifactBase = $artifactBase
            Predecessors = @($predecessors)
        }
    }
    return $graph
}

function Get-TopologicalPredecessors {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][hashtable]$Graph
    )

    if (-not $Graph.ContainsKey($Target)) {
        throw "Dependency graph has no row for $Target."
    }
    $states = @{}
    $ordered = [System.Collections.Generic.List[string]]::new()
    $visit = $null
    $visit = {
        param([string]$Band)

        if (-not $Graph.ContainsKey($Band)) {
            throw "Dependency graph has no row for predecessor $Band."
        }
        $state = if ($states.ContainsKey($Band)) { $states[$Band] } else { 0 }
        if ($state -eq 1) {
            throw "Dependency graph contains a cycle at $Band."
        }
        if ($state -eq 2) {
            return
        }
        $states[$Band] = 1
        foreach ($predecessor in $Graph[$Band].Predecessors) {
            if ($predecessor -notmatch '^B[0-9]{2}$') {
                throw "Invalid predecessor '$predecessor' of $Band."
            }
            & $visit $predecessor
        }
        $states[$Band] = 2
        [void]$ordered.Add($Band)
    }
    & $visit $Target
    return @($ordered | Where-Object { $_ -ne $Target })
}

function Read-CacheInputSpec {
    if (-not (Test-Path -LiteralPath $cacheInputFile -PathType Leaf)) {
        throw "Cache input specification is missing: $cacheInputFile"
    }
    Assert-NotReparsePoint `
        -Path $cacheInputFile `
        -Description 'Cache input specification'

    $lines = [System.IO.File]::ReadAllLines($cacheInputFile, $utf8NoBom)
    if ($lines.Count -lt 2) {
        throw "Cache input specification is empty: $cacheInputFile"
    }
    $lines[0] = $lines[0].TrimStart([char]0xFEFF)
    if ($lines[0] -ne "kind`tpath") {
        throw "Cache input specification has an invalid header: $cacheInputFile"
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $spec = [System.Collections.Generic.List[object]]::new()
    for ($index = 1; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        if ([string]::IsNullOrWhiteSpace($line) -or
            $line.TrimStart().StartsWith('#')) {
            continue
        }
        $columns = [regex]::Split($line, "`t")
        if ($columns.Count -ne 2) {
            throw "Malformed cache input row at ${cacheInputFile}:$($index + 1)."
        }
        $kind = $columns[0].Trim()
        $path = ConvertTo-NormalizedRelativePath $columns[1].Trim()
        if ($kind -notin @('file', 'tree', 'root_extension')) {
            throw "Unknown cache input kind '$kind' at ${cacheInputFile}:$($index + 1)."
        }
        if ($kind -eq 'root_extension') {
            if ($path -notmatch '^\.[A-Za-z0-9]+$') {
                throw "Invalid root extension '$path' at ${cacheInputFile}:$($index + 1)."
            }
        }
        else {
            $probe = if ($kind -eq 'tree') { "$path/.cache-input-probe" } else { $path }
            [void](Get-SafeChildPath `
                -Root $repoRoot `
                -RelativePath $probe `
                -Description "Cache input $kind")
            if ($path -match '^(?:\.git|registry|registry-cache|\.registry-cache-[^/]+)(?:/|$)') {
                throw "Generated or VCS path is forbidden in cache inputs: $path"
            }
        }
        $key = "$kind`t$path"
        if (-not $seen.Add($key)) {
            throw "Duplicate cache input row '$kind $path'."
        }
        [void]$spec.Add([pscustomobject]@{ Kind = $kind; Path = $path })
    }
    if ($spec.Count -eq 0) {
        throw "Cache input specification has no rows: $cacheInputFile"
    }
    return @($spec)
}

function Get-ExpectedSourcePaths {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][object[]]$InputSpec
    )

    $paths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($entry in $InputSpec) {
        switch ($entry.Kind) {
            'file' {
                $fullPath = Get-SafeChildPath `
                    -Root $repoRoot `
                    -RelativePath $entry.Path `
                    -Description 'Configured cache input file'
                if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
                    throw "Configured cache input file is missing: $($entry.Path)"
                }
                Assert-NotReparsePoint `
                    -Path $fullPath `
                    -Description 'Configured cache input file'
                [void]$paths.Add($entry.Path)
            }
            'tree' {
                $treeRoot = Get-SafeChildPath `
                    -Root $repoRoot `
                    -RelativePath "$($entry.Path)/.cache-input-probe" `
                    -Description 'Configured cache input tree'
                $treeRoot = Split-Path -Parent $treeRoot
                if (-not (Test-Path -LiteralPath $treeRoot -PathType Container)) {
                    throw "Configured cache input tree is missing: $($entry.Path)"
                }
                Assert-NotReparsePoint `
                    -Path $treeRoot `
                    -Description 'Configured cache input tree'
                $members = @(Get-ChildItem `
                    -LiteralPath $treeRoot `
                    -Recurse `
                    -Force)
                foreach ($member in $members) {
                    Assert-NotReparsePoint `
                        -Path $member.FullName `
                        -Description 'Configured cache input tree member'
                    if (-not $member.PSIsContainer) {
                        if (-not (Test-Path -LiteralPath $member.FullName -PathType Leaf)) {
                            throw "Non-file below configured input tree: $($member.FullName)"
                        }
                        [void]$paths.Add((Get-RepoRelativePath $member.FullName))
                    }
                }
            }
            'root_extension' {
                foreach ($file in Get-ChildItem `
                    -LiteralPath $repoRoot `
                    -Force) {
                    if (-not $file.Name.EndsWith(
                        $entry.Path,
                        [System.StringComparison]::Ordinal
                    )) {
                        continue
                    }
                    Assert-NotReparsePoint `
                        -Path $file.FullName `
                        -Description 'Root cache input'
                    if ($file.PSIsContainer) {
                        throw "Root cache input is not a file: $($file.Name)"
                    }
                    [void]$paths.Add((Get-RepoRelativePath $file.FullName))
                }
            }
        }
    }

    if (-not $paths.Contains('cache-inputs.tsv')) {
        throw 'cache-inputs.tsv must include itself as a file input.'
    }
    foreach ($record in $Graph.Values) {
        if (-not $paths.Contains($record.Source)) {
            throw "Dependency source is not covered by cache-inputs.tsv: $($record.Source)"
        }
    }

    return @($paths | Sort-Object)
}

function Get-ExpectedArtifactPaths {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][string[]]$PredecessorBands
    )

    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($band in $PredecessorBands) {
        foreach ($extension in @('aux', 'pdf', 'registry.tsv', 'debug.log')) {
            [void]$paths.Add("$($Graph[$band].ArtifactBase).$extension")
        }
    }
    return @($paths)
}

function Get-ExpectedMetadataPaths {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][string[]]$PredecessorBands
    )

    return @($PredecessorBands | ForEach-Object {
        "$($Graph[$_].ArtifactBase).log"
    })
}

function Get-FirstVersionLine {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$PreferredPattern = '',
        [switch]$RequirePreferredMatch
    )

    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Required tool '$Command' was not found on PATH."
    }
    # Several TeX/Poppler tools print their version (and MiKTeX's console-code
    # notice) on stderr.  In Windows PowerShell that stream becomes a
    # non-terminating NativeCommandError when the global preference is Stop.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Command @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw "Version query failed for $Command (exit $exitCode)."
    }
    $nonEmptyLines = @($output | ForEach-Object { "$_".Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $line = @()
    if (-not [string]::IsNullOrWhiteSpace($PreferredPattern)) {
        $line = @($nonEmptyLines | Where-Object { $_ -match $PreferredPattern } |
            Select-Object -First 1)
    }
    if ($line.Count -eq 0 -and $RequirePreferredMatch) {
        throw "Version query for $Command did not return a line matching '$PreferredPattern'."
    }
    if ($line.Count -eq 0) {
        $line = @($nonEmptyLines | Select-Object -First 1)
    }
    if ($line.Count -ne 1) {
        throw "Version query returned no text for $Command."
    }
    return [regex]::Replace($line[0], '\s+', ' ')
}

function Get-CurrentToolVersions {
    $osDescription = if ($PSVersionTable.ContainsKey('OS')) {
        "$($PSVersionTable.OS)"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:OS)) {
        $env:OS
    }
    else {
        [System.Environment]::OSVersion.VersionString
    }

    return [ordered]@{
        PowerShell = "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition); $osDescription)"
        latexmk = Get-FirstVersionLine -Command 'latexmk' -Arguments @('-version') `
            -PreferredPattern '^Latexmk,' -RequirePreferredMatch
        lualatex = Get-FirstVersionLine -Command 'lualatex' -Arguments @('--version') `
            -PreferredPattern 'Lua(?:HB)?TeX.*Version' -RequirePreferredMatch
        pdftotext = Get-FirstVersionLine -Command 'pdftotext' -Arguments @('-v') `
            -PreferredPattern '^pdftotext version' -RequirePreferredMatch
    }
}

function Get-SourceRows {
    param([Parameter(Mandatory)][string[]]$SourcePaths)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($relativePath in $SourcePaths) {
        $fullPath = Get-SafeChildPath `
            -Root $repoRoot `
            -RelativePath $relativePath `
            -Description 'Source input'
        $signature = Get-FileSignature `
            -FullPath $fullPath `
            -Description "Source input $relativePath"
        [void]$rows.Add((New-ManifestRow `
            -Kind 'source' `
            -Path $relativePath `
            -Size "$($signature.Size)" `
            -Sha256 $signature.Sha256))
    }
    return @($rows)
}

function Assert-SourceRowsEqual {
    param(
        [Parameter(Mandatory)][object[]]$Expected,
        [Parameter(Mandatory)][object[]]$Actual,
        [Parameter(Mandatory)][string]$Context
    )

    if ($Expected.Count -ne $Actual.Count) {
        throw "$Context changed the source input count: expected $($Expected.Count), got $($Actual.Count)."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        $before = $Expected[$index]
        $after = $Actual[$index]
        if ($before.Path -ne $after.Path -or
            $before.Size -ne $after.Size -or
            $before.Sha256 -ne $after.Sha256) {
            throw "$Context changed source input '$($before.Path)' (before $($before.Sha256), after $($after.Sha256))."
        }
    }
}

function Assert-ExactSet {
    param(
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string[]]$Actual,
        [Parameter(Mandatory)][string]$Description
    )

    $expectedSet = [System.Collections.Generic.HashSet[string]]::new(
        $Expected,
        [System.StringComparer]::Ordinal
    )
    $actualSet = [System.Collections.Generic.HashSet[string]]::new(
        $Actual,
        [System.StringComparer]::Ordinal
    )
    if ($actualSet.Count -ne $Actual.Count) {
        throw "$Description contains duplicate entries."
    }
    $missing = @($expectedSet | Where-Object { -not $actualSet.Contains($_) } |
        Sort-Object)
    $extra = @($actualSet | Where-Object { -not $expectedSet.Contains($_) } |
        Sort-Object)
    if ($missing.Count -gt 0 -or $extra.Count -gt 0) {
        throw "$Description does not match the expected set. Missing: $(
            if ($missing.Count) { $missing -join ', ' } else { '(none)' }
        ). Extra: $(
            if ($extra.Count) { $extra -join ', ' } else { '(none)' }
        )."
    }
}

function Read-CacheManifest {
    param([Parameter(Mandatory)][string]$Root)

    $manifestPath = Get-SafeChildPath `
        -Root $Root `
        -RelativePath $manifestName `
        -Description 'Cache manifest'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Cache manifest is missing: $manifestPath"
    }
    Assert-NotReparsePoint -Path $manifestPath -Description 'Cache manifest'
    $lines = [System.IO.File]::ReadAllLines($manifestPath, $utf8NoBom)
    if ($lines.Count -lt 3) {
        throw "Cache manifest is truncated: $manifestPath"
    }
    $lines[0] = $lines[0].TrimStart([char]0xFEFF)
    if ($lines[0] -ne "manifest_version`t$manifestVersion") {
        throw "Unsupported cache manifest version in $manifestPath."
    }
    if ($lines[1] -ne "kind`tpath`tcache_path`tsize`tsha256`tvalue") {
        throw "Cache manifest has an invalid header: $manifestPath"
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    for ($index = 2; $index -lt $lines.Count; $index++) {
        if ([string]::IsNullOrWhiteSpace($lines[$index])) {
            throw "Cache manifest contains an empty row at line $($index + 1)."
        }
        $columns = [regex]::Split($lines[$index], "`t")
        if ($columns.Count -ne 6) {
            throw "Cache manifest row $($index + 1) must contain six TSV fields."
        }
        [void]$rows.Add((New-ManifestRow `
            -Kind $columns[0] `
            -Path $columns[1] `
            -CachePath $columns[2] `
            -Size $columns[3] `
            -Sha256 $columns[4] `
            -Value $columns[5]))
    }
    return @($rows)
}

function Assert-FileRow {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string]$FullPath,
        [Parameter(Mandatory)][string]$Description,
        [switch]$AllowEmpty
    )

    $expectedSize = 0L
    if (-not [long]::TryParse($Row.Size, [ref]$expectedSize) -or
        $expectedSize -lt 0) {
        throw "$Description has an invalid size in the manifest: $($Row.Size)"
    }
    if ($Row.Sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "$Description has an invalid SHA-256 in the manifest."
    }
    $actual = Get-FileSignature `
        -FullPath $FullPath `
        -Description $Description `
        -AllowEmpty:$AllowEmpty
    if ($actual.Size -ne $expectedSize) {
        throw "$Description size mismatch: expected $expectedSize, got $($actual.Size)."
    }
    if ($actual.Sha256 -ne $Row.Sha256) {
        throw "$Description SHA-256 mismatch: expected $($Row.Sha256), got $($actual.Sha256)."
    }
}

function Test-RegistryCache {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$SourcePaths,
        [Parameter(Mandatory)][string[]]$ArtifactPaths,
        [Parameter(Mandatory)][string[]]$MetadataPaths,
        [switch]$CheckToolVersions
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Registry cache directory is missing: $Root"
    }
    Assert-NotReparsePoint -Path $Root -Description 'Registry cache directory'
    $rows = @(Read-CacheManifest -Root $Root)
    $sourceRows = @($rows | Where-Object Kind -eq 'source')
    $artifactRows = @($rows | Where-Object Kind -eq 'artifact')
    $metadataRows = @($rows | Where-Object Kind -eq 'metadata')
    $toolRows = @($rows | Where-Object Kind -eq 'tool')
    $unknownRows = @($rows | Where-Object {
        $_.Kind -notin @('source', 'artifact', 'metadata', 'tool')
    })
    if ($unknownRows.Count -gt 0) {
        throw "Cache manifest contains unknown row kinds: $(
            @($unknownRows.Kind | Sort-Object -Unique) -join ', '
        )."
    }

    Assert-ExactSet -Expected $SourcePaths -Actual @($sourceRows.Path) `
        -Description 'Manifest source inputs'
    Assert-ExactSet -Expected $ArtifactPaths -Actual @($artifactRows.Path) `
        -Description 'Manifest artifacts'
    Assert-ExactSet -Expected $MetadataPaths -Actual @($metadataRows.Path) `
        -Description 'Manifest metadata'
    Assert-ExactSet -Expected $requiredToolNames -Actual @($toolRows.Path) `
        -Description 'Manifest tool versions'

    foreach ($row in $sourceRows) {
        if ($row.CachePath -ne '' -or $row.Value -ne '') {
            throw "Malformed source row for $($row.Path)."
        }
        $sourcePath = Get-SafeChildPath `
            -Root $repoRoot `
            -RelativePath $row.Path `
            -Description 'Manifest source input'
        Assert-FileRow `
            -Row $row `
            -FullPath $sourcePath `
            -Description "Source input $($row.Path)"
    }

    foreach ($row in $artifactRows) {
        $expectedCachePath = "files/$($row.Path)"
        if ($row.CachePath -ne $expectedCachePath -or $row.Value -ne '') {
            throw "Malformed artifact row for $($row.Path)."
        }
        $cachePath = Get-SafeChildPath `
            -Root $Root `
            -RelativePath $row.CachePath `
            -Description 'Cached artifact'
        Assert-FileRow `
            -Row $row `
            -FullPath $cachePath `
            -Description "Cached artifact $($row.Path)" `
            -AllowEmpty:($row.Path.EndsWith('.debug.log'))
    }

    foreach ($row in $metadataRows) {
        $expectedCachePath = "metadata/$($row.Path)"
        if ($row.CachePath -ne $expectedCachePath -or $row.Value -ne '') {
            throw "Malformed metadata row for $($row.Path)."
        }
        $cachePath = Get-SafeChildPath `
            -Root $Root `
            -RelativePath $row.CachePath `
            -Description 'Cached build metadata'
        Assert-FileRow `
            -Row $row `
            -FullPath $cachePath `
            -Description "Cached build metadata $($row.Path)"
    }

    foreach ($row in $toolRows) {
        if ($row.CachePath -ne '' -or $row.Size -ne '' -or
            $row.Sha256 -ne '' -or [string]::IsNullOrWhiteSpace($row.Value)) {
            throw "Malformed tool row for $($row.Path)."
        }
    }
    if ($CheckToolVersions) {
        $currentVersions = Get-CurrentToolVersions
        foreach ($row in $toolRows) {
            if ($currentVersions[$row.Path] -ne $row.Value) {
                throw "Tool version mismatch for $($row.Path): cache='$($row.Value)', current='$($currentVersions[$row.Path])'."
            }
        }
    }

    $expectedFiles = @($manifestName) + @($artifactRows.CachePath) +
        @($metadataRows.CachePath)
    $actualFiles = @(
        Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
            ForEach-Object {
                Assert-NotReparsePoint `
                    -Path $_.FullName `
                    -Description 'Registry cache member'
                $prefix = $Root.TrimEnd([char[]]@([char]92, [char]47)) +
                    [System.IO.Path]::DirectorySeparatorChar
                ConvertTo-NormalizedRelativePath $_.FullName.Substring($prefix.Length)
            }
    )
    Assert-ExactSet -Expected $expectedFiles -Actual $actualFiles `
        -Description 'Files in registry cache'

    $expectedDirectories = @('files', 'files/registry', 'metadata', 'metadata/registry')
    $actualDirectories = @(
        Get-ChildItem -LiteralPath $Root -Recurse -Directory -Force |
            ForEach-Object {
                Assert-NotReparsePoint `
                    -Path $_.FullName `
                    -Description 'Registry cache directory member'
                $prefix = $Root.TrimEnd([char[]]@([char]92, [char]47)) +
                    [System.IO.Path]::DirectorySeparatorChar
                ConvertTo-NormalizedRelativePath $_.FullName.Substring($prefix.Length)
            }
    )
    Assert-ExactSet -Expected $expectedDirectories -Actual $actualDirectories `
        -Description 'Directories in registry cache'

    return [pscustomobject]@{
        Rows = $rows
        ArtifactRows = $artifactRows
    }
}

function Write-CacheManifest {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][object[]]$Rows
    )

    $manifestPath = Get-SafeChildPath `
        -Root $Root `
        -RelativePath $manifestName `
        -Description 'Cache manifest'
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add("manifest_version`t$manifestVersion")
    [void]$lines.Add("kind`tpath`tcache_path`tsize`tsha256`tvalue")
    foreach ($row in $Rows) {
        [void]$lines.Add((@(
            $row.Kind,
            $row.Path,
            $row.CachePath,
            $row.Size,
            $row.Sha256,
            $row.Value
        ) -join "`t"))
    }
    [System.IO.File]::WriteAllLines($manifestPath, $lines, $utf8NoBom)
}

function Assert-LiveBuildFreshness {
    param(
        [Parameter(Mandatory)][string[]]$SourcePaths,
        [Parameter(Mandatory)][string[]]$ArtifactPaths,
        [Parameter(Mandatory)][string[]]$MetadataPaths
    )

    $newestSourceUtc = [datetime]::MinValue
    foreach ($relativePath in $SourcePaths) {
        $fullPath = Get-SafeChildPath `
            -Root $repoRoot `
            -RelativePath $relativePath `
            -Description 'Source input'
        $signature = Get-FileSignature `
            -FullPath $fullPath `
            -Description "Source input $relativePath"
        if ($signature.LastWriteTimeUtc -gt $newestSourceUtc) {
            $newestSourceUtc = $signature.LastWriteTimeUtc
        }
    }

    foreach ($relativePath in @($ArtifactPaths + $MetadataPaths)) {
        $fullPath = Get-SafeChildPath `
            -Root $repoRoot `
            -RelativePath $relativePath `
            -Description 'Live build output'
        $signature = Get-FileSignature `
            -FullPath $fullPath `
            -Description "Live build output $relativePath" `
            -AllowEmpty:($relativePath.EndsWith('.debug.log'))
        if ($signature.LastWriteTimeUtc -lt $newestSourceUtc.AddSeconds(-2)) {
            throw "Live build output predates a source input and must be rebuilt: $relativePath"
        }
    }

    foreach ($relativePath in @('B05.log', 'B05.pdf')) {
        $fullPath = Get-SafeChildPath `
            -Root $repoRoot `
            -RelativePath $relativePath `
            -Description 'B05 build proof'
        $signature = Get-FileSignature `
            -FullPath $fullPath `
            -Description "Successful B05 build proof $relativePath"
        if ($signature.LastWriteTimeUtc -lt $newestSourceUtc.AddSeconds(-2)) {
            throw "$relativePath is older than a cache source input; run the B05 build again."
        }
    }
}

function Copy-FileIntoCache {
    param(
        [Parameter(Mandatory)][string]$StageRoot,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$LiveRelativePath,
        [Parameter(Mandatory)][string]$CacheRelativePath,
        [switch]$AllowEmpty
    )

    $livePath = Get-SafeChildPath `
        -Root $repoRoot `
        -RelativePath $LiveRelativePath `
        -Description 'Live build output'
    $liveSignature = Get-FileSignature `
        -FullPath $livePath `
        -Description "Live build output $LiveRelativePath" `
        -AllowEmpty:$AllowEmpty
    $destination = Get-SafeChildPath `
        -Root $StageRoot `
        -RelativePath $CacheRelativePath `
        -Description 'Staged cache output'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) |
        Out-Null
    Copy-Item -LiteralPath $livePath -Destination $destination
    $cachedSignature = Get-FileSignature `
        -FullPath $destination `
        -Description "Staged cache output $CacheRelativePath" `
        -AllowEmpty:$AllowEmpty
    if ($cachedSignature.Size -ne $liveSignature.Size -or
        $cachedSignature.Sha256 -ne $liveSignature.Sha256) {
        throw "Source changed while copying cache member: $LiveRelativePath"
    }
    return New-ManifestRow `
        -Kind $Kind `
        -Path $LiveRelativePath `
        -CachePath $CacheRelativePath `
        -Size "$($cachedSignature.Size)" `
        -Sha256 $cachedSignature.Sha256
}

function New-RegistryCache {
    param(
        [Parameter(Mandatory)][string[]]$SourcePaths,
        [Parameter(Mandatory)][string[]]$ArtifactPaths,
        [Parameter(Mandatory)][string[]]$MetadataPaths
    )

    Assert-FixedCacheRoot -Path $cacheRoot
    Assert-LiveBuildFreshness `
        -SourcePaths $SourcePaths `
        -ArtifactPaths $ArtifactPaths `
        -MetadataPaths $MetadataPaths
    $initialSourceRows = @(Get-SourceRows -SourcePaths $SourcePaths)
    $toolVersions = Get-CurrentToolVersions

    $token = [Guid]::NewGuid().ToString('N')
    $stageRoot = Join-Path $repoRoot ".registry-cache-stage-$token"
    $backupRoot = Join-Path $repoRoot ".registry-cache-backup-$token"
    $stagePattern = '^\.registry-cache-stage-[0-9a-f]{32}$'
    $backupPattern = '^\.registry-cache-backup-[0-9a-f]{32}$'
    Assert-SafeGeneratedDirectory `
        -Path $stageRoot `
        -Parent $repoRoot `
        -LeafPattern $stagePattern `
        -Description 'Cache publication staging directory'
    Assert-SafeGeneratedDirectory `
        -Path $backupRoot `
        -Parent $repoRoot `
        -LeafPattern $backupPattern `
        -Description 'Cache publication backup directory'
    if ((Test-Path -LiteralPath $stageRoot) -or
        (Test-Path -LiteralPath $backupRoot)) {
        throw 'A generated cache publication directory already exists.'
    }
    New-Item -ItemType Directory -Path $stageRoot | Out-Null

    $published = $false
    $backedUp = $false
    try {
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $initialSourceRows) {
            [void]$rows.Add($row)
        }
        foreach ($relativePath in $ArtifactPaths) {
            $cachePath = "files/$relativePath"
            $row = Copy-FileIntoCache `
                -StageRoot $stageRoot `
                -Kind 'artifact' `
                -LiveRelativePath $relativePath `
                -CacheRelativePath $cachePath `
                -AllowEmpty:($relativePath.EndsWith('.debug.log'))
            [void]$rows.Add($row)
        }
        foreach ($relativePath in $MetadataPaths) {
            $cachePath = "metadata/$relativePath"
            $row = Copy-FileIntoCache `
                -StageRoot $stageRoot `
                -Kind 'metadata' `
                -LiveRelativePath $relativePath `
                -CacheRelativePath $cachePath
            [void]$rows.Add($row)
        }
        foreach ($toolName in $requiredToolNames) {
            [void]$rows.Add((New-ManifestRow `
                -Kind 'tool' `
                -Path $toolName `
                -Value $toolVersions[$toolName]))
        }

        $finalSourceRows = @(Get-SourceRows -SourcePaths $SourcePaths)
        Assert-SourceRowsEqual `
            -Expected $initialSourceRows `
            -Actual $finalSourceRows `
            -Context 'Cache packaging'
        Assert-LiveBuildFreshness `
            -SourcePaths $SourcePaths `
            -ArtifactPaths $ArtifactPaths `
            -MetadataPaths $MetadataPaths

        Write-CacheManifest -Root $stageRoot -Rows @($rows)
        [void](Test-RegistryCache `
            -Root $stageRoot `
            -SourcePaths $SourcePaths `
            -ArtifactPaths $ArtifactPaths `
            -MetadataPaths $MetadataPaths `
            -CheckToolVersions:$RequireToolMatch)

        if (Test-Path -LiteralPath $cacheRoot) {
            Assert-FixedCacheRoot -Path $cacheRoot
            if (-not (Test-Path -LiteralPath $cacheRoot -PathType Container)) {
                throw "Existing cache root is not a directory: $cacheRoot"
            }
            Assert-DirectoryTreeNoReparsePoints `
                -Path $cacheRoot `
                -Description 'Existing cache root'
            # Both directories are verified direct children of the workspace;
            # the move preserves the complete old publication for rollback.
            Move-Item -LiteralPath $cacheRoot -Destination $backupRoot
            $backedUp = $true
        }
        Move-Item -LiteralPath $stageRoot -Destination $cacheRoot
        $published = $true
        if ($env:DGM_REGISTRY_CACHE_TEST_FAIL_PUBLISH_FINAL -eq '1') {
            throw 'TEST ONLY: injected cache publication failure after swap.'
        }
        [void](Test-RegistryCache `
            -Root $cacheRoot `
            -SourcePaths $SourcePaths `
            -ArtifactPaths $ArtifactPaths `
            -MetadataPaths $MetadataPaths `
            -CheckToolVersions:$RequireToolMatch)
    }
    catch {
        $failure = $_.Exception.Message
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        if ($published -and (Test-Path -LiteralPath $cacheRoot)) {
            try { Remove-FixedCacheRoot }
            catch { [void]$rollbackErrors.Add("remove new cache: $($_.Exception.Message)") }
        }
        if ($backedUp -and (Test-Path -LiteralPath $backupRoot)) {
            try {
                if (Test-Path -LiteralPath $cacheRoot) {
                    throw "cache root still exists: $cacheRoot"
                }
                Assert-SafeGeneratedDirectory `
                    -Path $backupRoot `
                    -Parent $repoRoot `
                    -LeafPattern $backupPattern `
                    -Description 'Cache publication backup directory'
                Move-Item -LiteralPath $backupRoot -Destination $cacheRoot
            }
            catch { [void]$rollbackErrors.Add("restore old cache: $($_.Exception.Message)") }
        }
        if (Test-Path -LiteralPath $stageRoot) {
            try {
                Remove-SafeGeneratedDirectory `
                    -Path $stageRoot `
                    -Parent $repoRoot `
                    -LeafPattern $stagePattern `
                    -Description 'Cache publication staging directory'
            }
            catch { [void]$rollbackErrors.Add("remove staging: $($_.Exception.Message)") }
        }
        $suffix = if ($rollbackErrors.Count) {
            " Rollback errors: $($rollbackErrors -join '; ')"
        }
        else {
            ' Publication was rolled back.'
        }
        throw "Registry cache publication failed: $failure$suffix"
    }

    if ($backedUp -and (Test-Path -LiteralPath $backupRoot)) {
        Remove-SafeGeneratedDirectory `
            -Path $backupRoot `
            -Parent $repoRoot `
            -LeafPattern $backupPattern `
            -Description 'Cache publication backup directory'
    }
    Write-Host "Registry cache packed, published, and finally verified: $cacheRoot"
}

function Restore-RegistryCache {
    param(
        [Parameter(Mandatory)]$Verification
    )

    $registryPath = Get-SafeChildPath `
        -Root $repoRoot `
        -RelativePath 'registry/.safety-check' `
        -Description 'Live registry directory'
    $registryPath = Split-Path -Parent $registryPath
    if (Test-Path -LiteralPath $registryPath) {
        if (-not (Test-Path -LiteralPath $registryPath -PathType Container)) {
            throw "Live registry path is not a directory: $registryPath"
        }
        Assert-NotReparsePoint `
            -Path $registryPath `
            -Description 'Live registry directory'
    }
    else {
        New-Item -ItemType Directory -Path $registryPath | Out-Null
    }

    $token = [Guid]::NewGuid().ToString('N')
    $stageRoot = Join-Path $registryPath ".registry-cache-restore-stage-$token"
    $backupRoot = Join-Path $registryPath ".registry-cache-restore-backup-$token"
    $stagePattern = '^\.registry-cache-restore-stage-[0-9a-f]{32}$'
    $backupPattern = '^\.registry-cache-restore-backup-[0-9a-f]{32}$'
    Assert-SafeGeneratedDirectory `
        -Path $stageRoot `
        -Parent $registryPath `
        -LeafPattern $stagePattern `
        -Description 'Registry restore staging directory'
    Assert-SafeGeneratedDirectory `
        -Path $backupRoot `
        -Parent $registryPath `
        -LeafPattern $backupPattern `
        -Description 'Registry restore backup directory'
    if ((Test-Path -LiteralPath $stageRoot) -or
        (Test-Path -LiteralPath $backupRoot)) {
        throw 'A generated registry restore directory already exists.'
    }
    New-Item -ItemType Directory -Path $stageRoot | Out-Null
    New-Item -ItemType Directory -Path $backupRoot | Out-Null

    $entries = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($row in @($Verification.ArtifactRows | Sort-Object Path)) {
            $source = Get-SafeChildPath `
                -Root $cacheRoot `
                -RelativePath $row.CachePath `
                -Description 'Cached artifact'
            $destination = Get-SafeChildPath `
                -Root $repoRoot `
                -RelativePath $row.Path `
                -Description 'Live registry artifact'
            if (Test-Path -LiteralPath $destination) {
                Assert-NotReparsePoint `
                    -Path $destination `
                    -Description 'Existing live registry artifact'
                if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
                    throw "Live registry artifact is not a file: $destination"
                }
            }
            $leaf = [System.IO.Path]::GetFileName($destination)
            $staged = Join-Path $stageRoot $leaf
            $backup = Join-Path $backupRoot $leaf
            if ((Test-Path -LiteralPath $staged) -or
                (Test-Path -LiteralPath $backup)) {
                throw "Duplicate restore target: $leaf"
            }
            Copy-Item -LiteralPath $source -Destination $staged
            Assert-FileRow `
                -Row $row `
                -FullPath $staged `
                -Description "Staged restore artifact $($row.Path)" `
                -AllowEmpty:($row.Path.EndsWith('.debug.log'))
            [void]$entries.Add([pscustomobject]@{
                Row = $row
                Destination = $destination
                Staged = $staged
                Backup = $backup
                BackedUp = $false
                Installed = $false
            })
        }
        if ($entries.Count -ne $Verification.ArtifactRows.Count) {
            throw "Restore staging count mismatch: expected $($Verification.ArtifactRows.Count), got $($entries.Count)."
        }
    }
    catch {
        $failure = $_.Exception.Message
        Remove-SafeGeneratedDirectory `
            -Path $stageRoot `
            -Parent $registryPath `
            -LeafPattern $stagePattern `
            -Description 'Registry restore staging directory'
        Remove-SafeGeneratedDirectory `
            -Path $backupRoot `
            -Parent $registryPath `
            -LeafPattern $backupPattern `
            -Description 'Registry restore backup directory'
        throw "Registry cache restore staging failed before live changes: $failure"
    }

    try {
        $installedCount = 0
        foreach ($entry in $entries) {
            if (Test-Path -LiteralPath $entry.Destination) {
                Move-Item `
                    -LiteralPath $entry.Destination `
                    -Destination $entry.Backup
                $entry.BackedUp = $true
            }
            Move-Item `
                -LiteralPath $entry.Staged `
                -Destination $entry.Destination
            $entry.Installed = $true
            $installedCount++
            if ($env:DGM_REGISTRY_CACHE_TEST_FAIL_RESTORE_COMMIT -eq '1' -and
                $installedCount -eq 5) {
                throw 'TEST ONLY: injected registry restore commit failure.'
            }
        }

        # Keep all backups until every installed artifact has passed its final
        # size and SHA-256 check as one complete live set.
        foreach ($entry in $entries) {
            Assert-FileRow `
                -Row $entry.Row `
                -FullPath $entry.Destination `
                -Description "Restored artifact $($entry.Row.Path)" `
                -AllowEmpty:($entry.Row.Path.EndsWith('.debug.log'))
        }
    }
    catch {
        $failure = $_.Exception.Message
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in @($entries | Sort-Object Destination -Descending)) {
            if ($entry.Installed -and
                (Test-Path -LiteralPath $entry.Destination)) {
                try {
                    Assert-NotReparsePoint `
                        -Path $entry.Destination `
                        -Description 'Failed restored artifact'
                    Remove-Item -LiteralPath $entry.Destination -Force
                }
                catch { [void]$rollbackErrors.Add("remove $($entry.Destination): $($_.Exception.Message)") }
            }
            if ($entry.BackedUp -and (Test-Path -LiteralPath $entry.Backup)) {
                try {
                    if (Test-Path -LiteralPath $entry.Destination) {
                        throw "destination still exists: $($entry.Destination)"
                    }
                    Move-Item `
                        -LiteralPath $entry.Backup `
                        -Destination $entry.Destination
                }
                catch { [void]$rollbackErrors.Add("restore $($entry.Destination): $($_.Exception.Message)") }
            }
        }
        if ($rollbackErrors.Count -eq 0) {
            Remove-SafeGeneratedDirectory `
                -Path $stageRoot `
                -Parent $registryPath `
                -LeafPattern $stagePattern `
                -Description 'Registry restore staging directory'
            Remove-SafeGeneratedDirectory `
                -Path $backupRoot `
                -Parent $registryPath `
                -LeafPattern $backupPattern `
                -Description 'Registry restore backup directory'
        }
        $suffix = if ($rollbackErrors.Count) {
            " Rollback errors: $($rollbackErrors -join '; '); staged/backup data was retained."
        }
        else {
            ' All live changes were rolled back.'
        }
        throw "Registry cache restore failed: $failure$suffix"
    }

    Remove-SafeGeneratedDirectory `
        -Path $stageRoot `
        -Parent $registryPath `
        -LeafPattern $stagePattern `
        -Description 'Registry restore staging directory'
    Remove-SafeGeneratedDirectory `
        -Path $backupRoot `
        -Parent $registryPath `
        -LeafPattern $backupPattern `
        -Description 'Registry restore backup directory'
    Write-Host "Registry cache restored as a finally verified set: $registryPath"
}

$graph = Read-BandDependencyGraph
$predecessorBands = @(Get-TopologicalPredecessors -Target 'B05' -Graph $graph)
if (($predecessorBands -join ',') -ne 'B01,B02,B03,B04') {
    throw "B05 cache requires the canonical predecessor graph B01,B02,B03,B04; got '$($predecessorBands -join ',')'."
}
if ($SkipBuildForTest -and $Mode -ne 'Pack') {
    throw '-SkipBuildForTest is valid only with -Mode Pack.'
}
$inputSpec = @(Read-CacheInputSpec)
$sourcePaths = @(Get-ExpectedSourcePaths -Graph $graph -InputSpec $inputSpec)
$artifactPaths = @(Get-ExpectedArtifactPaths `
    -Graph $graph `
    -PredecessorBands $predecessorBands)
$metadataPaths = @(Get-ExpectedMetadataPaths `
    -Graph $graph `
    -PredecessorBands $predecessorBands)

switch ($Mode) {
    'Pack' {
        $sourceRowsBeforeBuild = @(Get-SourceRows -SourcePaths $sourcePaths)
        if ($SkipBuildForTest) {
            Write-Warning 'TEST ONLY: skipping the clean B05 build before Pack.'
        }
        else {
            $buildScript = Get-SafeChildPath `
                -Root $repoRoot `
                -RelativePath 'scripts/build-b03.ps1' `
                -Description 'Clean B05 build script'
            Write-Host 'Running the owned clean B05 build before cache packaging.'
            & $buildScript -Target B05
        }

        $graphAfterBuild = Read-BandDependencyGraph
        $inputSpecAfterBuild = @(Read-CacheInputSpec)
        $sourcePathsAfterBuild = @(Get-ExpectedSourcePaths `
            -Graph $graphAfterBuild `
            -InputSpec $inputSpecAfterBuild)
        Assert-ExactSet `
            -Expected $sourcePaths `
            -Actual $sourcePathsAfterBuild `
            -Description 'Source inputs before and after the B05 build'
        $sourceRowsAfterBuild = @(Get-SourceRows `
            -SourcePaths $sourcePathsAfterBuild)
        Assert-SourceRowsEqual `
            -Expected $sourceRowsBeforeBuild `
            -Actual $sourceRowsAfterBuild `
            -Context 'The clean B05 build'
        $sourcePaths = $sourcePathsAfterBuild

        New-RegistryCache `
            -SourcePaths $sourcePaths `
            -ArtifactPaths $artifactPaths `
            -MetadataPaths $metadataPaths
    }
    'Verify' {
        Assert-FixedCacheRoot -Path $cacheRoot
        [void](Test-RegistryCache `
            -Root $cacheRoot `
            -SourcePaths $sourcePaths `
            -ArtifactPaths $artifactPaths `
            -MetadataPaths $metadataPaths `
            -CheckToolVersions:$RequireToolMatch)
        Write-Host "Registry cache is complete, exact, and current: $cacheRoot"
    }
    'Restore' {
        Assert-FixedCacheRoot -Path $cacheRoot
        $verification = Test-RegistryCache `
            -Root $cacheRoot `
            -SourcePaths $sourcePaths `
            -ArtifactPaths $artifactPaths `
            -MetadataPaths $metadataPaths `
            -CheckToolVersions:$RequireToolMatch
        Restore-RegistryCache -Verification $verification
    }
}
