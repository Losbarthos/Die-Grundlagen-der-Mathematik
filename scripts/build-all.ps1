[CmdletBinding()]
param(
    [ValidatePattern('^B[0-9]{2}$')][string]$From = 'B00',
    [ValidatePattern('^B[0-9]{2}$')][string]$To = 'B48',
    [switch]$SkipMain,
    [switch]$SkipPublish,
    [string]$Python = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command 'latexmk'
Assert-Command 'lualatex'
Assert-Command 'pdftotext'
$graph = Read-BandDependencyGraph -Path $dependencyFile
if (-not $graph.ContainsKey($From) -or -not $graph.ContainsKey($To) -or $From -gt $To) {
    throw "Invalid build range: $From through $To"
}
New-Item -ItemType Directory -Force -Path $registryDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/build-all') | Out-Null
$selected = @($graph.Keys | Sort-Object | Where-Object { $_ -ge $From -and $_ -le $To })
# Resuming a publishing build must also refresh the overview's printed references.
if (-not $SkipPublish -and 'B00' -notin $selected -and $graph.ContainsKey('B00')) {
    $selected += 'B00'
}
# The overview is printed first but imports the results of the subject volumes.
$buildOrder = [System.Collections.Generic.List[string]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new()
foreach ($target in $selected) {
    foreach ($candidate in @((Get-TopologicalPredecessors -Band $target -Graph $graph)) + @($target)) {
        if ($candidate -in $selected -and $seen.Add($candidate)) { $buildOrder.Add($candidate) }
    }
}
$bands = @($buildOrder)
# The pilot editions read canonical B08/B11 results, while those volumes link
# back to the editions. Build the editions after the last selected source
# volume or required predecessor, then audit the source volumes' remote links.
# A partial range ending at B08 requires existing B11 artifacts for the pilot's
# application section; the pilot builder checks this without extending the range.
$needsCsbPilot = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B08', 'B11', 'B48') }).Count -gt 0)
$pilotTriggerBand = $null
if ($needsCsbPilot) {
    $pilotDependencies = @('B08', 'B11') + @($graph['B08'].Predecessors) + @($graph['B11'].Predecessors)
    $pilotTriggerBand = $bands | Where-Object { $_ -in $pilotDependencies } | Select-Object -Last 1
}
$deferredPilotAudits = [System.Collections.Generic.List[string]]::new()
$pilotsBuilt = $false
# B10 retains the recursion theorem and its usable function interface. The
# construction and registered subsidiary results live in the 10E companion.
$needsDedekind = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B10') }).Count -gt 0)
$dedekindTriggerBand = $null
if ($needsDedekind) {
    $dedekindDependencies = @('B10') + @($graph['B10'].Predecessors)
    $dedekindTriggerBand = $bands | Where-Object { $_ -in $dedekindDependencies } | Select-Object -Last 1
}
$deferredDedekindAudits = [System.Collections.Generic.List[string]]::new()
$dedekindBuilt = $false
# B28 keeps only the public counterexample theorem. Its proof companion owns
# the example-specific foundations formerly in B21 and the construction
# under prefix 28E. Build it before the reading edition and after B21/B28
# (or their last selected predecessor), before auditing navigation links.
# B37 uses the public B28 theorem.
$needsMogiljanskaja = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B21', 'B28') }).Count -gt 0)
$mogiljanskajaTriggerBand = $null
if ($needsMogiljanskaja) {
    $mogiljanskajaDependencies = @('B21', 'B28') + @($graph['B21'].Predecessors) + @($graph['B28'].Predecessors)
    $mogiljanskajaTriggerBand = $bands | Where-Object { $_ -in $mogiljanskajaDependencies } | Select-Object -Last 1
}
$deferredMogiljanskajaAudits = [System.Collections.Generic.List[string]]::new()
$mogiljanskajaBuilt = $false

# B28 retains the three public product statements. The seven proof blocks
# live in their companion, which must exist before auditing B28/B00 links.
$needsBracketing = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B28') }).Count -gt 0)
$bracketingTriggerBand = $null
if ($needsBracketing) {
    $bracketingDependencies = @('B28') + @($graph['B28'].Predecessors)
    $bracketingTriggerBand = $bands | Where-Object { $_ -in $bracketingDependencies } | Select-Object -Last 1
}
$deferredBracketingAudits = [System.Collections.Generic.List[string]]::new()
$bracketingBuilt = $false

# B17 keeps the complete axiomatic interface and externally used statements.
# Build its model companions before B41's reading, which links to their
# private construction results, even when B17 itself is outside the range.
$needsIntegers = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B17', 'B41') }).Count -gt 0)
$integersTriggerBand = $null
if ($needsIntegers) {
    $integersDependencies = @('B17') + @($graph['B17'].Predecessors)
    $integersTriggerBand = $bands | Where-Object { $_ -in $integersDependencies } | Select-Object -Last 1
}
$deferredIntegersAudits = [System.Collections.Generic.List[string]]::new()
$integersBuilt = $false

# B41 retains its public embedding theorem; the construction lives in 41E.
$needsDifferences = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B41') }).Count -gt 0)
$differencesTriggerBand = $null
if ($needsDifferences) {
    $differencesDependencies = @('B41') + @($graph['B41'].Predecessors)
    $differencesTriggerBand = $bands | Where-Object { $_ -in $differencesDependencies } | Select-Object -Last 1
}
$deferredDifferencesAudits = [System.Collections.Generic.List[string]]::new()
$differencesBuilt = $false

# B45 keeps every canonical statement and its original destination. The
# companions import those statements and contain the reading and proof tables.
$needsSemilattice = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B45') }).Count -gt 0)
$semilatticeTriggerBand = $null
if ($needsSemilattice) {
    $semilatticeDependencies = @('B45') + @($graph['B45'].Predecessors)
    $semilatticeTriggerBand = $bands | Where-Object { $_ -in $semilatticeDependencies } | Select-Object -Last 1
}
$deferredSemilatticeAudits = [System.Collections.Generic.List[string]]::new()
$semilatticeBuilt = $false

# B46 retains every statement and its original destination. Its companions
# contain the reading and the 17 proof tables for the small-member cases.
$needsFrankl = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B46') }).Count -gt 0)
$franklTriggerBand = $null
if ($needsFrankl) {
    $franklDependencies = @('B46') + @($graph['B46'].Predecessors)
    $franklTriggerBand = $bands | Where-Object { $_ -in $franklDependencies } | Select-Object -Last 1
}
$deferredFranklAudits = [System.Collections.Generic.List[string]]::new()
$franklBuilt = $false

# B40 keeps the canonical reconstruction statements and the registered inner
# proof result. The companions own only their explanatory and table proofs.
$needsReconstruction = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B40') }).Count -gt 0)
$reconstructionTriggerBand = $null
if ($needsReconstruction) {
    $reconstructionDependencies = @('B40') + @($graph['B40'].Predecessors)
    $reconstructionTriggerBand = $bands | Where-Object { $_ -in $reconstructionDependencies } | Select-Object -Last 1
}
$deferredReconstructionAudits = [System.Collections.Generic.List[string]]::new()
$reconstructionBuilt = $false

# B37 owns the public reconstruction theorem; its private proof statements
# use 37E in the companion. Build both editions before checking outgoing links.
$needsNullproducts = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B37') }).Count -gt 0)
$nullproductsTriggerBand = $null
if ($needsNullproducts) {
    $nullproductsDependencies = @('B37') + @($graph['B37'].Predecessors)
    $nullproductsTriggerBand = $bands | Where-Object { $_ -in $nullproductsDependencies } | Select-Object -Last 1
}
$deferredNullproductsAudits = [System.Collections.Generic.List[string]]::new()
$nullproductsBuilt = $false

# B47 owns the public compactness statements; its private proof lemmas
# use 47E in the companion. Build both editions before checking outgoing links.
$needsCompactness = (-not $SkipMain) -or (@($bands | Where-Object { $_ -in @('B00', 'B47') }).Count -gt 0)
$compactnessTriggerBand = $null
if ($needsCompactness) {
    $compactnessDependencies = @('B47') + @($graph['B47'].Predecessors)
    $compactnessTriggerBand = $bands | Where-Object { $_ -in $compactnessDependencies } | Select-Object -Last 1
}
$deferredCompactnessAudits = [System.Collections.Generic.List[string]]::new()
$compactnessBuilt = $false

function Invoke-LoggedBuild {
    param([string]$Source, [string]$JobName, [string]$OutDir = 'registry')
    $consoleLog = Join-Path $repoRoot "tmp/build-all/$JobName.console.log"
    Write-Host "Building $Source (console log: $consoleLog)"
    $arguments = @('-norc', '-gg', '-lualatex', '-interaction=nonstopmode',
        '-halt-on-error', '-file-line-error', "-jobname=$JobName", "-outdir=$OutDir", $Source)
    & latexmk @arguments *> $consoleLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $consoleLog -Tail 60 | Write-Host
        throw "latexmk failed for $Source; see $consoleLog"
    }
}

Push-Location $repoRoot
try {
    if ($needsCsbPilot -and -not $pilotTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-csb-pilot.ps1') -EditionsOnly -Python $Python
        $pilotsBuilt = $true
    }
    if ($needsMogiljanskaja -and -not $mogiljanskajaTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-mogiljanskaja-editions.ps1') -EditionsOnly -Python $Python
        $mogiljanskajaBuilt = $true
    }
    if ($needsDedekind -and -not $dedekindTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-dedekind-editions.ps1') -EditionsOnly -Python $Python
        $dedekindBuilt = $true
    }
    if ($needsBracketing -and -not $bracketingTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-bracketing-editions.ps1') -EditionsOnly -Python $Python
        $bracketingBuilt = $true
    }
    if ($needsIntegers -and -not $integersTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-integers-editions.ps1') -EditionsOnly -Python $Python
        $integersBuilt = $true
    }
    if ($needsDifferences -and -not $differencesTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-differences-editions.ps1') -EditionsOnly -Python $Python
        & $Python (Join-Path $PSScriptRoot 'integers-editions.py') audit
        if ($LASTEXITCODE -ne 0) { throw 'Integer reciprocal-navigation audit failed.' }
        $differencesBuilt = $true
    }
    if ($needsSemilattice -and -not $semilatticeTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-semilattice-editions.ps1') -EditionsOnly -Python $Python
        $semilatticeBuilt = $true
    }
    if ($needsFrankl -and -not $franklTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-frankl-editions.ps1') -EditionsOnly -Python $Python
        $franklBuilt = $true
    }
    if ($needsReconstruction -and -not $reconstructionTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-reconstruction-editions.ps1') -EditionsOnly -Python $Python
        $reconstructionBuilt = $true
    }
    if ($needsNullproducts -and -not $nullproductsTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-nullproducts-editions.ps1') -EditionsOnly -Python $Python
        $nullproductsBuilt = $true
    }
    if ($needsCompactness -and -not $compactnessTriggerBand) {
        & (Join-Path $PSScriptRoot 'build-compactness-editions.ps1') -EditionsOnly -Python $Python
        $compactnessBuilt = $true
    }
    foreach ($band in $bands) {
        # Each volume is rebuilt once. A resumed range uses already audited
        # predecessors and never recursively rebuilds the same prefix.
        $record = $graph[$band]
        foreach ($predecessor in $record.Predecessors) {
            foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
                Assert-Artifact -RelativePath "$($graph[$predecessor].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
            }
        }
        $started = Get-Date
        Invoke-LoggedBuild -Source $record.Source -JobName "_$band"
        $stage = New-BuildStage -Record $record -Started $started
        Assert-BuildStageArtifacts -Stage $stage
        if ($band -eq $pilotTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-csb-pilot.ps1') -EditionsOnly -Python $Python
            $pilotsBuilt = $true
            foreach ($deferredBand in $deferredPilotAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $mogiljanskajaTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-mogiljanskaja-editions.ps1') -EditionsOnly -Python $Python
            $mogiljanskajaBuilt = $true
            foreach ($deferredBand in $deferredMogiljanskajaAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $dedekindTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-dedekind-editions.ps1') -EditionsOnly -Python $Python
            $dedekindBuilt = $true
            foreach ($deferredBand in $deferredDedekindAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $bracketingTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-bracketing-editions.ps1') -EditionsOnly -Python $Python
            $bracketingBuilt = $true
            foreach ($deferredBand in $deferredBracketingAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $integersTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-integers-editions.ps1') -EditionsOnly -Python $Python
            $integersBuilt = $true
            foreach ($deferredBand in $deferredIntegersAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $differencesTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-differences-editions.ps1') -EditionsOnly -Python $Python
            & $Python (Join-Path $PSScriptRoot 'integers-editions.py') audit
            if ($LASTEXITCODE -ne 0) { throw 'Integer reciprocal-navigation audit failed.' }
            $differencesBuilt = $true
            foreach ($deferredBand in $deferredDifferencesAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $semilatticeTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-semilattice-editions.ps1') -EditionsOnly -Python $Python
            $semilatticeBuilt = $true
            foreach ($deferredBand in $deferredSemilatticeAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $franklTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-frankl-editions.ps1') -EditionsOnly -Python $Python
            $franklBuilt = $true
            foreach ($deferredBand in $deferredFranklAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $reconstructionTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-reconstruction-editions.ps1') -EditionsOnly -Python $Python
            $reconstructionBuilt = $true
            foreach ($deferredBand in $deferredReconstructionAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $nullproductsTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-nullproducts-editions.ps1') -EditionsOnly -Python $Python
            $nullproductsBuilt = $true
            foreach ($deferredBand in $deferredNullproductsAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -eq $compactnessTriggerBand) {
            & (Join-Path $PSScriptRoot 'build-compactness-editions.ps1') -EditionsOnly -Python $Python
            $compactnessBuilt = $true
            foreach ($deferredBand in $deferredCompactnessAudits) {
                & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($deferredBand)
            }
        }
        if ($band -in @('B08', 'B11') -and -not $pilotsBuilt) {
            $deferredPilotAudits.Add($band)
        } elseif ($band -in @('B21', 'B28') -and -not $mogiljanskajaBuilt) {
            $deferredMogiljanskajaAudits.Add($band)
        } elseif ($band -eq 'B10' -and -not $dedekindBuilt) {
            $deferredDedekindAudits.Add($band)
        } elseif ($band -eq 'B28' -and -not $bracketingBuilt) {
            $deferredBracketingAudits.Add($band)
        } elseif ($band -eq 'B17' -and -not $integersBuilt) {
            $deferredIntegersAudits.Add($band)
        } elseif ($band -eq 'B41' -and -not $differencesBuilt) {
            $deferredDifferencesAudits.Add($band)
        } elseif ($band -eq 'B45' -and -not $semilatticeBuilt) {
            $deferredSemilatticeAudits.Add($band)
        } elseif ($band -eq 'B46' -and -not $franklBuilt) {
            $deferredFranklAudits.Add($band)
        } elseif ($band -eq 'B40' -and -not $reconstructionBuilt) {
            $deferredReconstructionAudits.Add($band)
        } elseif ($band -eq 'B37' -and -not $nullproductsBuilt) {
            $deferredNullproductsAudits.Add($band)
        } elseif ($band -eq 'B47' -and -not $compactnessBuilt) {
            $deferredCompactnessAudits.Add($band)
        } else {
            & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands @($band)
        }
    }
    if (-not $SkipMain) {
        Invoke-LoggedBuild -Source 'main.tex' -JobName 'main' -OutDir '.'
        & (Join-Path $PSScriptRoot 'audit-build.ps1') -Bands $bands -IncludeMain
    }
    if (-not $SkipPublish) {
        $publishArguments = @((Join-Path $PSScriptRoot 'publish-pdfs.py'))
        if ($SkipMain) { $publishArguments += '--skip-main' }
        & $Python @publishArguments
        if ($LASTEXITCODE -ne 0) { throw 'PDF publication or link audit failed.' }
    }
    Write-Host "Build completed: $From through $To"
}
finally { Pop-Location }
