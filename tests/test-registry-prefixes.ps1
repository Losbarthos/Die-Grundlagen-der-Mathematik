# Regression for exact, explicitly allowed companion namespaces; no TeX build.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/build-b03.ps1') -FunctionsOnly
$fixtureDirectory = Join-Path $repoRoot 'tmp/registry-prefix-regression'
New-Item -ItemType Directory -Force -Path $fixtureDirectory | Out-Null
$fixtureRegistry = 'tmp/registry-prefix-regression/_B37.registry.tsv'
$fixtureAux = 'tmp/registry-prefix-regression/_B37.aux'
$fixtureCount = 0

function Write-PrefixFixture([string[]]$Numbers) {
    $script:fixtureCount++
    $script:fixtureRegistry = "tmp/registry-prefix-regression/_B37.fixture$fixtureCount.registry.tsv"
    $script:fixtureAux = "tmp/registry-prefix-regression/_B37.fixture$fixtureCount.aux"
    $rows = @(); $labels = @(); $i = 0
    foreach ($number in $Numbers) {
        $i++
        $label = "thm:fixture$i"
        $rows += "1`t$label`ttheorem`t$number`tkey$i`tP$i"
        $labels += '\newlabel{' + $label + '}{{' + $number + '}{1}{}{section*.' + $i + '}{}}'
    }
    [IO.File]::WriteAllLines((Join-Path $repoRoot $fixtureRegistry), $rows)
    [IO.File]::WriteAllLines((Join-Path $repoRoot $fixtureAux), $labels)
}
function Assert-Rejected([scriptblock]$Action) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (-not $rejected) { throw 'An unapproved namespace was accepted.' }
}

Write-PrefixFixture @('37.3.1.1')
Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux
Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux -ExpectedNumberPrefix '37'
Write-PrefixFixture @('37I.0.1.1')
Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux -ExpectedNumberPrefix '37I'
Assert-Rejected { Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux }
Assert-Rejected { Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux -ExpectedNumberPrefixes @('37','37T') }
Write-PrefixFixture @('37.4.1.1 (H1)', '37T.0.2.1')
Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux -ExpectedNumberPrefixes @('37','37T')
Assert-Rejected { Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux -ExpectedNumberPrefix '37' }
Write-PrefixFixture @('37TX.0.2.1')
Assert-Rejected { Assert-RegistryLabelsInAux -RegistryPath $fixtureRegistry -AuxPath $fixtureAux -ExpectedNumberPrefixes @('37','37T') }
Write-Output 'PASS exact registry namespaces, old scalar alias, mixed H/private prefixes and rejected foreign prefixes.'
