[CmdletBinding()]
param(
    [string]$Python = 'python',
    [string]$LuaLaTeX = 'lualatex',
    # Compatibility with the companion calls in build-all; this builder only
    # builds/audits the editions and never publishes or rebuilds main volumes.
    [switch]$EditionsOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-b03.ps1') -FunctionsOnly
Assert-Command $LuaLaTeX
Assert-Command $Python

function Invoke-ZeroTransportEdition {
    param([ValidateSet('proofs', 'reading')][string]$Edition)
    $job = "_B28-zero-transport-$Edition"
    $base = "registry/zero-transport/$job"
    $source = "editions/b28-zero-transport-$Edition.tex"
    # At least two passes resolve the edition's own registry and local labels.
    # Extra passes are bounded and run only when LaTeX requests another pass.
    for ($pass = 1; $pass -le 5; $pass++) {
        $consoleLog = Join-Path $repoRoot "tmp/zero-transport-editions/$job.pass-$pass.console.log"
        Write-Host "Building $job, pass $pass (log: $consoleLog)"
        & $LuaLaTeX --disable-installer --disable-write18 -interaction=nonstopmode -halt-on-error -file-line-error -recorder "--jobname=$job" -output-directory=registry/zero-transport $source *> $consoleLog
        if ($LASTEXITCODE -ne 0) {
            Get-Content -LiteralPath $consoleLog -Tail 55 | Write-Host
            throw "Build failed for $job (pass $pass)."
        }
        $log = [System.IO.File]::ReadAllText((Join-Path $repoRoot "$base.log"))
        if ($pass -ge 2 -and $log -notmatch 'Rerun to get|Rerun to get outlines right|Please rerun LaTeX|Label\(s\) may have changed') { break }
        if ($pass -eq 5) { throw "$job did not stabilize after five passes." }
    }
    Assert-CleanLog -RelativePath "$base.log"
    Assert-CleanDebugLog -RelativePath "$base.debug.log"
    Assert-RegistryLabelsInAux -RegistryPath "$base.registry.tsv" -AuxPath "$base.aux" -ExpectedNumberPrefix '28Z'
}

Push-Location $repoRoot
try {
    $graph = Read-BandDependencyGraph -Path $dependencyFile
    foreach ($band in @($graph['B33'].Predecessors) + @('B33')) {
        foreach ($extension in @('aux', 'pdf', 'registry.tsv')) {
            Assert-Artifact -RelativePath "$($graph[$band].ArtifactBase).$extension" -NotBefore ([datetime]::MinValue)
        }
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'registry/zero-transport') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'tmp/zero-transport-editions') | Out-Null
    Invoke-ZeroTransportEdition -Edition 'proofs'
    Invoke-ZeroTransportEdition -Edition 'reading'
    # Use the publisher's pypdf fallback when pdftotext is unavailable.
    $audit = @'
from pathlib import Path
import runpy, sys
from pypdf import PdfReader
root = Path(sys.argv[1]).resolve()
publisher = runpy.run_path(str(root / 'scripts/publish-pdfs.py'))
directory = root / 'registry/zero-transport'
cache = {}
for edition in ('proofs', 'reading'):
    pdf = directory / f'_B28-zero-transport-{edition}.pdf'
    reader = PdfReader(pdf)
    publisher['assert_build_ready'](pdf, reader)
    publisher['audit_local_targets'](reader, pdf)
    if f'zero-transport.{edition}' not in reader.named_destinations:
        raise ValueError(f'{pdf.name}: missing entry destination')
    for action in publisher['remote_actions'](reader):
        target = (pdf.parent / publisher['file_name'](action)).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            raise ValueError(f'{pdf.name}: missing/outside target {target}')
        if target not in cache:
            cache[target] = PdfReader(target).named_destinations
        if not isinstance(action.get('/D'), str) or action['/D'] not in cache[target]:
            raise ValueError(f'{pdf.name}: unresolved destination in {target}')
    registry = pdf.with_suffix('.registry.tsv').read_text(encoding='utf-8')
    if edition == 'reading' and registry.strip():
        raise ValueError('The reading edition must not register duplicate statements')
    if edition == 'proofs' and 'ID\tPowerSemigroupZeroTransport\t' not in registry:
        raise ValueError('The proof registry is missing the general zero-transport theorem')
    print(f'Zero transport {edition}: {len(reader.pages)} pages; references and links passed.')
'@
    $audit | & $Python -B - $repoRoot
    if ($LASTEXITCODE -ne 0) { throw 'Zero-transport reference or PDF audit failed.' }
    Write-Host 'Zero-transport companion build and audits completed.'
} finally { Pop-Location }
