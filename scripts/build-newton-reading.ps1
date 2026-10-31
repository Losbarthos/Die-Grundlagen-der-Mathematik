[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipPublish
)

# Retain the established entry point. Both linked companions and their guide
# are built together so publication cannot leave a missing proof target.
& (Join-Path $PSScriptRoot 'build-newton-editions.ps1') @PSBoundParameters
