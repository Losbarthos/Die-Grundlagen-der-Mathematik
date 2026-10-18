# Compatibility entry point: both B31 coordinate editions share one build.
[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$SkipPublish
)
& (Join-Path $PSScriptRoot 'build-coordinates-editions.ps1') -Python $Python -SkipPublish:$SkipPublish
