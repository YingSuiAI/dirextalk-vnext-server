$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$cargoScript = Join-Path $PSScriptRoot 'cargo.ps1'

Push-Location $repositoryRoot
try {
    if ($env:OS -eq 'Windows_NT') {
        $metadataJson = & $cargoScript metadata --format-version 1 --no-deps
    } else {
        $metadataJson = & cargo metadata --format-version 1 --no-deps
    }
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE"
    }
    $metadata = $metadataJson | ConvertFrom-Json
    $violations = foreach ($package in $metadata.packages) {
        if ($package.name -eq 'dtx-testkit') {
            continue
        }
        foreach ($dependency in $package.dependencies) {
            if ($dependency.name -eq 'dtx-testkit' -and $dependency.kind -ne 'dev') {
                "$($package.name):$($dependency.kind)"
            }
        }
    }
    if ($violations.Count -gt 0) {
        throw "dtx-testkit must be dev-only; invalid dependencies: $($violations -join ', ')"
    }
} finally {
    Pop-Location
}
