$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$cargoScript = Join-Path $PSScriptRoot 'cargo.ps1'

function Invoke-CargoChecked {
    param([Parameter(Mandatory = $true)][string[]]$CargoArguments)

    & $cargoScript @CargoArguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo command failed: cargo $($CargoArguments -join ' ')"
    }
}

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$CommandName)

    if ($LASTEXITCODE -ne 0) {
        throw "$CommandName failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repositoryRoot
try {
    Invoke-CargoChecked -CargoArguments @('run', '-p', 'dtx-protocol', '--locked', '--', 'check-generated', '.')
    Invoke-CargoChecked -CargoArguments @('run', '-p', 'dtx-protocol', '--locked', '--', 'generate', '.')
    Invoke-CargoChecked -CargoArguments @('run', '-p', 'dtx-protocol', '--locked', '--', 'check-generated', '.')
    Invoke-CargoChecked -CargoArguments @('run', '-p', 'dtx-protocol', '--locked', '--', 'validate', '.')
    Invoke-CargoChecked -CargoArguments @('run', '-p', 'dtx-protocol', '--locked', '--', 'check-breaking', '.')

    Push-Location (Join-Path $repositoryRoot 'protocol/generated/dart')
    $webSmokeOutput = Join-Path $repositoryRoot 'target/dtx-protocol-web-smoke.js'
    try {
        & dart pub get --enforce-lockfile
        Assert-LastExitCode 'dart pub get'
        & dart format --output=none --set-exit-if-changed .
        Assert-LastExitCode 'dart format'
        & dart analyze --fatal-infos
        Assert-LastExitCode 'dart analyze'
        & dart test
        Assert-LastExitCode 'dart test'
        & dart compile js tool/web_smoke.dart -O2 -o $webSmokeOutput
        Assert-LastExitCode 'dart compile js'
        & node $webSmokeOutput
        Assert-LastExitCode 'Dart web conformance smoke'
    } finally {
        Remove-Item -LiteralPath $webSmokeOutput -Force -ErrorAction SilentlyContinue
        Pop-Location
    }

    Invoke-CargoChecked -CargoArguments @('fmt', '--all', '--', '--check')
    Invoke-CargoChecked -CargoArguments @('clippy', '--workspace', '--locked', '--all-targets', '--all-features', '--', '-D', 'warnings')
    Invoke-CargoChecked -CargoArguments @('test', '--workspace', '--locked')
    Invoke-CargoChecked -CargoArguments @('deny', 'check')
    Invoke-CargoChecked -CargoArguments @('audit')

    & git diff --check
    Assert-LastExitCode 'git diff --check'
} finally {
    Pop-Location
}
