[CmdletBinding()]
param(
    [ValidateSet('up', 'down', 'status', 'logs', 'reset')]
    [string]$Action = 'up',
    [switch]$NoBuild,
    [switch]$Follow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repositoryRoot 'docker-compose.local.yml'
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw 'The local Compose file is missing.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker Desktop with Docker Compose is required for the local cluster.'
}

$composePrefix = @('compose', '--project-directory', $repositoryRoot, '-f', $composeFile)

function Invoke-LocalCompose {
    param([string[]]$ComposeArguments)

    & docker @composePrefix @ComposeArguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $Action failed with exit code $LASTEXITCODE."
    }
}

switch ($Action) {
    'up' {
        $composeArguments = @('up', '--detach', '--wait', '--wait-timeout', '300')
        if (-not $NoBuild) {
            $composeArguments += '--build'
        }
        Invoke-LocalCompose $composeArguments
    }
    'down' {
        Invoke-LocalCompose @('down', '--remove-orphans')
    }
    'status' {
        Invoke-LocalCompose @('ps')
    }
    'logs' {
        $composeArguments = @('logs', '--tail', '200')
        if ($Follow) {
            $composeArguments += '--follow'
        }
        Invoke-LocalCompose $composeArguments
    }
    'reset' {
        Invoke-LocalCompose @('down', '--volumes', '--remove-orphans')
    }
}
