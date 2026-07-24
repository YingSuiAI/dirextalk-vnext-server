$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$cargoScript = Join-Path $PSScriptRoot 'cargo.ps1'
$sqlxToolBin = Join-Path $env:LOCALAPPDATA 'Dirextalk\tools\sqlx-cli-0.9.0\bin'
$postgresImage = 'postgres:18.4-alpine3.24'
$containerName = "dtx-sqlx-$([Guid]::NewGuid().ToString('N'))"
$previousDatabaseUrl = $env:DATABASE_URL
$containerStarted = $false

if (Test-Path -LiteralPath $sqlxToolBin) {
    $env:Path = "$sqlxToolBin;$env:Path"
}

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$CommandName)

    if ($LASTEXITCODE -ne 0) {
        throw "$CommandName failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repositoryRoot
try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker is required for the SQLx migration/metadata gate.'
    }

    & $cargoScript sqlx --version
    if ($LASTEXITCODE -ne 0) {
        throw 'sqlx-cli 0.9.0 is required for the migration/prepare gate; install it with the command documented in COMMANDS.md.'
    }

    & docker run --detach --name $containerName `
        --env POSTGRES_HOST_AUTH_METHOD=trust `
        --env POSTGRES_USER=dtx_sqlx `
        --env POSTGRES_DB=dtx_sqlx `
        --publish '127.0.0.1::5432' `
        --tmpfs /var/lib/postgresql `
        $postgresImage | Out-Null
    Assert-LastExitCode 'docker run'
    $containerStarted = $true

    $ready = $false
    foreach ($attempt in 1..60) {
        $running = (& docker inspect --format '{{.State.Running}}' $containerName).Trim()
        if ($running -ne 'true') {
            break
        }
        $previousErrorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        & docker exec $containerName pg_isready --username dtx_sqlx --dbname dtx_sqlx *> $null
        $ErrorActionPreference = $previousErrorPreference
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        $running = (& docker inspect --format '{{.State.Running}}' $containerName).Trim()
        if ($running -ne 'true') {
            throw 'Ephemeral PostgreSQL exited before it became ready.'
        }
        throw 'Ephemeral PostgreSQL did not become ready within 60 seconds.'
    }

    $published = (& docker port $containerName '5432/tcp').Trim()
    Assert-LastExitCode 'docker port'
    $hostPort = $published.Substring($published.LastIndexOf(':') + 1)
    if ($hostPort -notmatch '^\d+$') {
        throw 'Docker returned an invalid PostgreSQL host port.'
    }
    $env:DATABASE_URL = "postgres://dtx_sqlx@127.0.0.1:$hostPort/dtx_sqlx?sslmode=disable"

    & $cargoScript sqlx migrate run --source migrations
    Assert-LastExitCode 'cargo sqlx migrate run'
    & $cargoScript sqlx prepare --workspace --check
    Assert-LastExitCode 'cargo sqlx prepare --workspace --check'
} finally {
    if ($null -eq $previousDatabaseUrl) {
        Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
    } else {
        $env:DATABASE_URL = $previousDatabaseUrl
    }
    if ($containerStarted) {
        $previousErrorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        & docker rm --force $containerName *> $null
        $ErrorActionPreference = $previousErrorPreference
    }
    Pop-Location
}
