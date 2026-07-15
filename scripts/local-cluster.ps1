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

function Get-LocalHttpStatus {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [ValidateSet('Post', 'Put')]
        [string]$Method
    )

    try {
        return [int](Invoke-WebRequest -Uri $Uri -Method $Method -UseBasicParsing -TimeoutSec 3).StatusCode
    }
    catch {
        if ($null -ne $_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode
        }
        throw
    }
}

function Confirm-LocalContractRoute {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [ValidateSet('Post', 'Put')]
        [string]$Method
    )

    $deadline = (Get-Date).AddSeconds(30)
    $lastFailure = $null
    do {
        try {
            $status = Get-LocalHttpStatus -Uri $Uri -Method $Method
            if ($status -eq 422) {
                return
            }
            $lastFailure = "HTTP $status"
        }
        catch {
            $lastFailure = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "Local $Name did not reject the safe malformed request as expected: $lastFailure"
}

function Confirm-LocalClusterEndpoints {
    $requests = @(
        @{ Name = 'identity-a'; Method = 'Post'; Uri = 'http://127.0.0.1:18080/v1/identity/bootstrap' },
        @{ Name = 'mailbox-a'; Method = 'Put'; Uri = 'http://127.0.0.1:14812/v1/mailboxes/0190f2a5-7b1c-7abc-8def-0123456789c1' },
        @{ Name = 'group-a'; Method = 'Put'; Uri = 'http://127.0.0.1:14814/v1/groups/controlled-public-channel/0190f2a5-7b1c-7abc-8def-0123456789c0' },
        @{ Name = 'identity-b'; Method = 'Post'; Uri = 'http://127.0.0.1:18081/v1/identity/bootstrap' },
        @{ Name = 'mailbox-b'; Method = 'Put'; Uri = 'http://127.0.0.1:14813/v1/mailboxes/0190f2a5-7b1c-7abc-8def-0123456789c1' },
        @{ Name = 'group-b'; Method = 'Put'; Uri = 'http://127.0.0.1:14815/v1/groups/controlled-public-channel/0190f2a5-7b1c-7abc-8def-0123456789c0' },
        @{ Name = 'identity-c'; Method = 'Post'; Uri = 'http://127.0.0.1:18082/v1/identity/bootstrap' },
        @{ Name = 'mailbox-c'; Method = 'Put'; Uri = 'http://127.0.0.1:14816/v1/mailboxes/0190f2a5-7b1c-7abc-8def-0123456789c1' },
        @{ Name = 'group-c'; Method = 'Put'; Uri = 'http://127.0.0.1:14817/v1/groups/controlled-public-channel/0190f2a5-7b1c-7abc-8def-0123456789c0' }
    )

    foreach ($request in $requests) {
        Confirm-LocalContractRoute -Name $request.Name -Uri $request.Uri -Method $request.Method
    }
}

switch ($Action) {
    'up' {
        $composeArguments = @('up', '--detach', '--wait', '--wait-timeout', '300')
        if (-not $NoBuild) {
            $composeArguments += '--build'
        }
        Invoke-LocalCompose $composeArguments
        Confirm-LocalClusterEndpoints
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
