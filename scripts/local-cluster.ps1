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
        [ValidateSet('Get', 'Post', 'Put')]
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
        [ValidateSet('Get', 'Post', 'Put')]
        [string]$Method,
        [Parameter(Mandatory)]
        [int]$ExpectedStatus
    )

    $deadline = (Get-Date).AddSeconds(30)
    $lastFailure = $null
    do {
        try {
            $status = Get-LocalHttpStatus -Uri $Uri -Method $Method
            if ($status -eq $ExpectedStatus) {
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
        @{ Name = 'node-a identity'; Method = 'Post'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18080/v1/identity/bootstrap' },
        @{ Name = 'node-a mailbox'; Method = 'Put'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18080/v1/mailboxes/0190f2a5-7b1c-7abc-8def-0123456789c1' },
        @{ Name = 'node-a group'; Method = 'Put'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18080/v1/groups/controlled-public-channel/0190f2a5-7b1c-7abc-8def-0123456789c0' },
        @{ Name = 'node-a public feed'; Method = 'Get'; ExpectedStatus = 400; Uri = 'http://127.0.0.1:18080/.well-known/dirextalk/public/v1/not-a-stable-id' },
        @{ Name = 'node-a indexer'; Method = 'Get'; ExpectedStatus = 400; Uri = 'http://127.0.0.1:18080/v1/public-search' },
        @{ Name = 'node-b identity'; Method = 'Post'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18081/v1/identity/bootstrap' },
        @{ Name = 'node-b mailbox'; Method = 'Put'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18081/v1/mailboxes/0190f2a5-7b1c-7abc-8def-0123456789c1' },
        @{ Name = 'node-b group'; Method = 'Put'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18081/v1/groups/controlled-public-channel/0190f2a5-7b1c-7abc-8def-0123456789c0' },
        @{ Name = 'node-b public feed'; Method = 'Get'; ExpectedStatus = 400; Uri = 'http://127.0.0.1:18081/.well-known/dirextalk/public/v1/not-a-stable-id' },
        @{ Name = 'node-b indexer'; Method = 'Get'; ExpectedStatus = 400; Uri = 'http://127.0.0.1:18081/v1/public-search' },
        @{ Name = 'node-c identity'; Method = 'Post'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18082/v1/identity/bootstrap' },
        @{ Name = 'node-c mailbox'; Method = 'Put'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18082/v1/mailboxes/0190f2a5-7b1c-7abc-8def-0123456789c1' },
        @{ Name = 'node-c group'; Method = 'Put'; ExpectedStatus = 422; Uri = 'http://127.0.0.1:18082/v1/groups/controlled-public-channel/0190f2a5-7b1c-7abc-8def-0123456789c0' },
        @{ Name = 'node-c public feed'; Method = 'Get'; ExpectedStatus = 400; Uri = 'http://127.0.0.1:18082/.well-known/dirextalk/public/v1/not-a-stable-id' },
        @{ Name = 'node-c indexer'; Method = 'Get'; ExpectedStatus = 400; Uri = 'http://127.0.0.1:18082/v1/public-search' }
    )

    foreach ($request in $requests) {
        Confirm-LocalContractRoute -Name $request.Name -Uri $request.Uri -Method $request.Method -ExpectedStatus $request.ExpectedStatus
    }
}

function Confirm-LocalDirectoryRoleIsolation {
    $query = @'
SELECT CASE WHEN
    has_table_privilege('dtx_public_feed_node', 'directory.public_subjects', 'SELECT')
    AND NOT has_table_privilege('dtx_public_feed_node', 'directory.index_registrations', 'SELECT')
    AND has_table_privilege('dtx_indexer_node', 'directory.index_registrations', 'SELECT')
    AND NOT has_table_privilege('dtx_indexer_node', 'directory.public_subjects', 'SELECT')
THEN 'isolated' ELSE 'unsafe' END
'@
    foreach ($database in @('dtx_node_a', 'dtx_node_b', 'dtx_node_c')) {
        $output = & docker @composePrefix exec --no-TTY postgres psql `
            --username=postgres --dbname=$database --tuples-only --no-align `
            --set=ON_ERROR_STOP=1 --command=$query
        if ($LASTEXITCODE -ne 0 -or ($output | Out-String).Trim() -ne 'isolated') {
            throw "Local directory roles are not isolated in $database."
        }
    }
}

switch ($Action) {
    'up' {
        $composeArguments = @('up', '--detach', '--wait', '--wait-timeout', '300', '--remove-orphans')
        if (-not $NoBuild) {
            $composeArguments += '--build'
        }
        Invoke-LocalCompose $composeArguments
        Confirm-LocalDirectoryRoleIsolation
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
