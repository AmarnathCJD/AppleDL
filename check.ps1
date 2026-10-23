$ErrorActionPreference = 'Stop'
$cache = Join-Path $PSScriptRoot '.cache'
$env:TEMP = Join-Path $cache 'tmp'
$env:TMP = $env:TEMP
$env:GOCACHE = Join-Path $cache 'go-build'
$env:GOMODCACHE = Join-Path $cache 'go-mod'
$env:GOPATH = Join-Path $cache 'gopath'
$env:CGO_ENABLED = '0'
New-Item -ItemType Directory -Force -Path $env:TEMP,$env:GOCACHE,$env:GOMODCACHE,$env:GOPATH | Out-Null
Push-Location $PSScriptRoot
try {
    go test ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go build ./...
    exit $LASTEXITCODE
} finally { Pop-Location }
