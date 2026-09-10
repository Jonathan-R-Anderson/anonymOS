$ErrorActionPreference = "Stop"

$clientRoot = Split-Path -Parent $PSScriptRoot
Push-Location $clientRoot

try {
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null

    # GOARM only matters for linux/arm. 6 rather than 7 so ONE 32-bit ARM build
    # runs on every Pi anybody actually volunteers -- a Zero or a 1 is armv6l, a
    # 2/3 on a 32-bit OS is armv7l, and armv7 code faults on the former.
    $targets = @(
        @{ OS = "linux";   Arch = "amd64"; Suffix = "" },
        @{ OS = "linux";   Arch = "arm64"; Suffix = "" },
        @{ OS = "linux";   Arch = "arm";   Suffix = ""; Arm = "6" },
        @{ OS = "darwin";  Arch = "amd64"; Suffix = "" },
        @{ OS = "darwin";  Arch = "arm64"; Suffix = "" },
        @{ OS = "windows"; Arch = "amd64"; Suffix = ".exe" },
        @{ OS = "windows"; Arch = "arm64"; Suffix = ".exe" }
    )

    $env:CGO_ENABLED = "0"
    foreach ($target in $targets) {
        $env:GOOS = $target.OS
        $env:GOARCH = $target.Arch
        $env:GOARM = $target.Arm
        $output = "dist/syndichan-node-$($target.OS)-$($target.Arch)$($target.Suffix)"
        Write-Host "building $output"
        & go build -trimpath "-ldflags=-s -w" -o $output ./cmd/syndichan-node
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $($target.OS)/$($target.Arch)"
        }
    }
}
finally {
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:GOARM -ErrorAction SilentlyContinue
    Pop-Location
}
