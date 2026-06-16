param(
    [string]$BuildDir = "build",
    [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Lab 2 Windows Tests ==="

New-Item -ItemType Directory -Force -Path "docs/evidence" | Out-Null

ctest --test-dir $BuildDir -C $Config --output-on-failure 2>&1 | Tee-Object -FilePath "docs/evidence/ctest_windows.log"

Write-Host "=== Tests completed ==="