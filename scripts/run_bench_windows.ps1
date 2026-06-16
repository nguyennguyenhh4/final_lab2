param(
    [string]$BuildDir = "build",
    [string]$Config = "Release",
    [int]$Runs = 30
)

$ErrorActionPreference = "Stop"

Write-Host "=== Lab 2 Windows Benchmark ==="
Write-Host "Build dir: $BuildDir"
Write-Host "Config   : $Config"
Write-Host "Runs     : $Runs"

New-Item -ItemType Directory -Force -Path "docs/evidence" | Out-Null

$BenchExe = Join-Path $BuildDir "Release/bench.exe"

if (!(Test-Path $BenchExe)) {
    $BenchExe = Join-Path $BuildDir "bench.exe"
}

if (!(Test-Path $BenchExe)) {
    throw "bench.exe not found. Build first."
}

& $BenchExe --runs $Runs --csv docs/evidence/benchmark_windows.csv *>&1 | Tee-Object -FilePath "docs/evidence/benchmark_windows.log"

if ($LASTEXITCODE -ne 0) {
    throw "Benchmark failed"
}

Write-Host "=== Benchmark completed ==="
Write-Host "CSV saved to docs/evidence/benchmark_windows.csv"