param(
    [string]$BuildDir = "build",
    [string]$Config = "Release",
    [string]$Generator = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=== Lab 2 Windows Build ==="
Write-Host "Build dir: $BuildDir"
Write-Host "Config   : $Config"

New-Item -ItemType Directory -Force -Path "docs/evidence" | Out-Null

if (Test-Path $BuildDir) {
    Remove-Item -Recurse -Force $BuildDir
}

$cmakeArgs = @(
    "-S", ".",
    "-B", $BuildDir,
    "-DCMAKE_BUILD_TYPE=$Config",
    "-Wno-dev"
)

if ($Generator -ne "") {
    $cmakeArgs += @("-G", $Generator)
    Write-Host "Generator: $Generator"
} else {
    Write-Host "Generator: default CMake generator"
}

& cmake @cmakeArgs *>&1 | Tee-Object -FilePath "docs/evidence/build_windows_configure.log"

if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed"
}

& cmake --build $BuildDir --config $Config *>&1 | Tee-Object -FilePath "docs/evidence/build_windows_compile.log"

if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed"
}

Write-Host "=== Build completed ==="