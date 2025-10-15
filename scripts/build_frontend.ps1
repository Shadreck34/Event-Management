<#
PowerShell script to prepare a frontend static build package for deployment.
- Copies files from frontend/ to dist/
- Optionally replaces API_BASE if you pass -ApiBase or set FRONTEND_API_BASE env var
- Zips dist/ to build/webapp.zip
#>
param(
    [string]$ApiBase
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = (Resolve-Path "$scriptRoot\..\")
$src = Join-Path $projectRoot "frontend"
$dest = Join-Path $projectRoot "dist"
$buildDir = Join-Path $projectRoot "build"

Write-Host "Project root: $projectRoot"
Write-Host "Source frontend: $src"
Write-Host "Destination (dist): $dest"

# Ensure source exists
if (-not (Test-Path $src)) {
    Write-Error "Frontend folder not found at $src"
    exit 1
}

# Clean destination
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
New-Item -ItemType Directory -Path $dest | Out-Null

# Copy frontend files
Write-Host "Copying frontend files..."
Copy-Item -Path (Join-Path $src '*') -Destination $dest -Recurse -Force

# Determine API base
if (-not $ApiBase) {
    $ApiBase = $env:FRONTEND_API_BASE
}

if (-not $ApiBase) {
    Write-Host "No API base provided via -ApiBase or FRONTEND_API_BASE env var. Skipping API_BASE patching."
} else {
    Write-Host "Patching API_BASE to: $ApiBase"
    # Replace common JS/HTML patterns that define API_BASE
    $patterns = @('*.js','*.html')
    foreach ($pat in $patterns) {
        Get-ChildItem -Path $dest -Recurse -Include $pat -File | ForEach-Object {
            $file = $_.FullName
            (Get-Content -Raw $file) -replace "const\s+API_BASE\s*=\s*['\"].*?['\"];","const API_BASE = '$ApiBase';" | Set-Content $file
            (Get-Content -Raw $file) -replace "var\s+API_BASE\s*=\s*['\"].*?['\"];","var API_BASE = '$ApiBase';" | Set-Content $file
        }
    }
}

# Create build directory
if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir | Out-Null }
$zipPath = Join-Path $buildDir "webapp.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Write-Host "Creating zip package: $zipPath"
Compress-Archive -Path (Join-Path $dest '*') -DestinationPath $zipPath -Force

Write-Host "Frontend build complete. Dist folder: $dest"
Write-Host "Packaged zip: $zipPath"
Write-Host "Next: upload $zipPath to your static host (S3, Netlify, Vercel, or copy to nginx)."
