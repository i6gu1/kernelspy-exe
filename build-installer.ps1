# ============================================================
#  KernelSpy Scanner - WPF Edition build & installer script
# ============================================================
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root

function Assert-Published {
    param([string]$RelativePath, [string]$Description)

    $full = Join-Path $root $RelativePath
    if (-not (Test-Path $full)) {
        throw "Missing $Description at '$RelativePath'. The published application would not be standalone."
    }
    Write-Host "    OK  $RelativePath" -ForegroundColor DarkGray
}

try {
    Write-Host "==> Publishing self-contained win-x64 build..." -ForegroundColor Cyan
    if (Test-Path "publish") { Remove-Item "publish" -Recurse -Force }

    dotnet publish "KernelSpyScanner.csproj" -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=false -p:PublishTrimmed=false -o "publish"
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

    Write-Host "==> Verifying self-contained runtime and bundled tools..." -ForegroundColor Cyan
    Assert-Published "publish\KernelSpy Scanner.exe" "application executable"
    Assert-Published "publish\coreclr.dll" "bundled .NET runtime (coreclr.dll)"
    Assert-Published "publish\hostfxr.dll" "bundled .NET host (hostfxr.dll)"
    Assert-Published "publish\Rules\kernelspy-semgrep.yml" "Semgrep rule pack"
    Assert-Published "publish\tools\node\node.exe" "bundled Node.js runtime"
    Assert-Published "publish\tools\eslint-10.13.0\eslint-10.13.0\bin\eslint.js" "bundled ESLint"
    Assert-Published "publish\tools\semgrep-runtime\semgrep\bin\semgrep-core.exe" "bundled Semgrep core"

    Write-Host "==> Locating Inno Setup compiler..." -ForegroundColor Cyan
    $isccCandidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    $iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $iscc) {
        Write-Warning "ISCC.exe was not found. The standalone publish output is ready in .\publish"
        Write-Warning "Install Inno Setup 6, then run: ISCC.exe KernelSpy_Scanner_WPF.iss"
        return
    }

    Write-Host "==> Compiling installer with $iscc" -ForegroundColor Cyan

    # Compile into a staging directory and only publish the setup after a
    # successful build. ISCC writes the output incrementally, so compiling
    # directly to .\installer leaves a truncated, unlaunchable .exe if the
    # build is interrupted.
    $issText = Get-Content "KernelSpy_Scanner_WPF.iss" -Raw
    if ($issText -notmatch '#define\s+MyAppVersion\s+"([^"]+)"') {
        throw "Could not read MyAppVersion from KernelSpy_Scanner_WPF.iss."
    }
    $setupName = "KernelSpy_Scanner_Setup_WPF_$($Matches[1])"
    $staging = Join-Path $root "installer\.staging"
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null

    & $iscc "/O$staging" "/F$setupName" "KernelSpy_Scanner_WPF.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }

    $staged = Join-Path $staging "$setupName.exe"
    if (-not (Test-Path $staged)) {
        throw "Inno Setup reported success but '$setupName.exe' was not produced."
    }
    Copy-Item $staged (Join-Path $root "installer\$setupName.exe") -Force
    Remove-Item $staging -Recurse -Force

    $setup = Get-Item (Join-Path $root "installer\$setupName.exe")
    Write-Host "    OK  installer size: $([math]::Round($setup.Length / 1MB, 1)) MB" -ForegroundColor DarkGray
    Write-Host "    OK  setup: $($setup.FullName)" -ForegroundColor DarkGray
    Write-Host "==> Done. Installer is in .\installer" -ForegroundColor Green
}
finally {
    Pop-Location
}
