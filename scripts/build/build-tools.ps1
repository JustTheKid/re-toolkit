# Builds small native helper tools in _tools/ with the installed MSVC toolchain into build\tools\.
#   video_frames.exe  Media Foundation video probe / frame grabber (_tools/video_frames.cpp)
# Usage: powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\build-tools.ps1
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot
$out = Join-Path $repo 'build\tools'
New-Item -ItemType Directory -Force $out | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$envCmd = Join-Path $out 'env.cmd'
Set-Content -Path $envCmd -Encoding ascii -Value "@set `"PATH=$(Split-Path $vswhere);%PATH%`"`r`n@call `"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul`r`n@set"
foreach ($line in (cmd /c $envCmd)) {
    if ($line -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}

& cl.exe /nologo /O2 /MT /W4 /EHsc /utf-8 /std:c++20 "/Fo$out\" "/Fe$out\video_frames.exe" (Join-Path $PSScriptRoot 'video_frames.cpp')
if ($LASTEXITCODE -ne 0) { throw "cl failed ($LASTEXITCODE)" }
Write-Host "Built $out\video_frames.exe"
