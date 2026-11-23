# Builds the stock UE 4.5.1 engine in D:\UE\4.5.1 with Visual Studio 2013 (ADR-0001 phase 4a).
# 4.5.1's 2014 batch files need three environment fixes on this machine:
#  - NoDefaultCurrentDirectoryInExePath cleared: the scripts call sibling .bat files by bare name (GetVSComnToolsPath),
#    which cmd will not look up in the current folder while that variable is set (it is set in our tool shells).
#  - INCLUDE and LIB cleared: when both are set (e.g. by a newer Visual Studio's vcvars), the scripts skip the VS2013
#    lookup and build with whatever compiler is on PATH.
#  - VS120COMNTOOLS taken from the machine environment: shells started before the VS2013 install do not have it.
# Usage: powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\build-ue45.ps1 [-GenerateProjectFiles]
#          [-Target UE4Editor] [-Platform Win64] [-Config Development]
param([string]$Root = 'D:\UE\4.5.1', [string]$Target = 'UE4Editor', [string]$Platform = 'Win64',
      [string]$Config = 'Development', [switch]$GenerateProjectFiles)
$ErrorActionPreference = 'Stop'

$env:NoDefaultCurrentDirectoryInExePath = $null
$env:INCLUDE = $null
$env:LIB = $null
$vs = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').VS120COMNTOOLS
if (-not $vs) { throw 'VS120COMNTOOLS is not set machine-wide: is Visual Studio 2013 installed?' }
$env:VS120COMNTOOLS = $vs

if ($GenerateProjectFiles) {
    & cmd /c "$Root\GenerateProjectFiles.bat"
    if ($LASTEXITCODE) { throw "GenerateProjectFiles.bat failed (exit $LASTEXITCODE)" }
}
& cmd /c "$Root\Engine\Build\BatchFiles\Build.bat" $Target $Platform $Config
exit $LASTEXITCODE
