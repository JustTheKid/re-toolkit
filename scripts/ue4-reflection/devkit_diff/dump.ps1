# DevKit module diff, step 3: our reflection. The modules of <Work>\modules.tsv that have a DevKit DLL are dumped in
# one AtlasFormatTest run into <Work>\ours\<Module> (-reflectionall with a list; one name alone would dump into <out>
# itself and skip the list mode's setup), after Settings, LevelEditor and SoundMod: editor modules expect the Settings
# module, Levels' commands LevelEditor's context, SoundModImporter SoundMod's DLL; the list mode also registers Slate's
# generic commands, which Kismet and LandscapeEditor need through MainFrame (engine 6698536). A module still missing
# afterwards is retried alone after the same three. The commandlet's exit code counts the listed packages without
# classes or structs (Settings and LevelEditor have none), so the folders decide. -Build first builds UE4Editor
# (build-ue45.ps1; about 75 min after an Engine header change) and stops on errors. Never next to a Ghidra JVM or
# another build / commandlet (16 GB). Logs: <Work>\logs\. The work folder must not contain spaces (UE's command line).
# Usage: powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\devkit_diff\dump.ps1 -Work <dir>
#          [-Modules AnimGraph,Paper*] [-Engine D:\UE\4.5.1] [-Preload Settings,LevelEditor,SoundMod] [-Build] [-DryRun]
#   -DryRun  print the commands instead of running them
param([Parameter(Mandatory = $true)][string]$Work, [string[]]$Modules = @(), [string]$Engine = '',
      [string[]]$Preload = @('Settings', 'LevelEditor', 'SoundMod'), [switch]$Build, [switch]$DryRun)

$tools = Split-Path $PSScriptRoot -Parent
if (-not $Engine) { $Engine = if ($env:ATLAS_ENGINE_ROOT) { $env:ATLAS_ENGINE_ROOT } else { 'D:\UE\4.5.1' } }
$Work = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Work)
if ($Work -match '\s') { throw "the work folder must not contain spaces (UE's command line): $Work" }
$exe = Join-Path $Engine 'Engine\Binaries\Win64\UE4Editor-Cmd.exe'
$out = Join-Path $Work 'ours'
$logs = Join-Path $Work 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null

$split = { param($list) $list | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
$pats = @(& $split $Modules)
# at least one package before the modules, so even one module gets the list mode
$Preload = @(& $split $Preload)
if (-not $Preload) { $Preload = @('Settings') }
$rows = @(Import-Csv -LiteralPath (Join-Path $Work 'modules.tsv') -Delimiter "`t" | Where-Object {
    $m = $_.module; -not $pats -or @($pats | Where-Object { $m -like $_ }).Count })
$todo = @($rows | Where-Object { $_.dll } | ForEach-Object { $_.module })
if (-not $todo) { 'nothing to dump (no module with a DevKit DLL selected)'; exit 0 }

# runs the commandlet for one list of packages with its log; returns the exit code
function Invoke-Dump([string[]]$packages, [string]$log) {
    $argv = @('-run=AtlasFormatTest', "-reflectionall=$($packages -join ',')", "-out=$out", '-unattended', '-nopause',
              '-nosplash', "-abslog=$log")
    if ($DryRun) { Write-Host "  $exe $($argv -join ' ')"; return 0 }
    & $exe @argv | Out-Null
    return $LASTEXITCODE
}

if ($Build) {
    $log = Join-Path $logs 'build_editor.log'
    if ($DryRun) {
        Write-Host "  powershell -ExecutionPolicy Bypass -File $tools\build-ue45.ps1 -Root $Engine -Target UE4Editor > $log"
    } else {
        Set-Content -Path $log -Value '' -Encoding utf8
        & powershell -ExecutionPolicy Bypass -File (Join-Path $tools 'build-ue45.ps1') -Root $Engine -Target UE4Editor 2>&1 |
            ForEach-Object {
                $_
                Add-Content -Path $log -Value $_ -Encoding utf8
            }
        $code = $LASTEXITCODE
        if (Select-String -Path $log -Pattern ' error C[0-9]+:| error LNK[0-9]+:|: fatal error|ERROR: UBT ERROR|error : |Error: |UnrealHeaderTool failed' -Quiet) { $code = 1 }
        "BUILD EXIT $code"
        if ($code -ne 0) { 'stopping: build failed'; exit 1 }
    }
}

# a module's old dump goes first, so nothing of a removed type survives
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($m in $todo) {
    $d = Join-Path $out $m
    if (Test-Path -LiteralPath $d) {
        if ($DryRun) { Write-Host "  remove $d" } else { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}
"dumping $($todo.Count) modules in one run into $out"
$code = Invoke-Dump (@($Preload + $todo) | Select-Object -Unique) (Join-Path $logs 'refl_ours.log')
"batch exit $code"
if ($DryRun) { '(dry run: modules missing after the batch would be retried alone)'; exit 0 }

foreach ($m in @($todo | Where-Object { -not (Test-Path -LiteralPath (Join-Path $out $_)) })) {
    "retry alone: $m"
    $code = Invoke-Dump (@($Preload + $m) | Select-Object -Unique) (Join-Path $logs "refl_$m.log")
    "  exit $code, dumped: $(Test-Path -LiteralPath (Join-Path $out $m))"
}
$missing = @($todo | Where-Object { -not (Test-Path -LiteralPath (Join-Path $out $_)) })
"dumped $($todo.Count - $missing.Count) of $($todo.Count) modules; missing: $(if ($missing) { $missing -join ', ' } else { 'none' })"
exit $missing.Count
