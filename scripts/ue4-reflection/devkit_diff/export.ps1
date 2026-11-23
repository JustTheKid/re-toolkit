# DevKit module diff, step 2: per DevKit DLL in <Work>\modules.tsv, the Ghidra import if the devkit project does not
# have the DLL yet (--pdb-only; --no-pdb, a full analysis, for a DLL shipped without its PDB), the metadata export
# (every Z_Construct_* of the DLL, untyped: <Corpus>\<module>) and, for a DLL with a PDB, the typed export (classes,
# structs and functions with the import slots retyped, ghidra_find.py --fix-imports: <Corpus>\<module>-typed). A DLL
# without a PDB gets no typed export: --fix-imports turns its calls into PTR_DAT_ and loses their parameters, so
# diffs.py reads its untyped export. Resumable: an import is skipped when the project has the program, the exports skip
# existing files. Step 1.9d: 65 DLLs in 2.5 h (about 3 min per PDB-only import, exports seconds to a minute).
# One Ghidra JVM at a time: never next to a build or a commandlet (16 GB). Logs: <Work>\logs\<module>.<step>.txt;
# one status line per module here.
# Usage: powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\devkit_diff\export.ps1 -Work <dir>
#          [-Modules AnimGraph,Paper*] [-MaxPayload 1024] [-Workers 4] [-Timeout 1500] [-Corpus <dir>]
#          [-Project <dir>] [-Name devkit] [-DryRun]
#   -Modules     names or wildcards from modules.tsv, comma separated (default: all)
#   -MaxPayload  decompiler output limit in MB (the Engine's AActor and FPostProcessSettings need 1024)
#   -DryRun      print the commands instead of running them
param([Parameter(Mandatory = $true)][string]$Work, [string[]]$Modules = @(), [int]$MaxPayload = 0, [int]$Workers = 4,
      [int]$Timeout = 1500, [string]$Corpus = '', [string]$Project = '', [string]$Name = 'devkit', [switch]$DryRun)

$tools = Split-Path $PSScriptRoot -Parent
$repo = Split-Path $tools -Parent
$py = Join-Path $tools 'ghidra-mcp-venv\Scripts\python.exe'
if (-not $Corpus) { $Corpus = Join-Path $repo '_re\corpus\devkit' }
if (-not $Project) { $Project = Join-Path $repo '_re\ghidra-devkit' }
# absolute paths (ghidra_find.py needs an absolute project path)
$full = { param($p) $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }
$Work, $Corpus, $Project = (& $full $Work), (& $full $Corpus), (& $full $Project)
$logs = Join-Path $Work 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null

$pats = @($Modules | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$rows = @(Import-Csv -LiteralPath (Join-Path $Work 'modules.tsv') -Delimiter "`t" | Where-Object {
    $m = $_.module; -not $pats -or @($pats | Where-Object { $m -like $_ }).Count })
$index = Join-Path $Project "$Name.rep\idata\~index.dat"

function Test-InProject([string]$leaf) {
    if (-not (Test-Path -LiteralPath $index)) { return $false }
    return [IO.File]::ReadAllText($index, [Text.Encoding]::GetEncoding(28591)).Contains($leaf)
}

function Get-FileCount([string]$dir) {
    if (Test-Path -LiteralPath $dir) { @(Get-ChildItem -LiteralPath $dir -File).Count } else { 0 }
}

# runs one tool with its output in $log; returns the exit code
function Invoke-Tool([string]$log, [string[]]$argv) {
    if ($DryRun) {
        $shown = $argv | ForEach-Object { if ($_ -match '[\s|()]') { "'$_'" } else { $_ } }
        Write-Host "  $py -I $($shown -join ' ') *> $log"
        return 0
    }
    & $py -I @argv *> $log
    return $LASTEXITCODE
}

"$($rows.Count) modules from $(Join-Path $Work 'modules.tsv')"
foreach ($r in $rows) {
    $m = $r.module
    if (-not $r.dll) { "${m}: no DevKit DLL"; continue }
    $low = $m.ToLower()
    $leaf = Split-Path $r.dll -Leaf
    $log = Join-Path $logs $low
    if (-not (Test-InProject $leaf)) {
        $mode = if ($r.pdb -eq 'pdb') { '--pdb-only' } else { '--no-pdb' }
        $code = Invoke-Tool "$log.analyze.txt" @("$tools\ghidra_analyze.py", $r.dll, '--project', $Project, '--name', $Name, $mode)
        if ($code) { "${m}: import failed (exit $code), see $log.analyze.txt"; continue }
    }
    $meta = Invoke-Tool "$log.meta.txt" @("$tools\devkit_metadata.py", 'export', '--dll', $r.dll, '--out', "$Corpus\$low",
                                          '--project', $Project, '--name', $Name)
    $typed = 'none (no PDB)'
    if ($r.pdb -eq 'pdb') {
        $argv = @("$tools\ghidra_find.py", '^Z_Construct_U(Class|ScriptStruct|Function)_(?!.*_NoRegister$)', '--decompile',
                  '--skip-existing', '--limit', '1000000', '--workers', $Workers, '--timeout', $Timeout, '--project', $Project,
                  '--name', $Name, '--program', $leaf, '--fix-imports', $r.dll, '--out', "$Corpus\$low-typed")
        if ($MaxPayload) { $argv += @('--max-payload', $MaxPayload) }
        $code = Invoke-Tool "$log.typed.txt" $argv
        $typed = "exit $code, $(Get-FileCount "$Corpus\$low-typed") files"
    }
    "${m}: meta exit $meta, $(Get-FileCount "$Corpus\$low") files; typed $typed"
}
'export done'
