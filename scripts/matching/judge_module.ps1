# Judge one engine module against ATLAS's server: every unity unit Module.<Module>.N_of_<Count>.cpp rebuilt over our
# files (unity_unit.py), compiled with ATLAS's command line (recompile_unit.py --source) and judged (func_match.py);
# with -Generated also the module's UHT units <Module>.generated.N.cpp. Per unit a folder <Out>\<unit>\ (the unit,
# its object, match.json, match.out); <Out>\summary.tsv (unit, functions in ours, found in the original,
# byte-identical, percent, MATCH-L: identical but for fatal-log source locations, Q-0017) and a total line. One
# build, judge or commandlet at a time.
# Usage: powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\judge_module.ps1 -Out <dir> [-Module Engine]
#          [-Count 26] [-Units 1,2,...] [-Generated 3] [-Causes]   (-Units also as "1,2,5")
#   ATLAS's server has unity units for Engine (26), Renderer (7), Core (5), Slate, CoreUObject, HoudiniEngineRuntime
#   (3 each); the other modules are single-file units. -Causes also runs judge_causes.py on each unit.
# 2026-10-25 (phase 4d, step 1.11: the weight of every Engine difference).
param([Parameter(Mandatory = $true)][string]$Out, [string]$Module = 'Engine', [int]$Count = 26, [string]$Units,
      [int]$Generated = 0, [switch]$Causes)
$py = 'D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe'
$sv = 'D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe'
# -Units arrives as one string through powershell -File ("1,2,5"): split it
$list = if ($Units) { $Units -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { [int]$_ } } else { 1..$Count }
New-Item -ItemType Directory -Force $Out | Out-Null
$tsv = Join-Path $Out 'summary.tsv'
Set-Content -Path $tsv -Value "unit`tfunctions`tfound`tidentical`tpercent`tlines_only" -Encoding utf8
Set-Location D:\ATLAS
$jobs = @()
foreach ($n in $list) { $jobs += , @("Module.$Module.${n}_of_$Count.cpp", ('Module\.' + $Module + '\.' + $n + '_of_' + $Count + '\.cpp\.obj$'), $true) }
if ($Generated -gt 0) {
    foreach ($n in 1..$Generated) { $jobs += , @("$Module.generated.$n.cpp", ($Module + '[\\/]' + $Module + '\.generated\.' + $n + '\.cpp\.obj$'), $false) }
}
$sum = @(0, 0, 0, 0)
foreach ($j in $jobs) {
    $unit, $rx, $unity = $j
    $dir = Join-Path $Out $unit
    $t = Get-Date
    if ($unity) {
        & $py -I _tools\unity_unit.py $sv $rx --out $dir | Select-Object -Skip 1 -First 1
        & $py -I _tools\recompile_unit.py $sv $rx --source (Join-Path $dir $unit) --out $dir | Select-Object -Last 1
    } else {
        & $py -I _tools\recompile_unit.py $sv $rx --out $dir | Select-Object -Last 1
    }
    $obj = Join-Path $dir "$unit.obj"
    if (-not (Test-Path $obj)) { "{0}: no object (compile failed, see {1})" -f $unit, (Join-Path $dir "$unit.log"); continue }
    & $py -I _tools\func_match.py $obj $sv --json (Join-Path $dir 'match.json') 2>&1 |
        Out-File -FilePath (Join-Path $dir 'match.out') -Encoding utf8
    $line = Get-Content (Join-Path $dir 'match.out') | Where-Object { $_ -match 'functions; in the original' } | Select-Object -First 1
    if ($line -match ': (\d+) functions; in the original (\d+); byte-identical (\d+) \(([\d.]+)%[^;]*(; line numbers only (\d+))?') {
        $lo = if ($Matches[6]) { [int]$Matches[6] } else { 0 }
        Add-Content -Path $tsv -Value ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $unit, $Matches[1], $Matches[2], $Matches[3], $Matches[4], $lo) -Encoding utf8
        $sum[0] += [int]$Matches[1]; $sum[1] += [int]$Matches[2]; $sum[2] += [int]$Matches[3]; $sum[3] += $lo
    }
    if ($Causes) {
        & $py -I _tools\judge_causes.py $obj $sv (Join-Path $dir 'match.json') 2>&1 |
            Out-File -FilePath (Join-Path $dir 'causes.out') -Encoding utf8
    }
    "{0}: {1} ({2:N0} s)" -f $unit, $line.Trim(), ((Get-Date) - $t).TotalSeconds
}
$pct = if ($sum[1]) { 100.0 * $sum[2] / $sum[1] } else { 0 }
Add-Content -Path $tsv -Value ("total`t{0}`t{1}`t{2}`t{3:N1}`t{4}" -f $sum[0], $sum[1], $sum[2], $pct, $sum[3]) -Encoding utf8
"JUDGE MODULE DONE: {0} of {1} functions byte-identical ({2:N1}%), {4} more identical but for line numbers; {3}" -f $sum[2], $sum[1], $pct, $tsv, $sum[3]
