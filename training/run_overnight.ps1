# Overnight full benchmark run - all three datasets, SEQUENTIAL.
# Each dataset: 50 Optuna trials, K=20 MCCV iterations.
#
# BEFORE RUNNING: set $N to the subsample size chosen from the learning curve
# (run: python train.py --dataset OG10 --learning-curve ; and for GenS10).
# Until then, the spec default is 20000.
#
# Usage:  cd training ;  .\run_overnight.ps1
# Output: everything is appended to results\overnight.log (tail it to watch progress).

$ErrorActionPreference = "Continue"   # keep going even if one dataset errors

$N = 10000                            # chosen at learning-curve plateau (OG10 peaks @10k; GenS10 flat from 5k)
$root = $PSScriptRoot                 # the training\ folder this script lives in
Set-Location $root

$resultsDir = Join-Path $root "results"
if (-not (Test-Path $resultsDir)) { New-Item -ItemType Directory -Path $resultsDir | Out-Null }
$log = Join-Path $resultsDir "overnight.log"

"=== OVERNIGHT RUN START $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  N=$N ===" | Tee-Object -FilePath $log -Append

foreach ($ds in @("OG10", "Gen10", "GenS10")) {
    "=== $ds START $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Tee-Object -FilePath $log -Append
    python train.py --dataset $ds --n-trials 50 --K 20 --n-subsample $N *>> $log
    "=== $ds END (exit=$LASTEXITCODE) $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Tee-Object -FilePath $log -Append
}

"=== ALL DONE $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Tee-Object -FilePath $log -Append
