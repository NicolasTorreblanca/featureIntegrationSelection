@echo off
REM Overnight full benchmark run - all three datasets, SEQUENTIAL (pure cmd).
REM Each dataset: 50 Optuna trials, K=20 MCCV iterations, N=10000 benign subsample.
REM Usage: double-click this file, or from a cmd window run:  run_overnight.bat
REM Output: appended to results\overnight.log  (per-dataset stage progress is included)

setlocal enabledelayedexpansion
cd /d "%~dp0"
set N=10000
if not exist results mkdir results
set LOG=results\overnight.log

echo === OVERNIGHT START %date% %time%  N=%N% === >> "%LOG%"
echo Logging to %LOG%

for %%D in (OG10 Gen10 GenS10) do (
    echo === %%D START %date% %time% === >> "%LOG%"
    echo [%time%] running %%D ...
    python train.py --dataset %%D --n-trials 50 --K 20 --n-subsample %N% >> "%LOG%" 2>&1
    echo === %%D END exit=!errorlevel! %date% %time% === >> "%LOG%"
)

echo === ALL DONE %date% %time% === >> "%LOG%"
echo All datasets finished. See %LOG% and the results\ subfolders.
endlocal
