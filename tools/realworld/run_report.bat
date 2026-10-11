@echo off
rem Run the MemoryGraph testing report on this computer (no internet needed).
rem   run_report.bat --check
rem   run_report.bat --dump D:\images\case1.raw
rem   run_report.bat --simulate
rem Uses the project's own virtual environment (.venv) when it exists, otherwise the Python on the PATH.
setlocal
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set QT_QPA_PLATFORM=offscreen
set PYTHONIOENCODING=utf-8
if exist "%ROOT%\.venv\Scripts\python.exe" (set "PY=%ROOT%\.venv\Scripts\python.exe") else (set "PY=python")
"%PY%" "%HERE%run_report.py" %*
echo.
pause
