@echo off
setlocal
cd /d "%~dp0"
py -3 -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>&1
if not errorlevel 1 (
  py -3 app.py --open %*
  exit /b
)
python -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>&1
if not errorlevel 1 (
  python app.py --open %*
  exit /b
)
echo Python 3.10 or newer is required. Install it from https://www.python.org/downloads/
echo Then double-click StartLab.cmd again. No Python packages are required.
pause
exit /b 1
