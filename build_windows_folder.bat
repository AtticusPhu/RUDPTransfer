@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo [1/3] Installing build dependencies...
python -m pip install -r build_requirements.txt
if errorlevel 1 goto :error

echo [2/3] Building folder-mode executable with PyInstaller...
pyinstaller --clean --noconfirm RUDPTransfer.spec
if errorlevel 1 goto :error

echo [3/3] Building NSIS installer...
where makensis >nul 2>nul
if errorlevel 1 (
  echo NSIS makensis.exe was not found in PATH.
  echo Folder build is ready at dist\RUDPTransfer\RUDPTransfer.exe
  echo Install NSIS, add it to PATH, then run:
  echo   makensis installer\RUDPTransfer.nsi
  goto :done
)
makensis installer\RUDPTransfer.nsi
if errorlevel 1 goto :error

echo Build finished.
echo Folder build: dist\RUDPTransfer\RUDPTransfer.exe
echo Installer:    dist\RUDPTransfer_Setup.exe
goto :done

:error
echo Build failed.
exit /b 1

:done
pause
