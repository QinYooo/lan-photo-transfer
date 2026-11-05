@echo off
chcp 65001 >nul
cd /d "%~dp0"
py -3 --version >nul 2>&1
if not errorlevel 1 (
    py -3 "%~dp0receiver.py" %*
    goto end
)
python --version >nul 2>&1
if not errorlevel 1 (
    python "%~dp0receiver.py" %*
    goto end
)
echo 需要安装 Python 3.10 或更高版本。
echo 请从 https://www.python.org/downloads/windows/ 安装官方 Python。
echo 安装时勾选 Add python.exe to PATH，然后重新双击本文件。
:end
echo.
pause
