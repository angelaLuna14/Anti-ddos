@echo off
REM Anti-DDoS Protection System - Windows Installer
REM ================================================

echo =============================================
echo   Anti-DDoS Protection System Installer
echo =============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Please run as administrator
    pause
    exit /b 1
)

REM Check for build tools
where cmake >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: CMake is required but not found
    echo Please install CMake from https://cmake.org/download/
    pause
    exit /b 1
)

REM Create directories
echo Creating directories...
if not exist "%ProgramFiles%\AntiDDoS" mkdir "%ProgramFiles%\AntiDDoS"
if not exist "%ProgramData%\AntiDDoS" mkdir "%ProgramData%\AntiDDoS"
if not exist "%ProgramData%\AntiDDoS\logs" mkdir "%ProgramData%\AntiDDoS\logs"
if not exist "%ProgramData%\AntiDDoS\config" mkdir "%ProgramData%\AntiDDoS\config"

REM Build project
echo Building project...
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
cd ..

REM Check if binaries were built
if not exist "bin\Release\antiddos-cli.exe" (
    echo Error: Build failed - bin\Release\antiddos-cli.exe not found
    pause
    exit /b 1
)

REM Install binaries
echo Installing binaries...
copy "bin\Release\antiddos-cli.exe" "%ProgramFiles%\AntiDDoS\"
copy "bin\Release\antiddos-daemon.exe" "%ProgramFiles%\AntiDDoS\"

REM Copy any additional binaries
if exist "bin\Release\xdp-cli.exe" (
    copy "bin\Release\xdp-cli.exe" "%ProgramFiles%\AntiDDoS\"
)
if exist "bin\Release\xdp-loader.exe" (
    copy "bin\Release\xdp-loader.exe" "%ProgramFiles%\AntiDDoS\"
)

REM Install configuration
echo Installing configuration...
copy config\config.ini "%ProgramData%\AntiDDoS\config\"

REM Add to PATH
echo Adding to PATH...
setx PATH "%PATH%;%ProgramFiles%\AntiDDoS" /M

REM Create Windows Service
echo Creating Windows Service...
sc create AntiDDoS binPath= "%ProgramFiles%\AntiDDoS\antiddos-daemon.exe" start= auto
sc description AntiDDoS "Anti-DDoS Protection Service"

echo.
echo =============================================
echo   Installation Complete!
echo =============================================
echo.
echo Installed binaries:
echo   %ProgramFiles%\AntiDDoS\antiddos-cli.exe    - Main CLI
echo   %ProgramFiles%\AntiDDoS\antiddos-daemon.exe - Service daemon
echo.
echo Usage:
echo   Start:     net start AntiDDoS
echo   Stop:      net stop AntiDDoS
echo   Status:    sc query AntiDDoS
echo   CLI:       antiddos-cli.exe help
echo.
echo Configuration: %ProgramData%\AntiDDoS\config\config.ini
echo Logs: %ProgramData%\AntiDDoS\logs\
echo.
pause