@echo off
REM Anti-DDoS Build Script for Windows
REM ====================================

echo =============================================
echo   Building Anti-DDoS Protection System
echo =============================================
echo.

REM Clean previous build
if exist build rmdir /s /q build
if exist bin rmdir /s /q bin

REM Create directories
mkdir build
mkdir bin

REM Configure
echo Configuring...
cd build
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release

REM Build
echo Building...
cmake --build . --config Release

REM Copy binaries to bin\
echo Copying binaries to bin\...
if exist "Release\antiddos-cli.exe" (
    copy "Release\antiddos-cli.exe" "..\bin\"
)
if exist "Release\antiddos-daemon.exe" (
    copy "Release\antiddos-daemon.exe" "..\bin\"
)
if exist "Release\xdp-cli.exe" (
    copy "Release\xdp-cli.exe" "..\bin\"
)
if exist "Release\xdp-loader.exe" (
    copy "Release\xdp-loader.exe" "..\bin\"
)

cd ..

echo.
echo =============================================
echo   Build Complete!
echo =============================================
echo.
echo Binaries available in bin\:
dir bin\
echo.