@echo off
setlocal
rem Build the PI Log Tools Notepad++ plugin (requires w64devkit / MinGW-w64).

set "ROOT=%~dp0.."
set "KIT=C:\Users\roger.ward\w64devkit\w64devkit\bin"
set "CXX=%KIT%\g++.exe"
set "WINDRES=%KIT%\windres.exe"
set "INC=%ROOT%\include"
set "SRC=%ROOT%\src"

if not exist "%CXX%" (
    echo ERROR: g++ not found at %CXX%
    exit /b 1
)

rem Make sure the assembler/linker from the kit are findable.
set "PATH=%KIT%;%PATH%"

rem Local includes (resource.h, LogParser.h) resolve relative to the sources;
rem only the API headers need an explicit -I (use "-I <path>" to keep spaces safe).
"%WINDRES%" "%SRC%\dialog.rc" -O coff -o "%SRC%\dialog.o"
if errorlevel 1 exit /b 1

"%CXX%" -std=c++17 -O2 -Wall -shared -static-libgcc -static-libstdc++ ^
    -I "%INC%" ^
    "%SRC%\PILogTools.cpp" "%SRC%\LogParser.cpp" "%SRC%\dialog.o" ^
    -o "%SRC%\PILogTools.dll"
if errorlevel 1 exit /b 1

echo.
echo Build OK: %SRC%\PILogTools.dll

if /i "%~1"=="install" (
    set "NPPDLL=C:\Program Files\Notepad++\plugins\PILogTools\PILogTools.dll"
    echo.
    echo Copying to %NPPDLL% ...
    powershell -NoProfile -Command "New-Item -ItemType Directory -Path 'C:\Program Files\Notepad++\plugins\PILogTools' -Force | Out-Null; Copy-Item -LiteralPath '%SRC%\PILogTools.dll' -Destination '%NPPDLL%' -Force"
    if not errorlevel 1 echo Installed. Restart Notepad++ to load the plugin.
)
endlocal
