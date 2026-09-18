@echo off
rem Builds the nocrt demo with no CRT and no default libraries, then prints the
rem import table so the absence of any CRT module is visible in the output.
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist build mkdir build
cl /nologo /O2 /W4 /Oi- /GS- /EHs-c- /GR- /std:c++latest /Iinclude ^
   src\nocrt.cpp src\entry.cpp src\demo.cpp ^
   /Febuild\nocrt-demo.exe /link /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /Oi- /GS- /EHs-c- /GR- /std:c++latest /Iinclude ^
   src\nocrt.cpp src\entry.cpp tools\patscan\patscan.cpp ^
   /Febuild\patscan.exe /link /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib
if errorlevel 1 exit /b 1
echo.
echo === import table (must show KERNEL32 only) ===
dumpbin /imports build\nocrt-demo.exe | findstr /i /c:".dll"
echo === patscan imports ===
dumpbin /imports build\patscan.exe | findstr /i /c:".dll"
