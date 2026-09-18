@echo off
rem Builds the nocrt demo and companion with no CRT and no default libraries,
rem then prints import tables. The zero-import build links NO libraries at
rem all: every Win32 call is resolved through the lazy PEB/export walker.
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist build mkdir build
cl /nologo /O2 /W4 /GS- /EHs-c- /GR- /std:c++latest /Iinclude ^
   src\nocrt.cpp src\entry.cpp src\demo.cpp ^
   /Febuild\nocrt-demo.exe /link /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /GS- /EHs-c- /GR- /std:c++latest /Iinclude ^
   src\nocrt.cpp src\entry.cpp tools\patscan\patscan.cpp ^
   /Febuild\patscan.exe /link /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /GS- /EHs-c- /GR- /std:c++latest /Iinclude /DNOCRT_ZERO_IMPORT=1 ^
   src\nocrt.cpp src\entry.cpp src\demo.cpp ^
   /Febuild\nocrt-zero.exe /link /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB
if errorlevel 1 exit /b 1
echo.
echo === nocrt-demo imports (expect KERNEL32 only) ===
dumpbin /imports build\nocrt-demo.exe | findstr /i /c:".dll"
echo === patscan imports (expect KERNEL32 only) ===
dumpbin /imports build\patscan.exe | findstr /i /c:".dll"
echo === nocrt-zero imports (expect none) ===
dumpbin /imports build\nocrt-zero.exe | findstr /i /c:".dll"
echo === done ===
exit /b 0
