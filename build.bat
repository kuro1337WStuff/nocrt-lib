@echo off
rem Builds the nocrt images with no CRT and no default libraries, strips
rem fingerprintable metadata (Rich header, debug dirs), then prints import
rem tables and sizes. The zero-import build links NO libraries at all: every
rem Win32 call resolves through the lazy PEB/export walker.
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist build mkdir build

rem Dev tool first (CRT allowed here; it never ships).
cl /nologo /O2 tools\strip\strip.cpp /Febuild\strip.exe
if errorlevel 1 exit /b 1

rem /Zl stops objects requesting LIBCMT; /OPT shrinks; /DEBUG:NONE keeps PDB
rem paths out (strip.exe also zeroes Rich + debug dirs post-link).
rem NOTE: /GL+/LTCG are deliberately absent - C2268: LTCG cannot compile
rem objects that redefine compiler predefined library helpers (memcpy etc).
rem /Gw + /Zc:inline let REF/ICF drop unreferenced globals and inline bodies
rem (research fold-in 3). Merges collapse 5 sections to 2: .pdata and .reloc
rem are located via DataDirectory not name; .rdata into .text stays RX.
rem .data is NOT merged (would create RWX). /ALIGN:16 deliberately skipped:
rem sub-page alignment destroys per-section RX/RW protection granularity.
set CFL=/nologo /O2 /W4 /Zl /Gw /Zc:inline /GS- /EHs-c- /GR- /std:c++latest /Iinclude
set LKF=/OPT:REF,ICF /DEBUG:NONE /INCREMENTAL:NO /MANIFEST:NO ^
        /MERGE:.pdata=.rdata /MERGE:.rdata=.text

cl %CFL% src\nocrt.cpp src\entry.cpp src\demo.cpp ^
   /Febuild\nocrt-demo.exe /link %LKF% /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib
if errorlevel 1 exit /b 1
build\strip.exe build\nocrt-demo.exe

cl %CFL% src\nocrt.cpp src\entry.cpp tools\patscan\patscan.cpp ^
   /Febuild\patscan.exe /link %LKF% /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib
if errorlevel 1 exit /b 1
build\strip.exe build\patscan.exe

cl %CFL% /DNOCRT_ZERO_IMPORT=1 src\nocrt.cpp src\entry.cpp src\demo.cpp ^
   /Febuild\nocrt-zero.exe /link %LKF% /ENTRY:nocrt_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB
if errorlevel 1 exit /b 1
build\strip.exe build\nocrt-zero.exe

rem The shipped artifact: a zero-import DLL, image-based relocatable.
cl %CFL% /DNOCRT_ZERO_IMPORT=1 src\nocrt.cpp tools\testdll\testdll.cpp ^
   /Febuild\testdll.dll /link %LKF% /DLL /ENTRY:NocrtDllEntry /SUBSYSTEM:WINDOWS /NODEFAULTLIB /FIXED:NO
if errorlevel 1 exit /b 1
build\strip.exe build\testdll.dll

rem Dev/test tools (CRT allowed; they never ship inside the target).
rem /MD on host so the CRT is a loaded module (ucrtbase.dll) that the injected
rem DLL can reach by export hash; a /MT host would hide the CRT inside itself.
cl /nologo /O2 /MD tools\host\host.cpp /Febuild\host.exe
if errorlevel 1 exit /b 1
cl /nologo /O2 tools\inject\inject.cpp /Febuild\inject.exe
if errorlevel 1 exit /b 1
cl /nologo /O2 tools\stackwalk\stackwalk.cpp /Febuild\stackwalk.exe
if errorlevel 1 exit /b 1
cl /nologo /O2 tools\metrics\metrics.cpp /Febuild\metrics.exe
if errorlevel 1 exit /b 1

echo.
echo === nocrt-demo imports (expect KERNEL32 only) ===
dumpbin /imports build\nocrt-demo.exe | findstr /i /c:".dll"
echo === nocrt-zero imports (expect none) ===
dumpbin /imports build\nocrt-zero.exe | findstr /i /c:".dll"
echo === testdll imports (expect none) ===
dumpbin /imports build\testdll.dll | findstr /i /c:".dll"
echo === testdll base reloc (0 is valid for x64 RIP-relative image) ===
dumpbin /headers build\testdll.dll | findstr /i /c:"base relocation"
echo === sizes ===
for %%F in (build\nocrt-demo.exe build\patscan.exe build\nocrt-zero.exe build\testdll.dll) do @echo %%~nxF %%~zF bytes
echo === done ===
exit /b 0
