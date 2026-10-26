@echo off
rem Windows launcher for run.sh. Finds Git for Windows' bash.exe (not WSL's) and hands over.
setlocal EnableExtensions
set "ARMIS_BASH="
if defined CLAUDE_CODE_GIT_BASH_PATH if exist "%CLAUDE_CODE_GIT_BASH_PATH%" set "ARMIS_BASH=%CLAUDE_CODE_GIT_BASH_PATH%"
if not defined ARMIS_BASH for /f "delims=" %%G in ('where git 2^>nul') do if not defined ARMIS_BASH if exist "%%~dpG..\bin\bash.exe" set "ARMIS_BASH=%%~dpG..\bin\bash.exe"
if not defined ARMIS_BASH for %%D in ("%ProgramFiles%" "%ProgramFiles(x86)%" "%LocalAppData%\Programs") do if not defined ARMIS_BASH if exist "%%~D\Git\bin\bash.exe" set "ARMIS_BASH=%%~D\Git\bin\bash.exe"
if not defined ARMIS_BASH (
    echo ERROR: Git for Windows bash.exe not found. Install Git for Windows or set CLAUDE_CODE_GIT_BASH_PATH. 1>&2
    exit /b 1
)
rem Forward slashes: run.sh takes PLUGIN_DIR from dirname "$0", which splits on "/" only.
rem Not cd /d, since the server falls back to its CWD (the user's project) for repo paths.
set "ARMIS_RUN_SH=%~dp0run.sh"
"%ARMIS_BASH%" "%ARMIS_RUN_SH:\=/%" %*
exit /b %ERRORLEVEL%
