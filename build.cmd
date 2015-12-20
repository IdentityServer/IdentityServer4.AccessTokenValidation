@echo off
cd %~dp0

SETLOCAL
SET CACHED_NUGET=%LocalAppData%\NuGet\NuGet.exe

IF EXIST %CACHED_NUGET% goto copynuget
echo Downloading latest version of NuGet.exe...
IF NOT EXIST %LocalAppData%\NuGet md %LocalAppData%\NuGet
@powershell -NoProfile -ExecutionPolicy unrestricted -Command "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest 'https://www.nuget.org/nuget.exe' -OutFile '%CACHED_NUGET%'"

:copynuget
IF EXIST .nuget\nuget.exe goto restore
md .nuget
copy %CACHED_NUGET% .nuget\nuget.exe > nul

:restore
IF EXIST packages\psake goto run
.nuget\NuGet.exe install psake -ExcludeVersion -o packages -nocache

:run
:: Get Psake to Return Non-Zero Return Code on Build Failure (https://github.com/psake/psake/issues/58)
@powershell -NoProfile -ExecutionPolicy unrestricted -command "&{ Import-Module .\packages\psake\tools\psake.psm1; Invoke-Psake .\scripts\default.ps1 -parameters @{'configuration'='Release'}; exit !($psake.build_success) }"