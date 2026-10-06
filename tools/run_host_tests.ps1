$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -property installationPath
if (!$vs) { throw 'Install Visual Studio C++ Build Tools, or run test/protocol_test.cpp with g++ on Linux.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
New-Item -ItemType Directory -Force (Join-Path $root 'test/.build') | Out-Null
Push-Location (Join-Path $root 'test/.build')
try {
    & cmd.exe /d /c "`"$vcvars`" >nul && cl /nologo /std:c++14 /EHsc /W4 /Fe:protocol_test.exe ..\protocol_test.cpp && protocol_test.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Protocol tests failed' }
} finally { Pop-Location }
