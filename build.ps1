$ErrorActionPreference = "Stop"
$csc = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    throw "未找到 .NET Framework 4.x 编译器: $csc"
}

& $csc /nologo /target:winexe /optimize+ `
    /win32icon:"$PSScriptRoot\AgySwitcher.ico" `
    /out:"$PSScriptRoot\AgySwitcher.exe" `
    /r:System.Windows.Forms.dll `
    /r:System.Drawing.dll `
    /r:System.Security.dll `
    /r:System.Web.Extensions.dll `
    /r:System.Management.dll `
    "$PSScriptRoot\AgySwitcher.cs"

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "编译成功: $PSScriptRoot\AgySwitcher.exe"
