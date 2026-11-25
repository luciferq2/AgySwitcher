<#
.SYNOPSIS
    Windows 本地手动切换 Antigravity 2.0 登录凭证快照工具（零外部依赖，DPAPI 加密保存）
.DESCRIPTION
    直接调用 Windows 原生 advapi32.dll (CredRead/CredWrite) 与 System.Security DPAPI，
    无需安装 NuGet 或 CredentialManager 模块。
    1. 请先打开 Windows「凭据管理器 -> Windows 凭据」，确认 Antigravity/Gemini 对应的凭据名称，填入下方 $TargetName。
    2. 确认本机 Antigravity 2.0 可执行文件路径，填入 $AntigravityExe。
    3. 仅用于本人合法账号的纯手动切换，每次切换前需确保 Antigravity 2.0 已完全退出。
.EXAMPLE
    .\switch-agy.ps1 -Action save -ProfileName work
    .\switch-agy.ps1 -Action switch -ProfileName personal
    .\switch-agy.ps1 -Action list
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("save", "switch", "list")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$ProfileName
)

# ==================== 配置区（请根据本机实际情况修改） ====================
$TargetName     = "gemini:antigravity"
$AntigravityExe = "$env:LOCALAPPDATA\Programs\Antigravity\Antigravity.exe"
$VaultDir       = "$env:USERPROFILE\.agy-profiles"
# ==========================================================================

Add-Type -AssemblyName System.Security

$nativeCode = @"
using System;
using System.Runtime.InteropServices;

public static class WinCredHelper {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public UInt32 Flags;
        public UInt32 Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, UInt32 type, UInt32 reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref CREDENTIAL userCredential, UInt32 flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr cred);

    public class CredRecord {
        public string UserName;
        public byte[] Blob;
        public UInt32 Persist;
    }

    public static CredRecord ReadGeneric(string target) {
        IntPtr credPtr = IntPtr.Zero;
        if (!CredRead(target, 1, 0, out credPtr)) {
            return null;
        }
        try {
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
            byte[] blob = new byte[cred.CredentialBlobSize];
            if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero) {
                Marshal.Copy(cred.CredentialBlob, blob, 0, (int)cred.CredentialBlobSize);
            }
            return new CredRecord {
                UserName = cred.UserName != IntPtr.Zero ? Marshal.PtrToStringUni(cred.UserName) : "",
                Blob = blob,
                Persist = cred.Persist
            };
        } finally {
            CredFree(credPtr);
        }
    }

    public static void WriteGeneric(string target, string userName, byte[] blob, UInt32 persist) {
        CREDENTIAL cred = new CREDENTIAL();
        cred.Type = 1; // CRED_TYPE_GENERIC
        cred.Persist = persist == 0 ? 2u : persist; // default CRED_PERSIST_LOCAL_MACHINE
        cred.TargetName = Marshal.StringToCoTaskMemUni(target);
        cred.UserName = Marshal.StringToCoTaskMemUni(userName ?? "");
        cred.CredentialBlobSize = (UInt32)(blob != null ? blob.Length : 0);
        cred.CredentialBlob = cred.CredentialBlobSize > 0 ? Marshal.AllocCoTaskMem(blob.Length) : IntPtr.Zero;
        try {
            if (cred.CredentialBlobSize > 0) {
                Marshal.Copy(blob, 0, cred.CredentialBlob, blob.Length);
            }
            if (!CredWrite(ref cred, 0)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally {
            if (cred.TargetName != IntPtr.Zero) Marshal.FreeCoTaskMem(cred.TargetName);
            if (cred.UserName != IntPtr.Zero) Marshal.FreeCoTaskMem(cred.UserName);
            if (cred.CredentialBlob != IntPtr.Zero) Marshal.FreeCoTaskMem(cred.CredentialBlob);
        }
    }
}
"@

Add-Type -TypeDefinition $nativeCode -Language CSharp

function Assert-Config {
    if ($TargetName -like "<*>") {
        Write-Error "请先编辑脚本顶部的 `$TargetName，填入 Windows 凭据管理器中的实际目标名称。"
        exit 1
    }
}

function Assert-AppClosed {
    $running = Get-Process -Name "*Antigravity*" -ErrorAction SilentlyContinue
    if ($running) {
        Write-Warning "检测到 Antigravity 进程仍在运行，请先完全退出（包括系统托盘）后再执行。"
        exit 1
    }
}

New-Item -ItemType Directory -Force -Path $VaultDir | Out-Null

if ($Action -eq "list") {
    $files = Get-ChildItem -Path $VaultDir -Filter "*.cred.json" -ErrorAction SilentlyContinue
    if (-not $files) {
        Write-Host "当前没有已保存的账号快照（目录: $VaultDir）。"
    } else {
        Write-Host "已保存的账号快照："
        $files | ForEach-Object { Write-Host " - $($_.BaseName -replace '\.cred$', '')" }
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($ProfileName)) {
    Write-Error "执行 save 或 switch 时必须指定 -ProfileName。"
    exit 1
}

Assert-Config
Assert-AppClosed

$ProfileFile = Join-Path $VaultDir "$ProfileName.cred.json"

if ($Action -eq "save") {
    $cred = [WinCredHelper]::ReadGeneric($TargetName)
    if (-not $cred) {
        Write-Error "未在 Windows 凭据管理器中找到目标: $TargetName"
        exit 1
    }

    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
        $cred.Blob,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    $payload = @{
        UserName      = $cred.UserName
        Persist       = $cred.Persist
        EncryptedBlob = [Convert]::ToBase64String($protected)
        SavedAt       = (Get-Date).ToString("s")
    } | ConvertTo-Json

    Set-Content -Path $ProfileFile -Value $payload -Encoding UTF8
    Write-Host "已加密保存账号快照 '$ProfileName' -> $ProfileFile"
}
elseif ($Action -eq "switch") {
    if (-not (Test-Path $ProfileFile)) {
        Write-Error "未找到账号快照: $ProfileFile"
        exit 1
    }

    $data = Get-Content -Path $ProfileFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $protected = [Convert]::FromBase64String($data.EncryptedBlob)
    $blob = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $protected,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    [WinCredHelper]::WriteGeneric($TargetName, $data.UserName, $blob, [uint32]$data.Persist)
    Write-Host "已切换本地凭证至账号: $ProfileName"

    if (Test-Path $AntigravityExe) {
        Start-Process -FilePath $AntigravityExe
        Write-Host "已启动 Antigravity。"
    } else {
        Write-Warning "未找到可执行文件 '$AntigravityExe'，请手动启动 Antigravity。"
    }
}
