using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace AgySwitcher
{
    public class CredProfile
    {
        public string UserName { get; set; }
        public uint Persist { get; set; }
        public string EncryptedBlob { get; set; }
        public string SavedAt { get; set; }
        public string Email { get; set; }
        public string Remark { get; set; }
    }

    public class SwitcherConfig
    {
        public string ExtraArgs { get; set; }
        public string CustomShortcutOrExe { get; set; }
        public string LastActiveProfile { get; set; }
    }

    internal static class WinCredHelper
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite(ref CREDENTIAL userCredential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr cred);

        public class CredRecord
        {
            public string UserName;
            public byte[] Blob;
            public uint Persist;
        }

        public static CredRecord ReadGeneric(string target)
        {
            IntPtr credPtr;
            if (!CredRead(target, 1, 0, out credPtr))
            {
                return null;
            }
            try
            {
                CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                byte[] blob = new byte[cred.CredentialBlobSize];
                if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                {
                    Marshal.Copy(cred.CredentialBlob, blob, 0, (int)cred.CredentialBlobSize);
                }
                return new CredRecord
                {
                    UserName = cred.UserName != IntPtr.Zero ? Marshal.PtrToStringUni(cred.UserName) : "",
                    Blob = blob,
                    Persist = cred.Persist
                };
            }
            finally
            {
                CredFree(credPtr);
            }
        }

        public static void WriteGeneric(string target, string userName, byte[] blob, uint persist)
        {
            CREDENTIAL cred = new CREDENTIAL();
            cred.Type = 1; // CRED_TYPE_GENERIC
            cred.Persist = persist == 0 ? 2u : persist; // CRED_PERSIST_LOCAL_MACHINE
            cred.TargetName = Marshal.StringToCoTaskMemUni(target);
            cred.UserName = Marshal.StringToCoTaskMemUni(userName ?? "");
            cred.CredentialBlobSize = (uint)(blob != null ? blob.Length : 0);
            cred.CredentialBlob = cred.CredentialBlobSize > 0 ? Marshal.AllocCoTaskMem(blob.Length) : IntPtr.Zero;
            try
            {
                if (cred.CredentialBlobSize > 0)
                {
                    Marshal.Copy(blob, 0, cred.CredentialBlob, blob.Length);
                }
                if (!CredWrite(ref cred, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                if (cred.TargetName != IntPtr.Zero) Marshal.FreeCoTaskMem(cred.TargetName);
                if (cred.UserName != IntPtr.Zero) Marshal.FreeCoTaskMem(cred.UserName);
                if (cred.CredentialBlob != IntPtr.Zero) Marshal.FreeCoTaskMem(cred.CredentialBlob);
            }
        }
    }

    internal static class LaunchHelper
    {
        public class LaunchPlan
        {
            public string Source { get; set; }
            public string FilePath { get; set; }
            public string Arguments { get; set; }
            public string WorkingDirectory { get; set; }
        }

        public static LaunchPlan CaptureRunningMainProcess()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE Name LIKE '%Antigravity%'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string exe = obj["ExecutablePath"] as string;
                        string cmdLine = obj["CommandLine"] as string;
                        if (string.IsNullOrEmpty(exe) || string.IsNullOrEmpty(cmdLine)) continue;
                        if (!exe.EndsWith("Antigravity.exe", StringComparison.OrdinalIgnoreCase)) continue;
                        if (cmdLine.IndexOf("--type=", StringComparison.OrdinalIgnoreCase) >= 0) continue;

                        return new LaunchPlan
                        {
                            Source = "运行中主进程参数",
                            FilePath = exe,
                            Arguments = ExtractArgsFromCommandLine(cmdLine),
                            WorkingDirectory = Path.GetDirectoryName(exe)
                        };
                    }
                }
            }
            catch { }
            return null;
        }

        private static string ExtractArgsFromCommandLine(string cmdLine)
        {
            if (string.IsNullOrWhiteSpace(cmdLine)) return "";
            string trimmed = cmdLine.Trim();
            if (trimmed.StartsWith("\""))
            {
                int endQuote = trimmed.IndexOf('"', 1);
                if (endQuote > 0 && endQuote + 1 < trimmed.Length)
                {
                    return trimmed.Substring(endQuote + 1).Trim();
                }
                return "";
            }
            int firstSpace = trimmed.IndexOf(' ');
            if (firstSpace > 0 && firstSpace + 1 < trimmed.Length)
            {
                return trimmed.Substring(firstSpace + 1).Trim();
            }
            return "";
        }

        public static LaunchPlan FindShortcutLaunch(string customPath)
        {
            if (!string.IsNullOrWhiteSpace(customPath) &&
                customPath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) &&
                File.Exists(customPath))
            {
                var customLnk = ReadLnk(customPath);
                if (customLnk != null) return customLnk;
            }

            var candidates = new List<string>();
            string[] dirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.Programs),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
            };

            foreach (string dir in dirs)
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                try
                {
                    candidates.AddRange(Directory.GetFiles(dir, "Antigravity*.lnk", SearchOption.TopDirectoryOnly));
                    string sub = Path.Combine(dir, "Antigravity");
                    if (Directory.Exists(sub))
                    {
                        candidates.AddRange(Directory.GetFiles(sub, "*.lnk", SearchOption.TopDirectoryOnly));
                    }
                }
                catch { }
            }

            foreach (string lnk in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (lnk.IndexOf("Uninstall", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                var plan = ReadLnk(lnk);
                if (plan != null) return plan;
            }
            return null;
        }

        private static LaunchPlan ReadLnk(string lnkPath)
        {
            object shell = null;
            object shortcut = null;
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) return null;
                shell = Activator.CreateInstance(shellType);
                shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
                if (shortcut == null) return null;

                Type scType = shortcut.GetType();
                string target = scType.InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, null) as string;
                string args = scType.InvokeMember("Arguments", BindingFlags.GetProperty, null, shortcut, null) as string;
                string workDir = scType.InvokeMember("WorkingDirectory", BindingFlags.GetProperty, null, shortcut, null) as string;

                if (string.IsNullOrWhiteSpace(target) || !File.Exists(target)) return null;

                return new LaunchPlan
                {
                    Source = "快捷方式 (" + Path.GetFileName(lnkPath) + ")",
                    FilePath = target,
                    Arguments = (args ?? "").Trim(),
                    WorkingDirectory = !string.IsNullOrWhiteSpace(workDir) ? workDir : Path.GetDirectoryName(target)
                };
            }
            catch
            {
                return null;
            }
            finally
            {
                if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.ReleaseComObject(shortcut);
                if (shell != null && Marshal.IsComObject(shell)) Marshal.ReleaseComObject(shell);
            }
        }

        public static void CreateLnk(string lnkPath, string targetExe, string arguments, string description)
        {
            object shell = null;
            object shortcut = null;
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) throw new InvalidOperationException("无法创建 WScript.Shell");
                shell = Activator.CreateInstance(shellType);
                shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
                Type scType = shortcut.GetType();
                scType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { targetExe });
                scType.InvokeMember("Arguments", BindingFlags.SetProperty, null, shortcut, new object[] { arguments ?? "" });
                scType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { Path.GetDirectoryName(targetExe) });
                scType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { targetExe + ",0" });
                scType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { description ?? "" });
                scType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
            }
            finally
            {
                if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.ReleaseComObject(shortcut);
                if (shell != null && Marshal.IsComObject(shell)) Marshal.ReleaseComObject(shell);
            }
        }

        public static LaunchPlan FindDefaultExeLaunch(string customPath, string extraArgs)
        {
            var candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(customPath) &&
                !customPath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                candidates.Add(customPath);
            }
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Programs\Antigravity\Antigravity.exe"));
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                @"Antigravity\Antigravity.exe"));

            foreach (string exe in candidates)
            {
                if (!string.IsNullOrWhiteSpace(exe) && File.Exists(exe))
                {
                    return new LaunchPlan
                    {
                        Source = string.IsNullOrWhiteSpace(extraArgs) ? "默认 EXE 启动" : "默认 EXE + 附加参数",
                        FilePath = exe,
                        Arguments = (extraArgs ?? "").Trim(),
                        WorkingDirectory = Path.GetDirectoryName(exe)
                    };
                }
            }
            return null;
        }

        public static string MergeExtraArgs(string baseArgs, string extraArgs)
        {
            string b = (baseArgs ?? "").Trim();
            string e = (extraArgs ?? "").Trim();
            if (string.IsNullOrEmpty(e)) return b;
            if (string.IsNullOrEmpty(b)) return e;
            if (b.IndexOf(e, StringComparison.OrdinalIgnoreCase) >= 0) return b;
            return b + " " + e;
        }
    }

    internal static class SwitcherCore
    {
        public const string TargetName = "gemini:antigravity";
        public static readonly string VaultDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".agy-profiles");
        public static readonly string ConfigFile = Path.Combine(VaultDir, "switcher-config.json");
        public static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

        private static readonly Regex EmailRegex = new Regex(
            @"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            RegexOptions.Compiled);

        public static SwitcherConfig LoadConfig()
        {
            Directory.CreateDirectory(VaultDir);
            try
            {
                if (File.Exists(ConfigFile))
                {
                    var loaded = Json.Deserialize<SwitcherConfig>(File.ReadAllText(ConfigFile, Encoding.UTF8));
                    if (loaded != null) return loaded;
                }
            }
            catch { }
            return new SwitcherConfig();
        }

        public static void SaveConfig(SwitcherConfig cfg)
        {
            Directory.CreateDirectory(VaultDir);
            try
            {
                File.WriteAllText(ConfigFile, Json.Serialize(cfg), Encoding.UTF8);
            }
            catch { }
        }

        public static List<string> GetSortedProfileNames()
        {
            Directory.CreateDirectory(VaultDir);
            return Directory.GetFiles(VaultDir, "*.cred.json")
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                .Select(f =>
                {
                    string n = Path.GetFileName(f);
                    return n.EndsWith(".cred.json", StringComparison.OrdinalIgnoreCase)
                        ? n.Substring(0, n.Length - ".cred.json".Length)
                        : n;
                })
                .ToList();
        }

        public static string SuggestNextProfileId()
        {
            var existing = new HashSet<string>(GetSortedProfileNames(), StringComparer.OrdinalIgnoreCase);
            for (char c = 'A'; c <= 'Z'; c++)
            {
                string candidate = "account" + c;
                if (!existing.Contains(candidate)) return candidate;
            }
            int i = 1;
            while (existing.Contains("account" + i)) i++;
            return "account" + i;
        }

        public static string GetProfileFilePath(string profileName)
        {
            return Path.Combine(VaultDir, profileName + ".cred.json");
        }

        public static string ResolveNextProfileName(SwitcherConfig cfg, out string error)
        {
            error = null;
            var names = GetSortedProfileNames();
            if (names.Count == 0)
            {
                error = "暂无已保存的账号快照，请先打开 AgySwitcher 保存至少两个账号。";
                return null;
            }
            if (names.Count == 1)
            {
                error = "当前只保存了 1 个账号（" + names[0] + "），请先保存第二个账号后再轮转切换。";
                return null;
            }

            int idx = -1;
            if (!string.IsNullOrEmpty(cfg.LastActiveProfile))
            {
                idx = names.FindIndex(n => string.Equals(n, cfg.LastActiveProfile, StringComparison.OrdinalIgnoreCase));
            }
            int nextIdx = (idx >= 0) ? (idx + 1) % names.Count : 0;
            return names[nextIdx];
        }

        public static List<Process> GetAntigravityProcesses()
        {
            return Process.GetProcesses()
                .Where(p =>
                {
                    try { return p.ProcessName.IndexOf("Antigravity", StringComparison.OrdinalIgnoreCase) >= 0; }
                    catch { return false; }
                })
                .ToList();
        }

        public static bool CloseAntigravityProcesses()
        {
            var procs = GetAntigravityProcesses();
            if (procs.Count == 0) return true;

            foreach (var p in procs)
            {
                try { if (p.MainWindowHandle != IntPtr.Zero) p.CloseMainWindow(); }
                catch { }
            }

            var deadline = DateTime.UtcNow.AddMilliseconds(2500);
            while (DateTime.UtcNow < deadline && GetAntigravityProcesses().Count > 0)
            {
                Thread.Sleep(150);
            }

            foreach (var p in GetAntigravityProcesses())
            {
                try { p.Kill(); p.WaitForExit(2000); }
                catch { }
            }

            Thread.Sleep(400);
            return GetAntigravityProcesses().Count == 0;
        }

        public static LaunchHelper.LaunchPlan ResolveLaunchPlan(
            SwitcherConfig cfg,
            LaunchHelper.LaunchPlan capturedBeforeClose)
        {
            if (capturedBeforeClose != null && File.Exists(capturedBeforeClose.FilePath))
            {
                capturedBeforeClose.Arguments = LaunchHelper.MergeExtraArgs(
                    capturedBeforeClose.Arguments, cfg.ExtraArgs);
                return capturedBeforeClose;
            }

            var lnkPlan = LaunchHelper.FindShortcutLaunch(cfg.CustomShortcutOrExe);
            if (lnkPlan != null)
            {
                lnkPlan.Arguments = LaunchHelper.MergeExtraArgs(lnkPlan.Arguments, cfg.ExtraArgs);
                return lnkPlan;
            }

            return LaunchHelper.FindDefaultExeLaunch(cfg.CustomShortcutOrExe, cfg.ExtraArgs);
        }

        public static bool SwitchToProfile(
            string profileName,
            SwitcherConfig cfg,
            LaunchHelper.LaunchPlan preCaptured,
            Action<string> onProgress,
            out string resultMessage)
        {
            bool createdNew;
            using (var mutex = new Mutex(false, @"Local\AgySwitcher_Switch_Lock", out createdNew))
            {
                bool acquired = false;
                try
                {
                    acquired = mutex.WaitOne(0);
                    if (!acquired)
                    {
                        resultMessage = "已有切换任务正在执行，请勿重复点击。";
                        return false;
                    }

                    string filePath = GetProfileFilePath(profileName);
                    if (!File.Exists(filePath))
                    {
                        resultMessage = "未找到账号快照：" + profileName;
                        return false;
                    }

                    var captured = LaunchHelper.CaptureRunningMainProcess() ?? preCaptured;

                    if (GetAntigravityProcesses().Count > 0)
                    {
                        if (onProgress != null) onProgress("正在关闭 Antigravity 客户端...");
                        if (!CloseAntigravityProcesses())
                        {
                            resultMessage = "无法自动关闭全部 Antigravity 进程，请手动退出后再试。";
                            return false;
                        }
                    }

                    var data = Json.Deserialize<CredProfile>(File.ReadAllText(filePath, Encoding.UTF8));
                    byte[] protectedBytes = Convert.FromBase64String(data.EncryptedBlob);
                    byte[] rawBlob = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);

                    WinCredHelper.WriteGeneric(TargetName, data.UserName, rawBlob, data.Persist);

                    cfg.LastActiveProfile = profileName;
                    SaveConfig(cfg);

                    var plan = ResolveLaunchPlan(cfg, captured);
                    if (plan != null && File.Exists(plan.FilePath))
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = plan.FilePath,
                            Arguments = plan.Arguments ?? "",
                            WorkingDirectory = plan.WorkingDirectory ?? Path.GetDirectoryName(plan.FilePath),
                            UseShellExecute = true
                        };
                        Process.Start(psi);
                        string display = !string.IsNullOrWhiteSpace(data.Remark) ? data.Remark : profileName;
                        resultMessage = string.Format("已切至 {0}（{1}）", display, plan.Source);
                    }
                    else
                    {
                        resultMessage = "凭证已切换至 " + profileName + "，请手动启动客户端。";
                    }
                    return true;
                }
                catch (Exception ex)
                {
                    resultMessage = "切换失败：" + ex.Message;
                    return false;
                }
                finally
                {
                    if (acquired) mutex.ReleaseMutex();
                }
            }
        }

        public static string TryExtractEmail(byte[] blob)
        {
            if (blob == null || blob.Length == 0) return "";

            string[] candidates = new[]
            {
                Encoding.UTF8.GetString(blob),
                Encoding.Unicode.GetString(blob)
            };

            foreach (string text in candidates)
            {
                var m = EmailRegex.Match(text);
                if (m.Success) return m.Value;

                foreach (Match jwtPart in Regex.Matches(text, @"eyJ[A-Za-z0-9_\-]{10,}"))
                {
                    try
                    {
                        string s = jwtPart.Value.Replace('-', '+').Replace('_', '/');
                        switch (s.Length % 4)
                        {
                            case 2: s += "=="; break;
                            case 3: s += "="; break;
                        }
                        string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(s));
                        var em = EmailRegex.Match(decoded);
                        if (em.Success) return em.Value;
                    }
                    catch { }
                }
            }
            return "";
        }
    }

    public class QuotaSummary
    {
        public bool Success { get; set; }
        public bool IsLoading { get; set; }
        public bool HasExhausted { get; set; }
        public bool AllExhausted { get; set; }
        public double? FiveHourFraction { get; set; }
        public string FiveHourReset { get; set; }
        public double? WeeklyFraction { get; set; }
        public string WeeklyReset { get; set; }
        public double? GeminiFraction { get; set; }
        public string GeminiReset { get; set; }
        public string Text { get; set; }
        public string TooltipText { get; set; }
    }

    public class QuotaRingControl : Control
    {
        private double? _outerFraction;
        private double? _innerFraction;
        private bool _isLoading;
        private bool _hasError;
        private bool _isActiveCard;
        private readonly float _scale;

        public QuotaRingControl(float dpiScale)
        {
            _scale = Math.Max(1.0f, dpiScale);
            SetStyle(
                ControlStyles.AllPaintingInWmPaint |
                ControlStyles.UserPaint |
                ControlStyles.OptimizedDoubleBuffer |
                ControlStyles.ResizeRedraw |
                ControlStyles.SupportsTransparentBackColor,
                true);
            BackColor = Color.Transparent;
            Size = new Size((int)Math.Round(56 * _scale), (int)Math.Round(56 * _scale));
            Cursor = Cursors.Hand;
        }

        public void SetState(QuotaSummary summary, bool isActiveCard)
        {
            _isActiveCard = isActiveCard;
            if (summary == null)
            {
                _isLoading = false;
                _hasError = false;
                _outerFraction = null;
                _innerFraction = null;
            }
            else if (summary.IsLoading)
            {
                _isLoading = true;
                _hasError = false;
                _outerFraction = null;
                _innerFraction = null;
            }
            else if (!summary.Success)
            {
                _isLoading = false;
                _hasError = true;
                _outerFraction = null;
                _innerFraction = null;
            }
            else
            {
                _isLoading = false;
                _hasError = false;
                // Outer ring = Gemini 5h, Inner ring = Gemini weekly (Claude not shown on rings)
                _outerFraction = summary.GeminiFraction ?? summary.FiveHourFraction;
                _innerFraction = summary.WeeklyFraction;
            }
            Invalidate();
        }

        private static Color GetRingColor(double frac, Color normalColor)
        {
            if (frac <= 0.005) return Color.FromArgb(239, 68, 68);   // Red
            if (frac <= 0.30) return Color.FromArgb(245, 158, 11);   // Amber
            return normalColor;
        }

        private void DrawRing(Graphics g, RectangleF rect, float strokeWidth, double? fraction, Color normalColor, Color trackColor)
        {
            using (var trackPen = new Pen(trackColor, strokeWidth))
            {
                trackPen.StartCap = LineCap.Round;
                trackPen.EndCap = LineCap.Round;
                g.DrawEllipse(trackPen, rect);
            }

            if (!fraction.HasValue) return;

            double clamped = Math.Max(0.0, Math.Min(1.0, fraction.Value));
            if (clamped <= 0.005)
            {
                // Draw subtle red ring indicator when 0%
                using (var zeroPen = new Pen(Color.FromArgb(120, 239, 68, 68), strokeWidth))
                {
                    g.DrawEllipse(zeroPen, rect);
                }
                return;
            }

            Color arcColor = GetRingColor(clamped, normalColor);
            using (var arcPen = new Pen(arcColor, strokeWidth))
            {
                arcPen.StartCap = LineCap.Round;
                arcPen.EndCap = LineCap.Round;
                if (clamped >= 0.995)
                {
                    g.DrawEllipse(arcPen, rect);
                }
                else
                {
                    float radius = rect.Width / 2f;
                    // Compensate for round caps so small gaps (like 97%) remain clearly visible
                    float capDeg = radius > 1f ? (float)((strokeWidth / radius) * (180.0 / Math.PI)) : 0f;
                    float rawSweep = (float)(360.0 * clamped);
                    float sweep = Math.Max(4f, Math.Min(rawSweep, 360f - capDeg - 4f));
                    g.DrawArc(arcPen, rect, -90f, sweep);
                }
            }
        }

        private static void DrawSparkle(Graphics g, float cx, float cy, float radius, Color color)
        {
            float ctrl = radius * 0.22f;
            using (var path = new GraphicsPath())
            {
                path.AddBezier(cx, cy - radius, cx + ctrl, cy - ctrl, cx + ctrl, cy - ctrl, cx + radius, cy);
                path.AddBezier(cx + radius, cy, cx + ctrl, cy + ctrl, cx + ctrl, cy + ctrl, cx, cy + radius);
                path.AddBezier(cx, cy + radius, cx - ctrl, cy + ctrl, cx - ctrl, cy + ctrl, cx - radius, cy);
                path.AddBezier(cx - radius, cy, cx - ctrl, cy - ctrl, cx - ctrl, cy - ctrl, cx, cy - radius);
                path.CloseFigure();

                using (var brush = new SolidBrush(color))
                {
                    g.FillPath(brush, path);
                }
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;

            float size = Math.Min(Width, Height);
            float cx = Width / 2f;
            float cy = Height / 2f;

            float outerStroke = 4.2f * _scale;
            float innerStroke = 3.4f * _scale;
            float outerRadius = (size / 2f) - outerStroke * 0.85f - 2f * _scale;
            float innerRadius = outerRadius - outerStroke - 3.6f * _scale;

            Color trackColor = _isActiveCard
                ? Color.FromArgb(214, 226, 245)
                : Color.FromArgb(229, 234, 241);

            if (_hasError)
            {
                trackColor = Color.FromArgb(254, 226, 226);
            }

            var outerRect = new RectangleF(cx - outerRadius, cy - outerRadius, outerRadius * 2f, outerRadius * 2f);
            var innerRect = new RectangleF(cx - innerRadius, cy - innerRadius, innerRadius * 2f, innerRadius * 2f);

            Color outerNormal = Color.FromArgb(34, 197, 94);   // Emerald Green (5h)
            Color innerNormal = Color.FromArgb(14, 165, 233);  // Sky Blue (Weekly)

            DrawRing(g, outerRect, outerStroke, _outerFraction, outerNormal, trackColor);
            DrawRing(g, innerRect, innerStroke, _innerFraction, innerNormal, trackColor);

            Color starColor = _isLoading
                ? Color.FromArgb(167, 139, 250)
                : (_hasError
                    ? Color.FromArgb(239, 68, 68)
                    : Color.FromArgb(139, 92, 246));

            float starRadius = Math.Max(6f * _scale, innerRadius * 0.56f);
            DrawSparkle(g, cx, cy, starRadius, starColor);
        }
    }

    internal static class QuotaHelper
    {
        private class OAuthClientPair
        {
            public string ClientId;
            public string ClientSecret;
        }

        private static readonly object OAuthLock = new object();
        private static List<OAuthClientPair> _cachedClients;

        static QuotaHelper()
        {
            try
            {
                // Enable TLS 1.2 on .NET Framework 4.x
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            }
            catch { }
        }

        private static string FindAgyExe()
        {
            string local = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "agy", "bin", "agy.exe");
            if (File.Exists(local)) return local;

            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathEnv.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string candidate = Path.Combine(dir.Trim(), "agy.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch { }
            }
            return null;
        }

        private static List<OAuthClientPair> GetOAuthClients()
        {
            lock (OAuthLock)
            {
                if (_cachedClients != null) return _cachedClients;
                var pairs = new List<OAuthClientPair>();
                try
                {
                    string agyExe = FindAgyExe();
                    if (!string.IsNullOrEmpty(agyExe) && File.Exists(agyExe))
                    {
                        byte[] bytes = File.ReadAllBytes(agyExe);
                        string text = Encoding.ASCII.GetString(bytes);

                        var cids = new List<string>();
                        foreach (Match m in Regex.Matches(text, @"[0-9]{10,15}-[a-z0-9]{20,40}\.apps\.googleusercontent\.com"))
                        {
                            if (!cids.Contains(m.Value)) cids.Add(m.Value);
                        }
                        // Prioritize known Antigravity client id first
                        cids = cids
                            .OrderByDescending(c => c.StartsWith("1071006060591-", StringComparison.Ordinal))
                            .ToList();

                        var secs = new List<string>();
                        foreach (Match m in Regex.Matches(text, @"GOCSPX-[A-Za-z0-9_\-]{28}"))
                        {
                            if (!secs.Contains(m.Value)) secs.Add(m.Value);
                        }

                        foreach (string cid in cids)
                        {
                            foreach (string sec in secs)
                            {
                                pairs.Add(new OAuthClientPair { ClientId = cid, ClientSecret = sec });
                            }
                        }
                    }
                }
                catch { }
                _cachedClients = pairs;
                return _cachedClients;
            }
        }

        private static string HttpPostJson(string url, string bearerToken, string jsonBody, out int statusCode)
        {
            statusCode = 0;
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.Timeout = 10000;
            req.ReadWriteTimeout = 10000;
            req.ContentType = "application/json";
            req.UserAgent = "antigravity/2.35.2 windows/amd64";
            if (!string.IsNullOrEmpty(bearerToken))
            {
                req.Headers["Authorization"] = "Bearer " + bearerToken;
            }
            byte[] data = Encoding.UTF8.GetBytes(jsonBody ?? "{}");
            req.ContentLength = data.Length;
            using (var stream = req.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }
            try
            {
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    statusCode = (int)resp.StatusCode;
                    using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
            catch (WebException wex)
            {
                var errResp = wex.Response as HttpWebResponse;
                if (errResp != null)
                {
                    statusCode = (int)errResp.StatusCode;
                }
                throw;
            }
        }

        private static string RefreshAccessToken(string refreshToken, out string error)
        {
            error = null;
            if (string.IsNullOrEmpty(refreshToken))
            {
                error = "缺少 refresh_token";
                return null;
            }

            var clients = GetOAuthClients();
            if (clients.Count == 0)
            {
                error = "未找到 agy.exe 以获取 OAuth 客户端参数";
                return null;
            }

            foreach (var pair in clients)
            {
                try
                {
                    string form = string.Format(
                        "client_id={0}&client_secret={1}&refresh_token={2}&grant_type=refresh_token",
                        Uri.EscapeDataString(pair.ClientId),
                        Uri.EscapeDataString(pair.ClientSecret),
                        Uri.EscapeDataString(refreshToken));
                    var req = (HttpWebRequest)WebRequest.Create("https://oauth2.googleapis.com/token");
                    req.Method = "POST";
                    req.Timeout = 8000;
                    req.ContentType = "application/x-www-form-urlencoded";
                    byte[] bodyBytes = Encoding.ASCII.GetBytes(form);
                    req.ContentLength = bodyBytes.Length;
                    using (var s = req.GetRequestStream())
                    {
                        s.Write(bodyBytes, 0, bodyBytes.Length);
                    }
                    using (var resp = (HttpWebResponse)req.GetResponse())
                    using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    {
                        var dict = SwitcherCore.Json.DeserializeObject(reader.ReadToEnd()) as Dictionary<string, object>;
                        if (dict != null && dict.ContainsKey("access_token"))
                        {
                            string tok = dict["access_token"] as string;
                            if (!string.IsNullOrEmpty(tok))
                            {
                                // Keep working pair first for subsequent calls
                                lock (OAuthLock)
                                {
                                    _cachedClients = new List<OAuthClientPair> { pair };
                                }
                                return tok;
                            }
                        }
                    }
                }
                catch (WebException wex)
                {
                    var errResp = wex.Response as HttpWebResponse;
                    if (errResp != null && (int)errResp.StatusCode == 400)
                    {
                        error = "refresh_token 已失效";
                    }
                }
                catch { }
            }

            if (error == null) error = "Token 刷新失败";
            return null;
        }

        private static string FormatResetTime(string isoUtc)
        {
            if (string.IsNullOrEmpty(isoUtc)) return "";
            DateTime dt;
            if (DateTime.TryParse(isoUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out dt))
            {
                DateTime local = dt.ToLocalTime();
                if (local.Date == DateTime.Now.Date)
                {
                    return local.ToString("HH:mm");
                }
                return local.ToString("MM-dd HH:mm");
            }
            return "";
        }

        private static string FormatGroup(string label, double? minFrac, string resetIso)
        {
            if (!minFrac.HasValue) return null;
            int pct = (int)Math.Round(Math.Max(0.0, Math.Min(1.0, minFrac.Value)) * 100.0);
            string reset = FormatResetTime(resetIso);
            string status = pct <= 0 ? "0% 已耗尽" : pct + "%";
            if (!string.IsNullOrEmpty(reset))
            {
                return string.Format("{0} {1} ({2}重置)", label, status, reset);
            }
            return string.Format("{0} {1}", label, status);
        }

        public static QuotaSummary FetchProfileQuota(CredProfile profile)
        {
            try
            {
                if (profile == null || string.IsNullOrEmpty(profile.EncryptedBlob))
                {
                    return new QuotaSummary { Success = false, Text = "额度：无凭证数据" };
                }

                byte[] raw = ProtectedData.Unprotect(
                    Convert.FromBase64String(profile.EncryptedBlob),
                    null,
                    DataProtectionScope.CurrentUser);
                string jsonText = Encoding.UTF8.GetString(raw);
                var root = SwitcherCore.Json.DeserializeObject(jsonText) as Dictionary<string, object>;
                if (root == null || !root.ContainsKey("token"))
                {
                    return new QuotaSummary { Success = false, Text = "额度：未识别的凭证格式" };
                }

                var tokenObj = root["token"] as Dictionary<string, object>;
                if (tokenObj == null)
                {
                    return new QuotaSummary { Success = false, Text = "额度：Token 字段为空" };
                }

                string accessToken = tokenObj.ContainsKey("access_token") ? tokenObj["access_token"] as string : null;
                string refreshToken = tokenObj.ContainsKey("refresh_token") ? tokenObj["refresh_token"] as string : null;
                string expiryStr = tokenObj.ContainsKey("expiry") ? tokenObj["expiry"] as string : null;

                bool needRefresh = string.IsNullOrEmpty(accessToken);
                if (!needRefresh && !string.IsNullOrEmpty(expiryStr))
                {
                    DateTime exp;
                    if (DateTime.TryParse(expiryStr, null, System.Globalization.DateTimeStyles.RoundtripKind, out exp))
                    {
                        if (DateTime.UtcNow.AddMinutes(2) >= exp.ToUniversalTime())
                        {
                            needRefresh = true;
                        }
                    }
                }

                if (needRefresh)
                {
                    string err;
                    string refreshed = RefreshAccessToken(refreshToken, out err);
                    if (string.IsNullOrEmpty(refreshed))
                    {
                        return new QuotaSummary { Success = false, Text = "额度：" + (err ?? "刷新失败") };
                    }
                    accessToken = refreshed;
                }

                string summaryText = null;
                int code;
                try
                {
                    summaryText = HttpPostJson(
                        "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
                        accessToken,
                        "{\"project\":\"aicode-consumers\"}",
                        out code);
                }
                catch (WebException)
                {
                    string err;
                    string refreshed = RefreshAccessToken(refreshToken, out err);
                    if (string.IsNullOrEmpty(refreshed))
                    {
                        return new QuotaSummary { Success = false, Text = "额度：查询失败（请检查网络/代理）" };
                    }
                    accessToken = refreshed;
                    summaryText = HttpPostJson(
                        "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
                        accessToken,
                        "{\"project\":\"aicode-consumers\"}",
                        out code);
                }

                double? gem5h = null;
                string gem5hReset = null;
                double? gemWeek = null;
                string gemWeekReset = null;
                double? claude5h = null;
                string claude5hReset = null;
                double? claudeWeek = null;
                string claudeWeekReset = null;

                var summaryDict = SwitcherCore.Json.DeserializeObject(summaryText) as Dictionary<string, object>;
                if (summaryDict != null && summaryDict.ContainsKey("groups"))
                {
                    var groups = summaryDict["groups"] as object[];
                    if (groups != null)
                    {
                        foreach (var gObj in groups)
                        {
                            var gDict = gObj as Dictionary<string, object>;
                            if (gDict == null || !gDict.ContainsKey("buckets")) continue;
                            string gName = gDict.ContainsKey("displayName") ? (gDict["displayName"] as string ?? "") : "";
                            bool isGeminiGroup = gName.IndexOf("Gemini", StringComparison.OrdinalIgnoreCase) >= 0;
                            bool isClaudeGroup = gName.IndexOf("Claude", StringComparison.OrdinalIgnoreCase) >= 0;

                            var buckets = gDict["buckets"] as object[];
                            if (buckets == null) continue;
                            foreach (var bObj in buckets)
                            {
                                var bDict = bObj as Dictionary<string, object>;
                                if (bDict == null) continue;
                                string bucketId = bDict.ContainsKey("bucketId") ? (bDict["bucketId"] as string ?? "") : "";
                                string win = bDict.ContainsKey("window") ? (bDict["window"] as string ?? "") : "";
                                if (!bDict.ContainsKey("remainingFraction") || bDict["remainingFraction"] == null) continue;
                                double frac = Convert.ToDouble(bDict["remainingFraction"]);
                                string reset = bDict.ContainsKey("resetTime") ? bDict["resetTime"] as string : null;

                                bool isGem = isGeminiGroup || bucketId.StartsWith("gemini-", StringComparison.OrdinalIgnoreCase);
                                bool is3p = isClaudeGroup || bucketId.StartsWith("3p-", StringComparison.OrdinalIgnoreCase);

                                if (isGem)
                                {
                                    if (string.Equals(win, "5h", StringComparison.OrdinalIgnoreCase))
                                    {
                                        gem5h = frac; gem5hReset = reset;
                                    }
                                    else if (string.Equals(win, "weekly", StringComparison.OrdinalIgnoreCase))
                                    {
                                        gemWeek = frac; gemWeekReset = reset;
                                    }
                                }
                                else if (is3p)
                                {
                                    if (string.Equals(win, "5h", StringComparison.OrdinalIgnoreCase))
                                    {
                                        claude5h = frac; claude5hReset = reset;
                                    }
                                    else if (string.Equals(win, "weekly", StringComparison.OrdinalIgnoreCase))
                                    {
                                        claudeWeek = frac; claudeWeekReset = reset;
                                    }
                                }
                            }
                        }
                    }
                }

                // Fallback to fetchAvailableModels if Gemini 5h not present in summary
                if (!gem5h.HasValue)
                {
                    try
                    {
                        int mCode;
                        string respText = HttpPostJson(
                            "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
                            accessToken,
                            "{}",
                            out mCode);
                        var respDict = SwitcherCore.Json.DeserializeObject(respText) as Dictionary<string, object>;
                        var models = (respDict != null && respDict.ContainsKey("models"))
                            ? respDict["models"] as Dictionary<string, object>
                            : null;
                        if (models != null)
                        {
                            foreach (var kv in models)
                            {
                                string modelId = kv.Key ?? "";
                                if (modelId.StartsWith("tab_", StringComparison.OrdinalIgnoreCase)) continue;
                                if (modelId.IndexOf("gemini", StringComparison.OrdinalIgnoreCase) < 0) continue;
                                var mDict = kv.Value as Dictionary<string, object>;
                                var qDict = (mDict != null && mDict.ContainsKey("quotaInfo")) ? mDict["quotaInfo"] as Dictionary<string, object> : null;
                                if (qDict == null || !qDict.ContainsKey("remainingFraction") || qDict["remainingFraction"] == null) continue;
                                double frac = Convert.ToDouble(qDict["remainingFraction"]);
                                string reset = qDict.ContainsKey("resetTime") ? qDict["resetTime"] as string : null;
                                if (!gem5h.HasValue || frac < gem5h.Value)
                                {
                                    gem5h = frac;
                                    gem5hReset = reset;
                                }
                            }
                        }
                    }
                    catch { }
                }

                Func<double?, string, string> fmtVal = (v, resetIso) =>
                {
                    if (!v.HasValue) return "--";
                    int p = (int)Math.Round(Math.Max(0.0, Math.Min(1.0, v.Value)) * 100.0);
                    string r = FormatResetTime(resetIso);
                    if (!string.IsNullOrEmpty(r))
                    {
                        // For weekly reset like "12-03 15:29", keep compact "12-03" in main line if space matters
                        if (r.Length > 5 && r.IndexOf(' ') > 0) r = r.Substring(0, r.IndexOf(' '));
                        return p + "%(" + r + ")";
                    }
                    return p + "%";
                };

                var lineParts = new List<string>();
                if (gem5h.HasValue || gemWeek.HasValue)
                {
                    lineParts.Add(string.Format("G: {0} · 周{1}", fmtVal(gem5h, gem5hReset), fmtVal(gemWeek, gemWeekReset)));
                }
                if (claude5h.HasValue || claudeWeek.HasValue)
                {
                    lineParts.Add(string.Format("C: {0} · {1}", fmtVal(claude5h, claude5hReset), fmtVal(claudeWeek, claudeWeekReset)));
                }

                if (lineParts.Count == 0)
                {
                    return new QuotaSummary { Success = true, Text = "暂无可统计额度" };
                }

                var tips = new List<string>();
                if (gem5h.HasValue) tips.Add("Gemini 5h (外环): " + FormatGroup("", gem5h, gem5hReset).Trim());
                if (gemWeek.HasValue) tips.Add("Gemini 周 (内环): " + FormatGroup("", gemWeek, gemWeekReset).Trim());
                if (claude5h.HasValue) tips.Add("Claude 5h: " + FormatGroup("", claude5h, claude5hReset).Trim());
                if (claudeWeek.HasValue) tips.Add("Claude 周: " + FormatGroup("", claudeWeek, claudeWeekReset).Trim());

                bool g5Zero = gem5h.HasValue && gem5h.Value <= 0.005;
                bool gwZero = gemWeek.HasValue && gemWeek.Value <= 0.005;
                bool c5Zero = claude5h.HasValue && claude5h.Value <= 0.005;
                bool cwZero = claudeWeek.HasValue && claudeWeek.Value <= 0.005;
                bool anyZero = g5Zero || gwZero || c5Zero || cwZero;
                bool allZero = (!gem5h.HasValue || g5Zero) && (!gemWeek.HasValue || gwZero) && (!claude5h.HasValue || c5Zero) && (!claudeWeek.HasValue || cwZero);

                return new QuotaSummary
                {
                    Success = true,
                    HasExhausted = anyZero,
                    AllExhausted = allZero,
                    GeminiFraction = gem5h,
                    GeminiReset = gem5hReset,
                    FiveHourFraction = gem5h,
                    FiveHourReset = gem5hReset,
                    WeeklyFraction = gemWeek,
                    WeeklyReset = gemWeekReset,
                    Text = string.Join("  |  ", lineParts.ToArray()),
                    TooltipText = string.Join("\n", tips.ToArray())
                };
            }
            catch (Exception ex)
            {
                return new QuotaSummary { Success = false, Text = "额度：查询异常 (" + ex.Message + ")" };
            }
        }
    }

    internal class BufferedFlowLayoutPanel : FlowLayoutPanel
    {
        public BufferedFlowLayoutPanel()
        {
            DoubleBuffered = true;
        }
    }

    public class MainForm : Form
    {
        private static readonly Color PrimaryBlue = Color.FromArgb(26, 115, 232);
        private static readonly Color BgCanvas = Color.FromArgb(245, 247, 250);
        private static readonly Color CardBorder = Color.FromArgb(224, 229, 236);
        private static readonly Color ActiveCardBg = Color.FromArgb(238, 245, 255);

        private readonly float _dpiScale;
        private SwitcherConfig _config;
        private LaunchHelper.LaunchPlan _lastCapturedLaunch;

        private Label _lblProcessStatus;
        private Button _btnKillApp;
        private FlowLayoutPanel _profilePanel;
        private TextBox _txtNewName;
        private TextBox _txtNewRemark;
        private Label _lblFooter;
        private System.Windows.Forms.Timer _statusTimer;
        private System.Windows.Forms.Timer _resizeTimer;
        private Button _btnRefreshQuota;
        private int _quotaRefreshingCount;
        private readonly Dictionary<string, QuotaSummary> _quotaCache =
            new Dictionary<string, QuotaSummary>(StringComparer.OrdinalIgnoreCase);
        private readonly ToolTip _quotaToolTip = new ToolTip();

        public MainForm()
        {
            DoubleBuffered = true;
            using (Graphics g = CreateGraphics())
            {
                _dpiScale = Math.Max(1.0f, g.DpiX / 96.0f);
            }

            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "Antigravity 账号切换器";
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            ClientSize = new Size(S(660), S(560));
            MinimumSize = new Size(S(560), S(450));
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9.5F);
            BackColor = BgCanvas;

            _config = SwitcherCore.LoadConfig();
            BuildUi();
            RefreshProfiles();
            UpdateProcessStatus();

            _resizeTimer = new System.Windows.Forms.Timer { Interval = 35 };
            _resizeTimer.Tick += (s, e) =>
            {
                _resizeTimer.Stop();
                AdjustCardWidths();
            };
            Resize += (s, e) =>
            {
                _resizeTimer.Stop();
                _resizeTimer.Start();
            };
            ResizeEnd += (s, e) =>
            {
                _resizeTimer.Stop();
                AdjustCardWidths();
            };

            _statusTimer = new System.Windows.Forms.Timer { Interval = 2500 };
            _statusTimer.Tick += (s, e) => UpdateProcessStatus();
            _statusTimer.Start();

            Shown += (s, e) => RefreshAllQuotasAsync();
        }

        private int S(int px)
        {
            return (int)Math.Round(px * _dpiScale);
        }

        private Button MakeButton(string text, bool isPrimary, EventHandler onClick)
        {
            var btn = new Button
            {
                Text = text,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(S(10), S(4), S(10), S(4)),
                Margin = new Padding(0, 0, S(6), S(2)),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            if (isPrimary)
            {
                btn.BackColor = PrimaryBlue;
                btn.ForeColor = Color.White;
                btn.FlatAppearance.BorderColor = PrimaryBlue;
                btn.FlatAppearance.BorderSize = 1;
            }
            else
            {
                btn.BackColor = Color.White;
                btn.ForeColor = Color.FromArgb(45, 55, 72);
                btn.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
                btn.FlatAppearance.BorderSize = 1;
            }
            if (onClick != null) btn.Click += onClick;
            return btn;
        }

        private void BuildUi()
        {
            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            // Top Header (2 clean rows: status row + action toolbar)
            var topHeader = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 1,
                RowCount = 2,
                BackColor = Color.White,
                Padding = new Padding(S(14), S(10), S(14), S(10)),
                Margin = Padding.Empty
            };
            topHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

            var statusRow = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, S(8))
            };
            statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _lblProcessStatus = new Label
            {
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Font = new Font("Microsoft YaHei UI", 9.5F, FontStyle.Bold),
                Text = "● 状态检测中...",
                Margin = new Padding(0, S(4), S(8), S(4))
            };

            var utilityBtns = new FlowLayoutPanel
            {
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Margin = Padding.Empty
            };
            var btnLaunchSettings = MakeButton("启动设置", false, (s, e) => EditLaunchSettings());
            var btnRefresh = MakeButton("刷新", false, (s, e) =>
            {
                _config = SwitcherCore.LoadConfig();
                RefreshProfiles();
                UpdateProcessStatus();
            });
            btnRefresh.Margin = Padding.Empty;
            utilityBtns.Controls.Add(btnLaunchSettings);
            utilityBtns.Controls.Add(btnRefresh);

            statusRow.Controls.Add(_lblProcessStatus, 0, 0);
            statusRow.Controls.Add(utilityBtns, 1, 0);

            var actionRow = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = true,
                Margin = Padding.Empty
            };
            var btnNext = MakeButton("切下一个账号", true, (s, e) => SwitchNextFromUi());
            _btnKillApp = MakeButton("关闭客户端", false, (s, e) =>
            {
                var captured = LaunchHelper.CaptureRunningMainProcess();
                if (captured != null) _lastCapturedLaunch = captured;
                SwitcherCore.CloseAntigravityProcesses();
                UpdateProcessStatus();
                SetFooter("已尝试关闭 Antigravity 进程。", false);
            });
            var btnShortcut = MakeButton("生成一键快捷方式", false, (s, e) => CreateQuickSwitchShortcuts());
            _btnRefreshQuota = MakeButton("刷新额度", false, (s, e) => RefreshAllQuotasAsync());

            actionRow.Controls.Add(btnNext);
            actionRow.Controls.Add(_btnKillApp);
            actionRow.Controls.Add(btnShortcut);
            actionRow.Controls.Add(_btnRefreshQuota);

            topHeader.Controls.Add(statusRow, 0, 0);
            topHeader.Controls.Add(actionRow, 0, 1);

            // Middle scrollable list
            _profilePanel = new BufferedFlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(S(14), S(12), S(14), S(8)),
                Margin = Padding.Empty
            };

            // Bottom panel
            var bottomPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Bottom,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = Color.White,
                Padding = new Padding(S(14), S(10), S(14), S(10)),
                Margin = Padding.Empty
            };
            bottomPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

            var inputRow = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 4,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, S(8))
            };
            inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58F));
            inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42F));

            var lblRemark = new Label { Text = "备注名称：", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 4, 4, 4) };
            _txtNewRemark = new TextBox { Dock = DockStyle.Fill, Margin = new Padding(0, 2, S(10), 2) };
            var lblName = new Label { Text = "唯一编号：", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 4, 4, 4) };
            _txtNewName = new TextBox
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 0, 2),
                Text = SwitcherCore.SuggestNextProfileId()
            };

            inputRow.Controls.Add(lblRemark, 0, 0);
            inputRow.Controls.Add(_txtNewRemark, 1, 0);
            inputRow.Controls.Add(lblName, 2, 0);
            inputRow.Controls.Add(_txtNewName, 3, 0);

            var btnSave = MakeButton("保存当前登录为新快照", true, (s, e) => SaveCurrentProfile());
            btnSave.Dock = DockStyle.Top;
            btnSave.Margin = new Padding(0, 0, 0, S(6));

            _lblFooter = new Label
            {
                AutoSize = true,
                Dock = DockStyle.Top,
                ForeColor = Color.FromArgb(100, 116, 139),
                Text = "提示：点击「生成一键快捷方式」可在桌面与开始菜单创建无界面直切图标。"
            };

            bottomPanel.Controls.Add(inputRow, 0, 0);
            bottomPanel.Controls.Add(btnSave, 0, 1);
            bottomPanel.Controls.Add(_lblFooter, 0, 2);

            root.Controls.Add(topHeader, 0, 0);
            root.Controls.Add(_profilePanel, 0, 1);
            root.Controls.Add(bottomPanel, 0, 2);
            Controls.Add(root);
        }

        private void UpdateProcessStatus()
        {
            var procs = SwitcherCore.GetAntigravityProcesses();
            if (procs.Count > 0)
            {
                _lblProcessStatus.Text = string.Format("● Antigravity 运行中 ({0} 个进程)", procs.Count);
                _lblProcessStatus.ForeColor = PrimaryBlue;
                _btnKillApp.Enabled = true;
            }
            else
            {
                _lblProcessStatus.Text = "● Antigravity 未运行";
                _lblProcessStatus.ForeColor = Color.FromArgb(22, 163, 74);
                _btnKillApp.Enabled = false;
            }
        }

        private void CreateQuickSwitchShortcuts()
        {
            try
            {
                string exePath = Application.ExecutablePath;
                string lnkName = "切换下一个 Antigravity 账号.lnk";
                string desktopLnk = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    lnkName);
                string startMenuLnk = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Programs),
                    lnkName);

                LaunchHelper.CreateLnk(desktopLnk, exePath, "--next", "一键静默切换到下一个 Antigravity 账号并重启");
                LaunchHelper.CreateLnk(startMenuLnk, exePath, "--next", "一键静默切换到下一个 Antigravity 账号并重启");

                SetFooter("已在桌面与开始菜单生成「切换下一个 Antigravity 账号」快捷方式。", false);
                MessageBox.Show(
                    "已生成一键切换快捷方式：\n\n1. 桌面：" + desktopLnk + "\n2. 开始菜单：" + startMenuLnk +
                    "\n\n以后点击该图标即可无界面直接切到下一个账号并重启客户端；\n也可在开始菜单右键将其「固定到开始屏幕」或「固定到任务栏」。",
                    "生成成功",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                SetFooter("生成快捷方式失败：" + ex.Message, true);
            }
        }

        private void SwitchNextFromUi()
        {
            string err;
            string nextName = SwitcherCore.ResolveNextProfileName(_config, out err);
            if (nextName == null)
            {
                SetFooter(err, true);
                return;
            }
            SwitchToProfile(nextName);
        }

        private void EditLaunchSettings()
        {
            var preview = SwitcherCore.ResolveLaunchPlan(
                _config,
                LaunchHelper.CaptureRunningMainProcess() ?? _lastCapturedLaunch);
            string previewText = preview != null
                ? string.Format("当前探测：{0}\n路径：{1}\n参数：{2}",
                    preview.Source,
                    preview.FilePath,
                    string.IsNullOrEmpty(preview.Arguments) ? "(无)" : preview.Arguments)
                : "当前未探测到 Antigravity 快捷方式或默认 EXE。";

            using (var dlg = new Form())
            {
                dlg.AutoScaleMode = AutoScaleMode.Dpi;
                dlg.Text = "启动设置（三层回退策略）";
                try { dlg.Icon = Icon; } catch { }
                dlg.ClientSize = new Size(S(500), S(280));
                dlg.MinimumSize = new Size(S(420), S(250));
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.Font = Font;
                dlg.BackColor = Color.White;

                var layout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    ColumnCount = 1,
                    RowCount = 6,
                    Padding = new Padding(S(14))
                };
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

                var lblPreview = new Label
                {
                    Text = previewText,
                    AutoSize = true,
                    MaximumSize = new Size(S(460), 0),
                    ForeColor = Color.FromArgb(100, 116, 139),
                    Margin = new Padding(0, 0, 0, S(10))
                };

                var l1 = new Label { Text = "自定义附加参数（如 --remote-debugging-port=0）：", AutoSize = true, Margin = new Padding(0, 2, 0, 4) };
                var tArgs = new TextBox { Text = _config.ExtraArgs ?? "", Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, S(10)) };

                var l2 = new Label { Text = "自定义 .lnk 或 .exe 路径（留空则自动探测）：", AutoSize = true, Margin = new Padding(0, 2, 0, 4) };
                var tPath = new TextBox { Text = _config.CustomShortcutOrExe ?? "", Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, S(12)) };

                var btnFlow = new FlowLayoutPanel
                {
                    Dock = DockStyle.Top,
                    FlowDirection = FlowDirection.RightToLeft,
                    AutoSize = true
                };
                var btnCancel = MakeButton("取消", false, null);
                btnCancel.DialogResult = DialogResult.Cancel;
                var btnOk = MakeButton("保存", true, null);
                btnOk.DialogResult = DialogResult.OK;
                btnFlow.Controls.Add(btnCancel);
                btnFlow.Controls.Add(btnOk);

                layout.Controls.Add(lblPreview, 0, 0);
                layout.Controls.Add(l1, 0, 1);
                layout.Controls.Add(tArgs, 0, 2);
                layout.Controls.Add(l2, 0, 3);
                layout.Controls.Add(tPath, 0, 4);
                layout.Controls.Add(btnFlow, 0, 5);

                dlg.Controls.Add(layout);
                dlg.AcceptButton = btnOk;
                dlg.CancelButton = btnCancel;

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _config.ExtraArgs = tArgs.Text.Trim();
                    _config.CustomShortcutOrExe = tPath.Text.Trim();
                    SwitcherCore.SaveConfig(_config);
                    SetFooter("已保存启动设置。", false);
                }
            }
        }

        private int GetCardWidth()
        {
            int w = _profilePanel.ClientSize.Width - _profilePanel.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth - S(4);
            return Math.Max(S(360), w);
        }

        private void AdjustCardWidths()
        {
            int cardWidth = GetCardWidth();
            _profilePanel.SuspendLayout();
            foreach (Control c in _profilePanel.Controls)
            {
                if (c is Panel)
                {
                    if (c.Width != cardWidth)
                    {
                        c.MinimumSize = new Size(cardWidth, 0);
                        c.MaximumSize = new Size(cardWidth, 0);
                        c.Width = cardWidth;
                    }
                }
            }
            _profilePanel.ResumeLayout(true);
        }

        private void RefreshProfiles()
        {
            _profilePanel.SuspendLayout();
            _profilePanel.Controls.Clear();

            var names = SwitcherCore.GetSortedProfileNames();
            if (names.Count == 0)
            {
                _profilePanel.Controls.Add(new Label
                {
                    Text = "暂无已保存的账号快照，请先在下方填写备注并保存。",
                    AutoSize = true,
                    ForeColor = Color.Gray,
                    Margin = new Padding(4, 12, 4, 4)
                });
            }
            else
            {
                int cardWidth = GetCardWidth();
                foreach (var name in names)
                {
                    string file = SwitcherCore.GetProfileFilePath(name);
                    CredProfile data = null;
                    try
                    {
                        data = SwitcherCore.Json.Deserialize<CredProfile>(File.ReadAllText(file, Encoding.UTF8));
                        if (data != null && data.Email == null && !string.IsNullOrEmpty(data.EncryptedBlob))
                        {
                            byte[] raw = ProtectedData.Unprotect(
                                Convert.FromBase64String(data.EncryptedBlob),
                                null,
                                DataProtectionScope.CurrentUser);
                            data.Email = SwitcherCore.TryExtractEmail(raw);
                            File.WriteAllText(file, SwitcherCore.Json.Serialize(data), Encoding.UTF8);
                        }
                    }
                    catch { }

                    bool isCurrent = string.Equals(name, _config.LastActiveProfile, StringComparison.OrdinalIgnoreCase);
                    bool hasRemark = data != null && !string.IsNullOrWhiteSpace(data.Remark);
                    string displayTitle = hasRemark ? data.Remark.Trim() : name;
                    string emailText = (data != null && !string.IsNullOrEmpty(data.Email))
                        ? data.Email
                        : "未识别到 Gmail（点「编辑」补充）";
                    string savedAt = (data != null && !string.IsNullOrEmpty(data.SavedAt))
                        ? data.SavedAt.Replace("T", " ")
                        : "";
                    string metaLine = string.Format("编号：{0}{1}", name, string.IsNullOrEmpty(savedAt) ? "" : "  ·  " + savedAt);

                    var card = new Panel
                    {
                        Width = cardWidth,
                        MinimumSize = new Size(cardWidth, 0),
                        MaximumSize = new Size(cardWidth, 0),
                        AutoSize = true,
                        AutoSizeMode = AutoSizeMode.GrowAndShrink,
                        Padding = new Padding(1),
                        BackColor = isCurrent ? ActiveCardBg : Color.White,
                        Margin = new Padding(0, 0, 0, S(10))
                    };
                    card.Paint += (s, pe) =>
                    {
                        Color borderColor = isCurrent ? PrimaryBlue : CardBorder;
                        using (var pen = new Pen(borderColor, 1))
                        {
                            pe.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1);
                        }
                    };

                    var inner = new TableLayoutPanel
                    {
                        Dock = DockStyle.Top,
                        AutoSize = true,
                        AutoSizeMode = AutoSizeMode.GrowAndShrink,
                        ColumnCount = 3,
                        RowCount = 1,
                        Padding = new Padding(S(12), S(10), S(12), S(12)),
                        Margin = Padding.Empty,
                        BackColor = Color.Transparent
                    };
                    inner.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                    inner.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
                    inner.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                    inner.RowStyles.Add(new RowStyle(SizeType.AutoSize));

                    var textStack = new TableLayoutPanel
                    {
                        Dock = DockStyle.Top,
                        AutoSize = true,
                        AutoSizeMode = AutoSizeMode.GrowAndShrink,
                        ColumnCount = 1,
                        RowCount = 4,
                        Margin = Padding.Empty
                    };
                    textStack.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
                    textStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                    textStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                    textStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                    textStack.RowStyles.Add(new RowStyle(SizeType.AutoSize));

                    string titleText = (isCurrent ? "当前 · " : "") + displayTitle;
                    var lblTitle = new Label
                    {
                        Text = titleText,
                        Font = new Font("Microsoft YaHei UI", 10.5F, FontStyle.Bold),
                        ForeColor = isCurrent ? PrimaryBlue : Color.FromArgb(30, 41, 59),
                        AutoSize = true,
                        Margin = new Padding(0, 0, 0, S(2))
                    };
                    var lblEmail = new Label
                    {
                        Text = emailText,
                        ForeColor = Color.FromArgb(51, 65, 85),
                        Font = new Font("Microsoft YaHei UI", 9F),
                        AutoSize = true,
                        Margin = new Padding(0, 0, 0, S(3))
                    };

                    QuotaSummary qSummary;
                    _quotaCache.TryGetValue(name, out qSummary);
                    string quotaText = qSummary != null ? qSummary.Text : "点击「刷新额度」查看 5h 与周额度";
                    Color quotaColor = Color.FromArgb(100, 116, 139);
                    if (qSummary != null && !qSummary.IsLoading)
                    {
                        if (!qSummary.Success)
                        {
                            quotaColor = Color.FromArgb(180, 83, 9);
                        }
                        else if (qSummary.AllExhausted)
                        {
                            quotaColor = Color.FromArgb(220, 38, 38);
                        }
                        else if (qSummary.HasExhausted)
                        {
                            quotaColor = Color.FromArgb(217, 119, 6);
                        }
                        else
                        {
                            quotaColor = Color.FromArgb(22, 163, 74);
                        }
                    }

                    var lblQuota = new Label
                    {
                        Text = quotaText,
                        ForeColor = quotaColor,
                        Font = new Font("Microsoft YaHei UI", 8.5F, (qSummary != null && qSummary.HasExhausted) ? FontStyle.Bold : FontStyle.Regular),
                        AutoSize = true,
                        AutoEllipsis = true,
                        Margin = new Padding(0, 0, 0, S(3))
                    };

                    var lblMeta = new Label
                    {
                        Text = metaLine,
                        ForeColor = Color.FromArgb(148, 163, 184),
                        Font = new Font("Microsoft YaHei UI", 8F),
                        AutoSize = true,
                        Margin = Padding.Empty
                    };

                    textStack.Controls.Add(lblTitle, 0, 0);
                    textStack.Controls.Add(lblEmail, 0, 1);
                    textStack.Controls.Add(lblQuota, 0, 2);
                    textStack.Controls.Add(lblMeta, 0, 3);

                    var ring = new QuotaRingControl(_dpiScale)
                    {
                        Anchor = AnchorStyles.Left,
                        Margin = new Padding(0, 0, S(12), 0)
                    };
                    ring.SetState(qSummary, isCurrent);
                    string tip = (qSummary != null && !string.IsNullOrEmpty(qSummary.TooltipText))
                        ? qSummary.TooltipText
                        : "外环：5h 额度  |  内环：周额度\n点击顶部「刷新额度」更新";
                    _quotaToolTip.SetToolTip(ring, tip);
                    _quotaToolTip.SetToolTip(lblQuota, tip);

                    string targetFile = file;
                    string profileName = name;

                    var btnBox = new FlowLayoutPanel
                    {
                        AutoSize = true,
                        AutoSizeMode = AutoSizeMode.GrowAndShrink,
                        FlowDirection = FlowDirection.LeftToRight,
                        WrapContents = false,
                        Anchor = AnchorStyles.Right,
                        Margin = new Padding(S(10), 0, 0, 0)
                    };
                    var btnEdit = MakeButton("编辑", false, (s, e) => EditRemarkAndEmail(profileName, targetFile));
                    var btnSwitch = MakeButton("切换并重启", !isCurrent, (s, e) => SwitchToProfile(profileName));
                    btnSwitch.Margin = Padding.Empty;

                    btnBox.Controls.Add(btnEdit);
                    btnBox.Controls.Add(btnSwitch);

                    inner.Controls.Add(ring, 0, 0);
                    inner.Controls.Add(textStack, 1, 0);
                    inner.Controls.Add(btnBox, 2, 0);
                    card.Controls.Add(inner);
                    _profilePanel.Controls.Add(card);
                }
            }

            _profilePanel.ResumeLayout();
        }

        private void EditRemarkAndEmail(string profileName, string filePath)
        {
            try
            {
                var data = SwitcherCore.Json.Deserialize<CredProfile>(File.ReadAllText(filePath, Encoding.UTF8));
                if (data == null) return;

                using (var dlg = new Form())
                {
                    dlg.AutoScaleMode = AutoScaleMode.Dpi;
                    dlg.Text = "编辑账号信息 - " + profileName;
                    try { dlg.Icon = Icon; } catch { }
                    dlg.ClientSize = new Size(S(400), S(175));
                    dlg.MinimumSize = new Size(S(350), S(165));
                    dlg.StartPosition = FormStartPosition.CenterParent;
                    dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                    dlg.MaximizeBox = false;
                    dlg.MinimizeBox = false;
                    dlg.Font = Font;
                    dlg.BackColor = Color.White;

                    var layout = new TableLayoutPanel
                    {
                        Dock = DockStyle.Fill,
                        ColumnCount = 2,
                        RowCount = 3,
                        Padding = new Padding(S(14))
                    };
                    layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                    layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

                    var l1 = new Label { Text = "备注（主标题）：", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 4, 8, 8) };
                    var tRemark = new TextBox { Text = data.Remark ?? "", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 8) };

                    var l2 = new Label { Text = "Gmail 账号：", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 4, 8, 10) };
                    var tEmail = new TextBox { Text = data.Email ?? "", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 10) };

                    var btnFlow = new FlowLayoutPanel
                    {
                        Dock = DockStyle.Fill,
                        FlowDirection = FlowDirection.RightToLeft,
                        AutoSize = true
                    };
                    var btnCancel = MakeButton("取消", false, null);
                    btnCancel.DialogResult = DialogResult.Cancel;
                    var btnOk = MakeButton("保存", true, null);
                    btnOk.DialogResult = DialogResult.OK;
                    btnFlow.Controls.Add(btnCancel);
                    btnFlow.Controls.Add(btnOk);

                    layout.Controls.Add(l1, 0, 0);
                    layout.Controls.Add(tRemark, 1, 0);
                    layout.Controls.Add(l2, 0, 1);
                    layout.Controls.Add(tEmail, 1, 1);
                    layout.Controls.Add(btnFlow, 1, 2);

                    dlg.Controls.Add(layout);
                    dlg.AcceptButton = btnOk;
                    dlg.CancelButton = btnCancel;

                    if (dlg.ShowDialog(this) == DialogResult.OK)
                    {
                        data.Remark = tRemark.Text.Trim();
                        data.Email = tEmail.Text.Trim();
                        File.WriteAllText(filePath, SwitcherCore.Json.Serialize(data), Encoding.UTF8);
                        RefreshProfiles();
                        SetFooter("已更新 '" + profileName + "' 的显示信息。", false);
                    }
                }
            }
            catch (Exception ex)
            {
                SetFooter("更新失败：" + ex.Message, true);
            }
        }

        private void SwitchToProfile(string profileName)
        {
            string msg;
            bool ok = SwitcherCore.SwitchToProfile(
                profileName,
                _config,
                _lastCapturedLaunch,
                progress =>
                {
                    SetFooter(progress, false);
                    Application.DoEvents();
                },
                out msg);

            if (ok)
            {
                _lastCapturedLaunch = null;
                RefreshProfiles();
            }
            SetFooter(msg, !ok);
            UpdateProcessStatus();
        }

        private void SaveCurrentProfile()
        {
            string name = (_txtNewName.Text ?? "").Trim();
            string remark = (_txtNewRemark.Text ?? "").Trim();

            if (string.IsNullOrEmpty(name))
            {
                name = SwitcherCore.SuggestNextProfileId();
            }
            if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                SetFooter("编号包含非法字符，请重新输入。", true);
                return;
            }

            if (SwitcherCore.GetAntigravityProcesses().Count > 0)
            {
                var res = MessageBox.Show(
                    "检测到 Antigravity 仍在运行，建议先关闭后再保存。\n是否现在自动关闭客户端并保存？",
                    "确认",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (res != DialogResult.Yes) return;
                var captured = LaunchHelper.CaptureRunningMainProcess();
                if (captured != null) _lastCapturedLaunch = captured;
                SwitcherCore.CloseAntigravityProcesses();
                UpdateProcessStatus();
            }

            try
            {
                var cred = WinCredHelper.ReadGeneric(SwitcherCore.TargetName);
                if (cred == null)
                {
                    SetFooter("未在凭据管理器中找到目标：" + SwitcherCore.TargetName, true);
                    return;
                }

                string detectedEmail = SwitcherCore.TryExtractEmail(cred.Blob);
                byte[] protectedBytes = ProtectedData.Protect(cred.Blob, null, DataProtectionScope.CurrentUser);
                var payload = new CredProfile
                {
                    UserName = cred.UserName,
                    Persist = cred.Persist,
                    EncryptedBlob = Convert.ToBase64String(protectedBytes),
                    SavedAt = DateTime.Now.ToString("s"),
                    Email = detectedEmail,
                    Remark = remark
                };

                string outFile = SwitcherCore.GetProfileFilePath(name);
                File.WriteAllText(outFile, SwitcherCore.Json.Serialize(payload), Encoding.UTF8);

                _config.LastActiveProfile = name;
                SwitcherCore.SaveConfig(_config);

                _txtNewRemark.Clear();
                _txtNewName.Text = SwitcherCore.SuggestNextProfileId();
                RefreshProfiles();
                SetFooter("已加密保存快照：" + (!string.IsNullOrEmpty(remark) ? remark + " (" + name + ")" : name), false);
            }
            catch (Exception ex)
            {
                SetFooter("保存失败：" + ex.Message, true);
            }
        }

        private void SetFooter(string msg, bool isError)
        {
            _lblFooter.Text = msg;
            _lblFooter.ForeColor = isError ? Color.Crimson : Color.FromArgb(22, 163, 74);
        }

        private void RefreshAllQuotasAsync()
        {
            if (_quotaRefreshingCount > 0) return;

            var names = SwitcherCore.GetSortedProfileNames();
            if (names.Count == 0)
            {
                SetFooter("暂无可查询的账号快照。", false);
                return;
            }

            _quotaRefreshingCount = names.Count;
            if (_btnRefreshQuota != null)
            {
                _btnRefreshQuota.Enabled = false;
                _btnRefreshQuota.Text = "查询中...";
            }
            SetFooter("正在并发查询各账号额度...", false);

            foreach (var name in names)
            {
                _quotaCache[name] = new QuotaSummary { IsLoading = true, Text = "额度：查询中..." };
            }
            RefreshProfiles();

            foreach (var name in names)
            {
                string profileName = name;
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    QuotaSummary result;
                    try
                    {
                        string file = SwitcherCore.GetProfileFilePath(profileName);
                        var data = SwitcherCore.Json.Deserialize<CredProfile>(File.ReadAllText(file, Encoding.UTF8));
                        result = QuotaHelper.FetchProfileQuota(data);
                    }
                    catch (Exception ex)
                    {
                        result = new QuotaSummary { Success = false, Text = "额度：读取失败 (" + ex.Message + ")" };
                    }

                    if (IsDisposed || !IsHandleCreated) return;
                    try
                    {
                        BeginInvoke((Action)(() =>
                        {
                            if (IsDisposed) return;
                            _quotaCache[profileName] = result;
                            _quotaRefreshingCount = Math.Max(0, _quotaRefreshingCount - 1);
                            RefreshProfiles();
                            if (_quotaRefreshingCount == 0)
                            {
                                if (_btnRefreshQuota != null)
                                {
                                    _btnRefreshQuota.Enabled = true;
                                    _btnRefreshQuota.Text = "刷新额度";
                                }
                                SetFooter("已完成所有账号额度查询。", false);
                            }
                        }));
                    }
                    catch { }
                });
            }
        }
    }

    internal static class Program
    {
        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();

        [STAThread]
        private static void Main(string[] args)
        {
            SetProcessDPIAware();

            if (args != null && args.Length > 0)
            {
                string cmd = args[0].Trim().ToLowerInvariant();
                if (cmd == "--next" || cmd == "-next")
                {
                    var cfg = SwitcherCore.LoadConfig();
                    string err;
                    string nextName = SwitcherCore.ResolveNextProfileName(cfg, out err);
                    if (nextName == null)
                    {
                        MessageBox.Show(err, "Antigravity 账号切换器", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    string resultMsg;
                    if (!SwitcherCore.SwitchToProfile(nextName, cfg, null, null, out resultMsg))
                    {
                        MessageBox.Show(resultMsg, "Antigravity 账号切换器", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    return;
                }

                if ((cmd == "--switch" || cmd == "-switch") && args.Length > 1)
                {
                    var cfg = SwitcherCore.LoadConfig();
                    string targetProfile = args[1].Trim();
                    string resultMsg;
                    if (!SwitcherCore.SwitchToProfile(targetProfile, cfg, null, null, out resultMsg))
                    {
                        MessageBox.Show(resultMsg, "Antigravity 账号切换器", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    return;
                }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
