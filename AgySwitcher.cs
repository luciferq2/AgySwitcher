using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
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

        public MainForm()
        {
            using (Graphics g = CreateGraphics())
            {
                _dpiScale = Math.Max(1.0f, g.DpiX / 96.0f);
            }

            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "Antigravity 账号切换器";
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            ClientSize = new Size(S(560), S(540));
            MinimumSize = new Size(S(480), S(440));
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9.5F);
            BackColor = BgCanvas;

            _config = SwitcherCore.LoadConfig();
            BuildUi();
            RefreshProfiles();
            UpdateProcessStatus();

            Resize += (s, e) => AdjustCardWidths();

            _statusTimer = new System.Windows.Forms.Timer { Interval = 2500 };
            _statusTimer.Tick += (s, e) => UpdateProcessStatus();
            _statusTimer.Start();
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

            actionRow.Controls.Add(btnNext);
            actionRow.Controls.Add(_btnKillApp);
            actionRow.Controls.Add(btnShortcut);

            topHeader.Controls.Add(statusRow, 0, 0);
            topHeader.Controls.Add(actionRow, 0, 1);

            // Middle scrollable list
            _profilePanel = new FlowLayoutPanel
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
            foreach (Control c in _profilePanel.Controls)
            {
                if (c is Panel)
                {
                    c.MinimumSize = new Size(cardWidth, 0);
                    c.MaximumSize = new Size(cardWidth, 0);
                    c.Width = cardWidth;
                }
            }
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
                        ColumnCount = 2,
                        RowCount = 1,
                        Padding = new Padding(S(12), S(10), S(12), S(10)),
                        Margin = Padding.Empty,
                        BackColor = Color.Transparent
                    };
                    inner.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
                    inner.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

                    var textStack = new TableLayoutPanel
                    {
                        Dock = DockStyle.Fill,
                        AutoSize = true,
                        AutoSizeMode = AutoSizeMode.GrowAndShrink,
                        ColumnCount = 1,
                        RowCount = 3,
                        Margin = Padding.Empty
                    };
                    textStack.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

                    string titleText = (isCurrent ? "当前 · " : "") + displayTitle;
                    var lblTitle = new Label
                    {
                        Text = titleText,
                        Font = new Font("Microsoft YaHei UI", 10.5F, FontStyle.Bold),
                        ForeColor = isCurrent ? PrimaryBlue : Color.FromArgb(30, 41, 59),
                        AutoSize = true,
                        Margin = new Padding(0, 0, 0, S(3))
                    };
                    var lblEmail = new Label
                    {
                        Text = emailText,
                        ForeColor = Color.FromArgb(51, 65, 85),
                        Font = new Font("Microsoft YaHei UI", 9F),
                        AutoSize = true,
                        Margin = new Padding(0, 0, 0, S(3))
                    };
                    var lblMeta = new Label
                    {
                        Text = metaLine,
                        ForeColor = Color.FromArgb(148, 163, 184),
                        Font = new Font("Microsoft YaHei UI", 8.25F),
                        AutoSize = true,
                        Margin = Padding.Empty
                    };

                    textStack.Controls.Add(lblTitle, 0, 0);
                    textStack.Controls.Add(lblEmail, 0, 1);
                    textStack.Controls.Add(lblMeta, 0, 2);

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

                    inner.Controls.Add(textStack, 0, 0);
                    inner.Controls.Add(btnBox, 1, 0);
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
