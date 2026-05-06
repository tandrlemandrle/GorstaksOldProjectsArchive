using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Monitors
{
    /// <summary>
    /// Monitors new process creation via WMI events.
    /// Detects renamed LOLBins and suspicious command lines.
    /// Falls back to polling if WMI events are unavailable.
    /// </summary>
    public static class ProcessMonitor
    {
        private static ManagementEventWatcher _watcher;
        private static bool _usePolling;
        private static Dictionary<int, bool> _knownPids = new Dictionary<int, bool>();
        private static readonly object _lock = new object();
        private static int _selfPid;

        public static void Initialize()
        {
            _selfPid = System.Diagnostics.Process.GetCurrentProcess().Id;

            // Try WMI event subscription first
            try
            {
                WqlEventQuery query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                _watcher = new ManagementEventWatcher(query);
                _watcher.EventArrived += OnProcessCreated;
                _watcher.Start();
                Logger.Log("ProcessMonitor: started via WMI event subscription");
                return;
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("ProcessMonitor: WMI events failed ({0}), using polling", ex.Message), LogLevel.WARN);
            }

            // Fallback: seed known PIDs for polling mode
            _usePolling = true;
            SeedKnownPids();
            Logger.Log("ProcessMonitor: started via polling fallback");
        }

        /// <summary>Called by job scheduler on interval when using polling mode.</summary>
        public static void Poll()
        {
            if (!_usePolling) return;

            List<ProcessInfo> current = WmiHelper.GetProcesses();
            Dictionary<int, bool> currentPids = new Dictionary<int, bool>();

            for (int i = 0; i < current.Count; i++)
            {
                ProcessInfo proc = current[i];
                currentPids[proc.ProcessId] = true;

                bool isKnown;
                lock (_lock)
                {
                    isKnown = _knownPids.ContainsKey(proc.ProcessId);
                }

                if (!isKnown)
                {
                    // New process detected
                    AnalyzeNewProcess(proc.ProcessId, proc.Name, proc.ExecutablePath, proc.CommandLine);
                }
            }

            lock (_lock)
            {
                _knownPids = currentPids;
            }
        }

        public static void Shutdown()
        {
            if (_watcher != null)
            {
                try
                {
                    _watcher.Stop();
                    _watcher.Dispose();
                }
                catch { }
            }
        }

        private static void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                int pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                string name = (e.NewEvent.Properties["ProcessName"].Value ?? "").ToString();

                if (pid == _selfPid || pid <= 4) return;

                // Get full process info via WMI
                ProcessInfo info = WmiHelper.GetProcess(pid);
                string exePath = (info != null) ? info.ExecutablePath : null;
                string cmdLine = (info != null) ? info.CommandLine : null;

                AnalyzeNewProcess(pid, name, exePath, cmdLine);
            }
            catch { }
        }

        private static void AnalyzeNewProcess(int pid, string name, string exePath, string cmdLine)
        {
            if (pid == _selfPid) return;
            if (Config.IsProtectedProcess(name)) return;

            // Resolve the real identity of the binary via original filename
            // Catches renamed LOLBins (e.g., powershell.exe copied to update.exe)
            string realName = name;
            if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
            {
                try
                {
                    System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(exePath);
                    if (!string.IsNullOrEmpty(fvi.OriginalFilename))
                    {
                        string origLower = fvi.OriginalFilename.ToLowerInvariant().Replace(".mui", "");
                        string nameLower = (name ?? "").ToLowerInvariant();
                        if (origLower != nameLower && origLower != nameLower.Replace(".exe", "") + ".exe")
                        {
                            // Check if this is a known framework rebrand (not suspicious)
                            bool isFrameworkRebrand = false;
                            for (int fr = 0; fr < _frameworkOriginalNames.Length; fr++)
                            {
                                if (origLower.Contains(_frameworkOriginalNames[fr]))
                                { isFrameworkRebrand = true; break; }
                            }

                            if (!isFrameworkRebrand)
                            {
                                // Only flag if the original name is a LOLBin or system tool
                                bool isLolBinRename = false;
                                for (int lb = 0; lb < _lolBinOriginalNames.Length; lb++)
                                {
                                    if (origLower.Contains(_lolBinOriginalNames[lb]))
                                    { isLolBinRename = true; break; }
                                }

                                if (isLolBinRename)
                                {
                                    Logger.Log(string.Format("Renamed LOLBin: {0} is actually {1} (path: {2})",
                                        name, fvi.OriginalFilename, exePath), LogLevel.THREAT, "process_monitor.log");
                                    GidrState.IncrementThreats();
                                    JsonLogger.LogProcess("renamed-lolbin", name, pid, exePath, cmdLine, 70,
                                        "OriginalFilename: " + fvi.OriginalFilename);

                                    ThreatInfo renThreat = new ThreatInfo();
                                    renThreat.ThreatType = "RenamedLOLBin";
                                    renThreat.ThreatPath = exePath;
                                    renThreat.Severity = ThreatSeverity.Critical;
                                    renThreat.ProcessId = pid;
                                    renThreat.ProcessName = name;
                                    renThreat.CommandLine = cmdLine;
                                    renThreat.Confidence = 70;
                                    renThreat.Details["OriginalFilename"] = fvi.OriginalFilename;
                                    ResponseQueue.Enqueue(renThreat);
                                }
                            }

                            realName = fvi.OriginalFilename;
                        }
                    }
                }
                catch { }
            }

            // Command line analysis — use realName (original filename) for LOLBin matching
            if (!string.IsNullOrEmpty(cmdLine))
            {
                AnalyzeCommandLine(pid, realName, cmdLine);
            }
        }

        /// <summary>Check command line against threat intel patterns.</summary>
        private static void AnalyzeCommandLine(int pid, string name, string cmdLine)
        {
            string cmdLower = cmdLine.ToLowerInvariant();
            int score = 0;
            List<string> reasons = new List<string>();

            // Check LOLBin argument patterns
            string procName = (name ?? "").ToLowerInvariant();
            foreach (KeyValuePair<string, string[]> kvp in ThreatIntel.LOLBinArgs)
            {
                if (!procName.Contains(kvp.Key.Replace(".exe", "").ToLowerInvariant())) continue;

                string[] patterns = kvp.Value;
                int matchCount = 0;
                for (int i = 0; i < patterns.Length; i++)
                {
                    if (cmdLower.Contains(patterns[i].ToLowerInvariant()))
                        matchCount++;
                }
                if (matchCount > 0)
                {
                    score += matchCount * 15;
                    reasons.Add(string.Format("LOLBin:{0} ({1} patterns)", kvp.Key, matchCount));
                }
            }

            // Check command-line regex patterns
            for (int i = 0; i < ThreatIntel.CmdPatterns.Length; i++)
            {
                ThreatIntel.CmdPattern pat = ThreatIntel.CmdPatterns[i];
                try
                {
                    if (System.Text.RegularExpressions.Regex.IsMatch(cmdLine, pat.Pattern,
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    {
                        score += pat.Score;
                        reasons.Add(string.Format("{0} [{1}]", pat.Description, pat.MitreId));
                    }
                }
                catch { }
            }

            // High-entropy command line detection (base64 blobs, obfuscated scripts)
            if (cmdLine.Length > 100 && (procName.Contains("powershell") || procName.Contains("cmd")
                || procName.Contains("wscript") || procName.Contains("cscript") || procName.Contains("mshta")))
            {
                double cmdEntropy = CalculateStringEntropy(cmdLine);
                if (cmdEntropy > 5.5)
                {
                    score += 30;
                    reasons.Add(string.Format("High-entropy cmdline ({0:F1}) [T1027]", cmdEntropy));
                }
            }

            // Check suspicious parent-child chains
            ProcessInfo parentInfo = null;
            ProcessInfo procInfo = WmiHelper.GetProcess(pid);
            if (procInfo != null && procInfo.ParentProcessId > 0)
                parentInfo = WmiHelper.GetProcess(procInfo.ParentProcessId);

            if (parentInfo != null)
            {
                string parentName = (parentInfo.Name ?? "").ToLowerInvariant();
                string childName = (name ?? "").ToLowerInvariant();
                for (int i = 0; i < ThreatIntel.SuspiciousChains.Length; i++)
                {
                    ThreatIntel.ChainRule rule = ThreatIntel.SuspiciousChains[i];
                    if (parentName == rule.Parent.ToLowerInvariant() && childName == rule.Child.ToLowerInvariant())
                    {
                        score += rule.Score;
                        reasons.Add(string.Format("Chain: {0}", rule.Description));
                    }
                }
            }

            if (score >= Config.AlertThreshold)
            {
                ThreatSeverity sev = score >= Config.AutoKillThreshold ? ThreatSeverity.Critical
                    : score >= Config.AutoQuarantineThreshold ? ThreatSeverity.High : ThreatSeverity.Medium;

                Logger.Log(string.Format("CmdLine threat: {0} (PID:{1}) score:{2} | {3}",
                    name, pid, score, string.Join(", ", reasons.ToArray())), LogLevel.THREAT, "process_monitor.log");

                ThreatInfo threat = new ThreatInfo();
                threat.ThreatType = "CommandLine";
                threat.ThreatPath = (procInfo != null) ? procInfo.ExecutablePath : name;
                threat.Severity = sev;
                threat.ProcessId = pid;
                threat.ProcessName = name;
                threat.CommandLine = cmdLine;
                threat.Confidence = score;
                for (int i = 0; i < reasons.Count; i++)
                    threat.DetectionMethods.Add(reasons[i]);

                ResponseQueue.Enqueue(threat);

                // Auto-response is handled by ResponseEngine based on threat type.
                // CommandLine threats ARE behavioral, so ResponseEngine will act on them.
            }
        }

        private static void SeedKnownPids()
        {
            lock (_lock)
            {
                _knownPids.Clear();
                List<ProcessInfo> procs = WmiHelper.GetProcesses();
                for (int i = 0; i < procs.Count; i++)
                    _knownPids[procs[i].ProcessId] = true;
            }
        }

        // Framework runtimes that legitimately rebrand their exe (not suspicious)
        private static readonly string[] _frameworkOriginalNames = new string[]
        {
            "electron.exe",         // Electron apps (VS Code, Kiro, Discord, Slack, Teams, etc.)
            "nw.exe",               // NW.js apps
            "cefsharp",             // CefSharp embedded browser
            "chromiumembedded",     // CEF apps
            "java.exe",             // Java apps with custom launchers
            "javaw.exe",
            "python.exe",           // Python-based apps with custom names
            "pythonw.exe",
            "node.exe",             // Node.js apps
            "php.exe",
            "ruby.exe",
            "dotnet.exe",
        };

        // LOLBins that are suspicious when renamed (attacker trying to hide)
        private static readonly string[] _lolBinOriginalNames = new string[]
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe",
            "regsvr32.exe", "rundll32.exe", "regasm.exe", "regsvcs.exe", "installutil.exe",
            "msbuild.exe", "cmstp.exe", "odbcconf.exe", "ieexec.exe",
            "sc.exe", "net.exe", "net1.exe", "netsh.exe", "bcdedit.exe",
            "schtasks.exe", "at.exe", "reg.exe", "taskkill.exe",
        };

        private static double CalculateStringEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            int[] freq = new int[256];
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c < 256) freq[c]++;
            }
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / s.Length;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }
    }

    /// <summary>Static threat intel data used by command line analysis.</summary>
    public static class ThreatIntel
    {
        public struct ChainRule
        {
            public string Parent, Child, Description;
            public int Score;
        }

        public struct CmdPattern
        {
            public string Pattern, Description, MitreId;
            public int Score;
        }

        public static readonly Dictionary<string, string[]> LOLBinArgs = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "powershell", new string[] { "-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "-ep bypass", "-executionpolicy bypass", "iex", "invoke-expression", "downloadstring", "downloadfile", "frombase64string" } },
            { "cmd", new string[] { "/c powershell", "/c mshta", "/c certutil", "/c bitsadmin", "/c wscript", "/c cscript" } },
            { "mshta", new string[] { "javascript:", "vbscript:", "http://", "https://" } },
            { "certutil", new string[] { "-urlcache", "-decode", "-encode", "http://", "https://", "-split" } },
            { "wmic", new string[] { "process call create", "/node:", "shadowcopy delete", "/format:" } },
            { "regsvr32", new string[] { "scrobj.dll", "/s", "/i:http" } },
            { "rundll32", new string[] { "javascript:", "shell32.dll", "url.dll" } },
            { "bitsadmin", new string[] { "/transfer", "/create", "/addfile" } },
            { "schtasks", new string[] { "/create", "/change", "/run" } },
            { "sc", new string[] { "create", "config", "binpath=" } },
        };

        public static readonly ChainRule[] SuspiciousChains = new ChainRule[]
        {
            new ChainRule { Parent="winword.exe",   Child="cmd.exe",        Score=40, Description="Office->cmd" },
            new ChainRule { Parent="winword.exe",   Child="powershell.exe", Score=50, Description="Office->PS" },
            new ChainRule { Parent="excel.exe",     Child="cmd.exe",        Score=40, Description="Excel->cmd" },
            new ChainRule { Parent="excel.exe",     Child="powershell.exe", Score=50, Description="Excel->PS" },
            new ChainRule { Parent="outlook.exe",   Child="cmd.exe",        Score=45, Description="Outlook->cmd" },
            new ChainRule { Parent="outlook.exe",   Child="powershell.exe", Score=55, Description="Outlook->PS" },
            new ChainRule { Parent="mshta.exe",     Child="powershell.exe", Score=60, Description="MSHTA->PS" },
            new ChainRule { Parent="wscript.exe",   Child="powershell.exe", Score=50, Description="WScript->PS" },
            new ChainRule { Parent="cscript.exe",   Child="powershell.exe", Score=50, Description="CScript->PS" },
            new ChainRule { Parent="services.exe",  Child="cmd.exe",        Score=40, Description="Services->CMD" },
            new ChainRule { Parent="wmiprvse.exe",  Child="powershell.exe", Score=55, Description="WMI->PS" },
            new ChainRule { Parent="svchost.exe",   Child="cmd.exe",        Score=35, Description="Svchost->CMD" },
            new ChainRule { Parent="w3wp.exe",      Child="cmd.exe",        Score=80, Description="IIS->CMD" },
            new ChainRule { Parent="w3wp.exe",      Child="powershell.exe", Score=90, Description="IIS->PS" },
            new ChainRule { Parent="sqlservr.exe",  Child="cmd.exe",        Score=80, Description="SQL->CMD" },
        };

        public static readonly CmdPattern[] CmdPatterns = new CmdPattern[]
        {
            new CmdPattern { Pattern=@"-enc\s",                           Score=30, Description="Encoded command",         MitreId="T1059.001" },
            new CmdPattern { Pattern=@"-nop\s.*-w\s+hidden",              Score=35, Description="Hidden PowerShell",       MitreId="T1059.001" },
            new CmdPattern { Pattern=@"frombase64string",                 Score=30, Description="Base64 decode",           MitreId="T1140" },
            new CmdPattern { Pattern=@"vssadmin.*delete\s+shadows",       Score=50, Description="Shadow copy deletion",    MitreId="T1490" },
            new CmdPattern { Pattern=@"bcdedit.*recoveryenabled.*no",     Score=50, Description="Recovery disabled",       MitreId="T1490" },
            new CmdPattern { Pattern=@"Set-MpPreference.*-Disable",       Score=45, Description="Defender disabled",       MitreId="T1562.001" },
            new CmdPattern { Pattern=@"Add-MpPreference.*-ExclusionPath", Score=40, Description="Defender exclusion",      MitreId="T1562.001" },
            new CmdPattern { Pattern=@"\|\s*iex",                         Score=40, Description="Pipeline to IEX",         MitreId="T1059.001" },
            new CmdPattern { Pattern=@"downloadstring\s*\(.*http",        Score=45, Description="Download and execute",    MitreId="T1059.001" },
            new CmdPattern { Pattern=@"clear-eventlog|wevtutil\s+cl",     Score=50, Description="Event log clearing",      MitreId="T1070.001" },
        };
    }
}
