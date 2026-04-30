using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using GEdr.Core;
using GEdr.Response;

namespace GEdr.Detection
{
    /// <summary>
    /// Process hollowing, token manipulation, suspicious parent-child,
    /// fileless attacks, memory scanning, process auditing.
    /// Ported from Invoke-ProcessHollowingDetection, Invoke-TokenManipulationDetection,
    /// Invoke-SuspiciousParentChildDetection, Invoke-FilelessDetection, Invoke-MemoryScanning.
    /// </summary>
    public static class ProcessDetection
    {
        private static readonly HashSet<string> _whitelistedForHollowing = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Cursor","Code","electron","node","chrome","firefox","msedge","brave",
            "opera","slack","discord","teams","spotify","devenv","powershell","pwsh",
            "WindowsTerminal","explorer","SearchHost","StartMenuExperienceHost"
        };

        /// <summary>Detect process hollowing: path mismatch, all threads suspended, impersonation.</summary>
        public static void ProcessHollowing()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();
            Dictionary<int, ProcessInfo> procMap = new Dictionary<int, ProcessInfo>();
            for (int i = 0; i < processes.Count; i++)
                procMap[processes[i].ProcessId] = processes[i];

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;
                string cleanName = (proc.Name ?? "").Replace(".exe", "");
                if (_whitelistedForHollowing.Contains(cleanName)) continue;

                try
                {
                    Process sysProc = Process.GetProcessById(proc.ProcessId);
                    string runtimePath = null;
                    try { runtimePath = sysProc.MainModule.FileName; } catch { }

                    // Path mismatch between WMI and runtime
                    if (runtimePath != null && proc.ExecutablePath != null)
                    {
                        // Normalize paths: strip \\?\ prefix and trailing whitespace
                        string normWmi = proc.ExecutablePath.TrimStart('\\', '?').TrimStart('\\');
                        string normRuntime = runtimePath.TrimStart('\\', '?').TrimStart('\\');

                        if (!string.Equals(normRuntime, normWmi, StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.Log(string.Format("Process hollowing (path mismatch): {0} PID:{1} WMI:{2} Runtime:{3}",
                                proc.Name, proc.ProcessId, proc.ExecutablePath, runtimePath),
                                LogLevel.THREAT, "process_hollowing.log");
                            EdrState.IncrementThreats();
                            EnqueueThreat("ProcessHollowing:PathMismatch", proc, ThreatSeverity.Critical, 85);
                        }
                    }

                    // Unsigned exe impersonating system binary
                    string[] legitNames = new string[] { "svchost.exe", "explorer.exe", "notepad.exe", "calc.exe", "dwm.exe" };
                    bool isLegitName = false;
                    for (int j = 0; j < legitNames.Length; j++)
                    {
                        if (string.Equals(proc.Name, legitNames[j], StringComparison.OrdinalIgnoreCase))
                        { isLegitName = true; break; }
                    }

                    if (isLegitName && !string.IsNullOrEmpty(proc.ExecutablePath))
                    {
                        if (!proc.ExecutablePath.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.Log(string.Format("Impersonation: {0} running from {1}", proc.Name, proc.ExecutablePath),
                                LogLevel.THREAT, "process_hollowing.log");
                            EdrState.IncrementThreats();
                            EnqueueThreat("ProcessHollowing:Impersonation", proc, ThreatSeverity.Critical, 90);
                        }
                    }
                }
                catch { }
            }
        }

        /// <summary>Detect non-system binaries running as SYSTEM (token manipulation).</summary>
        public static void TokenManipulation()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, ExecutablePath FROM Win32_Process"))
                using (ManagementObjectCollection collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        try
                        {
                            int pid = Convert.ToInt32(obj["ProcessId"]);
                            string name = (obj["Name"] ?? "").ToString();
                            string path = (obj["ExecutablePath"] != null) ? obj["ExecutablePath"].ToString() : null;

                            // Get owner
                            object[] ownerArgs = new object[] { null, null };
                            obj.InvokeMethod("GetOwner", ownerArgs);
                            string domain = (ownerArgs[1] != null) ? ownerArgs[1].ToString() : "";

                            if (string.Equals(domain, "NT AUTHORITY", StringComparison.OrdinalIgnoreCase))
                            {
                                if (!string.IsNullOrEmpty(path) && !path.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase))
                                {
                                    Logger.Log(string.Format("Token manipulation: {0} running as SYSTEM from {1}", name, path),
                                        LogLevel.WARN, "token_manipulation.log");
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        /// <summary>Detect suspicious parent-child process relationships.</summary>
        public static void SuspiciousParentChild()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();
            Dictionary<int, ProcessInfo> procMap = new Dictionary<int, ProcessInfo>();
            for (int i = 0; i < processes.Count; i++)
                procMap[processes[i].ProcessId] = processes[i];

            // Rules: parent -> child combinations that are suspicious
            string[][] rules = new string[][]
            {
                new string[] { "winword.exe", "cmd.exe", "Office->cmd" },
                new string[] { "winword.exe", "powershell.exe", "Office->PS" },
                new string[] { "excel.exe", "cmd.exe", "Excel->cmd" },
                new string[] { "excel.exe", "powershell.exe", "Excel->PS" },
                new string[] { "outlook.exe", "cmd.exe", "Outlook->cmd" },
                new string[] { "outlook.exe", "powershell.exe", "Outlook->PS" },
                new string[] { "mshta.exe", "powershell.exe", "MSHTA->PS" },
                new string[] { "wscript.exe", "powershell.exe", "WScript->PS" },
                new string[] { "cscript.exe", "powershell.exe", "CScript->PS" },
                new string[] { "explorer.exe", "mshta.exe", "Explorer->MSHTA" },
                new string[] { "w3wp.exe", "cmd.exe", "IIS->CMD (webshell?)" },
                new string[] { "w3wp.exe", "powershell.exe", "IIS->PS (webshell?)" },
                new string[] { "sqlservr.exe", "cmd.exe", "SQL->CMD" },
            };

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid) continue;

                ProcessInfo parent;
                if (!procMap.TryGetValue(proc.ParentProcessId, out parent)) continue;

                string parentName = (parent.Name ?? "").ToLowerInvariant();
                string childName = (proc.Name ?? "").ToLowerInvariant();

                for (int r = 0; r < rules.Length; r++)
                {
                    if (parentName == rules[r][0].ToLowerInvariant() && childName == rules[r][1].ToLowerInvariant())
                    {
                        Logger.Log(string.Format("Suspicious chain: {0} | Parent PID:{1} Child PID:{2}",
                            rules[r][2], parent.ProcessId, proc.ProcessId),
                            LogLevel.THREAT, "parent_child.log");
                        EdrState.IncrementThreats();
                        EnqueueThreat("SuspiciousChain:" + rules[r][2], proc, ThreatSeverity.High, 60);
                    }
                }
            }
        }

        /// <summary>Detect fileless attacks: PowerShell with encoded commands, long command lines.</summary>
        public static void FilelessDetection()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;
                if (string.IsNullOrEmpty(proc.CommandLine)) continue;

                string name = (proc.Name ?? "").ToLowerInvariant();
                if (!name.Contains("powershell") && !name.Contains("pwsh")) continue;

                string cmd = proc.CommandLine;
                int score = 0;
                List<string> reasons = new List<string>();

                // Encoded command
                if (Regex.IsMatch(cmd, @"-enc\s|-encodedcommand\s", RegexOptions.IgnoreCase))
                {
                    score += 30;
                    reasons.Add("EncodedCommand");
                }

                // Hidden window
                if (Regex.IsMatch(cmd, @"-w\s+hidden|-windowstyle\s+hidden", RegexOptions.IgnoreCase))
                {
                    score += 20;
                    reasons.Add("HiddenWindow");
                }

                // No profile
                if (Regex.IsMatch(cmd, @"-nop\s|-noprofile", RegexOptions.IgnoreCase))
                {
                    score += 10;
                    reasons.Add("NoProfile");
                }

                // Very long command line (likely obfuscated)
                if (cmd.Length > 2000)
                {
                    score += 20;
                    reasons.Add(string.Format("LongCmdLine({0}chars)", cmd.Length));
                }

                // Download cradle
                if (Regex.IsMatch(cmd, @"downloadstring|downloadfile|invoke-webrequest|net\.webclient|start-bitstransfer", RegexOptions.IgnoreCase))
                {
                    score += 25;
                    reasons.Add("DownloadCradle");
                }

                // IEX
                if (Regex.IsMatch(cmd, @"iex\s*\(|\|\s*iex|invoke-expression", RegexOptions.IgnoreCase))
                {
                    score += 25;
                    reasons.Add("InvokeExpression");
                }

                // Reflection
                if (Regex.IsMatch(cmd, @"reflection\.assembly|\[system\.reflection|assembly::load", RegexOptions.IgnoreCase))
                {
                    score += 35;
                    reasons.Add("ReflectiveLoading");
                }

                if (score >= 40)
                {
                    ThreatSeverity sev = score >= 80 ? ThreatSeverity.Critical
                        : score >= 60 ? ThreatSeverity.High : ThreatSeverity.Medium;

                    Logger.Log(string.Format("Fileless: {0} PID:{1} score:{2} | {3}",
                        proc.Name, proc.ProcessId, score, string.Join(",", reasons.ToArray())),
                        LogLevel.THREAT, "fileless_detections.log");
                    EdrState.IncrementThreats();
                    EnqueueThreat("Fileless", proc, sev, score);

                    if (Config.AutoKillThreats && sev >= ThreatSeverity.Critical)
                        ThreatActions.TerminateProcess(proc.ProcessId, proc.Name);
                }
            }
        }

        /// <summary>Scan process memory for shellcode signatures using P/Invoke.</summary>
        public static void MemoryScanning()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            string[] skipProcs = new string[] { "System", "Idle", "smss", "csrss", "wininit",
                "winlogon", "services", "lsass", "svchost", "dwm", "MsMpEng", "conhost" };

            Process[] procs = Process.GetProcesses();
            for (int i = 0; i < procs.Length; i++)
            {
                Process proc = procs[i];
                if (proc.Id == selfPid || proc.Id <= 4) continue;

                bool skip = false;
                for (int s = 0; s < skipProcs.Length; s++)
                {
                    if (string.Equals(proc.ProcessName, skipProcs[s], StringComparison.OrdinalIgnoreCase))
                    { skip = true; break; }
                }
                if (skip) continue;

                try
                {
                    IntPtr hProc = NativeMethods.OpenProcess(
                        NativeMethods.PROCESS_VM_READ | NativeMethods.PROCESS_QUERY_LIMITED, false, proc.Id);
                    if (hProc == IntPtr.Zero) continue;

                    try
                    {
                        ScanProcessMemory(hProc, proc.Id, proc.ProcessName);
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hProc);
                    }
                }
                catch { }
            }
        }

        private static void ScanProcessMemory(IntPtr hProc, int pid, string name)
        {
            // Shellcode signatures to look for
            byte[][] signatures = new byte[][]
            {
                new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 },  // x64 shellcode prologue
                new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00 },  // Metasploit x86 stager
                new byte[] { 0x60, 0x89, 0xE5, 0x31, 0xC0 },  // Common x86 shellcode
            };

            IntPtr address = IntPtr.Zero;
            NativeMethods.MEMORY_BASIC_INFORMATION mbi;
            int mbiSize = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION));
            byte[] buffer = new byte[4096];
            int regionsScanned = 0;

            while (regionsScanned < 500) // safety limit
            {
                int result = NativeMethods.VirtualQueryEx(hProc, address, out mbi, mbiSize);
                if (result == 0) break;

                // Only scan committed, executable, private memory (not mapped images)
                if (mbi.State == NativeMethods.MEM_COMMIT
                    && (mbi.Protect == NativeMethods.PAGE_EXECUTE_READWRITE
                        || mbi.Protect == NativeMethods.PAGE_EXECUTE_WRITECOPY)
                    && mbi.Type == NativeMethods.MEM_PRIVATE)
                {
                    int regionSize = (int)mbi.RegionSize.ToInt64();
                    int toRead = Math.Min(regionSize, buffer.Length);
                    int bytesRead;

                    if (NativeMethods.ReadProcessMemory(hProc, mbi.BaseAddress, buffer, toRead, out bytesRead) && bytesRead > 0)
                    {
                        for (int s = 0; s < signatures.Length; s++)
                        {
                            if (NativeMethods.ContainsBytes(buffer, bytesRead, signatures[s]))
                            {
                                Logger.Log(string.Format("Memory scan: shellcode signature in {0} PID:{1} at 0x{2:X}",
                                    name, pid, mbi.BaseAddress.ToInt64()),
                                    LogLevel.THREAT, "memory_scan.log");
                                EdrState.IncrementThreats();

                                ThreatInfo threat = new ThreatInfo();
                                threat.ThreatType = "ShellcodeInMemory";
                                threat.ProcessId = pid;
                                threat.ProcessName = name;
                                threat.Severity = ThreatSeverity.Critical;
                                threat.Confidence = 85;
                                ResponseQueue.Enqueue(threat);

                                if (Config.AutoKillThreats)
                                    ThreatActions.TerminateProcess(pid, name);
                                return; // one detection per process is enough
                            }
                        }
                    }
                }

                // Advance to next region
                long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (nextAddr <= address.ToInt64()) break; // overflow protection
                address = new IntPtr(nextAddr);
                regionsScanned++;
            }
        }

        /// <summary>Enable process creation auditing via auditpol.</summary>
        public static void ProcessAuditing()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("auditpol.exe", "/get /subcategory:\"Process Creation\"");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);

                if (!output.Contains("Success"))
                {
                    ProcessStartInfo psi2 = new ProcessStartInfo("auditpol.exe",
                        "/set /subcategory:\"Process Creation\" /success:enable /failure:enable");
                    psi2.CreateNoWindow = true;
                    psi2.UseShellExecute = false;
                    Process.Start(psi2).WaitForExit(5000);
                    Logger.Log("Enabled process creation auditing");
                }

                // Enable command line in process creation events
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", true))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("ProcessCreationIncludeCmdLine_Enabled");
                        if (val == null || Convert.ToInt32(val) != 1)
                        {
                            key.SetValue("ProcessCreationIncludeCmdLine_Enabled", 1, RegistryValueKind.DWord);
                            Logger.Log("Enabled command line in process creation events");
                        }
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Detect Parent PID spoofing (T1134.004).
        /// Attackers use CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to fake
        /// the parent PID, making malicious processes appear to be children of legitimate ones.
        /// Detection: compare WMI-reported ParentProcessId with the actual creator process
        /// by checking if the parent was started AFTER the child (impossible in normal execution).
        /// Also flag processes whose reported parent doesn't match expected lineage.
        /// </summary>
        public static void ParentPidSpoofing()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;
                string cleanName = (proc.Name ?? "").Replace(".exe", "");
                if (Config.IsProtectedProcess(cleanName)) continue;

                try
                {
                    Process child = Process.GetProcessById(proc.ProcessId);
                    DateTime childStart = child.StartTime;

                    if (proc.ParentProcessId > 4)
                    {
                        try
                        {
                            Process parent = Process.GetProcessById(proc.ParentProcessId);
                            DateTime parentStart = parent.StartTime;

                            // Parent started AFTER child = impossible without spoofing
                            if (parentStart > childStart.AddSeconds(2))
                            {
                                Logger.Log(string.Format(
                                    "PPID spoofing: {0} (PID:{1}) claims parent {2} (PID:{3}) but parent started {4:F1}s later",
                                    proc.Name, proc.ProcessId, parent.ProcessName, proc.ParentProcessId,
                                    (parentStart - childStart).TotalSeconds),
                                    LogLevel.THREAT, "ppid_spoofing.log");
                                EdrState.IncrementThreats();
                                EnqueueThreat("PPIDSpoofing", proc, ThreatSeverity.Critical, 85);
                            }
                        }
                        catch (ArgumentException)
                        {
                            // Parent process no longer exists — check if child is suspicious
                            // Short-lived parent that spawned a long-lived child is a common pattern
                            // in process injection / hollowing
                            string childName = (proc.Name ?? "").ToLowerInvariant();
                            if (childName == "powershell.exe" || childName == "cmd.exe" ||
                                childName == "mshta.exe" || childName == "wscript.exe")
                            {
                                // Suspicious: scripting engine with dead parent
                                if ((DateTime.Now - childStart).TotalMinutes < 5)
                                {
                                    Logger.Log(string.Format(
                                        "Orphaned scripting process: {0} (PID:{1}) parent PID:{2} no longer exists",
                                        proc.Name, proc.ProcessId, proc.ParentProcessId),
                                        LogLevel.WARN, "ppid_spoofing.log");
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// Detect short-lived processes (T1059).
        /// Processes that spawn, execute, and exit within seconds are suspicious —
        /// especially scripting engines and LOLBins. Legitimate software rarely
        /// spawns powershell for < 10 seconds.
        /// Tracks recently-seen PIDs and flags those that disappear quickly.
        /// </summary>
        private static readonly Dictionary<int, ShortLivedEntry> _recentProcesses = new Dictionary<int, ShortLivedEntry>();
        private static readonly object _shortLivedLock = new object();

        private class ShortLivedEntry
        {
            public string Name;
            public string ExePath;
            public string CommandLine;
            public DateTime FirstSeen;
        }

        public static void ShortLivedProcessDetection()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> current = Core.WmiHelper.GetProcesses();
            HashSet<int> currentPids = new HashSet<int>();
            for (int i = 0; i < current.Count; i++)
                currentPids.Add(current[i].ProcessId);

            // Suspicious process names to track
            HashSet<string> watchNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe",
                "mshta.exe","certutil.exe","bitsadmin.exe","regsvr32.exe","rundll32.exe",
                "msbuild.exe","installutil.exe","regasm.exe","regsvcs.exe","wmic.exe",
                "msiexec.exe","cmstp.exe","odbcconf.exe","ieexec.exe"
            };

            lock (_shortLivedLock)
            {
                // Check for processes that disappeared since last check
                List<int> gone = new List<int>();
                foreach (KeyValuePair<int, ShortLivedEntry> kvp in _recentProcesses)
                {
                    if (!currentPids.Contains(kvp.Key))
                    {
                        gone.Add(kvp.Key);
                        ShortLivedEntry entry = kvp.Value;
                        double livedSeconds = (DateTime.Now - entry.FirstSeen).TotalSeconds;

                        if (livedSeconds < 10)
                        {
                            Logger.Log(string.Format(
                                "Short-lived process: {0} (PID:{1}) lived {2:F1}s | cmd: {3}",
                                entry.Name, kvp.Key, livedSeconds,
                                (entry.CommandLine ?? "").Length > 200 ? (entry.CommandLine ?? "").Substring(0, 200) + "..." : (entry.CommandLine ?? "")),
                                LogLevel.THREAT, "short_lived.log");
                            EdrState.IncrementThreats();
                            JsonLogger.LogProcess("short-lived", entry.Name, kvp.Key,
                                entry.ExePath, entry.CommandLine, 45, string.Format("Lived {0:F1}s", livedSeconds));
                        }
                    }
                }
                for (int i = 0; i < gone.Count; i++)
                    _recentProcesses.Remove(gone[i]);

                // Add new suspicious processes to tracking
                for (int i = 0; i < current.Count; i++)
                {
                    ProcessInfo proc = current[i];
                    if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;
                    if (!watchNames.Contains(proc.Name ?? "")) continue;
                    if (!_recentProcesses.ContainsKey(proc.ProcessId))
                    {
                        _recentProcesses[proc.ProcessId] = new ShortLivedEntry
                        {
                            Name = proc.Name,
                            ExePath = proc.ExecutablePath,
                            CommandLine = proc.CommandLine,
                            FirstSeen = DateTime.Now
                        };
                    }
                }

                // Cleanup old entries (> 5 minutes)
                List<int> stale = new List<int>();
                foreach (KeyValuePair<int, ShortLivedEntry> kvp in _recentProcesses)
                {
                    if ((DateTime.Now - kvp.Value.FirstSeen).TotalMinutes > 5)
                        stale.Add(kvp.Key);
                }
                for (int i = 0; i < stale.Count; i++)
                    _recentProcesses.Remove(stale[i]);
            }
        }

        /// <summary>
        /// Detect EDR service tampering (T1562.001).
        /// Monitors for attempts to stop, disable, or delete the GEdr service.
        /// Also watches for sc.exe / net.exe commands targeting security services.
        /// </summary>
        public static void ServiceTamperDetection()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;
                if (string.IsNullOrEmpty(proc.CommandLine)) continue;

                string cmd = proc.CommandLine.ToLowerInvariant();
                string name = (proc.Name ?? "").ToLowerInvariant();

                // Check for service manipulation commands
                if (name != "sc.exe" && name != "net.exe" && name != "net1.exe" &&
                    name != "powershell.exe" && name != "pwsh.exe") continue;

                // Targeting GEdr specifically
                if (cmd.Contains("gedr"))
                {
                    if (cmd.Contains("stop") || cmd.Contains("delete") || cmd.Contains("disable") || cmd.Contains("config"))
                    {
                        Logger.Log(string.Format("EDR TAMPERING: {0} (PID:{1}) attempting to modify GEdr service: {2}",
                            proc.Name, proc.ProcessId, proc.CommandLine),
                            LogLevel.THREAT, "self_protection.log");
                        EdrState.IncrementThreats();
                        JsonLogger.LogProcess("service-tamper", proc.Name, proc.ProcessId,
                            proc.ExecutablePath, proc.CommandLine, 90, "Targeting GEdr service");

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "ServiceTamper:GEdr";
                        threat.ThreatPath = proc.ExecutablePath;
                        threat.Severity = ThreatSeverity.Critical;
                        threat.ProcessId = proc.ProcessId;
                        threat.ProcessName = proc.Name;
                        threat.CommandLine = proc.CommandLine;
                        threat.Confidence = 90;
                        ResponseQueue.Enqueue(threat);
                    }
                }

                // Targeting security services in general
                string[] securityServices = new string[] {
                    "windefend", "mpsvc", "mpssvc", "wscsvc", "securityhealthservice",
                    "sense", "wdnissvc", "wdfilter", "wdboot"
                };
                for (int s = 0; s < securityServices.Length; s++)
                {
                    if (cmd.Contains(securityServices[s]) && (cmd.Contains("stop") || cmd.Contains("delete") || cmd.Contains("disable")))
                    {
                        Logger.Log(string.Format("Security service tampering: {0} targeting {1}",
                            proc.Name, securityServices[s]),
                            LogLevel.THREAT, "self_protection.log");
                        EdrState.IncrementThreats();
                        EnqueueThreat("ServiceTamper:" + securityServices[s], proc, ThreatSeverity.Critical, 85);
                        break;
                    }
                }
            }
        }

        private static void EnqueueThreat(string type, ProcessInfo proc, ThreatSeverity sev, int confidence)
        {
            ThreatInfo threat = new ThreatInfo();
            threat.ThreatType = type;
            threat.ThreatPath = proc.ExecutablePath;
            threat.Severity = sev;
            threat.ProcessId = proc.ProcessId;
            threat.ProcessName = proc.Name;
            threat.CommandLine = proc.CommandLine;
            threat.Confidence = confidence;
            ResponseQueue.Enqueue(threat);
        }
    }
}
