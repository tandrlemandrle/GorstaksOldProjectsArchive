using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Threading;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Monitors
{
    /// <summary>
    /// ETW-based process creation monitoring via Windows Event Log.
    /// 
    /// Uses Security Event ID 4688 (Process Creation) which provides:
    /// - Zero-delay process creation events (no polling gap)
    /// - Full command line (when audit policy is enabled)
    /// - Creator process ID (for PPID spoofing detection)
    /// - Token elevation type
    /// 
    /// This supplements the WMI-based ProcessMonitor with gap-free coverage.
    /// Requires "Audit Process Creation" policy to be enabled.
    /// 
    /// Also monitors Event ID 4689 (Process Termination) for short-lived
    /// process detection.
    /// </summary>
    public static class EtwMonitor
    {
        private static EventLogWatcher _processCreateWatcher;
        private static EventLogWatcher _processExitWatcher;
        private static bool _available;
        private static int _selfPid;

        public static bool IsAvailable { get { return _available; } }

        public static void Initialize()
        {
            _selfPid = Process.GetCurrentProcess().Id;

            // Enable command line in process creation auditing
            EnableProcessAuditing();

            // Subscribe to Security Event 4688 (Process Creation)
            try
            {
                EventLogQuery createQuery = new EventLogQuery(
                    "Security", PathType.LogName,
                    "*[System[EventID=4688]]");
                _processCreateWatcher = new EventLogWatcher(createQuery);
                _processCreateWatcher.EventRecordWritten += OnProcessCreated;
                _processCreateWatcher.Enabled = true;
                _available = true;
                Logger.Log("EtwMonitor: Security Event 4688 subscription active (zero-gap process creation)");
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("EtwMonitor: Failed to subscribe to 4688 events ({0}). " +
                    "Enable 'Audit Process Creation' in Local Security Policy.", ex.Message), LogLevel.WARN);
            }

            // Subscribe to Security Event 4689 (Process Exit) for short-lived detection
            try
            {
                EventLogQuery exitQuery = new EventLogQuery(
                    "Security", PathType.LogName,
                    "*[System[EventID=4689]]");
                _processExitWatcher = new EventLogWatcher(exitQuery);
                _processExitWatcher.EventRecordWritten += OnProcessExited;
                _processExitWatcher.Enabled = true;
                Logger.Log("EtwMonitor: Security Event 4689 subscription active (process exit tracking)");
            }
            catch { }
        }

        public static void Shutdown()
        {
            try
            {
                if (_processCreateWatcher != null)
                {
                    _processCreateWatcher.Enabled = false;
                    _processCreateWatcher.Dispose();
                }
                if (_processExitWatcher != null)
                {
                    _processExitWatcher.Enabled = false;
                    _processExitWatcher.Dispose();
                }
            }
            catch { }
        }

        private static DateTime _lastEventReceived = DateTime.MinValue;
        private static volatile int _eventCount;

        /// <summary>
        /// ETW integrity check. Verifies events are still flowing.
        /// If no events received in 5 minutes, ETW may have been patched
        /// (ntdll!EtwEventWrite tampered). Alerts and falls back to polling.
        /// Called periodically by the job scheduler.
        /// </summary>
        public static void IntegrityCheck()
        {
            if (!_available) return;

            // After initial startup grace period (2 minutes), check for event flow
            if ((DateTime.Now - Process.GetCurrentProcess().StartTime).TotalMinutes < 2) return;

            if (_eventCount == 0 && (DateTime.Now - _lastEventReceived).TotalMinutes > 5)
            {
                // No events in 5 minutes — suspicious on an active system
                Logger.Log("ETW INTEGRITY WARNING: No process creation events received in 5 minutes. " +
                    "Possible EtwEventWrite patch detected.", LogLevel.THREAT, "etw_monitor.log");
                GidrState.IncrementThreats();
                JsonLogger.LogEvent("THREAT", "etw-integrity",
                    "No ETW events received in 5 minutes - possible ntdll!EtwEventWrite patch");

                // Also check ntdll!EtwEventWrite prologue
                VerifyEtwIntegrity();
            }

            // Reset counter for next check interval
            _eventCount = 0;
        }

        /// <summary>
        /// Check if ntdll!EtwEventWrite has been patched.
        /// Common bypass: patch first bytes to "ret" (0xC3) so no events are emitted.
        /// </summary>
        private static void VerifyEtwIntegrity()
        {
            try
            {
                IntPtr hNtdll = GetModuleHandleA("ntdll.dll");
                if (hNtdll == IntPtr.Zero) return;
                IntPtr etwAddr = GetProcAddress(hNtdll, "EtwEventWrite");
                if (etwAddr == IntPtr.Zero) return;

                byte[] prologue = new byte[4];
                System.Runtime.InteropServices.Marshal.Copy(etwAddr, prologue, 0, 4);

                // Normal prologue starts with: 4C 8B DC (mov r11, rsp) on x64
                // or various push/mov patterns. A "ret" (0xC3) as first byte = patched.
                if (prologue[0] == 0xC3)
                {
                    Logger.Log("ETW TAMPERED: ntdll!EtwEventWrite patched with RET instruction!",
                        LogLevel.THREAT, "etw_monitor.log");
                    GidrState.IncrementThreats();
                    JsonLogger.LogThreat("ETW-Tamper", "ntdll.dll!EtwEventWrite", null,
                        95, "CRITICAL", "Critical", "T1562.001", "EtwEventWrite patched to RET");
                }
                // Also check for "mov eax, 0; ret" pattern (xor eax,eax; ret = 33 C0 C3)
                else if (prologue[0] == 0x33 && prologue[1] == 0xC0 && prologue[2] == 0xC3)
                {
                    Logger.Log("ETW TAMPERED: ntdll!EtwEventWrite patched with xor eax,eax; ret!",
                        LogLevel.THREAT, "etw_monitor.log");
                    GidrState.IncrementThreats();
                    JsonLogger.LogThreat("ETW-Tamper", "ntdll.dll!EtwEventWrite", null,
                        95, "CRITICAL", "Critical", "T1562.001", "EtwEventWrite patched to return 0");
                }
            }
            catch { }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        private static extern IntPtr GetModuleHandleA(string moduleName);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        private static void OnProcessCreated(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            _lastEventReceived = DateTime.Now;
            _eventCount++;
            try
            {
                // Event 4688 properties:
                // [0] SubjectUserSid, [1] SubjectUserName, [2] SubjectDomainName,
                // [3] SubjectLogonId, [4] NewProcessId, [5] NewProcessName,
                // [6] TokenElevationType, [7] ProcessId (parent), [8] CommandLine,
                // [9] TargetUserSid, [10] TargetUserName, [11] TargetDomainName,
                // [12] TargetLogonId, [13] ParentProcessName, [14] MandatoryLabel

                EventRecord rec = e.EventRecord;
                string newProcessName = GetProperty(rec, 5);
                string commandLine = GetProperty(rec, 8);
                string parentProcessName = GetProperty(rec, 13);
                string newPidHex = GetProperty(rec, 4);
                string parentPidHex = GetProperty(rec, 7);
                string tokenType = GetProperty(rec, 6);

                int newPid = 0;
                if (!string.IsNullOrEmpty(newPidHex))
                {
                    newPidHex = newPidHex.Replace("0x", "");
                    int.TryParse(newPidHex, System.Globalization.NumberStyles.HexNumber, null, out newPid);
                }

                if (newPid == _selfPid || newPid <= 4) return;

                string processName = Path.GetFileName(newProcessName ?? "");
                if (Config.IsProtectedProcess(processName)) return;

                // Log to JSON for SIEM
                JsonLogger.LogProcess("etw-create", processName, newPid,
                    newProcessName, commandLine, 0, string.Format("parent={0} token={1}", parentProcessName, tokenType));

                // Check for suspicious patterns in the command line
                if (!string.IsNullOrEmpty(commandLine) && commandLine.Length > 10)
                {
                    string cmdLower = commandLine.ToLowerInvariant();

                    // Quick high-confidence checks (don't need full scan pipeline)
                    int score = 0;
                    string reason = null;

                    // Encoded PowerShell
                    if (cmdLower.Contains("powershell") && (cmdLower.Contains("-enc ") || cmdLower.Contains("-encodedcommand")))
                    {
                        score = 40;
                        reason = "Encoded PowerShell via ETW";
                    }
                    // Download cradle
                    else if (cmdLower.Contains("downloadstring") || cmdLower.Contains("invoke-webrequest"))
                    {
                        score = 45;
                        reason = "Download cradle via ETW";
                    }
                    // Shadow copy deletion
                    else if (cmdLower.Contains("vssadmin") && cmdLower.Contains("delete"))
                    {
                        score = 80;
                        reason = "Shadow copy deletion via ETW";
                    }
                    // Defender tampering
                    else if (cmdLower.Contains("set-mppreference") && cmdLower.Contains("disable"))
                    {
                        score = 70;
                        reason = "Defender tampering via ETW";
                    }
                    // Event log clearing
                    else if (cmdLower.Contains("wevtutil") && cmdLower.Contains(" cl "))
                    {
                        score = 75;
                        reason = "Event log clearing via ETW";
                    }

                    if (score >= 40)
                    {
                        ThreatSeverity sev = score >= 70 ? ThreatSeverity.Critical
                            : score >= 50 ? ThreatSeverity.High : ThreatSeverity.Medium;

                        Logger.Log(string.Format("ETW threat: {0} (PID:{1}) score:{2} | {3}",
                            processName, newPid, score, reason), LogLevel.THREAT, "etw_monitor.log");
                        GidrState.IncrementThreats();
                        JsonLogger.LogProcess("etw-threat", processName, newPid,
                            newProcessName, commandLine, score, reason);

                        // Let ResponseEngine handle the response — ETW command-line
                        // detections are behavioral, so they WILL be acted on.
                        ThreatInfo etwThreat = new ThreatInfo();
                        etwThreat.ThreatType = "etw-threat";
                        etwThreat.ThreatPath = newProcessName;
                        etwThreat.Severity = sev;
                        etwThreat.ProcessId = newPid;
                        etwThreat.ProcessName = processName;
                        etwThreat.CommandLine = commandLine;
                        etwThreat.Confidence = score;
                        ResponseQueue.Enqueue(etwThreat);
                    }
                }
            }
            catch { }
        }

        private static void OnProcessExited(object sender, EventRecordWrittenEventArgs e)
        {
            // Track process exits for short-lived process correlation
            // This fires immediately when a process exits, unlike polling
            if (e.EventRecord == null) return;
            try
            {
                EventRecord rec = e.EventRecord;
                string processName = GetProperty(rec, 5);
                string pidHex = GetProperty(rec, 4);

                if (!string.IsNullOrEmpty(processName))
                {
                    string name = Path.GetFileName(processName).ToLowerInvariant();
                    // Log exit of interesting processes for correlation
                    if (name.Contains("powershell") || name.Contains("cmd") ||
                        name.Contains("mshta") || name.Contains("wscript") ||
                        name.Contains("certutil") || name.Contains("bitsadmin"))
                    {
                        JsonLogger.LogEvent("INFO", "process-exit",
                            string.Format("name={0} pid={1}", name, pidHex));
                    }
                }
            }
            catch { }
        }

        /// <summary>Enable process creation auditing and command line logging.</summary>
        private static void EnableProcessAuditing()
        {
            try
            {
                // Enable command line in process creation events
                Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", true);
                if (key == null)
                {
                    key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit");
                }
                if (key != null)
                {
                    key.SetValue("ProcessCreationIncludeCmdLine_Enabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    key.Close();
                }
            }
            catch { }

            // Enable audit process creation via auditpol
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("auditpol.exe",
                    "/set /subcategory:\"Process Creation\" /success:enable /failure:enable");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                Process p = Process.Start(psi);
                p.WaitForExit(5000);
            }
            catch { }
        }

        private static string GetProperty(EventRecord rec, int index)
        {
            try
            {
                if (rec.Properties != null && rec.Properties.Count > index)
                {
                    object val = rec.Properties[index].Value;
                    return val != null ? val.ToString() : null;
                }
            }
            catch { }
            return null;
        }
    }
}
