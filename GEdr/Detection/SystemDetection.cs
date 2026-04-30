using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using GEdr.Core;
using GEdr.Response;
using Microsoft.Win32;

namespace GEdr.Detection
{
    /// <summary>
    /// Rootkit detection, driver watcher, BCD security, service monitoring,
    /// firewall rule monitoring, event log monitoring, USB monitoring,
    /// clipboard monitoring, shadow copy monitoring, DNS exfiltration,
    /// local proxy detection, script host detection, script content scan,
    /// HID macro guard, credential protection, security policy hardening,
    /// CVE mitigation, ASR rules, C2 block list, MITRE mapping,
    /// honeypot monitoring, memory acquisition detection, script block logging,
    /// crude payload guard, shadow proxy capture detection, NeuroBehavior monitor.
    /// </summary>
    public static class SystemDetection
    {
        private static readonly string[] _allowedDriverVendors = new string[] {
            "Microsoft","Realtek","Dolby","Intel","Advanced Micro Devices","AMD","NVIDIA","MediaTek"
        };

        public static void RootkitDetection()
        {
            // Check for unsigned/suspicious drivers
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT Name, ProviderName, OriginalFileName FROM Win32_SystemDriver"))
                using (ManagementObjectCollection c = s.Get())
                {
                    foreach (ManagementObject obj in c)
                    {
                        string provider = (obj["ProviderName"] ?? "").ToString();
                        string driverName = (obj["Name"] ?? "").ToString();
                        string path = (obj["OriginalFileName"] != null) ? obj["OriginalFileName"].ToString() : null;

                        bool isAllowed = false;
                        for (int i = 0; i < _allowedDriverVendors.Length; i++)
                        {
                            if (provider.IndexOf(_allowedDriverVendors[i], StringComparison.OrdinalIgnoreCase) >= 0)
                            { isAllowed = true; break; }
                        }

                        if (!isAllowed && !string.IsNullOrEmpty(path) && File.Exists(path))
                        {
                            if (!ThreatActions.IsFileSigned(path))
                            {
                                Logger.Log(string.Format("Rootkit: unsigned driver {0} by {1}", driverName, provider),
                                    LogLevel.THREAT, "rootkit_detections.log");
                                EdrState.IncrementThreats();
                            }
                        }
                    }
                }
            }
            catch { }

            // Hidden process detection: compare Process list vs performance counters
            try
            {
                HashSet<int> procList = new HashSet<int>();
                Process[] procs = Process.GetProcesses();
                for (int i = 0; i < procs.Length; i++) procList.Add(procs[i].Id);

                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process"))
                using (ManagementObjectCollection c = s.Get())
                {
                    foreach (ManagementObject obj in c)
                    {
                        int pid = Convert.ToInt32(obj["ProcessId"]);
                        if (pid > 4 && !procList.Contains(pid))
                        {
                            Logger.Log(string.Format("Rootkit: hidden process PID:{0} (in WMI but not Process list)", pid),
                                LogLevel.THREAT, "rootkit_detections.log");
                            EdrState.IncrementThreats();
                        }
                    }
                }
            }
            catch { }
        }

        public static void DriverWatcher()
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT DeviceName, DriverProviderName FROM Win32_PnPSignedDriver"))
                using (ManagementObjectCollection c = s.Get())
                {
                    foreach (ManagementObject obj in c)
                    {
                        string vendor = (obj["DriverProviderName"] ?? "").ToString();
                        if (string.IsNullOrEmpty(vendor)) continue;
                        bool allowed = false;
                        for (int i = 0; i < _allowedDriverVendors.Length; i++)
                        {
                            if (vendor.IndexOf(_allowedDriverVendors[i], StringComparison.OrdinalIgnoreCase) >= 0)
                            { allowed = true; break; }
                        }
                        if (!allowed)
                        {
                            Logger.Log(string.Format("DriverWatcher: non-whitelisted driver {0} by {1}",
                                obj["DeviceName"], vendor), LogLevel.WARN, "driver_watcher.log");
                        }
                    }
                }
            }
            catch { }

            // BYOVD: Check ALL loaded kernel modules (not just System32\drivers)
            // Attackers load vulnerable drivers from temp dirs, user folders, etc.
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT Name, PathName, DisplayName, State FROM Win32_SystemDriver WHERE State='Running'"))
                using (ManagementObjectCollection c = s.Get())
                {
                    foreach (ManagementObject obj in c)
                    {
                        string driverPath = (obj["PathName"] ?? "").ToString();
                        string driverName = (obj["Name"] ?? "").ToString();

                        if (string.IsNullOrEmpty(driverPath)) continue;

                        // Normalize path (WMI sometimes returns \??\C:\... format)
                        driverPath = driverPath.Replace(@"\??\", "").Replace(@"\\?\", "");
                        if (driverPath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                            driverPath = driverPath.Replace(@"\SystemRoot\", Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\");

                        string fileName = Path.GetFileName(driverPath).ToLowerInvariant();

                        // Check against known vulnerable driver names
                        for (int v = 0; v < _vulnerableDrivers.Length; v++)
                        {
                            if (fileName == _vulnerableDrivers[v])
                            {
                                Logger.Log(string.Format("BYOVD: Vulnerable driver LOADED: {0} from {1}",
                                    fileName, driverPath), LogLevel.THREAT, "driver_watcher.log");
                                EdrState.IncrementThreats();
                                JsonLogger.LogThreat("BYOVD", driverPath, null, 90, "CRITICAL", "Critical", "T1068",
                                    string.Format("Loaded vulnerable driver: {0}", fileName));
                            }
                        }

                        // Flag drivers loaded from non-standard paths
                        if (!string.IsNullOrEmpty(driverPath) && File.Exists(driverPath))
                        {
                            string dirLower = Path.GetDirectoryName(driverPath).ToLowerInvariant();
                            bool standardPath = dirLower.Contains(@"\windows\system32") ||
                                                dirLower.Contains(@"\windows\syswow64") ||
                                                dirLower.Contains(@"\program files");
                            if (!standardPath)
                            {
                                Logger.Log(string.Format("DriverWatcher: Driver loaded from non-standard path: {0} ({1})",
                                    driverName, driverPath), LogLevel.THREAT, "driver_watcher.log");
                                EdrState.IncrementThreats();
                                JsonLogger.LogThreat("SuspiciousDriver", driverPath, null, 70, "HIGH", "High", "T1068",
                                    "Driver loaded from non-standard path");
                            }
                        }
                    }
                }
            }
            catch { }
        }

        // Known vulnerable drivers used in BYOVD attacks
        private static readonly string[] _vulnerableDrivers = new string[]
        {
            "capcom.sys",           // Capcom driver - arbitrary kernel code execution
            "dbutil_2_3.sys",       // Dell BIOS utility - CVE-2021-21551
            "rtcore64.sys",         // MSI Afterburner - arbitrary R/W
            "gdrv.sys",             // GIGABYTE driver - arbitrary R/W
            "aswarpot.sys",         // Avast anti-rootkit - process termination
            "kprocesshacker.sys",   // Process Hacker - process manipulation
            "procexp152.sys",       // Process Explorer (old) - process manipulation
            "iqvw64e.sys",          // Intel Network Adapter - arbitrary R/W
            "asio64.sys",           // ASUS driver - arbitrary R/W
            "mhyprot2.sys",        // Genshin Impact anti-cheat - process termination
            "zemana.sys",           // Zemana anti-malware - process termination
            "ene.sys",              // ENE Technology - arbitrary R/W
            "winio64.sys",          // WinIO - direct port/memory access
        };

        public static void BCDSecurity()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("bcdedit.exe", "/enum");
                psi.CreateNoWindow = true; psi.UseShellExecute = false; psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);
                if (string.IsNullOrEmpty(output)) return;

                string[][] checks = new string[][] {
                    new string[] { "testsigning", "Yes", "Test signing enabled" },
                    new string[] { "nointegritychecks", "Yes", "Integrity checks disabled" },
                    new string[] { "nx", "OptOut", "DEP disabled" },
                };
                for (int i = 0; i < checks.Length; i++)
                {
                    if (output.IndexOf(checks[i][0], StringComparison.OrdinalIgnoreCase) >= 0
                        && output.IndexOf(checks[i][1], StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Logger.Log("BCD: " + checks[i][2], LogLevel.THREAT, "bcd_security.log");
                        EdrState.IncrementThreats();
                    }
                }
            }
            catch { }
        }

        public static void ServiceMonitoring()
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT Name, PathName, StartMode, State FROM Win32_Service"))
                using (ManagementObjectCollection c = s.Get())
                {
                    foreach (ManagementObject obj in c)
                    {
                        string path = (obj["PathName"] != null) ? obj["PathName"].ToString() : "";
                        if (string.IsNullOrEmpty(path)) continue;
                        if (path.StartsWith("C:\\Windows", StringComparison.OrdinalIgnoreCase)) continue;
                        if (path.StartsWith("\"C:\\Windows", StringComparison.OrdinalIgnoreCase)) continue;
                        if (path.StartsWith("C:\\Program Files", StringComparison.OrdinalIgnoreCase)) continue;
                        if (path.StartsWith("\"C:\\Program Files", StringComparison.OrdinalIgnoreCase)) continue;

                        string state = (obj["State"] ?? "").ToString();
                        if (state == "Running")
                        {
                            Logger.Log(string.Format("Service: {0} running from non-standard path: {1}",
                                obj["Name"], path), LogLevel.WARN, "service_monitoring.log");
                        }
                    }
                }
            }
            catch { }
        }

        public static void EventLogMonitoring()
        {
            try
            {
                // Check for recent security event log clearing (Event ID 1102)
                ProcessStartInfo psi = new ProcessStartInfo("wevtutil.exe",
                    "qe Security /q:\"*[System[(EventID=1102)]]\" /c:5 /rd:true /f:text");
                psi.CreateNoWindow = true; psi.UseShellExecute = false; psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);

                if (!string.IsNullOrEmpty(output) && output.Contains("1102"))
                {
                    Logger.Log("EventLog: Security log was recently cleared!", LogLevel.THREAT, "eventlog_monitoring.log");
                    EdrState.IncrementThreats();
                }
            }
            catch { }
        }

        public static void FirewallRuleMonitoring()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh.exe", "advfirewall firewall show rule name=all dir=in");
                psi.CreateNoWindow = true; psi.UseShellExecute = false; psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(15000);

                // Check for rules allowing all traffic
                if (output.IndexOf("Action:                  Allow", StringComparison.OrdinalIgnoreCase) >= 0
                    && output.IndexOf("RemoteIP:                Any", StringComparison.OrdinalIgnoreCase) >= 0
                    && output.IndexOf("LocalPort:               Any", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Logger.Log("Firewall: found rule allowing all inbound traffic", LogLevel.WARN, "firewall_monitoring.log");
                }
            }
            catch { }
        }

        public static void USBMonitoring()
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT DeviceID, Description, PNPDeviceID FROM Win32_USBControllerDevice"))
                using (ManagementObjectCollection c = s.Get())
                {
                    foreach (ManagementObject obj in c)
                    {
                        string dependent = (obj["Dependent"] ?? "").ToString();
                        if (dependent.IndexOf("USB\\VID_", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            // Log new USB devices (in production, compare against baseline)
                            Logger.Log(string.Format("USB device: {0}", dependent), LogLevel.DEBUG, "usb_monitoring.log");
                        }
                    }
                }
            }
            catch { }
        }

        public static void ShadowCopyMonitoring()
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT * FROM Win32_ShadowCopy"))
                using (ManagementObjectCollection c = s.Get())
                {
                    if (c.Count == 0)
                    {
                        Logger.Log("Shadow copies: NONE exist (potential ransomware indicator)", LogLevel.WARN, "shadow_copy.log");
                    }
                }
            }
            catch { }
        }

        public static void ClipboardMonitoring()
        {
            // Check if clipboard contains suspicious content (URLs to raw IPs, encoded commands)
            try
            {
                if (System.Windows.Forms.Clipboard.ContainsText())
                {
                    string text = System.Windows.Forms.Clipboard.GetText();
                    if (!string.IsNullOrEmpty(text) && text.Length > 50)
                    {
                        if (System.Text.RegularExpressions.Regex.IsMatch(text,
                            @"powershell.*-enc|cmd.*/c.*powershell|invoke-expression|downloadstring",
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                        {
                            Logger.Log("Clipboard: contains suspicious command", LogLevel.WARN, "clipboard_monitoring.log");
                        }
                    }
                }
            }
            catch { }
        }

        public static void DNSExfiltrationDetection()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("ipconfig.exe", "/displaydns");
                psi.CreateNoWindow = true; psi.UseShellExecute = false; psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);
                if (string.IsNullOrEmpty(output)) return;

                string[] lines = output.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    if (!line.StartsWith("Record Name", StringComparison.OrdinalIgnoreCase)) continue;

                    int colonIdx = line.IndexOf(':');
                    if (colonIdx < 0) continue;
                    string domain = line.Substring(colonIdx + 1).Trim();

                    // Long subdomains = potential DNS tunneling
                    if (domain.Length > 60)
                    {
                        Logger.Log(string.Format("DNS exfil: unusually long domain ({0} chars): {1}",
                            domain.Length, domain.Substring(0, Math.Min(domain.Length, 80))),
                            LogLevel.WARN, "dns_exfiltration.log");
                    }

                    // Hash-like subdomains
                    if (System.Text.RegularExpressions.Regex.IsMatch(domain, @"[0-9a-f]{32,}"))
                    {
                        Logger.Log(string.Format("DNS exfil: hash-like subdomain: {0}",
                            domain.Substring(0, Math.Min(domain.Length, 80))),
                            LogLevel.THREAT, "dns_exfiltration.log");
                        EdrState.IncrementThreats();
                    }
                }
            }
            catch { }
        }

        public static void LocalProxyDetection()
        {
            string[] vars = new string[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy" };
            for (int i = 0; i < vars.Length; i++)
            {
                string val = Environment.GetEnvironmentVariable(vars[i]);
                if (!string.IsNullOrEmpty(val) && (val.Contains("127.0.0.1") || val.Contains("localhost")))
                {
                    Logger.Log(string.Format("Local proxy: {0}={1}", vars[i], val), LogLevel.WARN, "local_proxy.log");
                }
            }

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", false))
                {
                    if (key != null)
                    {
                        object proxy = key.GetValue("ProxyServer");
                        if (proxy != null && proxy.ToString().Contains("127.0.0.1"))
                        {
                            Logger.Log("Local proxy: system proxy points to localhost", LogLevel.THREAT, "local_proxy.log");
                            EdrState.IncrementThreats();
                        }
                    }
                }
            }
            catch { }
        }

        public static void ScriptHostDetection()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            string[] scriptHosts = new string[] { "mshta", "wscript", "cscript", "scriptrunner" };
            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid) continue;
                string name = (proc.Name ?? "").ToLowerInvariant().Replace(".exe", "");
                bool isScriptHost = false;
                for (int s = 0; s < scriptHosts.Length; s++)
                {
                    if (name == scriptHosts[s]) { isScriptHost = true; break; }
                }
                if (!isScriptHost) continue;
                if (string.IsNullOrEmpty(proc.CommandLine)) continue;

                if (System.Text.RegularExpressions.Regex.IsMatch(proc.CommandLine,
                    @"https?://|javascript:|vbscript:|-encodedcommand|eval\s*\(",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                {
                    Logger.Log(string.Format("Script host abuse: {0} PID:{1} cmd:{2}",
                        proc.Name, proc.ProcessId, proc.CommandLine.Substring(0, Math.Min(proc.CommandLine.Length, 200))),
                        LogLevel.THREAT, "script_host.log");
                    EdrState.IncrementThreats();

                    if (Config.AutoKillThreats)
                        ThreatActions.TerminateProcess(proc.ProcessId, proc.Name);
                }
            }
        }

        public static void ScriptContentScan()
        {
            string[] scanPaths = new string[] {
                Environment.GetEnvironmentVariable("TEMP") ?? "",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            };
            string[] extensions = new string[] { "*.ps1", "*.vbs", "*.js", "*.bat", "*.cmd", "*.hta", "*.wsf" };
            System.Text.RegularExpressions.Regex suspicious = new System.Text.RegularExpressions.Regex(
                @"IEX\s*\(|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|FromBase64String|Bypass.*ExecutionPolicy|WScript\.Shell|eval\s*\(",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            int scanned = 0;
            for (int p = 0; p < scanPaths.Length; p++)
            {
                if (string.IsNullOrEmpty(scanPaths[p]) || !Directory.Exists(scanPaths[p])) continue;
                for (int e = 0; e < extensions.Length; e++)
                {
                    try
                    {
                        string[] files = Directory.GetFiles(scanPaths[p], extensions[e], SearchOption.TopDirectoryOnly);
                        for (int f = 0; f < files.Length && scanned < 200; f++)
                        {
                            scanned++;
                            try
                            {
                                FileInfo fi = new FileInfo(files[f]);
                                if (fi.Length > 1024 * 1024) continue; // skip > 1MB
                                string content = File.ReadAllText(files[f]);
                                if (content.Length > 8192) content = content.Substring(0, 8192);

                                int matchCount = 0;
                                System.Text.RegularExpressions.MatchCollection matches = suspicious.Matches(content);
                                matchCount = matches.Count;

                                if (matchCount >= 2)
                                {
                                    Logger.Log(string.Format("Script scan: suspicious script {0} ({1} patterns)",
                                        files[f], matchCount), LogLevel.THREAT, "script_content.log");
                                    EdrState.IncrementThreats();
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
        }

        public static void CredentialProtection()
        {
            // Check LSA protection
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Lsa", false))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("RunAsPPL");
                        if (val == null || Convert.ToInt32(val) != 1)
                        {
                            Logger.Log("Credential protection: LSA protection (RunAsPPL) not enabled", LogLevel.WARN, "credential_protection.log");
                        }
                    }
                }
            }
            catch { }

            // Check for credential dump tools in scheduled tasks
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", "/query /fo CSV");
                psi.CreateNoWindow = true; psi.UseShellExecute = false; psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);

                if (!string.IsNullOrEmpty(output))
                {
                    string[] tools = new string[] { "procdump", "mimikatz", "pwdump", "lsass" };
                    for (int t = 0; t < tools.Length; t++)
                    {
                        if (output.IndexOf(tools[t], StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            Logger.Log(string.Format("Credential protection: scheduled task references {0}", tools[t]),
                                LogLevel.THREAT, "credential_protection.log");
                            EdrState.IncrementThreats();
                        }
                    }
                }
            }
            catch { }
        }

        public static void MemoryAcquisitionDetection()
        {
            string[] toolNames = new string[] { "winpmem", "pmem", "osxpmem", "aff4imager", "memdump", "rawdump" };
            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();
            int selfPid = Process.GetCurrentProcess().Id;

            for (int i = 0; i < processes.Count; i++)
            {
                if (processes[i].ProcessId == selfPid) continue;
                string name = (processes[i].Name ?? "").ToLowerInvariant();
                for (int t = 0; t < toolNames.Length; t++)
                {
                    if (name.Contains(toolNames[t]))
                    {
                        Logger.Log(string.Format("Memory acquisition tool: {0} PID:{1}",
                            processes[i].Name, processes[i].ProcessId), LogLevel.THREAT, "memory_acquisition.log");
                        EdrState.IncrementThreats();
                        break;
                    }
                }
            }
        }

        private static readonly Dictionary<string, DateTime> _honeypotCreated = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        public static void HoneypotMonitoring()
        {
            string[] honeypots = new string[] {
                Path.Combine(Config.DatabasePath, "passwords.txt"),
                Path.Combine(Config.DatabasePath, "credentials.xlsx"),
                Path.Combine(Config.DatabasePath, "secrets.docx")
            };

            for (int i = 0; i < honeypots.Length; i++)
            {
                if (File.Exists(honeypots[i]))
                {
                    FileInfo fi = new FileInfo(honeypots[i]);
                    // Skip if we created this file ourselves (access time ~= creation time)
                    DateTime created;
                    if (_honeypotCreated.TryGetValue(honeypots[i], out created))
                    {
                        if (Math.Abs((fi.LastAccessTime - created).TotalSeconds) < 10)
                            continue;
                    }
                    // Skip if access time matches creation time (just created)
                    if (Math.Abs((fi.LastAccessTime - fi.CreationTime).TotalSeconds) < 10)
                        continue;

                    if ((DateTime.Now - fi.LastAccessTime).TotalMinutes < 5)
                    {
                        Logger.Log(string.Format("Honeypot accessed: {0}", honeypots[i]), LogLevel.THREAT, "honeypot.log");
                        EdrState.IncrementThreats();
                    }
                }
                else
                {
                    try
                    {
                        File.WriteAllText(honeypots[i], "HONEYPOT - This file is monitored for unauthorized access");
                        _honeypotCreated[honeypots[i]] = DateTime.Now;
                    }
                    catch { }
                }
            }
        }

        public static void ScriptBlockLoggingCheck()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", false))
                {
                    if (key == null)
                    {
                        Logger.Log("ScriptBlockLogging: policy key missing", LogLevel.WARN, "script_block_logging.log");
                        return;
                    }
                    object val = key.GetValue("EnableScriptBlockLogging");
                    if (val == null || Convert.ToInt32(val) != 1)
                    {
                        Logger.Log("ScriptBlockLogging: not enabled", LogLevel.WARN, "script_block_logging.log");
                    }
                }
            }
            catch { }
        }

        public static void CrudePayloadGuard()
        {
            System.Text.RegularExpressions.Regex pattern = new System.Text.RegularExpressions.Regex(
                @"(?i)(<script|javascript:|onerror=|onload=|alert\()");

            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();
            for (int i = 0; i < processes.Count; i++)
            {
                if (string.IsNullOrEmpty(processes[i].CommandLine)) continue;
                if (pattern.IsMatch(processes[i].CommandLine))
                {
                    Logger.Log(string.Format("Payload guard: XSS/payload in PID:{0} {1}",
                        processes[i].ProcessId, processes[i].Name), LogLevel.THREAT, "payload_guard.log");
                    EdrState.IncrementThreats();
                }
            }
        }

        public static void LateralMovementDetection()
        {
            System.Text.RegularExpressions.Regex pattern = new System.Text.RegularExpressions.Regex(
                @"psexec|paexec|wmic.*process.*call.*create|winrm|enter-pssession|invoke-command.*-computername|schtasks.*/create.*/s|at\.exe.*\\\\",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            List<ProcessInfo> processes = Core.WmiHelper.GetProcesses();
            for (int i = 0; i < processes.Count; i++)
            {
                if (string.IsNullOrEmpty(processes[i].CommandLine)) continue;
                if (pattern.IsMatch(processes[i].CommandLine))
                {
                    Logger.Log(string.Format("Lateral movement: {0} PID:{1}",
                        processes[i].Name, processes[i].ProcessId), LogLevel.THREAT, "lateral_movement.log");
                    EdrState.IncrementThreats();
                }
            }

            // Check SMB connections
            try
            {
                TcpConnectionInformation[] conns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                int smbCount = 0;
                for (int i = 0; i < conns.Length; i++)
                {
                    if (conns[i].RemoteEndPoint.Port == 445 && conns[i].State == TcpState.Established)
                        smbCount++;
                }
                if (smbCount > 5)
                {
                    Logger.Log(string.Format("Lateral movement: {0} active SMB connections", smbCount),
                        LogLevel.WARN, "lateral_movement.log");
                }
            }
            catch { }
        }

        public static void DataExfiltrationDetection()
        {
            try
            {
                TcpConnectionInformation[] conns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                Dictionary<string, int> byProcess = new Dictionary<string, int>();
                // Count established connections per remote IP
                for (int i = 0; i < conns.Length; i++)
                {
                    if (conns[i].State != TcpState.Established) continue;
                    string remote = conns[i].RemoteEndPoint.Address.ToString();
                    if (remote == "127.0.0.1" || remote == "::1") continue;
                    int count;
                    if (!byProcess.TryGetValue(remote, out count)) count = 0;
                    byProcess[remote] = count + 1;
                }

                foreach (KeyValuePair<string, int> kvp in byProcess)
                {
                    if (kvp.Value > 20)
                    {
                        Logger.Log(string.Format("Data exfil: {0} connections to {1}", kvp.Value, kvp.Key),
                            LogLevel.WARN, "data_exfiltration.log");
                    }
                }
            }
            catch { }
        }

        public static void QuarantineManagement()
        {
            try
            {
                if (!Directory.Exists(Config.QuarantinePath)) return;
                string[] files = Directory.GetFiles(Config.QuarantinePath);
                for (int i = 0; i < files.Length; i++)
                {
                    FileInfo fi = new FileInfo(files[i]);
                    if ((DateTime.Now - fi.CreationTime).TotalDays > 30)
                    {
                        try
                        {
                            File.Delete(files[i]);
                            Logger.Log("Quarantine cleanup: removed " + fi.Name);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
    }
}
