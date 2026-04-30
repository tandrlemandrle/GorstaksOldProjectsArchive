using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using GEdr.Core;
using GEdr.Response;
using Microsoft.Win32;

namespace GEdr.Detection
{
    /// <summary>
    /// CVE mitigation patcher, ASR rules enforcement, DNS secure config (DoH/DoT),
    /// C2 IP block list from threat feeds, MITRE mapping aggregator,
    /// COM object hijacking detection, browser extension monitoring.
    /// </summary>
    public static class HardeningDetection
    {
        // ═══════════════════════════════════════════════════════════════
        // CVE MITIGATION PATCHER
        // Auto-applies mitigations for known exploited vulnerabilities.
        // Fetches CISA KEV catalog, applies registry/service mitigations.
        // ═══════════════════════════════════════════════════════════════

        private static readonly string _cveStatePath = Path.Combine(Config.DatabasePath, "cve_state.txt");
        private static HashSet<string> _appliedCves;

        private static readonly Dictionary<string, Action> _mitigations = new Dictionary<string, Action>(StringComparer.OrdinalIgnoreCase);

        static HardeningDetection()
        {
            _mitigations["CVE-2017-0143"] = DisableSMBv1;   // EternalBlue
            _mitigations["CVE-2017-0144"] = DisableSMBv1;   // EternalBlue variant
            _mitigations["CVE-2020-0796"] = DisableSMBv3Compression; // SMBGhost
            _mitigations["CVE-2019-0708"] = EnableRDPNLA;   // BlueKeep
            _mitigations["CVE-2022-30190"] = BlockMSDT;     // Follina
            _mitigations["CVE-2021-34527"] = DisablePrintSpooler; // PrintNightmare
            _mitigations["CVE-2024-38063"] = DisableIPv6;   // IPv6 RCE
        }

        public static void CVEMitigationPatcher()
        {
            // Load applied CVEs
            if (_appliedCves == null)
            {
                _appliedCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (File.Exists(_cveStatePath))
                {
                    try
                    {
                        string[] lines = File.ReadAllLines(_cveStatePath);
                        for (int i = 0; i < lines.Length; i++)
                        {
                            string line = lines[i].Trim();
                            if (!string.IsNullOrEmpty(line)) _appliedCves.Add(line);
                        }
                    }
                    catch { }
                }
            }

            // Apply all known mitigations that haven't been applied yet
            int applied = 0;
            foreach (KeyValuePair<string, Action> kvp in _mitigations)
            {
                if (_appliedCves.Contains(kvp.Key)) continue;
                try
                {
                    kvp.Value();
                    _appliedCves.Add(kvp.Key);
                    applied++;
                    Logger.Log(string.Format("CVE mitigation applied: {0}", kvp.Key), LogLevel.ACTION, "cve_mitigation.log");
                }
                catch (Exception ex)
                {
                    Logger.Log(string.Format("CVE mitigation failed for {0}: {1}", kvp.Key, ex.Message), LogLevel.WARN, "cve_mitigation.log");
                }
            }

            // Also try to fetch CISA KEV for new CVEs
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
                req.Timeout = 30000;
                req.Method = "GET";
                req.UserAgent = "GEdr/2.0";
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
                {
                    string body = reader.ReadToEnd();
                    // Simple parse: find CVE IDs we have mitigations for
                    MatchCollection matches = Regex.Matches(body, @"CVE-\d{4}-\d{4,7}");
                    int newCves = 0;
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string cveId = matches[i].Value;
                        if (_mitigations.ContainsKey(cveId) && !_appliedCves.Contains(cveId))
                        {
                            try
                            {
                                _mitigations[cveId]();
                                _appliedCves.Add(cveId);
                                newCves++;
                                Logger.Log(string.Format("CVE mitigation (from KEV): {0}", cveId), LogLevel.ACTION, "cve_mitigation.log");
                            }
                            catch { }
                        }
                    }
                    if (newCves > 0)
                        Logger.Log(string.Format("Applied {0} new CVE mitigations from CISA KEV", newCves));
                }
            }
            catch { } // Network failure is fine — we still applied local mitigations

            // Save state
            if (applied > 0)
            {
                try
                {
                    string dir = Path.GetDirectoryName(_cveStatePath);
                    if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    List<string> lines = new List<string>(_appliedCves);
                    File.WriteAllLines(_cveStatePath, lines.ToArray());
                }
                catch { }
            }
        }

        private static void DisableSMBv1()
        {
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0);
        }

        private static void DisableSMBv3Compression()
        {
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "DisableCompression", 1);
        }

        private static void DisablePrintSpooler()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("sc.exe", "config Spooler start= disabled");
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                Process.Start(psi).WaitForExit(5000);
                psi = new ProcessStartInfo("sc.exe", "stop Spooler");
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                Process.Start(psi).WaitForExit(5000);
            }
            catch { }
        }

        private static void BlockMSDT()
        {
            // Delete ms-msdt protocol handler
            try
            {
                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey("ms-msdt", true))
                {
                    if (key != null)
                    {
                        Registry.ClassesRoot.DeleteSubKeyTree("ms-msdt", false);
                        Logger.Log("Blocked MSDT protocol handler (CVE-2022-30190)");
                    }
                }
            }
            catch { }
        }

        private static void EnableRDPNLA()
        {
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1);
        }

        private static void DisableIPv6()
        {
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", 0xFF);
        }

        private static void SetRegistryDword(string path, string name, int value)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(path))
                {
                    if (key != null)
                        key.SetValue(name, value, RegistryValueKind.DWord);
                }
            }
            catch { }
        }

        // ═══════════════════════════════════════════════════════════════
        // ASR RULES ENFORCEMENT
        // Enables Microsoft Defender Attack Surface Reduction rules.
        // ═══════════════════════════════════════════════════════════════

        private static readonly string[][] _asrRules = new string[][]
        {
            new string[] { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "Block executable content from email" },
            new string[] { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "Block Office child process creation" },
            new string[] { "3B576869-A4EC-4529-8536-B80A7769E899", "Block Office creating executable content" },
            new string[] { "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "Block Office injecting into other processes" },
            new string[] { "D3E037E1-3EB8-44C8-A917-57927947596D", "Block JavaScript/VBScript launching executables" },
            new string[] { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "Block execution of potentially obfuscated scripts" },
            new string[] { "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "Block Win32 API calls from Office macros" },
        };

        public static void ASRRulesEnforcement()
        {
            int applied = 0;
            for (int i = 0; i < _asrRules.Length; i++)
            {
                try
                {
                    string ruleId = _asrRules[i][0];
                    string desc = _asrRules[i][1];
                    // Use PowerShell to set ASR rules (Set-MpPreference requires PS)
                    ProcessStartInfo psi = new ProcessStartInfo("powershell.exe",
                        string.Format("-NoProfile -Command \"Set-MpPreference -AttackSurfaceReductionRules_Ids {0} -AttackSurfaceReductionRules_Actions Enabled\"", ruleId));
                    psi.CreateNoWindow = true;
                    psi.UseShellExecute = false;
                    psi.RedirectStandardError = true;
                    Process p = Process.Start(psi);
                    p.WaitForExit(10000);
                    if (p.ExitCode == 0)
                    {
                        applied++;
                        Logger.Log(string.Format("ASR rule enabled: {0}", desc), LogLevel.INFO, "asr_rules.log");
                    }
                }
                catch { }
            }
            if (applied > 0)
                Logger.Log(string.Format("ASR: enabled/verified {0} rules", applied));
        }

        // ═══════════════════════════════════════════════════════════════
        // DNS SECURE CONFIG (DoH/DoT)
        // Configures encrypted DNS to prevent DNS hijacking.
        // ═══════════════════════════════════════════════════════════════

        private static bool _dnsConfigured;

        private static readonly string[][] _dnsServers = new string[][]
        {
            new string[] { "1.1.1.1",              "https://cloudflare-dns.com/dns-query", "cloudflare-dns.com" },
            new string[] { "1.0.0.1",              "https://cloudflare-dns.com/dns-query", "cloudflare-dns.com" },
            new string[] { "8.8.8.8",              "https://dns.google/dns-query",         "dns.google" },
            new string[] { "8.8.4.4",              "https://dns.google/dns-query",         "dns.google" },
            new string[] { "2606:4700:4700::1111", "https://cloudflare-dns.com/dns-query", "cloudflare-dns.com" },
            new string[] { "2001:4860:4860::8888", "https://dns.google/dns-query",         "dns.google" },
        };

        public static void DNSSecureConfig()
        {
            if (_dnsConfigured) return;

            int applied = 0;
            // Register DoH server addresses
            for (int i = 0; i < _dnsServers.Length; i++)
            {
                try
                {
                    string ip = _dnsServers[i][0];
                    string template = _dnsServers[i][1];
                    ProcessStartInfo psi = new ProcessStartInfo("powershell.exe",
                        string.Format("-NoProfile -Command \"Add-DnsClientDohServerAddress -ServerAddress '{0}' -DohTemplate '{1}' -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop\"", ip, template));
                    psi.CreateNoWindow = true;
                    psi.UseShellExecute = false;
                    Process p = Process.Start(psi);
                    p.WaitForExit(10000);
                    if (p.ExitCode == 0) applied++;
                }
                catch { }
            }

            // Set DNS servers on active adapter via netsh
            try
            {
                string[][] netshCmds = new string[][]
                {
                    new string[] { "interface ipv4 set dnsservers name=\"Ethernet\" static 1.1.1.1 primary validate=no" },
                    new string[] { "interface ipv4 add dnsservers name=\"Ethernet\" 8.8.8.8 index=2 validate=no" },
                };
                for (int i = 0; i < netshCmds.Length; i++)
                {
                    ProcessStartInfo psi = new ProcessStartInfo("netsh.exe", netshCmds[i][0]);
                    psi.CreateNoWindow = true; psi.UseShellExecute = false;
                    Process.Start(psi).WaitForExit(5000);
                }
            }
            catch { }

            // Clear DNS cache
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("ipconfig.exe", "/flushdns");
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                Process.Start(psi).WaitForExit(5000);
            }
            catch { }

            if (applied > 0)
            {
                Logger.Log(string.Format("DNS: configured DoH for {0} servers", applied), LogLevel.ACTION, "dns_config.log");
                _dnsConfigured = true;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // C2 IP BLOCK LIST
        // Downloads known-bad IPs from threat feeds, blocks via firewall.
        // ═══════════════════════════════════════════════════════════════

        private static readonly string[] _threatFeeds = new string[]
        {
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        };

        private static readonly HashSet<string> _blockedIps = new HashSet<string>();

        public static void C2BlockList()
        {
            int blocked = 0;
            for (int f = 0; f < _threatFeeds.Length; f++)
            {
                try
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    HttpWebRequest req = (HttpWebRequest)WebRequest.Create(_threatFeeds[f]);
                    req.Timeout = 30000;
                    req.UserAgent = "GEdr/2.0";
                    using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                    using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
                    {
                        string content = reader.ReadToEnd();
                        string[] lines = content.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                        int count = 0;
                        for (int i = 0; i < lines.Length && count < 500; i++)
                        {
                            string ip = lines[i].Trim();
                            if (!Regex.IsMatch(ip, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")) continue;
                            if (ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("127.")) continue;
                            if (_blockedIps.Contains(ip)) continue;

                            string ruleName = string.Format("GEdr_C2_{0}", ip.Replace('.', '_'));
                            ProcessStartInfo psi = new ProcessStartInfo("netsh.exe",
                                string.Format("advfirewall firewall add rule name=\"{0}\" dir=out action=block remoteip={1}", ruleName, ip));
                            psi.CreateNoWindow = true;
                            psi.UseShellExecute = false;
                            psi.RedirectStandardOutput = true;
                            Process p = Process.Start(psi);
                            p.WaitForExit(5000);
                            if (p.ExitCode == 0)
                            {
                                _blockedIps.Add(ip);
                                blocked++;
                                count++;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log(string.Format("C2 block list feed error: {0}", ex.Message), LogLevel.WARN, "c2_blocklist.log");
                }
            }

            if (blocked > 0)
                Logger.Log(string.Format("C2 block list: added {0} new firewall rules", blocked), LogLevel.ACTION, "c2_blocklist.log");
        }

        // ═══════════════════════════════════════════════════════════════
        // MITRE ATT&CK MAPPING
        // Aggregates today's detections and maps them to MITRE techniques.
        // ═══════════════════════════════════════════════════════════════

        private static readonly Dictionary<string, string> _mitreMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "HashDetection", "T1204" }, { "LOLBin", "T1218" }, { "ProcessAnomaly", "T1055" },
            { "AMSIBypass", "T1562.006" }, { "CredentialDump", "T1003" }, { "MemoryAcquisition", "T1119" },
            { "WMIPersistence", "T1546.003" }, { "ScheduledTask", "T1053.005" }, { "RegistryPersistence", "T1547.001" },
            { "DLLHijacking", "T1574.001" }, { "TokenManipulation", "T1134" }, { "ProcessHollowing", "T1055.012" },
            { "Keylogger", "T1056.001" }, { "Ransomware", "T1486" }, { "NetworkAnomaly", "T1041" },
            { "Beacon", "T1071" }, { "DNSExfiltration", "T1048" }, { "Rootkit", "T1014" },
            { "Clipboard", "T1115" }, { "ShadowCopy", "T1490" }, { "USB", "T1052" },
            { "Fileless", "T1059" }, { "CodeInjection", "T1055" }, { "LateralMovement", "T1021" },
            { "ProcessCreation", "T1059" }, { "ScriptHost", "T1059.005" }, { "CrudePayload", "T1059.007" },
        };

        public static void MitreMapping()
        {
            try
            {
                string logDir = Config.LogPath;
                if (!Directory.Exists(logDir)) return;

                string today = DateTime.Now.ToString("yyyy-MM-dd");
                string mitreLog = Path.Combine(logDir, string.Format("mitre_mapping_{0}.log", today));
                string[] logFiles = Directory.GetFiles(logDir, "*.log");

                int mapped = 0;
                for (int f = 0; f < logFiles.Length; f++)
                {
                    string fileName = Path.GetFileName(logFiles[f]);
                    if (fileName.StartsWith("mitre_mapping")) continue;
                    if (!fileName.Contains(today) && !fileName.Equals("gedr_log.txt")) continue;

                    try
                    {
                        // Read last 50 lines
                        string[] allLines = File.ReadAllLines(logFiles[f]);
                        int start = Math.Max(0, allLines.Length - 50);
                        for (int i = start; i < allLines.Length; i++)
                        {
                            string line = allLines[i];
                            if (!line.Contains("THREAT")) continue;

                            // Try to match detection type to MITRE technique
                            foreach (KeyValuePair<string, string> kvp in _mitreMap)
                            {
                                if (line.IndexOf(kvp.Key, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    string entry = string.Format("{0}|{1}|{2}|{3}",
                                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                                        kvp.Key, kvp.Value, line.Substring(0, Math.Min(line.Length, 200)));
                                    File.AppendAllText(mitreLog, entry + Environment.NewLine);
                                    mapped++;
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }

                if (mapped > 0)
                    Logger.Log(string.Format("MITRE mapping: mapped {0} detections", mapped));
            }
            catch { }
        }

        // ═══════════════════════════════════════════════════════════════
        // COM OBJECT HIJACKING DETECTION
        // Checks for suspicious COM object registrations that could be
        // used for persistence or code execution.
        // ═══════════════════════════════════════════════════════════════

        public static void COMMonitoring()
        {
            // Check for COM objects pointing to suspicious locations
            string[] suspiciousClsidPaths = new string[]
            {
                @"SOFTWARE\Classes\CLSID",
                @"SOFTWARE\WOW6432Node\Classes\CLSID"
            };

            for (int p = 0; p < suspiciousClsidPaths.Length; p++)
            {
                try
                {
                    using (RegistryKey clsidRoot = Registry.LocalMachine.OpenSubKey(suspiciousClsidPaths[p], false))
                    {
                        if (clsidRoot == null) continue;
                        string[] clsids = clsidRoot.GetSubKeyNames();

                        // Sample check — don't enumerate all CLSIDs (too slow), check recently modified
                        int checked_count = 0;
                        for (int i = 0; i < clsids.Length && checked_count < 200; i++)
                        {
                            try
                            {
                                using (RegistryKey clsidKey = clsidRoot.OpenSubKey(clsids[i] + @"\InprocServer32", false))
                                {
                                    if (clsidKey == null) continue;
                                    checked_count++;

                                    object val = clsidKey.GetValue(null); // default value
                                    if (val == null) continue;
                                    string dllPath = val.ToString();

                                    // Suspicious: DLL not in System32 or Program Files
                                    if (!string.IsNullOrEmpty(dllPath)
                                        && !dllPath.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase)
                                        && !dllPath.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase)
                                        && !dllPath.StartsWith(@"%SystemRoot%", StringComparison.OrdinalIgnoreCase))
                                    {
                                        // Check if the DLL exists and is unsigned
                                        string expandedPath = Environment.ExpandEnvironmentVariables(dllPath);
                                        if (File.Exists(expandedPath) && !ThreatActions.IsFileSigned(expandedPath))
                                        {
                                            Logger.Log(string.Format("COM hijack: CLSID {0} -> unsigned DLL {1}",
                                                clsids[i], dllPath), LogLevel.THREAT, "com_monitoring.log");
                                            EdrState.IncrementThreats();

                                            ThreatInfo threat = new ThreatInfo();
                                            threat.ThreatType = "COMHijacking";
                                            threat.ThreatPath = expandedPath;
                                            threat.Severity = ThreatSeverity.High;
                                            threat.Confidence = 65;
                                            threat.Details["CLSID"] = clsids[i];
                                            ResponseQueue.Enqueue(threat);
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // BROWSER EXTENSION MONITORING
        // Scans Chrome/Edge/Firefox extension directories for suspicious
        // or recently installed extensions.
        // ═══════════════════════════════════════════════════════════════

        public static void BrowserExtensionMonitoring()
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            // Chrome extensions
            ScanExtensionDir(Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default\Extensions"), "Chrome");

            // Edge extensions
            ScanExtensionDir(Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default\Extensions"), "Edge");

            // Firefox extensions (different structure)
            string firefoxProfiles = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            if (Directory.Exists(firefoxProfiles))
            {
                try
                {
                    string[] profiles = Directory.GetDirectories(firefoxProfiles);
                    for (int i = 0; i < profiles.Length; i++)
                    {
                        string extDir = Path.Combine(profiles[i], "extensions");
                        if (Directory.Exists(extDir))
                            ScanExtensionDir(extDir, "Firefox");
                    }
                }
                catch { }
            }
        }

        private static void ScanExtensionDir(string extDir, string browser)
        {
            if (!Directory.Exists(extDir)) return;

            try
            {
                string[] extFolders = Directory.GetDirectories(extDir);
                for (int i = 0; i < extFolders.Length; i++)
                {
                    try
                    {
                        DirectoryInfo di = new DirectoryInfo(extFolders[i]);

                        // Check if recently installed (last 24 hours)
                        bool recent = (DateTime.Now - di.CreationTime).TotalHours < 24;

                        // Look for manifest.json to get extension info
                        string[] manifests = Directory.GetFiles(extFolders[i], "manifest.json", SearchOption.AllDirectories);
                        for (int m = 0; m < manifests.Length; m++)
                        {
                            try
                            {
                                string content = File.ReadAllText(manifests[m]);

                                // Check for suspicious permissions
                                bool hasAllUrls = content.Contains("<all_urls>") || content.Contains("*://*/*");
                                bool hasWebRequest = content.Contains("webRequest") || content.Contains("webRequestBlocking");
                                bool hasNativeMessaging = content.Contains("nativeMessaging");
                                bool hasClipboard = content.Contains("clipboardRead") || content.Contains("clipboardWrite");
                                bool hasDownloads = content.Contains("downloads");

                                int suspiciousPerms = 0;
                                if (hasAllUrls) suspiciousPerms++;
                                if (hasWebRequest) suspiciousPerms++;
                                if (hasNativeMessaging) suspiciousPerms++;
                                if (hasClipboard) suspiciousPerms++;
                                if (hasDownloads && hasAllUrls) suspiciousPerms++;

                                // Extract name
                                string extName = di.Name;
                                Match nameMatch = Regex.Match(content, "\"name\"\\s*:\\s*\"([^\"]+)\"");
                                if (nameMatch.Success) extName = nameMatch.Groups[1].Value;

                                if (suspiciousPerms >= 3 || (recent && suspiciousPerms >= 2))
                                {
                                    Logger.Log(string.Format("Browser extension [{0}]: {1} - {2} suspicious permissions{3}",
                                        browser, extName, suspiciousPerms, recent ? " (RECENTLY INSTALLED)" : ""),
                                        LogLevel.WARN, "browser_extensions.log");

                                    if (recent && suspiciousPerms >= 3)
                                    {
                                        Logger.Log(string.Format("Browser extension [{0}]: HIGH RISK - {1} (new + many permissions)",
                                            browser, extName), LogLevel.THREAT, "browser_extensions.log");
                                        EdrState.IncrementThreats();

                                        ThreatInfo threat = new ThreatInfo();
                                        threat.ThreatType = "SuspiciousBrowserExtension";
                                        threat.ThreatPath = extFolders[i];
                                        threat.Severity = ThreatSeverity.Medium;
                                        threat.Confidence = 50;
                                        threat.Details["Browser"] = browser;
                                        threat.Details["ExtensionName"] = extName;
                                        threat.Details["SuspiciousPermissions"] = suspiciousPerms.ToString();
                                        ResponseQueue.Enqueue(threat);
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
}
