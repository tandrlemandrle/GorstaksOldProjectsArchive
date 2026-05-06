using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Detection
{
    /// <summary>
    /// YARA rule-based file and memory scanning.
    /// Executes yara64.exe against suspicious files and memory regions.
    /// Designed for on-demand hunting and automated scanning of quarantined items.
    /// </summary>
    public static class YaraScanner
    {
        private static readonly object _scanLock = new object();
        private static DateTime _lastFullScan = DateTime.MinValue;

        /// <summary>
        /// Scan a single file or directory with YARA rules.
        /// </summary>
        public static bool ScanPath(string path, string rulePath = null)
        {
            if (!File.Exists(Config.YaraExePath))
            {
                // Try auto-bootstrap first
                Logger.Log("YARA not found, attempting auto-bootstrap...", LogLevel.INFO);
                if (!Bootstrap.AutoBootstrap())
                {
                    Logger.Log("YARA not available and auto-bootstrap failed: " + Config.YaraExePath, LogLevel.WARN);
                    return false;
                }

                // Wait a moment for bootstrap to start, but don't block forever
                System.Threading.Thread.Sleep(500);

                // Check again
                if (!File.Exists(Config.YaraExePath))
                {
                    Logger.Log("YARA still not available after auto-bootstrap attempt", LogLevel.WARN);
                    return false;
                }

                Logger.Log("YARA auto-bootstrap succeeded!", LogLevel.INFO);
            }

            if (!Directory.Exists(Config.RulesPath))
            {
                Logger.Log("YARA rules directory not found: " + Config.RulesPath, LogLevel.WARN);
                return false;
            }

            lock (_scanLock)
            {
                try
                {
                    string target = path;
                    if (!File.Exists(target) && !Directory.Exists(target))
                    {
                        Logger.Log("Scan target not found: " + path, LogLevel.WARN);
                        return false;
                    }

                    // Build YARA command
                    string rules = rulePath ?? Config.RulesPath + "\\*.yar";
                    string args = string.Format("-r -g \"{0}\" \"{1}\"", rules, target);

                    ProcessStartInfo psi = new ProcessStartInfo(Config.YaraExePath, args);
                    psi.CreateNoWindow = true;
                    psi.UseShellExecute = false;
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;
                    psi.StandardOutputEncoding = System.Text.Encoding.UTF8;

                    using (Process proc = Process.Start(psi))
                    {
                        string output = proc.StandardOutput.ReadToEnd();
                        string error = proc.StandardError.ReadToEnd();
                        proc.WaitForExit(60000); // 60 second timeout

                        if (proc.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                        {
                            // YARA matched - parse output
                            // Format: rule_name file_path
                            ParseYaraMatches(output, target);
                            return true;
                        }
                        else if (proc.ExitCode == 1)
                        {
                            // No matches - clean
                            Logger.Log(string.Format("YARA scan clean: {0}", target), LogLevel.INFO);
                            return true;
                        }
                        else if (!string.IsNullOrEmpty(error))
                        {
                            Logger.Log("YARA error: " + error, LogLevel.ERROR);
                            return false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("YARA scan failed: " + ex.Message, LogLevel.ERROR);
                }
            }

            return false;
        }

        /// <summary>
        /// Scan memory of a specific process (requires yara to read process memory).
        /// </summary>
        public static bool ScanProcessMemory(int pid, string processName = null)
        {
            // Auto-bootstrap check
            if (!File.Exists(Config.YaraExePath))
            {
                Bootstrap.AutoBootstrap();
                return false; // Can't scan this time, will be ready next time
            }

            lock (_scanLock)
            {
                try
                {
                    string args = string.Format("-p {0} \"{1}\"", pid, Config.RulesPath + "\\*.yar");

                    ProcessStartInfo psi = new ProcessStartInfo(Config.YaraExePath, args);
                    psi.CreateNoWindow = true;
                    psi.UseShellExecute = false;
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;

                    using (Process proc = Process.Start(psi))
                    {
                        string output = proc.StandardOutput.ReadToEnd();
                        proc.WaitForExit(30000);

                        if (proc.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                        {
                            ParseYaraMatches(output, string.Format("pid:{0}", pid));
                            return true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Process memory scan failed: " + ex.Message, LogLevel.ERROR);
                }
            }

            return false;
        }

        /// <summary>
        /// Scheduled job entry point - scan quarantined files periodically.
        /// </summary>
        public static void ScanQuarantine()
        {
            if (!Directory.Exists(Config.QuarantinePath))
                return;

            try
            {
                string[] files = Directory.GetFiles(Config.QuarantinePath);
                if (files.Length == 0) return;

                Logger.Log(string.Format("YARA scanning {0} quarantined files...", files.Length), LogLevel.INFO);

                int scanned = 0, detected = 0;
                foreach (string file in files)
                {
                    if (ScanPath(file))
                        detected++;
                    scanned++;
                }

                Logger.Log(string.Format("Quarantine scan complete: {0} scanned, {1} YARA matches", scanned, detected),
                    LogLevel.INFO);
            }
            catch (Exception ex)
            {
                Logger.Log("Quarantine scan error: " + ex.Message, LogLevel.ERROR);
            }
        }

        /// <summary>
        /// Hunt mode - scan common malware locations (runs on dedicated thread).
        /// </summary>
        public static void HuntSuspiciousLocations()
        {
            // Prevent running too frequently
            if ((DateTime.Now - _lastFullScan).TotalHours < 1)
                return;

            _lastFullScan = DateTime.Now;

            Logger.Log("Starting YARA hunt mode on suspicious locations...", LogLevel.INFO);

            string[] huntPaths = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Start Menu", "Programs", "StartUp")
            };

            int totalMatches = 0;
            foreach (string path in huntPaths)
            {
                if (!Directory.Exists(path)) continue;

                try
                {
                    // Only scan .exe, .dll, .ps1, .vbs, .js, .bat files for speed
                    var files = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories)
                        .Where(f => Regex.IsMatch(f, @"\.(exe|dll|ps1|vbs|js|bat|cmd|com|scr)$", RegexOptions.IgnoreCase))
                        .Take(100); // Limit to prevent hanging

                    foreach (string file in files)
                    {
                        if (ScanPath(file))
                            totalMatches++;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Hunt scan error for " + path + ": " + ex.Message, LogLevel.WARN);
                }
            }

            Logger.Log(string.Format("Hunt mode complete: {0} YARA matches found", totalMatches), LogLevel.INFO);
        }

        private static void ParseYaraMatches(string output, string target)
        {
            // YARA output format: rule_name [metadata] file_path
            // or for memory: rule_name [metadata] pid:123
            string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Extract rule name (first word)
                string ruleName = line.Split(' ')[0];

                Logger.Log(string.Format("YARA MATCH: {0} in {1}", ruleName, target),
                    LogLevel.THREAT, "yara_detections.log");

                GidrState.IncrementYaraMatches();

                // Create threat from YARA match
                ThreatInfo threat = new ThreatInfo();
                threat.ThreatType = "YaraMatch:" + ruleName;
                threat.ThreatPath = target;
                threat.Severity = ThreatSeverity.High;
                threat.Confidence = 85;
                threat.Details["YaraRule"] = ruleName;
                threat.Details["Target"] = target;

                // If it's a file, try to get process info
                if (File.Exists(target))
                {
                    threat.ThreatPath = target;
                }

                ResponseQueue.Enqueue(threat);
            }
        }
    }
}
