using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using GEdr.Core;
using GEdr.Response;
using Microsoft.Win32;
using WmiHelperCore = GEdr.Core.WmiHelper;

namespace GEdr.Detection
{
    /// <summary>
    /// Registry Run keys, scheduled tasks, WMI persistence, startup folder,
    /// service creation — all persistence mechanism detection.
    /// Ported from Invoke-RegistryPersistenceDetection, Invoke-ScheduledTaskDetection,
    /// Invoke-WMIPersistenceDetection, Invoke-StartupPersistenceDetection.
    /// </summary>
    public static class PersistenceDetection
    {
        private static readonly string[] _runKeyPaths = new string[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        private static readonly Regex _suspiciousValuePattern = new Regex(
            @"powershell.*-enc|cmd.*/c.*powershell|https?://|\.vbs|\.js|\.bat|\.cmd|wscript|cscript|mshta|rundll32.*\.dll|regsvr32.*\.dll",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>Scan registry Run keys for suspicious persistence entries.</summary>
        public static void RegistryPersistence()
        {
            RegistryKey[] hives = new RegistryKey[] { Registry.LocalMachine, Registry.CurrentUser };
            for (int h = 0; h < hives.Length; h++)
            {
                for (int k = 0; k < _runKeyPaths.Length; k++)
                {
                    try
                    {
                        using (RegistryKey key = hives[h].OpenSubKey(_runKeyPaths[k], false))
                        {
                            if (key == null) continue;
                            string[] names = key.GetValueNames();
                            for (int n = 0; n < names.Length; n++)
                            {
                                string name = names[n];
                                object valObj = key.GetValue(name);
                                if (valObj == null) continue;
                                string value = valObj.ToString();

                                if (_suspiciousValuePattern.IsMatch(value))
                                {
                                    string fullPath = string.Format("{0}\\{1}", _runKeyPaths[k], name);
                                    Logger.Log(string.Format("Registry persistence: {0} = {1}",
                                        fullPath, Truncate(value, 200)), LogLevel.THREAT, "persistence_detections.log");
                                    EdrState.IncrementThreats();

                                    ThreatInfo threat = new ThreatInfo();
                                    threat.ThreatType = "RegistryPersistence";
                                    threat.ThreatPath = fullPath;
                                    threat.Severity = ThreatSeverity.High;
                                    threat.Confidence = 60;
                                    threat.Details["Value"] = Truncate(value, 500);
                                    ResponseQueue.Enqueue(threat);
                                }

                                // Check for unsigned executables in Run keys
                                string exePath = ExtractExePath(value);
                                if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                                {
                                    if (!exePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
                                    {
                                        try
                                        {
                                            System.Security.Cryptography.X509Certificates.X509Certificate cert =
                                                System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(exePath);
                                        }
                                        catch
                                        {
                                            // Unsigned
                                            Logger.Log(string.Format("Unsigned exe in Run key: {0}", exePath), LogLevel.WARN, "persistence_detections.log");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        /// <summary>Detect suspicious scheduled tasks.</summary>
        public static void ScheduledTasks()
        {
            try
            {
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("schtasks.exe", "/query /fo CSV /v");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(15000);

                if (string.IsNullOrEmpty(output)) return;

                string[] lines = output.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                Regex suspiciousAction = new Regex(@"powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin", RegexOptions.IgnoreCase);

                for (int i = 1; i < lines.Length; i++) // skip header
                {
                    string line = lines[i];
                    if (suspiciousAction.IsMatch(line))
                    {
                        // Skip our own tasks
                        if (line.IndexOf("GEdr", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        if (line.IndexOf("AntivirusProtection", StringComparison.OrdinalIgnoreCase) >= 0) continue;

                        Logger.Log(string.Format("Suspicious scheduled task: {0}", Truncate(line, 300)),
                            LogLevel.WARN, "persistence_detections.log");
                    }
                }
            }
            catch { }
        }

        /// <summary>Detect WMI event subscription persistence.</summary>
        public static void WmiPersistence()
        {
            try
            {
                List<Dictionary<string, string>> filters = WmiHelperCore.GetWmiEventFilters();
                List<Dictionary<string, string>> consumers = WmiHelperCore.GetWmiCommandConsumers();

                for (int i = 0; i < filters.Count; i++)
                {
                    Logger.Log(string.Format("WMI event filter: {0} | Query: {1}",
                        filters[i]["Name"], Truncate(filters[i]["Query"], 200)),
                        LogLevel.WARN, "persistence_detections.log");
                }

                for (int i = 0; i < consumers.Count; i++)
                {
                    string cmd = consumers[i]["CommandLineTemplate"];
                    Logger.Log(string.Format("WMI command consumer: {0} | Cmd: {1}",
                        consumers[i]["Name"], Truncate(cmd, 200)),
                        LogLevel.THREAT, "persistence_detections.log");
                    EdrState.IncrementThreats();

                    ThreatInfo threat = new ThreatInfo();
                    threat.ThreatType = "WMIPersistence";
                    threat.ThreatPath = consumers[i]["Name"];
                    threat.Severity = ThreatSeverity.High;
                    threat.Confidence = 65;
                    threat.Details["Command"] = Truncate(cmd, 500);
                    ResponseQueue.Enqueue(threat);
                }
            }
            catch { }
        }

        /// <summary>Check startup folder for suspicious files.</summary>
        public static void StartupFolder()
        {
            string[] startupPaths = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup))
            };

            string[] suspiciousExts = new string[] { ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".bat", ".cmd", ".scr", ".hta" };

            for (int p = 0; p < startupPaths.Length; p++)
            {
                if (!Directory.Exists(startupPaths[p])) continue;
                try
                {
                    string[] files = Directory.GetFiles(startupPaths[p]);
                    for (int f = 0; f < files.Length; f++)
                    {
                        string ext = Path.GetExtension(files[f]).ToLowerInvariant();
                        bool suspicious = false;
                        for (int e = 0; e < suspiciousExts.Length; e++)
                        {
                            if (ext == suspiciousExts[e]) { suspicious = true; break; }
                        }
                        if (suspicious)
                        {
                            Logger.Log(string.Format("Suspicious startup file: {0}", files[f]),
                                LogLevel.WARN, "persistence_detections.log");
                        }
                    }
                }
                catch { }
            }
        }

        private static string ExtractExePath(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            string trimmed = value.Trim();
            if (trimmed.StartsWith("\""))
            {
                int end = trimmed.IndexOf('"', 1);
                if (end > 1) return trimmed.Substring(1, end - 1);
            }
            int space = trimmed.IndexOf(' ');
            return space > 0 ? trimmed.Substring(0, space) : trimmed;
        }

        private static string Truncate(string s, int max)
        {
            if (s == null) return "";
            return s.Length <= max ? s : s.Substring(0, max) + "...";
        }
    }

    // WMI helper methods are in Core.WmiHelper - extension methods here
    // use Core.WmiHelper.GetWmiEventFilters() and GetWmiCommandConsumers()
}
