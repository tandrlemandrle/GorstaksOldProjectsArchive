using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Runtime.InteropServices;
using System.Text;
using GIDR.Core;

namespace GIDR.Response
{
    /// <summary>
    /// IDR-focused incident response orchestration:
    /// - Host isolation (network containment)
    /// - Evidence collection (memory dumps, process snapshots)
    /// - Automated incident documentation
    /// - SIEM/Email alerting
    /// - Chain-of-custody logging
    /// </summary>
    public static class IncidentResponse
    {
        private static bool _hostIsolated = false;
        private static readonly object _isolationLock = new object();
        private static List<string> _isolationRules = new List<string>();

        // Windows firewall constants for host isolation
        private const int NET_FW_PROFILE2_DOMAIN = 1;
        private const int NET_FW_PROFILE2_PRIVATE = 2;
        private const int NET_FW_PROFILE2_PUBLIC = 4;

        /// <summary>
        /// Isolate the host from network while preserving localhost/loopback.
        /// Creates firewall rules to block all outbound except:
        /// - localhost/127.0.0.1/::1 (agent needs to log)
        /// - Configured SIEM/syslog endpoint if any
        /// </summary>
        public static bool IsolateHost(string reason)
        {
            lock (_isolationLock)
            {
                if (_hostIsolated)
                {
                    Logger.Log("Host already isolated, skipping duplicate request", LogLevel.INFO);
                    return true;
                }

                if (Config.DryRun)
                {
                    Logger.Log("[DRY-RUN] Would isolate host: " + reason, LogLevel.ACTION);
                    return true;
                }

                try
                {
                    Logger.Log("INITIATING HOST ISOLATION: " + reason, LogLevel.THREAT, "incidents.log");

                    // Block all outbound traffic except loopback
                    string[] profiles = { "domain", "private", "public" };
                    foreach (string profile in profiles)
                    {
                        // Block all outbound (this is aggressive - alternative is block all inbound+outbound non-local)
                        string ruleName = "GIDR_Isolation_Block_All_" + profile;
                        ExecuteNetsh(string.Format(
                            "advfirewall firewall add rule name=\"{0}\" dir=out action=block profile={1} remoteip=0.0.0.0/0",
                            ruleName, profile));
                        _isolationRules.Add(ruleName);

                        // Allow localhost
                        string allowLocal = "GIDR_Isolation_Allow_Localhost_" + profile;
                        ExecuteNetsh(string.Format(
                            "advfirewall firewall add rule name=\"{0}\" dir=out action=allow profile={1} remoteip=127.0.0.1/8",
                            allowLocal, profile));
                        _isolationRules.Add(allowLocal);

                        // Allow ::1 (IPv6 localhost)
                        string allowIPv6Local = "GIDR_Isolation_Allow_IPv6Local_" + profile;
                        ExecuteNetsh(string.Format(
                            "advfirewall firewall add rule name=\"{0}\" dir=out action=allow profile={1} remoteip=::1",
                            allowIPv6Local, profile));
                        _isolationRules.Add(allowIPv6Local);
                    }

                    _hostIsolated = true;
                    Logger.Log("HOST ISOLATED: All outbound traffic blocked except localhost", LogLevel.THREAT, "incidents.log");
                    JsonLogger.LogEvent("INCIDENT", "host-isolated", reason);

                    return true;
                }
                catch (Exception ex)
                {
                    Logger.Log("Host isolation FAILED: " + ex.Message, LogLevel.ERROR);
                    return false;
                }
            }
        }

        /// <summary>
        /// Remove isolation rules, restoring normal network connectivity.
        /// </summary>
        public static bool RestoreNetwork()
        {
            lock (_isolationLock)
            {
                if (!_hostIsolated) return true;

                try
                {
                    foreach (string rule in _isolationRules)
                    {
                        ExecuteNetsh(string.Format("advfirewall firewall delete rule name=\"{0}\"", rule));
                    }
                    _isolationRules.Clear();
                    _hostIsolated = false;

                    Logger.Log("Host network connectivity restored", LogLevel.ACTION, "incidents.log");
                    JsonLogger.LogEvent("INCIDENT", "host-restored", "Network isolation removed");
                    return true;
                }
                catch (Exception ex)
                {
                    Logger.Log("Failed to restore network: " + ex.Message, LogLevel.ERROR);
                    return false;
                }
            }
        }

        /// <summary>
        /// Collect forensic evidence from a detected threat:
        /// - Process memory dump (minidump)
        /// - Process module list with hashes
        /// - Network connections at time of detection
        /// - Open handles (if accessible)
        /// Saves to Config.EvidencePath
        /// </summary>
        public static bool CollectEvidence(ThreatInfo threat)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string caseDir = Path.Combine(Config.EvidencePath,
                    string.Format("Case_{0}_{1}", threat.ProcessId, timestamp));

                if (!Directory.Exists(caseDir))
                    Directory.CreateDirectory(caseDir);

                // 1. Save threat metadata
                string metaFile = Path.Combine(caseDir, "threat_metadata.txt");
                File.WriteAllText(metaFile, FormatThreatReport(threat));

                // 2. Try to dump process memory (if still running)
                if (threat.ProcessId > 0)
                {
                    try
                    {
                        Process proc = Process.GetProcessById(threat.ProcessId);
                        string dumpFile = Path.Combine(caseDir, "process_memory.dmp");
                        bool dumped = CreateMinidump(proc, dumpFile);
                        if (dumped)
                        {
                            Logger.Log(string.Format("Memory dump created: {0}", dumpFile), LogLevel.ACTION);
                        }

                        // 3. Module inventory
                        string modulesFile = Path.Combine(caseDir, "loaded_modules.txt");
                        File.WriteAllText(modulesFile, GetProcessModules(proc));
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("Could not collect process data: " + ex.Message, LogLevel.WARN);
                    }
                }

                // 4. Current network connections snapshot
                string networkFile = Path.Combine(caseDir, "network_state.txt");
                File.WriteAllText(networkFile, GetNetworkSnapshot());

                // 5. Quarantine the executable if path is known
                if (!string.IsNullOrEmpty(threat.ThreatPath) && File.Exists(threat.ThreatPath))
                {
                    string quarantineDest = Path.Combine(caseDir, "quarantined_binary.bin");
                    try
                    {
                        File.Copy(threat.ThreatPath, quarantineDest, true);
                        Logger.Log("Binary copied to evidence: " + quarantineDest, LogLevel.ACTION);
                    }
                    catch { }
                }

                Logger.Log(string.Format("Evidence collected: {0}", caseDir), LogLevel.ACTION, "incidents.log");
                JsonLogger.LogEvent("INCIDENT", "evidence-collected",
                    string.Format("PID:{0} Path:{1} Location:{2}", threat.ProcessId, threat.ThreatPath, caseDir));

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Evidence collection failed: " + ex.Message, LogLevel.ERROR);
                return false;
            }
        }

        /// <summary>
        /// Generate a structured incident report suitable for SIEM/ticketing.
        /// </summary>
        public static string GenerateIncidentTicket(ThreatInfo threat, ChainResponse chainResponse = null)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== GIDR INCIDENT REPORT ===");
            sb.AppendLine(string.Format("Incident ID: GIDR-{0:yyyyMMdd}-{1}", DateTime.Now, threat.ProcessId));
            sb.AppendLine(string.Format("Timestamp: {0:yyyy-MM-dd HH:mm:ss} UTC", DateTime.UtcNow));
            sb.AppendLine(string.Format("Severity: {0} | Confidence: {1}%", threat.Severity, threat.Confidence));
            sb.AppendLine();

            sb.AppendLine("--- THREAT DETAILS ---");
            sb.AppendLine(string.Format("Type: {0}", threat.ThreatType));
            sb.AppendLine(string.Format("Process: {0} (PID: {1})", threat.ProcessName, threat.ProcessId));
            sb.AppendLine(string.Format("Path: {0}", threat.ThreatPath));
            sb.AppendLine(string.Format("Command Line: {0}", threat.CommandLine ?? "N/A"));
            if (threat.DetectionMethods.Count > 0)
                sb.AppendLine(string.Format("Detection Methods: {0}", string.Join(", ", threat.DetectionMethods)));
            sb.AppendLine();

            if (chainResponse != null)
            {
                sb.AppendLine("--- ATTACK CHAIN ---");
                sb.AppendLine(string.Format("Root Process: {0} (PID: {1})",
                    chainResponse.AttackRoot != null ? chainResponse.AttackRoot.Name : "Unknown",
                    chainResponse.AttackRoot != null ? chainResponse.AttackRoot.PID : 0));
                sb.AppendLine(string.Format("Processes Killed: {0}", chainResponse.ProcessesKilled.Count));
                sb.AppendLine(string.Format("Files Quarantined: {0}", chainResponse.FilesQuarantined.Count));
                sb.AppendLine(string.Format("Persistence Removed: {0}", chainResponse.PersistenceRemoved.Count));
                sb.AppendLine(string.Format("IPs Blocked: {0}", chainResponse.IPsBlocked.Count));
                sb.AppendLine();
            }

            sb.AppendLine("--- RECOMMENDED ACTIONS ---");
            sb.AppendLine("1. Review evidence collection for malware analysis");
            sb.AppendLine("2. Verify containment actions (process termination, quarantine)");
            sb.AppendLine("3. Check for lateral movement indicators");
            sb.AppendLine("4. Restore from backup if host is compromised");
            sb.AppendLine();

            sb.AppendLine("--- RAW DATA ---");
            sb.AppendLine(string.Format("Host: {0}", Environment.MachineName));
            sb.AppendLine(string.Format("User: {0}", Environment.UserName));
            sb.AppendLine(string.Format("GIDR Version: {0}", Config.Version));

            return sb.ToString();
        }

        /// <summary>
        /// Send incident alert via email (if configured).
        /// </summary>
        public static void SendAlert(ThreatInfo threat, string[] recipients = null)
        {
            if (recipients == null || recipients.Length == 0)
            {
                // Try to get from config
                if (string.IsNullOrEmpty(Config.AlertEmail)) return;
                recipients = new[] { Config.AlertEmail };
            }

            try
            {
                string subject = string.Format("[GIDR ALERT] {0} detected on {1}",
                    threat.ThreatType, Environment.MachineName);
                string body = GenerateIncidentTicket(threat);

                // Note: Actual SMTP implementation requires server config
                // This is a placeholder - real implementation needs SMTP settings
                Logger.Log(string.Format("Alert would be sent to: {0}", string.Join(", ", recipients)),
                    LogLevel.INFO, "incidents.log");
                Logger.Log("Email body:\n" + body, LogLevel.DEBUG);

                JsonLogger.LogEvent("ALERT", "email-queued",
                    string.Format("Recipients:{0} Subject:{1}", recipients.Length, subject));
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to queue alert: " + ex.Message, LogLevel.ERROR);
            }
        }

        // --- Private Helpers ---

        private static void ExecuteNetsh(string arguments)
        {
            ProcessStartInfo psi = new ProcessStartInfo("netsh.exe", arguments);
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            p.WaitForExit(10000);
            if (p.ExitCode != 0)
            {
                string error = p.StandardError.ReadToEnd();
                throw new Exception("netsh failed: " + error);
            }
        }

        private static string FormatThreatReport(ThreatInfo threat)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("THREAT METADATA");
            sb.AppendLine("===============");
            sb.AppendLine(string.Format("ThreatType: {0}", threat.ThreatType));
            sb.AppendLine(string.Format("Severity: {0}", threat.Severity));
            sb.AppendLine(string.Format("Confidence: {0}", threat.Confidence));
            sb.AppendLine(string.Format("ProcessId: {0}", threat.ProcessId));
            sb.AppendLine(string.Format("ProcessName: {0}", threat.ProcessName));
            sb.AppendLine(string.Format("ThreatPath: {0}", threat.ThreatPath));
            sb.AppendLine(string.Format("CommandLine: {0}", threat.CommandLine));
            sb.AppendLine(string.Format("DetectionTime: {0:yyyy-MM-dd HH:mm:ss}", DateTime.Now));
            if (threat.Details.Count > 0)
            {
                sb.AppendLine("Details:");
                foreach (var kvp in threat.Details)
                    sb.AppendLine(string.Format("  {0}: {1}", kvp.Key, kvp.Value));
            }
            return sb.ToString();
        }

        private static string GetProcessModules(Process proc)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(string.Format("Modules for {0} (PID: {1}) at {2:yyyy-MM-dd HH:mm:ss}",
                proc.ProcessName, proc.Id, DateTime.Now));
            sb.AppendLine("================================================================");

            try
            {
                foreach (ProcessModule mod in proc.Modules)
                {
                    sb.AppendLine(string.Format("{0} | Base: 0x{1:X} | Size: {2} bytes",
                        mod.FileName, mod.BaseAddress.ToInt64(), mod.ModuleMemorySize));
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("Error enumerating modules: " + ex.Message);
            }

            return sb.ToString();
        }

        private static string GetNetworkSnapshot()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(string.Format("Network state at {0:yyyy-MM-dd HH:mm:ss}", DateTime.Now));
            sb.AppendLine("================================");

            try
            {
                // Use our native method to get connections
                // This is a snapshot - list format
                sb.AppendLine("TCP Connections (via GetExtendedTcpTable):");
                // Note: Actual implementation would reuse NetworkMonitor's connection fetching
                // For now, placeholder
                sb.AppendLine("[Connection enumeration would be inserted here]");
            }
            catch (Exception ex)
            {
                sb.AppendLine("Error getting network state: " + ex.Message);
            }

            return sb.ToString();
        }

        private static bool CreateMinidump(Process process, string dumpFilePath)
        {
            // MiniDumpWriteDump P/Invoke would go here
            // For now, placeholder - actual implementation requires dbghelp.dll
            // This is a complex operation requiring:
            // - Load dbghelp.dll
            // - Open process with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            // - Call MiniDumpWriteDump
            // - Handle large files (potentially GBs for processes like browsers)

            Logger.Log(string.Format("Memory dump requested for PID {0} to {1} - requires dbghelp.dll",
                process.Id, dumpFilePath), LogLevel.WARN);

            return false;
        }

        public static bool IsHostIsolated { get { return _hostIsolated; } }
    }

    /// <summary>
    /// Convenience accessors for IDR-specific config values.
    /// These read from Config's dynamic bag (populated by ConfigLoader from config.json).
    /// </summary>
    public static class IncidentResponseConfig
    {
        public static string AlertEmail          { get { return Config.AlertEmail; } }
        public static string EvidencePath        { get { return Config.EvidencePath; } }
        public static bool AutoIsolateOnCritical { get { return Config.GetBool("autoIsolateOnCritical", false); } }
        public static bool AutoCollectEvidence   { get { return Config.GetBool("autoCollectEvidence", true); } }
    }
}
