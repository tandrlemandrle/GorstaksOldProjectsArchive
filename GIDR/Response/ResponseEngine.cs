using System;
using System.IO;
using GIDR.Core;

namespace GIDR.Response
{
    /// <summary>
    /// Processes the threat response queue: quarantine, kill, block, log.
    /// Ported from Invoke-ResponseEngine / Invoke-ResponseAction.
    /// </summary>
    public static class ResponseEngine
    {
        private const int MaxPerTick = 50;

        public static void Execute()
        {
            int processed = 0;
            while (ResponseQueue.Count > 0 && processed < MaxPerTick)
            {
                ThreatInfo threat = ResponseQueue.Dequeue();
                if (threat == null) break;

                try
                {
                    ProcessThreat(threat);
                    processed++;
                }
                catch (Exception ex)
                {
                    Logger.Log("ResponseEngine error: " + ex.Message, LogLevel.ERROR);
                }
            }

            if (processed > 0)
                Logger.Log(string.Format("ResponseEngine: processed {0} threat(s), queue: {1}", processed, ResponseQueue.Count));
        }

        private static void ProcessThreat(ThreatInfo threat)
        {
            Logger.Log(string.Format("RESPONSE: {0} | {1} | {2} | confidence:{3}",
                threat.ThreatType,
                threat.ThreatPath ?? threat.ProcessName ?? "N/A",
                threat.Severity,
                threat.Confidence), LogLevel.THREAT, "response_engine.log");

            // Auto-respond to active intrusions (processes caught in the act):
            // - C2/NetworkAnomaly: reverse shells, beaconing, suspicious connections
            // - Fileless: encoded PowerShell, in-memory execution
            // - DownloadCradle: download-and-execute patterns (IEX, etc)
            // - ReflectiveDll: memory-only DLL injection
            // - ProcessHollowing: hollowed process injection
            // - AudioHijack: microphone access by unknown processes
            // - CredentialDump: LSASS/SAM credential dumping (mimikatz, procdump, etc)
            // - Persistence: registry/WMI persistence mechanisms

            bool isIntrusion = IsIntrusionThreat(threat.ThreatType);

            switch (threat.Severity)
            {
                case ThreatSeverity.Critical:
                    if (isIntrusion)
                    {
                        // IDR: Collect evidence FIRST (before we kill the process)
                        if (IncidentResponseConfig.AutoCollectEvidence)
                        {
                            IncidentResponse.CollectEvidence(threat);
                        }

                        // Intrusion threats get full response - kill the attack chain
                        ChainResponse chainResult = ChainTracer.TraceAndNuke(threat);
                        Logger.Log(string.Format("ChainTrace: killed={0} quarantined={1} persistence={2} ips={3}",
                            chainResult.ProcessesKilled.Count,
                            chainResult.FilesQuarantined.Count,
                            chainResult.PersistenceRemoved.Count,
                            chainResult.IPsBlocked.Count), LogLevel.THREAT, "response_engine.log");

                        // IDR: Generate incident ticket
                        string ticket = IncidentResponse.GenerateIncidentTicket(threat, chainResult);
                        Logger.Log("Incident ticket generated:\n" + ticket, LogLevel.THREAT, "incidents.log");

                        // IDR: Host isolation for critical intrusions (if enabled)
                        if (IncidentResponseConfig.AutoIsolateOnCritical && !IncidentResponse.IsHostIsolated)
                        {
                            IncidentResponse.IsolateHost(string.Format("Critical intrusion: {0} in {1}",
                                threat.ThreatType, threat.ProcessName));
                        }

                        // IDR: Send alert
                        IncidentResponse.SendAlert(threat);
                    }
                    WriteAlert(threat);
                    break;

                case ThreatSeverity.High:
                    if (isIntrusion)
                    {
                        // High severity intrusion — trace and nuke
                        ChainResponse chainResult = ChainTracer.TraceAndNuke(threat);
                        Logger.Log(string.Format("ChainTrace: killed={0} quarantined={1} persistence={2} ips={3}",
                            chainResult.ProcessesKilled.Count,
                            chainResult.FilesQuarantined.Count,
                            chainResult.PersistenceRemoved.Count,
                            chainResult.IPsBlocked.Count), LogLevel.THREAT, "response_engine.log");
                    }
                    WriteAlert(threat);
                    break;

                case ThreatSeverity.Medium:
                    // Log only — not confident enough to trace-and-nuke
                    break;

                case ThreatSeverity.Low:
                    break;
            }
        }

        private static bool IsIntrusionThreat(string threatType)
        {
            if (string.IsNullOrEmpty(threatType)) return false;

            // All threat types that warrant a full chain trace + nuke response.
            // Previously only behavioralTypes was iterated — intrusionTypes was declared
            // but never checked, so NetworkAnomaly, Fileless, DownloadCradle, etc. never
            // triggered ChainTracer.TraceAndNuke. Both arrays are now merged into one.
            string[] intrusionTypes = new string[]
            {
                "NetworkAnomaly",       // Reverse shells, C2 beaconing
                "Fileless",             // Encoded PS, in-memory execution
                "DownloadCradle",       // IEX / download-and-execute
                "ReflectiveDll",        // Memory-only DLL injection
                "ProcessHollowing",     // Hollowed process injection
                "AudioHijack",          // Microphone access by unknown process
                "CredentialDump",       // LSASS/SAM dumping
                "RenamedLOLBin",        // LOLBin renamed to evade detection
                "CommandLine",          // High-score command-line behavioral match
                "etw-threat",           // ETW-sourced behavioral detection
                "Ransomware",           // Mass file modification / encryption
                "RegistryPersistence",  // Run key / registry persistence
                "WMIPersistence",       // WMI subscription persistence
            };

            for (int i = 0; i < intrusionTypes.Length; i++)
            {
                if (threatType.IndexOf(intrusionTypes[i], StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private static void WriteAlert(ThreatInfo threat)
        {
            try
            {
                System.Diagnostics.EventLog.WriteEntry(Config.EDRName,
                    string.Format("THREAT: {0} - {1} (Severity: {2})",
                        threat.ThreatType,
                        threat.ThreatPath ?? threat.ProcessName ?? "N/A",
                        threat.Severity),
                    System.Diagnostics.EventLogEntryType.Warning, 2000);
            }
            catch { }
        }
    }
}
