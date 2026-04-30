using System;
using System.IO;
using GEdr.Core;

namespace GEdr.Response
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

            switch (threat.Severity)
            {
                case ThreatSeverity.Critical:
                    TryQuarantine(threat);
                    TryKillProcess(threat);
                    TryBlockNetwork(threat);
                    WriteAlert(threat);
                    break;

                case ThreatSeverity.High:
                    TryQuarantine(threat);
                    WriteAlert(threat);
                    break;

                case ThreatSeverity.Medium:
                    // Log only (already logged above)
                    break;

                case ThreatSeverity.Low:
                    break;
            }
        }

        private static void TryQuarantine(ThreatInfo threat)
        {
            if (string.IsNullOrEmpty(threat.ThreatPath)) return;
            if (!File.Exists(threat.ThreatPath)) return;
            ThreatActions.Quarantine(threat.ThreatPath, threat.ThreatType);
        }

        private static void TryKillProcess(ThreatInfo threat)
        {
            if (threat.ProcessId <= 0) return;
            ThreatActions.TerminateProcess(threat.ProcessId, threat.ProcessName);
        }

        private static void TryBlockNetwork(ThreatInfo threat)
        {
            if (string.IsNullOrEmpty(threat.ThreatPath)) return;
            // Extract IP from "ip:port" format
            string path = threat.ThreatPath;
            int colonIdx = path.LastIndexOf(':');
            string ip = (colonIdx > 0) ? path.Substring(0, colonIdx) : path;

            System.Net.IPAddress addr;
            if (System.Net.IPAddress.TryParse(ip, out addr))
                ThreatActions.BlockIP(ip);
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
