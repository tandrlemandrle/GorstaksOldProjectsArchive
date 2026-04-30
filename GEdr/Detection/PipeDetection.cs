using System;
using System.Collections.Generic;
using System.IO;
using GEdr.Core;

namespace GEdr.Detection
{
    /// <summary>
    /// Monitors named pipes for indicators of C2 frameworks and lateral movement.
    /// 
    /// Cobalt Strike, Metasploit, Sliver, and other C2 tools create distinctive
    /// named pipes for communication. This is a high-signal, low-noise detection
    /// because legitimate software rarely creates pipes matching these patterns.
    /// 
    /// MITRE ATT&CK: T1570 (Lateral Tool Transfer), T1071 (Application Layer Protocol)
    /// </summary>
    public static class PipeDetection
    {
        // Known C2 framework pipe name patterns
        // These are well-documented indicators from threat intelligence
        private static readonly PipePattern[] _maliciousPipes = new PipePattern[]
        {
            // Cobalt Strike
            new PipePattern("MSSE-",           "Cobalt Strike default pipe",     "T1071", 80),
            new PipePattern("msagent_",        "Cobalt Strike SMB beacon",       "T1071", 80),
            new PipePattern("postex_",         "Cobalt Strike post-exploitation","T1071", 80),
            new PipePattern("postex_ssh_",     "Cobalt Strike SSH pivot",        "T1071", 80),
            new PipePattern("status_",         "Cobalt Strike status pipe",      "T1071", 70),
            new PipePattern("\\\\MSSE-",       "Cobalt Strike (UNC)",            "T1071", 80),

            // Metasploit / Meterpreter
            new PipePattern("meterpreter",     "Metasploit Meterpreter",         "T1071", 90),
            new PipePattern("msf_",            "Metasploit framework pipe",      "T1071", 85),

            // PsExec / Impacket
            new PipePattern("RemCom_",         "RemCom (PsExec alternative)",    "T1570", 70),
            new PipePattern("csexec",          "CsExec lateral movement",        "T1570", 75),

            // Mimikatz
            new PipePattern("mimikatz",        "Mimikatz credential tool",       "T1003", 90),

            // Sliver C2
            new PipePattern("sliver",          "Sliver C2 framework",            "T1071", 85),

            // Generic suspicious patterns
            new PipePattern("\\\\pipe\\\\evil",  "Suspicious pipe name",         "T1071", 60),
            new PipePattern("\\\\pipe\\\\shell", "Suspicious shell pipe",        "T1059", 50),
            new PipePattern("\\\\pipe\\\\cmd",   "Suspicious cmd pipe",          "T1059", 40),

            // Covenant C2
            new PipePattern("gruntsvc",        "Covenant C2 Grunt",              "T1071", 80),

            // Brute Ratel
            new PipePattern("\\\\pipe\\\\demoagent", "Brute Ratel default pipe", "T1071", 85),

            // WMI lateral movement
            new PipePattern("ahexec",          "WMIExec pipe",                   "T1047", 70),
        };

        // Known legitimate pipes to ignore (reduce false positives)
        private static readonly HashSet<string> _knownGoodPipes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "InitShutdown", "lsass", "ntsvcs", "scerpc", "browser", "wkssvc",
            "srvsvc", "winreg", "netlogon", "samr", "spoolss", "epmapper",
            "LSM_API_service", "eventlog", "atsvc", "MsFteWds", "openssh-ssh-agent",
            "PIPE_EVENTROOT", "gecko-crash-server-pipe", "chrome.sync",
            "discord-ipc-0", "discord-ipc-1", "mojo", "crashpad",
            "LOCAL\\chrome", "LOCAL\\mojo", "LOCAL\\discord",
            "dotnet-diagnostic", "clrhost", "ProtectedPrefix",
        };

        /// <summary>Scan all named pipes on the system for C2 indicators.</summary>
        public static void ScanNamedPipes()
        {
            try
            {
                string pipePath = @"\\.\pipe\";
                if (!Directory.Exists(pipePath)) return;

                string[] pipes;
                try
                {
                    pipes = Directory.GetFiles(pipePath);
                }
                catch { return; }

                int suspicious = 0;
                for (int i = 0; i < pipes.Length; i++)
                {
                    string pipeName = Path.GetFileName(pipes[i]);
                    if (string.IsNullOrEmpty(pipeName)) continue;

                    // Skip known good
                    bool isKnown = false;
                    foreach (string good in _knownGoodPipes)
                    {
                        if (pipeName.IndexOf(good, StringComparison.OrdinalIgnoreCase) >= 0)
                        { isKnown = true; break; }
                    }
                    if (isKnown) continue;

                    // Check against malicious patterns
                    for (int p = 0; p < _maliciousPipes.Length; p++)
                    {
                        PipePattern pat = _maliciousPipes[p];
                        if (pipeName.IndexOf(pat.Pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            suspicious++;
                            Logger.Log(string.Format("Malicious named pipe: {0} ({1}) [{2}]",
                                pipeName, pat.Description, pat.MitreId),
                                LogLevel.THREAT, "pipe_detection.log");
                            EdrState.IncrementThreats();
                            JsonLogger.LogThreat("PipeDetection", pipeName, null,
                                pat.Score, "CRITICAL", "Critical", pat.MitreId, pat.Description);

                            ThreatInfo threat = new ThreatInfo();
                            threat.ThreatType = "MaliciousPipe:" + pat.Description;
                            threat.ThreatPath = pipeName;
                            threat.Severity = pat.Score >= 80 ? ThreatSeverity.Critical : ThreatSeverity.High;
                            threat.Confidence = pat.Score;
                            threat.Details["PipeName"] = pipeName;
                            threat.Details["Pattern"] = pat.Pattern;
                            ResponseQueue.Enqueue(threat);
                            break; // One match per pipe is enough
                        }
                    }
                }

                if (suspicious > 0)
                    Logger.Log(string.Format("PipeDetection: {0} suspicious pipes found", suspicious), LogLevel.THREAT);
            }
            catch (Exception ex)
            {
                Logger.Log("PipeDetection error: " + ex.Message, LogLevel.WARN);
            }
        }

        private class PipePattern
        {
            public string Pattern;
            public string Description;
            public string MitreId;
            public int Score;

            public PipePattern(string pattern, string desc, string mitre, int score)
            {
                Pattern = pattern;
                Description = desc;
                MitreId = mitre;
                Score = score;
            }
        }
    }
}
