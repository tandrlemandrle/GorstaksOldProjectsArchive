using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using GEdr.Core;
using GEdr.Response;
using Microsoft.Win32;

namespace GEdr.Detection
{
    /// <summary>
    /// Detects account manipulation techniques:
    /// - ms-cxh / ms-cxh-full protocol handler abuse (OOBE hijacking)
    /// - COM auto-approval list tampering (UAC bypass)
    /// - rundll32/dllhost invoking suspicious GUIDs (WinDeploy, credential theft)
    /// - UserOOBEBroker.exe spawning unexpectedly
    /// - Credential provider manipulation
    /// 
    /// MITRE ATT&CK: T1098 (Account Manipulation), T1548.002 (UAC Bypass),
    ///               T1218.011 (Rundll32), T1546 (Event Triggered Execution)
    /// </summary>
    public static class AccountTamperDetection
    {
        // Known suspicious GUIDs used in COM auto-approval / UAC bypass attacks
        private static readonly string[][] _suspiciousGuids = new string[][]
        {
            new string[] { "ca8c87c1-929d-45ba-94db-ef8e6cb346ad", "WinDeploy COM object", "T1548.002" },
            new string[] { "3e5fc7f9-9a51-4367-9063-a120244fbec7", "EventVwr UAC bypass", "T1548.002" },
            new string[] { "0a29ff9e-7f9c-4437-8b11-f424491e3931", "CMSTPLUA UAC bypass", "T1548.002" },
            new string[] { "9ba05972-f6a8-11cf-a442-00a0c90a8f39", "ShellWindows COM", "T1218.011" },
            new string[] { "c08afd90-f2a1-11d1-8455-00a0c91f3880", "ShellBrowserWindow", "T1218.011" },
            new string[] { "9ac9fbe1-e0a2-4ad6-b4ee-e212013ea917", "CLSID UAC bypass (sdclt)", "T1548.002" },
            new string[] { "e9495b87-d950-4ab5-87a5-ff6d70ce3c4c", "Elevation:Administrator COM", "T1548.002" },
            new string[] { "d2e7025f-2709-4519-8078-5cfe7a0af8fd", "ICMLuaUtil UAC bypass", "T1548.002" },
            new string[] { "3ad05575-8857-4850-9277-11b85bdb8e09", "ColorDataProxy UAC bypass", "T1548.002" },
            new string[] { "bdb57ff2-79b9-4205-9447-f5fe85f37312", "ieinstal.exe COM", "T1548.002" },
        };

        // ms-cxh strings that are suspicious when invoked outside of normal OOBE
        private static readonly string[] _suspiciousCxhStrings = new string[]
        {
            "ms-cxh://SETADDNEWUSER",
            "ms-cxh://SETCHANGEPWD",
            "ms-cxh://AADWEBAUTH",
            "ms-cxh://NTHAADNGCRESET",
            "ms-cxh://NTHAADNGCRESETDESTRUCTIVE",
            "ms-cxh://NTHENTNGCRESET",
            "ms-cxh://NTHENTNGCRESETDESTRUCTIVE",
            "ms-cxh://MSAPINRESET",
            "ms-cxh://MSACFLPINRESET",
            "ms-cxh-full://",
        };

        /// <summary>
        /// Monitor for ms-cxh protocol handler abuse.
        /// Detects processes invoking OOBE/credential dialogs unexpectedly.
        /// </summary>
        public static void ProtocolHandlerAbuse()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;
                if (string.IsNullOrEmpty(proc.CommandLine)) continue;

                string cmdLower = proc.CommandLine.ToLowerInvariant();

                // Check for ms-cxh protocol invocations
                for (int c = 0; c < _suspiciousCxhStrings.Length; c++)
                {
                    if (cmdLower.Contains(_suspiciousCxhStrings[c].ToLowerInvariant()))
                    {
                        Logger.Log(string.Format(
                            "ACCOUNT TAMPER: ms-cxh protocol handler invoked: {0} (PID:{1}) cmd: {2}",
                            proc.Name, proc.ProcessId, proc.CommandLine),
                            LogLevel.THREAT, "account_tamper.log");
                        EdrState.IncrementThreats();
                        JsonLogger.LogThreat("AccountTamper:ms-cxh", proc.ExecutablePath,
                            null, 85, "CRITICAL", "Critical", "T1098",
                            "ms-cxh protocol handler abuse: " + _suspiciousCxhStrings[c]);

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "AccountTamper:ProtocolHandler";
                        threat.ThreatPath = proc.ExecutablePath;
                        threat.Severity = ThreatSeverity.Critical;
                        threat.ProcessId = proc.ProcessId;
                        threat.ProcessName = proc.Name;
                        threat.CommandLine = proc.CommandLine;
                        threat.Confidence = 85;
                        threat.Details["Protocol"] = _suspiciousCxhStrings[c];
                        ResponseQueue.Enqueue(threat);

                        // Kill the OOBE broker to prevent account manipulation
                        if (Config.AutoKillThreats && !Config.DryRun)
                        {
                            ThreatActions.TerminateProcess(proc.ProcessId, proc.Name);
                        }
                        break;
                    }
                }

                // Check for UserOOBEBroker.exe spawning outside of normal boot
                string name = (proc.Name ?? "").ToLowerInvariant();
                if (name == "useroobobroker.exe" || name == "useroobe broker.exe")
                {
                    // Check if system has been up for more than 10 minutes (not a fresh boot)
                    TimeSpan uptime = TimeSpan.FromMilliseconds(Environment.TickCount);
                    if (uptime.TotalMinutes > 10)
                    {
                        Logger.Log(string.Format(
                            "ACCOUNT TAMPER: UserOOBEBroker.exe running outside of boot (uptime: {0})",
                            uptime.ToString(@"d\.hh\:mm")),
                            LogLevel.THREAT, "account_tamper.log");
                        EdrState.IncrementThreats();
                    }
                }
            }
        }

        /// <summary>
        /// Monitor COM auto-approval list for UAC bypass attempts.
        /// Attackers add GUIDs to COMAutoApprovalList to elevate without UAC prompt.
        /// </summary>
        public static void COMAutoApprovalMonitor()
        {
            try
            {
                string keyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath, false))
                {
                    if (key == null) return;

                    string[] values = key.GetValueNames();
                    for (int v = 0; v < values.Length; v++)
                    {
                        string guidStr = values[v].ToLowerInvariant().Trim('{', '}');

                        // Check against known malicious GUIDs
                        for (int g = 0; g < _suspiciousGuids.Length; g++)
                        {
                            if (guidStr.Contains(_suspiciousGuids[g][0]))
                            {
                                object val = key.GetValue(values[v]);
                                // Value of 1 means auto-approved (bypass UAC)
                                if (val != null && val.ToString() != "0")
                                {
                                    Logger.Log(string.Format(
                                        "UAC BYPASS: COM auto-approval list contains suspicious GUID: {0} ({1}) [{2}]",
                                        values[v], _suspiciousGuids[g][1], _suspiciousGuids[g][2]),
                                        LogLevel.THREAT, "account_tamper.log");
                                    EdrState.IncrementThreats();
                                    JsonLogger.LogThreat("UACBypass:COMAutoApproval", values[v],
                                        null, 90, "CRITICAL", "Critical", _suspiciousGuids[g][2],
                                        _suspiciousGuids[g][1]);

                                    // Remove the malicious entry
                                    if (Config.AutoKillThreats && !Config.DryRun)
                                    {
                                        try
                                        {
                                            using (RegistryKey writeKey = Registry.LocalMachine.OpenSubKey(keyPath, true))
                                            {
                                                if (writeKey != null)
                                                {
                                                    writeKey.DeleteValue(values[v], false);
                                                    Logger.Log(string.Format("Removed malicious COM auto-approval: {0}", values[v]),
                                                        LogLevel.ACTION);
                                                }
                                            }
                                        }
                                        catch { }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Detect rundll32.exe and dllhost.exe invoking suspicious GUIDs.
        /// Attackers use these to load COM objects for UAC bypass, credential theft,
        /// or to invoke WinDeploy functionality.
        /// </summary>
        public static void SuspiciousGuidExecution()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;
                if (string.IsNullOrEmpty(proc.CommandLine)) continue;

                string name = (proc.Name ?? "").ToLowerInvariant();
                if (name != "rundll32.exe" && name != "dllhost.exe" && name != "mmc.exe") continue;

                string cmdLower = proc.CommandLine.ToLowerInvariant();

                // Check for suspicious GUIDs in command line
                for (int g = 0; g < _suspiciousGuids.Length; g++)
                {
                    if (cmdLower.Contains(_suspiciousGuids[g][0]))
                    {
                        Logger.Log(string.Format(
                            "SUSPICIOUS GUID: {0} (PID:{1}) invoking {2} ({3}) [{4}]",
                            proc.Name, proc.ProcessId, _suspiciousGuids[g][0],
                            _suspiciousGuids[g][1], _suspiciousGuids[g][2]),
                            LogLevel.THREAT, "account_tamper.log");
                        EdrState.IncrementThreats();
                        JsonLogger.LogThreat("SuspiciousGUID", proc.ExecutablePath,
                            null, 80, "CRITICAL", "Critical", _suspiciousGuids[g][2],
                            string.Format("{0} via {1}", _suspiciousGuids[g][1], proc.Name));

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "SuspiciousGUID:" + _suspiciousGuids[g][1];
                        threat.ThreatPath = proc.ExecutablePath;
                        threat.Severity = ThreatSeverity.Critical;
                        threat.ProcessId = proc.ProcessId;
                        threat.ProcessName = proc.Name;
                        threat.CommandLine = proc.CommandLine;
                        threat.Confidence = 80;
                        threat.Details["GUID"] = _suspiciousGuids[g][0];
                        threat.Details["Technique"] = _suspiciousGuids[g][1];
                        ResponseQueue.Enqueue(threat);

                        if (Config.AutoKillThreats && !Config.DryRun)
                            ThreatActions.TerminateProcess(proc.ProcessId, proc.Name);
                        break;
                    }
                }

                // Also flag dllhost.exe with /Processid: containing any unknown GUID
                // that isn't in the Windows standard set
                if (name == "dllhost.exe" && cmdLower.Contains("/processid:"))
                {
                    Match guidMatch = Regex.Match(proc.CommandLine,
                        @"/Processid:\{?([0-9a-fA-F\-]{36})\}?", RegexOptions.IgnoreCase);
                    if (guidMatch.Success)
                    {
                        string guid = guidMatch.Groups[1].Value.ToLowerInvariant();
                        // Check if it's a known-good Windows GUID
                        if (!IsKnownGoodDllHostGuid(guid))
                        {
                            Logger.Log(string.Format(
                                "Unknown dllhost GUID: {0} (PID:{1}) GUID:{2}",
                                proc.Name, proc.ProcessId, guid),
                                LogLevel.WARN, "account_tamper.log");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Monitor credential provider registry keys for tampering.
        /// Attackers can register malicious credential providers to intercept passwords.
        /// </summary>
        public static void CredentialProviderMonitor()
        {
            try
            {
                string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath, false))
                {
                    if (key == null) return;

                    string[] subkeys = key.GetSubKeyNames();
                    for (int s = 0; s < subkeys.Length; s++)
                    {
                        using (RegistryKey provider = key.OpenSubKey(subkeys[s]))
                        {
                            if (provider == null) continue;
                            string defaultVal = (provider.GetValue("") ?? "").ToString();

                            // Check if the credential provider DLL exists in a non-standard path
                            string clsidPath = string.Format(@"CLSID\{0}\InprocServer32", subkeys[s]);
                            using (RegistryKey clsid = Registry.ClassesRoot.OpenSubKey(clsidPath))
                            {
                                if (clsid == null) continue;
                                string dllPath = (clsid.GetValue("") ?? "").ToString();
                                if (string.IsNullOrEmpty(dllPath)) continue;

                                // Expand environment variables
                                dllPath = Environment.ExpandEnvironmentVariables(dllPath);

                                // Flag if DLL is not in System32
                                if (!string.IsNullOrEmpty(dllPath) &&
                                    !dllPath.ToLowerInvariant().Contains(@"\windows\system32") &&
                                    !dllPath.ToLowerInvariant().Contains(@"\windows\syswow64"))
                                {
                                    Logger.Log(string.Format(
                                        "SUSPICIOUS credential provider: {0} ({1}) DLL: {2}",
                                        subkeys[s], defaultVal, dllPath),
                                        LogLevel.THREAT, "account_tamper.log");
                                    EdrState.IncrementThreats();
                                    JsonLogger.LogThreat("CredentialProvider", dllPath,
                                        null, 90, "CRITICAL", "Critical", "T1556",
                                        "Non-standard credential provider: " + defaultVal);
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        // Known legitimate dllhost GUIDs (Windows standard COM objects)
        private static readonly HashSet<string> _knownGoodGuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "3eb3c877-1f16-487c-9050-104dbcd66683", // Windows Photo Viewer
            "ab8902b4-09ca-4bb6-b78d-a8f59079a8d5", // Thumbnail cache
            "fbeb8a05-beee-4442-804e-409d6c4515e9", // Shell handler
            "73fddc80-aef2-4b1d-a07b-2601b172b4c7", // DXP task host
            "dab491c0-c1d9-11cf-a24e-00aa00c10000", // DCOM server
        };

        private static bool IsKnownGoodDllHostGuid(string guid)
        {
            return _knownGoodGuids.Contains(guid);
        }
    }
}
