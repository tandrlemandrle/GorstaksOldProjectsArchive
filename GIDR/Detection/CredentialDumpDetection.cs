using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Detection
{
    /// <summary>
    /// Detects credential dumping attempts:
    /// - LSASS access (mimikatz, procdump, comsvcs.dll, etc)
    /// - SAM hive dumping
    /// - Security Account Manager access
    /// </summary>
    public static class CredentialDumpDetection
    {
        private static readonly HashSet<string> _dumpingTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "mimikatz", "mimidrv", "mimilib",
            "procdump", "procdump64",
            "comsvcs", "comsvcs.dll",
            "lsadump", "ntdsutil",
            "pwdump", "fgdump", "cachedump",
            "gsecdump", "quarkspwdump",
            "wce", "wceaux", "windows credential editor",
            "secretsdump", "pypykatz",
            "hashdump", "dcsync"
        };

        private static readonly HashSet<string> _suspiciousModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "dbghelp.dll", "dbgcore.dll"  // Used for memory dumping
        };

        public static void Detect()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            Process[] procs = Process.GetProcesses();

            for (int i = 0; i < procs.Length; i++)
            {
                if (procs[i].Id == selfPid || procs[i].Id <= 4) continue;

                try
                {
                    string procName = procs[i].ProcessName.ToLowerInvariant();
                    string exePath = "";
                    try { exePath = procs[i].MainModule.FileName; } catch { }

                    // Check process name against known dumping tools
                    foreach (string tool in _dumpingTools)
                    {
                        if (procName.Contains(tool) || exePath.ToLowerInvariant().Contains(tool))
                        {
                            EnqueueThreat("CredentialDump:Tool", procs[i], exePath, 95, "Known credential dumping tool: " + tool);
                            break;
                        }
                    }

                    // Check for LSASS handles (simplified check - in production you'd use NtQuerySystemInformation)
                    CheckLsassAccess(procs[i], exePath);
                }
                catch { }
            }
        }

        private static void CheckLsassAccess(Process proc, string exePath)
        {
            try
            {
                // Get process modules to check for suspicious DLLs loaded
                ProcessModuleCollection modules = proc.Modules;
                for (int i = 0; i < modules.Count; i++)
                {
                    string modName = modules[i].ModuleName.ToLowerInvariant();
                    if (_suspiciousModules.Contains(modName))
                    {
                        // Suspicious debugging DLL loaded - possible memory dumping
                        if (!IsLegitimateDebugger(proc.ProcessName, exePath))
                        {
                            EnqueueThreat("CredentialDump:MemoryAccess", proc, exePath, 80,
                                "Suspicious memory debugging module: " + modName);
                        }
                        break;
                    }
                }

                // Check command line for LSASS dumping patterns
                string cmdLine = GetCommandLine(proc);
                if (!string.IsNullOrEmpty(cmdLine))
                {
                    string cmdLower = cmdLine.ToLowerInvariant();
                    if (cmdLower.Contains("lsass") || 
                        cmdLower.Contains("minidump") ||
                        cmdLower.Contains("full dump") ||
                        (cmdLower.Contains("comsvcs") && cmdLower.Contains("minidump")) ||
                        cmdLower.Contains("sekurlsa") ||
                        cmdLower.Contains("kerberos::list") ||
                        cmdLower.Contains("privilege::debug"))
                    {
                        EnqueueThreat("CredentialDump:LSASS", proc, exePath, 90,
                            "LSASS credential dumping command pattern detected");
                    }
                }
            }
            catch { }
        }

        private static bool IsLegitimateDebugger(string procName, string exePath)
        {
            string[] legit = new string[] { "vsjitdebugger", "devenv", "wdexpress", "cdb", "windbg", "gdb" };
            string check = (procName + " " + exePath).ToLowerInvariant();
            for (int i = 0; i < legit.Length; i++)
                if (check.Contains(legit[i])) return true;
            return false;
        }

        private static string GetCommandLine(Process proc)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    string.Format("SELECT CommandLine FROM Win32_Process WHERE ProcessId = {0}", proc.Id)))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        string cmd = obj["CommandLine"] as string;
                        if (!string.IsNullOrEmpty(cmd)) return cmd;
                    }
                }
            }
            catch { }
            return "";
        }

        private static void EnqueueThreat(string type, Process proc, string exePath, int confidence, string details)
        {
            Logger.Log(string.Format("CREDENTIAL DUMP: {0} PID:{1} | {2}",
                proc.ProcessName, proc.Id, details),
                LogLevel.THREAT, "credential_dump.log");

            GidrState.IncrementThreats();

            ThreatInfo threat = new ThreatInfo();
            threat.ThreatType = type;
            threat.ThreatPath = exePath;
            threat.ProcessId = proc.Id;
            threat.ProcessName = proc.ProcessName;
            threat.Severity = ThreatSeverity.Critical;
            threat.Confidence = confidence;
            threat.Details["DetectionReason"] = details;

            ResponseQueue.Enqueue(threat);
        }
    }
}
