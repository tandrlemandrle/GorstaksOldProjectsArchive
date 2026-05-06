using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Detection
{
    /// <summary>
    /// Detects fileless malware execution and in-memory payload delivery.
    /// Catches: reflective DLL injection, process hollowing from memory,
    /// .NET in-memory loading, PowerShell download-cradle execution,
    /// and other "download + execute in memory" techniques.
    /// Ported from Invoke-FilelessDetection, Invoke-ReflectiveDLLInjectionDetection,
    /// Invoke-DownloadCradleDetection, Invoke-ShellcodeInjectionDetection.
    /// </summary>
    public static class MemoryExecutionDetection
    {
        private static readonly HashSet<string> _suspiciousParentForMemoryExec = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe",
            "wscript.exe", "cscript.exe", "msedge.exe", "chrome.exe", "firefox.exe",
            "iexplore.exe", "acrord32.exe", "acrobat.exe"
        };

        private static readonly HashSet<string> _suspiciousCmdPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "invoke-expression", "iex", "downloadstring", "downloadfile",
            "frombase64string", "tobase64string", "compressed", "gzipstream",
            "memorystream", "reflection.assembly", "load(", "::load(",
            "virtualalloc", "virtualprotect", "createremotethread",
            "writeprocessmemory", "readprocessmemory", "rtlmovememory",
            "memset", "copy(", "invoke-shellcode", "invoke-mimikatz",
            "invoke-bloodhound", "amsibypass", "etwbypass", "patch-amsi"
        };

        private static readonly HashSet<string> _suspiciousModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "clrjit.dll", "mscorlib.ni.dll", "system.management.automation.ni.dll"
        };

        private static readonly HashSet<string> _processedPids = new HashSet<string>();
        private static readonly object _processedPidsLock = new object();

        /// <summary>
        /// Main entry: detect all forms of in-memory execution.
        /// Called periodically by the monitor scheduler.
        /// </summary>
        public static void Detect()
        {
            FilelessExecution();
            DownloadCradle();
            ReflectiveDllInMemory();
            SuspiciousDotNetMemoryLoad();
            HollowFromMemory();
        }

        /// <summary>
        /// Detect fileless execution: processes with no backing file on disk
        /// or executing from non-standard locations.
        /// </summary>
        private static void FilelessExecution()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;

                string cacheKey = string.Format("{0}:{1}", proc.ProcessId, proc.Name);
                lock (_processedPidsLock)
                {
                    if (_processedPids.Contains(cacheKey)) continue;
                    _processedPids.Add(cacheKey);
                }

                try
                {
                    // Check if executable path is missing or suspicious
                    if (string.IsNullOrEmpty(proc.ExecutablePath))
                    {
                        // Process has no executable path - potentially injected/hollowed
                        Logger.Log(string.Format("Fileless execution: {0} PID:{1} has no executable path",
                            proc.Name, proc.ProcessId), LogLevel.THREAT, "memory_execution.log");
                        GidrState.IncrementThreats();

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "Fileless";
                        threat.ThreatPath = string.Format("pid:{0}", proc.ProcessId);
                        threat.Severity = ThreatSeverity.Critical;
                        threat.ProcessId = proc.ProcessId;
                        threat.ProcessName = proc.Name;
                        threat.Confidence = 80;
                        ResponseQueue.Enqueue(threat);
                        continue;
                    }

                    // Check if file doesn't exist on disk (running from memory only)
                    if (!File.Exists(proc.ExecutablePath))
                    {
                        Logger.Log(string.Format("Memory-only execution: {0} PID:{1} backing file missing: {2}",
                            proc.Name, proc.ProcessId, proc.ExecutablePath),
                            LogLevel.THREAT, "memory_execution.log");
                        GidrState.IncrementThreats();

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "Fileless";
                        threat.ThreatPath = proc.ExecutablePath != null ? proc.ExecutablePath : string.Format("pid:{0}", proc.ProcessId);
                        threat.Severity = ThreatSeverity.Critical;
                        threat.ProcessId = proc.ProcessId;
                        threat.ProcessName = proc.Name;
                        threat.Confidence = 85;
                        ResponseQueue.Enqueue(threat);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Fileless detection error: " + ex.Message, LogLevel.DEBUG);
                }
            }
        }

        /// <summary>
        /// Detect download cradle patterns in command lines:
        /// IEX (New-Object Net.WebClient).DownloadString(...)
        /// Invoke-Expression, etc.
        /// </summary>
        private static void DownloadCradle()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = WmiHelper.GetProcesses();

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid) continue;

                if (string.IsNullOrEmpty(proc.CommandLine)) continue;
                string cmdLower = proc.CommandLine.ToLowerInvariant();

                try
                {
                // Check for download cradle patterns
                bool isCradle = false;
                string detectedPattern = "";

                foreach (var pattern in _suspiciousCmdPatterns)
                {
                    if (cmdLower.Contains(pattern))
                    {
                        isCradle = true;
                        detectedPattern = pattern;
                        break;
                    }
                }

                if (isCradle)
                {
                    // Check for download indicators
                    bool hasDownload = cmdLower.Contains("http") || cmdLower.Contains("webclient") ||
                                     cmdLower.Contains("download") || cmdLower.Contains("net.socket") ||
                                     cmdLower.Contains("invoke-webrequest") || cmdLower.Contains("curl") ||
                                     cmdLower.Contains("wget");

                    if (hasDownload)
                    {
                        Logger.Log(string.Format("Download cradle detected: {0} PID:{1} Pattern:{2} Cmd:{3}",
                            proc.Name, proc.ProcessId, detectedPattern,
                            Truncate(proc.CommandLine, 200)),
                            LogLevel.THREAT, "memory_execution.log");
                        GidrState.IncrementThreats();

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "DownloadCradle";
                        threat.ThreatPath = proc.ExecutablePath;
                        threat.Severity = ThreatSeverity.Critical;
                        threat.ProcessId = proc.ProcessId;
                        threat.ProcessName = proc.Name;
                        threat.Confidence = 90;
                        ResponseQueue.Enqueue(threat);
                    }
                }

                // Check for base64 encoded commands (common in download cradles)
                if (cmdLower.Contains("frombase64string") || ContainsBase64Shellcode(proc.CommandLine))
                {
                    Logger.Log(string.Format("Base64 payload detected: {0} PID:{1} Cmd:{2}",
                        proc.Name, proc.ProcessId, Truncate(proc.CommandLine, 200)),
                        LogLevel.THREAT, "memory_execution.log");
                    GidrState.IncrementThreats();

                    ThreatInfo threat = new ThreatInfo();
                    threat.ThreatType = "DownloadCradle";
                    threat.ThreatPath = proc.ExecutablePath;
                    threat.Severity = ThreatSeverity.High;
                    threat.ProcessId = proc.ProcessId;
                    threat.ProcessName = proc.Name;
                    threat.Confidence = 75;
                    ResponseQueue.Enqueue(threat);
                }
                }
                catch (Exception ex)
                {
                    Logger.Log("Download cradle detection error: " + ex.Message, LogLevel.DEBUG);
                }
            }
        }

        /// <summary>
        /// Detect reflective DLL injection by monitoring for DLLs loaded
        /// without corresponding file on disk.
        /// </summary>
        private static void ReflectiveDllInMemory()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            Process[] procs = Process.GetProcesses();

            for (int i = 0; i < procs.Length; i++)
            {
                if (procs[i].Id == selfPid || procs[i].Id <= 4) continue;

                try
                {
                    ProcessModuleCollection modules = procs[i].Modules;
                    for (int m = 0; m < modules.Count; m++)
                    {
                        string fileName = modules[m].FileName;
                        if (string.IsNullOrEmpty(fileName)) continue;

                        // Check for DLL that exists in memory but not on disk
                        if (!File.Exists(fileName))
                        {
                            Logger.Log(string.Format("Reflective DLL injection: {0} PID:{1} has module not on disk: {2}",
                                procs[i].ProcessName, procs[i].Id, fileName),
                                LogLevel.THREAT, "memory_execution.log");
                            GidrState.IncrementThreats();

                            ThreatInfo threat = new ThreatInfo();
                            threat.ThreatType = "ReflectiveDll";
                            threat.ThreatPath = fileName;
                            threat.Severity = ThreatSeverity.Critical;
                            threat.ProcessId = procs[i].Id;
                            threat.ProcessName = procs[i].ProcessName;
                            threat.Confidence = 85;
                            ResponseQueue.Enqueue(threat);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Reflective DLL detection error for PID " + procs[i].Id + ": " + ex.Message, LogLevel.DEBUG);
                }
            }
        }

        /// <summary>
        /// Detect suspicious .NET assembly loading patterns that indicate
        /// in-memory execution (Assembly.Load from byte arrays).
        /// </summary>
        private static void SuspiciousDotNetMemoryLoad()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            Process[] procs = Process.GetProcesses();

            for (int i = 0; i < procs.Length; i++)
            {
                if (procs[i].Id == selfPid || procs[i].Id <= 4) continue;

                try
                {
                    // Check if process has .NET runtime loaded
                    bool hasDotNet = false;
                    ProcessModuleCollection modules = procs[i].Modules;
                    for (int m = 0; m < modules.Count; m++)
                    {
                        string modName = Path.GetFileName(modules[m].FileName).ToLowerInvariant();
                        if (modName.Contains("clr") || modName.Contains("mscor") || modName.Contains("coreclr"))
                        {
                            hasDotNet = true;
                            break;
                        }
                    }

                    if (!hasDotNet) continue;

                    // Check command line for suspicious patterns
                    string cmdLine = "";
                    try
                    {
                        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                            string.Format("SELECT CommandLine FROM Win32_Process WHERE ProcessId = {0}", procs[i].Id)))
                        using (ManagementObjectCollection results = searcher.Get())
                        {
                            foreach (ManagementObject obj in results)
                            {
                                cmdLine = obj["CommandLine"] != null ? obj["CommandLine"].ToString() : "";
                                break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("WMI query error for PID " + procs[i].Id + ": " + ex.Message, LogLevel.DEBUG);
                    }

                    string cmdLower = cmdLine.ToLowerInvariant();
                    if (cmdLower.Contains("assembly.load") || cmdLower.Contains("loadbyte") ||
                        cmdLower.Contains("[convert]::") || cmdLower.Contains("-encodedcommand") ||
                        cmdLower.Contains("-enc ") || cmdLower.Contains("reflection"))
                    {
                        Logger.Log(string.Format("Suspicious .NET memory load: {0} PID:{1} Cmd:{2}",
                            procs[i].ProcessName, procs[i].Id, Truncate(cmdLine, 200)),
                            LogLevel.THREAT, "memory_execution.log");
                        GidrState.IncrementThreats();

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "Fileless";
                        threat.ThreatPath = string.Format("pid:{0}", procs[i].Id);
                        threat.Severity = ThreatSeverity.High;
                        threat.ProcessId = procs[i].Id;
                        threat.ProcessName = procs[i].ProcessName;
                        threat.Confidence = 70;
                        ResponseQueue.Enqueue(threat);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log(".NET memory load detection error for PID " + procs[i].Id + ": " + ex.Message, LogLevel.DEBUG);
                }
            }
        }

        /// <summary>
        /// Detect process hollowing initiated from memory-based parents
        /// (browsers, office apps spawning suspicious children).
        /// </summary>
        private static void HollowFromMemory()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            List<ProcessInfo> processes = WmiHelper.GetProcesses();
            Dictionary<int, ProcessInfo> procMap = new Dictionary<int, ProcessInfo>();
            for (int i = 0; i < processes.Count; i++)
                procMap[processes[i].ProcessId] = processes[i];

            for (int i = 0; i < processes.Count; i++)
            {
                ProcessInfo proc = processes[i];
                if (proc.ProcessId == selfPid || proc.ProcessId <= 4) continue;

                // Check if parent is a suspicious process that shouldn't spawn children
                if (proc.ParentProcessId > 0 && procMap.ContainsKey(proc.ParentProcessId))
                {
                    ProcessInfo parent = procMap[proc.ParentProcessId];
                    string parentName = (parent.Name ?? "").ToLowerInvariant();

                    if (_suspiciousParentForMemoryExec.Contains(parentName))
                    {
                        // Check if child is suspicious (cmd, powershell, wscript, etc.)
                        string childName = (proc.Name ?? "").ToLowerInvariant();
                        if (childName.Contains("cmd") || childName.Contains("powershell") ||
                            childName.Contains("wscript") || childName.Contains("cscript") ||
                            childName.Contains("mshta") || childName.Contains("certutil") ||
                            childName.Contains("rundll32") || childName.Contains("regsvr32"))
                        {
                            Logger.Log(string.Format("Process injection from {0}: {1} PID:{2} parent:{3} PID:{4}",
                                parentName, proc.Name, proc.ProcessId, parent.Name, parent.ProcessId),
                                LogLevel.THREAT, "memory_execution.log");
                            GidrState.IncrementThreats();

                            ThreatInfo threat = new ThreatInfo();
                            threat.ThreatType = "ProcessHollowing";
                            threat.ThreatPath = proc.ExecutablePath;
                            threat.Severity = ThreatSeverity.Critical;
                            threat.ProcessId = proc.ProcessId;
                            threat.ProcessName = proc.Name;
                            threat.Confidence = 85;
                            ResponseQueue.Enqueue(threat);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Check if a string contains potential base64-encoded shellcode.
        /// </summary>
        private static bool ContainsBase64Shellcode(string text)
        {
            if (string.IsNullOrEmpty(text) || text.Length < 100) return false;

            // Look for long base64-like strings
            int base64Length = 0;
            int maxBase64Length = 0;

            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=')
                {
                    base64Length++;
                }
                else
                {
                    if (base64Length > maxBase64Length)
                        maxBase64Length = base64Length;
                    base64Length = 0;
                }
            }

            if (base64Length > maxBase64Length)
                maxBase64Length = base64Length;

            // Base64 shellcode is typically >200 chars
            return maxBase64Length > 200;
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...";
        }
    }
}
