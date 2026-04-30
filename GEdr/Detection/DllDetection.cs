using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using GEdr.Core;
using GEdr.Response;

namespace GEdr.Detection
{
    /// <summary>
    /// DLL hijacking, unsigned DLL scanning, ELF catcher (browser DLL monitoring),
    /// reflective DLL injection, keystroke injection DLL detection.
    /// Ported from Invoke-DLLHijackingDetection, Invoke-ElfCatcher, Invoke-ElfDLLUnloader,
    /// Invoke-UnsignedDLLRemover, Invoke-ReflectiveDLLInjectionDetection, Invoke-KeystrokeInjectionDetection.
    /// </summary>
    public static class DllDetection
    {
        private static readonly HashSet<string> _systemDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ntdll.dll","kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll",
            "msvcrt.dll","advapi32.dll","ws2_32.dll","shell32.dll","ole32.dll",
            "combase.dll","bcrypt.dll","crypt32.dll","sechost.dll","rpcrt4.dll",
            "imm32.dll","shcore.dll","shlwapi.dll","version.dll","winmm.dll"
        };

        private static readonly string[] _browserNames = new string[]
        {
            "chrome","msedge","firefox","brave","opera","vivaldi","iexplore","waterfox","palemoon"
        };

        private static readonly HashSet<string> _processedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Detect DLLs loaded from suspicious locations.</summary>
        public static void DllHijacking()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            string[] suspiciousPaths = new string[]
            {
                Environment.GetEnvironmentVariable("TEMP") ?? "",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop")
            };

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
                        if (!fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                        string dllName = Path.GetFileName(fileName).ToLowerInvariant();
                        if (_systemDlls.Contains(dllName)) continue;

                        // Check if DLL is in a suspicious location
                        bool suspicious = false;
                        for (int s = 0; s < suspiciousPaths.Length; s++)
                        {
                            if (!string.IsNullOrEmpty(suspiciousPaths[s])
                                && fileName.StartsWith(suspiciousPaths[s], StringComparison.OrdinalIgnoreCase))
                            {
                                suspicious = true;
                                break;
                            }
                        }

                        if (suspicious)
                        {
                            // Verify it's unsigned
                            if (!ThreatActions.IsFileSigned(fileName))
                            {
                                Logger.Log(string.Format("DLL hijacking: {0} loaded unsigned DLL from suspicious path: {1}",
                                    procs[i].ProcessName, fileName), LogLevel.THREAT, "dll_hijacking.log");
                                EdrState.IncrementThreats();

                                ThreatInfo threat = new ThreatInfo();
                                threat.ThreatType = "DLLHijacking";
                                threat.ThreatPath = fileName;
                                threat.Severity = ThreatSeverity.High;
                                threat.ProcessId = procs[i].Id;
                                threat.ProcessName = procs[i].ProcessName;
                                threat.Confidence = 65;
                                ResponseQueue.Enqueue(threat);
                            }
                        }
                    }
                }
                catch { } // Access denied is normal for system processes
            }
        }

        /// <summary>Monitor browser processes for suspicious DLLs (ELF catcher).</summary>
        public static void ElfCatcher()
        {
            for (int b = 0; b < _browserNames.Length; b++)
            {
                Process[] procs;
                try { procs = Process.GetProcessesByName(_browserNames[b]); }
                catch { continue; }

                for (int p = 0; p < procs.Length; p++)
                {
                    try
                    {
                        ProcessModuleCollection modules = procs[p].Modules;
                        for (int m = 0; m < modules.Count; m++)
                        {
                            string fileName = modules[m].FileName;
                            if (string.IsNullOrEmpty(fileName)) continue;

                            string dllName = Path.GetFileName(fileName).ToLowerInvariant();
                            string key = string.Format("{0}:{1}", procs[p].Id, fileName);
                            if (_processedDlls.Contains(key)) continue;

                            bool suspicious = false;
                            string reason = "";

                            // Random hex-named DLLs
                            if (System.Text.RegularExpressions.Regex.IsMatch(dllName, @"^[a-f0-9]{8,}\.dll$"))
                            {
                                suspicious = true;
                                reason = "Random hex-named DLL";
                            }

                            // DLLs from TEMP
                            if (fileName.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) >= 0
                                && !dllName.StartsWith("chrome_") && !dllName.StartsWith("edge_") && !dllName.StartsWith("moz"))
                            {
                                suspicious = true;
                                reason = "DLL from TEMP directory";
                            }

                            // .winmd outside Windows
                            if (dllName.EndsWith(".winmd") && fileName.IndexOf("\\Windows\\", StringComparison.OrdinalIgnoreCase) < 0)
                            {
                                suspicious = true;
                                reason = "WINMD outside Windows directory";
                            }

                            if (suspicious && !ThreatActions.IsFileSigned(fileName))
                            {
                                _processedDlls.Add(key);
                                Logger.Log(string.Format("ELF catcher: {0} in {1} PID:{2} - {3}",
                                    dllName, _browserNames[b], procs[p].Id, reason),
                                    LogLevel.THREAT, "elf_catcher.log");
                                EdrState.IncrementThreats();

                                ThreatInfo threat = new ThreatInfo();
                                threat.ThreatType = "ElfCatcher:" + reason;
                                threat.ThreatPath = fileName;
                                threat.Severity = ThreatSeverity.High;
                                threat.ProcessId = procs[p].Id;
                                threat.ProcessName = procs[p].ProcessName;
                                threat.Confidence = 70;
                                ResponseQueue.Enqueue(threat);
                            }
                        }
                    }
                    catch { }
                }
            }

            // Cleanup old entries
            if (_processedDlls.Count > 1000)
                _processedDlls.Clear();
        }

        /// <summary>Detect reflective DLL injection (memory-only modules).</summary>
        public static void ReflectiveDllInjection()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            Process[] procs = Process.GetProcesses();

            for (int i = 0; i < procs.Length; i++)
            {
                if (procs[i].Id == selfPid || procs[i].Id <= 4) continue;
                try
                {
                    int memOnlyCount = 0;
                    ProcessModuleCollection modules = procs[i].Modules;
                    for (int m = 0; m < modules.Count; m++)
                    {
                        if (!string.IsNullOrEmpty(modules[m].FileName) && !File.Exists(modules[m].FileName))
                            memOnlyCount++;
                    }

                    if (memOnlyCount > 5)
                    {
                        Logger.Log(string.Format("Reflective DLL: {0} PID:{1} has {2} memory-only modules",
                            procs[i].ProcessName, procs[i].Id, memOnlyCount),
                            LogLevel.THREAT, "reflective_dll.log");
                        EdrState.IncrementThreats();

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "ReflectiveDLLInjection";
                        threat.ProcessId = procs[i].Id;
                        threat.ProcessName = procs[i].ProcessName;
                        threat.Severity = ThreatSeverity.High;
                        threat.Confidence = 70;
                        threat.Details["MemoryOnlyModules"] = memOnlyCount.ToString();
                        ResponseQueue.Enqueue(threat);
                    }
                }
                catch { }
            }
        }

        /// <summary>Detect keystroke injection: processes with input APIs from suspicious locations.</summary>
        public static void KeystrokeInjection()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            HashSet<string> legitInjectors = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "explorer","dwm","csrss","winlogon","services","lsass","svchost",
                "powershell","pwsh","cmd","conhost","chrome","firefox","msedge",
                "teams","slack","discord","zoom","code","devenv","notepad",
                "autohotkey","ahk","osk","tabtip","textinputhost"
            };

            string[] injectionDlls = new string[] { "inputsimulator", "sendinput", "keyinjector", "hookdll", "inputhook" };

            Process[] procs = Process.GetProcesses();
            for (int i = 0; i < procs.Length; i++)
            {
                if (procs[i].Id == selfPid) continue;
                if (legitInjectors.Contains(procs[i].ProcessName)) continue;

                try
                {
                    ProcessModuleCollection modules = procs[i].Modules;
                    for (int m = 0; m < modules.Count; m++)
                    {
                        string modName = (modules[m].ModuleName ?? "").ToLowerInvariant();
                        for (int d = 0; d < injectionDlls.Length; d++)
                        {
                            if (modName.Contains(injectionDlls[d]))
                            {
                                if (!ThreatActions.IsFileSigned(procs[i].MainModule.FileName))
                                {
                                    Logger.Log(string.Format("Keystroke injection: {0} PID:{1} loaded {2}",
                                        procs[i].ProcessName, procs[i].Id, modName),
                                        LogLevel.THREAT, "keystroke_injection.log");
                                    EdrState.IncrementThreats();

                                    ThreatInfo threat = new ThreatInfo();
                                    threat.ThreatType = "KeystrokeInjection";
                                    threat.ProcessId = procs[i].Id;
                                    threat.ProcessName = procs[i].ProcessName;
                                    threat.Severity = ThreatSeverity.Critical;
                                    threat.Confidence = 80;
                                    ResponseQueue.Enqueue(threat);

                                    if (Config.AutoKillThreats)
                                        ThreatActions.TerminateProcess(procs[i].Id, procs[i].ProcessName);
                                }
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
    }
}
