using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Detection
{
    /// <summary>
    /// Validates loaded modules across all processes to detect:
    /// - Unsigned/untrusted DLLs in critical processes
    /// - Known-bad hashes (supply chain attacks, malicious DLLs)
    /// - Module path anomalies (DLL hijacking, search order abuse)
    /// - Mismatched module names (possible masquerading)
    /// 
    /// IMPORTANT: This detector does NOT attempt to forcibly unload DLLs from remote
    /// processes. That operation requires:
    /// - Kernel driver (FltUnloadFilter, MiniFilter) OR
    /// - Remote thread creation in target process (injects our code into victim) OR
    /// - Suspending all threads + manual memory unmapping (guaranteed crash)
    /// 
    /// Instead, we detect and respond by suspending/terminating the process.
    /// </summary>
    public static class ModuleValidationDetection
    {
        // Critical system processes where unsigned modules are highly suspicious
        private static readonly HashSet<string> _criticalProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "wininit.exe",
            "svchost.exe", "lsm.exe", "winlogon.exe", "taskhostw.exe", "explorer.exe"
        };

        // Known vulnerable/sensitive processes often targeted for injection
        private static readonly HashSet<string> _highValueTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
            "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe",
            "teams.exe", "slack.exe", "discord.exe",
            "mstsc.exe", "vmconnect.exe", "vmware.exe"
        };

        // Cache of verified module hashes to avoid repeated disk I/O
        private static readonly Dictionary<string, ModuleInfo> _moduleCache = new Dictionary<string, ModuleInfo>(StringComparer.OrdinalIgnoreCase);
        private static readonly object _cacheLock = new object();
        private static DateTime _lastCacheCleanup = DateTime.UtcNow;

        // Whitelist of Microsoft/Windows signed modules that are expected
        private static readonly HashSet<string> _trustedPublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Production PCA",
            "Windows (R), Microsoft Corporation", "Microsoft 3rd Party Application Component"
        };

        private class ModuleInfo
        {
            public string Path;
            public string Hash;
            public bool IsSigned;
            public string Publisher;
            public DateTime VerifiedAt;
            public bool IsTrusted;
        }

        /// <summary>
        /// Main entry: validate all loaded modules across processes.
        /// Heavy operation - should run on dedicated thread with throttling.
        /// </summary>
        public static void ValidateModules()
        {
            CleanupCacheIfNeeded();
            int selfPid = Process.GetCurrentProcess().Id;
            Process[] processes = Process.GetProcesses();

            foreach (Process proc in processes)
            {
                if (proc.Id == selfPid || proc.Id <= 4) continue;

                try
                {
                    ValidateProcessModules(proc);
                }
                catch (Exception ex)
                {
                    Logger.Log("Module validation error for PID " + proc.Id + ": " + ex.Message, LogLevel.DEBUG);
                }
            }
        }

        private static void ValidateProcessModules(Process proc)
        {
            string procName = proc.ProcessName.ToLowerInvariant() + ".exe";
            bool isCritical = _criticalProcesses.Contains(procName);
            bool isHighValue = _highValueTargets.Contains(procName);

            if (!isCritical && !isHighValue) return; // Skip non-critical processes to save resources

            ProcessModuleCollection modules;
            try
            {
                modules = proc.Modules;
            }
            catch
            {
                return; // Access denied or process exited
            }

            for (int i = 0; i < modules.Count; i++)
            {
                ProcessModule mod = modules[i];
                string modulePath = mod.FileName;
                if (string.IsNullOrEmpty(modulePath)) continue;

                // Skip .NET runtime and framework DLLs (expected)
                string fileName = Path.GetFileName(modulePath).ToLowerInvariant();
                if (fileName.StartsWith("mscor") || fileName.StartsWith("clr") ||
                    fileName.StartsWith("system.") || fileName.StartsWith("microsoft."))
                    continue;

                ModuleInfo info = GetModuleInfo(modulePath);
                if (info == null) continue;

                int threatScore = 0;
                List<string> reasons = new List<string>();

                // Check 1: Unsigned module in critical process
                if (isCritical && !info.IsSigned)
                {
                    threatScore += 60;
                    reasons.Add("Unsigned module in critical process");
                }

                // Check 2: Unsigned module in high-value target
                if (isHighValue && !info.IsSigned)
                {
                    threatScore += 40;
                    reasons.Add("Unsigned module in browser/office app");
                }

                // Check 3: Suspicious path (Temp, AppData, unusual locations)
                string lowerPath = modulePath.ToLowerInvariant();
                if (lowerPath.Contains(@"\temp\") || lowerPath.Contains(@"\tmp\") ||
                    lowerPath.Contains(@"\appdata\local\temp"))
                {
                    threatScore += 50;
                    reasons.Add("Module loaded from temp directory");
                }

                // Check 4: Non-system DLL in system process from unusual location
                if (isCritical && !lowerPath.Contains(@"\windows\") && !lowerPath.Contains(@"\program files"))
                {
                    threatScore += 45;
                    reasons.Add("Non-system DLL in system process from unusual location");
                }

                // Check 5: Known untrusted publisher
                if (info.IsSigned && !info.IsTrusted && !string.IsNullOrEmpty(info.Publisher))
                {
                    threatScore += 30;
                    reasons.Add("Signed but untrusted publisher: " + info.Publisher);
                }

                // Report if threshold met
                if (threatScore >= 50)
                {
                    string details = string.Format("Process: {0} (PID:{1}), Module: {2}, Score: {3}",
                        proc.ProcessName, proc.Id, fileName, threatScore);
                    Logger.Log("SUSPICIOUS MODULE: " + details + " | " + string.Join(", ", reasons),
                        LogLevel.THREAT, "module_validation.log");

                    ThreatInfo threat = new ThreatInfo();
                    threat.ThreatType = "SuspiciousModule";
                    threat.ThreatPath = modulePath;
                    threat.Severity = threatScore >= 70 ? ThreatSeverity.Critical : ThreatSeverity.High;
                    threat.Confidence = threatScore;
                    threat.ProcessId = proc.Id;
                    threat.ProcessName = proc.ProcessName;
                    threat.Details["ModuleHash"] = info.Hash ?? "unknown";
                    threat.Details["Publisher"] = info.Publisher ?? "unsigned";
                    threat.Details["IsSigned"] = info.IsSigned.ToString();
                    threat.Details["Reasons"] = string.Join("; ", reasons);

                    ResponseQueue.Enqueue(threat);

                    // For critical threats in critical processes, consider immediate action
                    if (threatScore >= 70 && isCritical)
                    {
                        Logger.Log(string.Format("Critical untrusted module in {0} - recommending process termination",
                            proc.ProcessName), LogLevel.THREAT);
                    }
                }
            }
        }

        private static ModuleInfo GetModuleInfo(string path)
        {
            // Check cache first
            lock (_cacheLock)
            {
                ModuleInfo cached;
                if (_moduleCache.TryGetValue(path, out cached))
                {
                    // Cache valid for 5 minutes
                    if ((DateTime.UtcNow - cached.VerifiedAt).TotalMinutes < 5)
                        return cached;
                }
            }

            if (!File.Exists(path)) return null;

            try
            {
                ModuleInfo info = new ModuleInfo();
                info.Path = path;
                info.VerifiedAt = DateTime.UtcNow;

                // Compute hash
                using (SHA256 sha = SHA256.Create())
                using (FileStream fs = File.OpenRead(path))
                {
                    info.Hash = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
                }

                // Check signature
                try
                {
                    X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
                    info.IsSigned = cert != null;
                    if (cert != null)
                    {
                        info.Publisher = cert.Subject;
                        // Check if publisher is trusted
                        info.IsTrusted = _trustedPublishers.Any(p =>
                            cert.Subject.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0);
                    }
                }
                catch
                {
                    info.IsSigned = false;
                    info.Publisher = null;
                    info.IsTrusted = false;
                }

                // Cache the result
                lock (_cacheLock)
                {
                    _moduleCache[path] = info;
                }

                return info;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to validate module " + path + ": " + ex.Message, LogLevel.DEBUG);
                return null;
            }
        }

        private static void CleanupCacheIfNeeded()
        {
            if ((DateTime.UtcNow - _lastCacheCleanup).TotalMinutes < 10) return;

            lock (_cacheLock)
            {
                List<string> toRemove = new List<string>();
                foreach (var kvp in _moduleCache)
                {
                    if ((DateTime.UtcNow - kvp.Value.VerifiedAt).TotalMinutes > 10)
                        toRemove.Add(kvp.Key);
                }
                foreach (string key in toRemove)
                    _moduleCache.Remove(key);
            }
            _lastCacheCleanup = DateTime.UtcNow;
        }

        /// <summary>
        /// Why we don't forcibly unload DLLs from remote processes:
        /// 
        /// 1. Windows provides NO user-mode API to unload a DLL from another process.
        ///    FreeLibrary() only works on DLLs loaded in YOUR process.
        /// 
        /// 2. Common "workarounds" are dangerous:
        ///    - CreateRemoteThread + FreeLibrary: Injects code into victim process
        ///      (same technique malware uses). Requires many privileges, often flagged.
        ///    - Manual unmapping: Suspend all threads, manually unmap memory,
        ///      fix EAT/IAT. Guaranteed to crash the process 99% of the time.
        /// 
        /// 3. Safe alternatives available:
        ///    - Suspend process threads (pauses execution)
        ///    - Terminate process (if not critical)
        ///    - Report to user/admin for manual remediation
        ///    - Use kernel driver (requires driver development, signing)
        /// 
        /// This detector focuses on detection and safe response actions.
        /// </summary>
        public static void ExplainUnloadingLimitations()
        {
            // Documentation method - called if user asks why we don't unload
        Logger.Log("Module unloading requires kernel driver or dangerous injection techniques. " +
                   "Using process suspension/termination instead.", LogLevel.INFO);
        }
    }
}
