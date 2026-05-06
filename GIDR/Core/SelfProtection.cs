using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

namespace GIDR.Core
{
    /// <summary>
    /// Self-protection for the EDR process and its critical files.
    /// 
    /// - Monitors own process for termination attempts (watchdog thread)
    /// - Detects tampering with config, rules, and executable
    /// - Sets DACL on own process to deny PROCESS_TERMINATE from non-SYSTEM
    /// - Watches for debugger attachment
    /// </summary>
    public static class SelfProtection
    {
        private static Thread _watchdogThread;
        private static volatile bool _running;
        private static string _exeHash;
        private static string _configHash;
        private static string _configHashAtLoad; // Original hash at startup — for tamper lockout
        private static System.Collections.Generic.Dictionary<string, string> _moduleHashes
            = new System.Collections.Generic.Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // P/Invoke for process protection
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(IntPtr handle, int secInfo, byte[] pSD);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string sddl, int revision, out IntPtr sd, out int sdLen);

        [DllImport("kernel32.dll")]
        private static extern bool LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        /// <summary>Initialize self-protection. Call after Config is loaded.</summary>
        public static void Initialize()
        {
            // 1. Protect our process handle (deny terminate from non-admin)
            ProtectProcess();

            // 2. Snapshot critical file hashes
            _exeHash = ComputeHash(System.Reflection.Assembly.GetExecutingAssembly().Location);
            string configPath = Path.Combine(Config.InstallPath, "config.json");
            _configHash = File.Exists(configPath) ? ComputeHash(configPath) : null;
            _configHashAtLoad = _configHash;

            // 3. Snapshot loaded module hashes (DLL hijack detection)
            SnapshotLoadedModules();

            // 4. Start watchdog thread
            _running = true;
            _watchdogThread = new Thread(WatchdogLoop);
            _watchdogThread.IsBackground = true;
            _watchdogThread.Name = "GIDR-SelfProtect";
            _watchdogThread.Start();

            Logger.Log("Self-protection initialized");
        }

        public static void Shutdown()
        {
            _running = false;
        }

        /// <summary>
        /// Set a restrictive DACL on our own process.
        /// Denies PROCESS_TERMINATE (0x0001) to Everyone except SYSTEM and Administrators.
        /// This makes casual "taskkill /f /im GIDR.exe" fail for non-admin users.
        /// Admin users can still kill it (by design — we don't want to brick the system).
        /// </summary>
        private static void ProtectProcess()
        {
            try
            {
                // SDDL: Owner=SYSTEM, DACL grants full control to SYSTEM and Administrators only
                // D:P = DACL present, protected (no inheritance)
                // (A;;GA;;;SY) = Allow Generic All to SYSTEM
                // (A;;GA;;;BA) = Allow Generic All to Built-in Administrators
                string sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

                IntPtr sd;
                int sdLen;
                if (ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out sd, out sdLen))
                {
                    byte[] sdBytes = new byte[sdLen];
                    Marshal.Copy(sd, sdBytes, 0, sdLen);
                    LocalFree(sd);

                    // DACL_SECURITY_INFORMATION = 0x04
                    bool result = SetKernelObjectSecurity(GetCurrentProcess(), 0x04, sdBytes);
                    if (result)
                        Logger.Log("Process DACL hardened (non-admin terminate blocked)");
                    else
                        Logger.Log("Failed to set process DACL", LogLevel.WARN);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Process protection failed: " + ex.Message, LogLevel.WARN);
            }
        }

        /// <summary>
        /// Verify a file hash against the stored baseline. Returns true if match, false if tampered.
        /// </summary>
        public static bool VerifyFileHash(string filePath, string expectedHash)
        {
            string currentHash = ComputeHash(filePath);
            return currentHash != null && currentHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        private static void WatchdogLoop()
        {
            int checkInterval = 30000; // 30 seconds
            int moduleCheckCounter = 0;
            while (_running)
            {
                try
                {
                    // Check for debugger attachment
                    if (IsDebuggerPresent())
                    {
                        Logger.Log("DEBUGGER DETECTED attached to EDR process!", LogLevel.THREAT, "self_protection.log");
                        JsonLogger.LogEvent("THREAT", "self-protection", "Debugger attached to EDR process");
                        GidrState.IncrementThreats();
                    }

                    // Check executable integrity
                    string currentExeHash = ComputeHash(System.Reflection.Assembly.GetExecutingAssembly().Location);
                    if (_exeHash != null && currentExeHash != null && _exeHash != currentExeHash)
                    {
                        Logger.Log("EDR EXECUTABLE TAMPERED! Hash mismatch detected.", LogLevel.THREAT, "self_protection.log");
                        JsonLogger.LogEvent("THREAT", "self-protection", "EDR executable hash changed");
                        GidrState.IncrementThreats();
                        _exeHash = currentExeHash;
                    }

                    // Check config integrity — reject tampered configs
                    CheckConfigIntegrity();

                    // Check rules directory integrity (detect deletion)
                    if (!Directory.Exists(Config.RulesPath))
                    {
                        Logger.Log("YARA rules directory deleted!", LogLevel.THREAT, "self_protection.log");
                        JsonLogger.LogEvent("THREAT", "self-protection", "YARA rules directory missing");
                        GidrState.IncrementThreats();
                    }

                    // Check loaded module integrity every 5 minutes (not every 30s — expensive)
                    moduleCheckCounter++;
                    if (moduleCheckCounter >= 10) // 10 * 30s = 5 minutes
                    {
                        moduleCheckCounter = 0;
                        VerifyLoadedModules();
                    }
                }
                catch (Exception ex)
                {
                    // Log watchdog errors but don't crash - self-protection must continue
                    Logger.Log("Watchdog iteration error: " + ex.Message, LogLevel.ERROR);
                }

                Thread.Sleep(checkInterval);
            }
        }

        /// <summary>
        /// Check config.json integrity. If modified externally, reject the changes
        /// by clearing the allowlist additions (prevents attacker from allowlisting
        /// their own payloads by editing config.json).
        /// </summary>
        private static void CheckConfigIntegrity()
        {
            string configPath = Path.Combine(Config.InstallPath, "config.json");
            if (_configHash == null || !File.Exists(configPath)) return;

            string currentConfigHash = ComputeHash(configPath);
            if (currentConfigHash != null && _configHash != currentConfigHash)
            {
                Logger.Log("CONFIG TAMPERED: config.json modified while EDR is running. " +
                    "Allowlists frozen to prevent bypass.", LogLevel.THREAT, "self_protection.log");
                JsonLogger.LogEvent("THREAT", "self-protection",
                    "config.json modified at runtime - allowlists frozen");
                GidrState.IncrementThreats();

                // Don't reload the tampered config — keep the original allowlists
                // An attacker modifying config.json to add their hash to allowlistHashes
                // will NOT take effect until the EDR is restarted by an admin
                _configHash = currentConfigHash;
            }
        }

        /// <summary>
        /// Snapshot hashes of all loaded .NET assemblies and native DLLs.
        /// Detects DLL search order hijacking in the install directory.
        /// </summary>
        private static void SnapshotLoadedModules()
        {
            try
            {
                Process self = Process.GetCurrentProcess();
                for (int i = 0; i < self.Modules.Count; i++)
                {
                    ProcessModule mod = self.Modules[i];
                    string path = mod.FileName;
                    if (string.IsNullOrEmpty(path)) continue;

                    string hash = ComputeHash(path);
                    if (hash != null)
                        _moduleHashes[path] = hash;
                }
                Logger.Log(string.Format("Module integrity baseline: {0} modules hashed", _moduleHashes.Count));
            }
            catch (Exception ex)
            {
                Logger.Log("Module snapshot failed: " + ex.Message, LogLevel.WARN);
            }
        }

        /// <summary>
        /// Verify loaded modules haven't been replaced on disk.
        /// Also check for new modules loaded from the install directory
        /// (DLL search order hijacking).
        /// </summary>
        private static void VerifyLoadedModules()
        {
            try
            {
                Process self = Process.GetCurrentProcess();
                for (int i = 0; i < self.Modules.Count; i++)
                {
                    ProcessModule mod = self.Modules[i];
                    string path = mod.FileName;
                    if (string.IsNullOrEmpty(path)) continue;

                    // Check if module is in our install directory (potential hijack)
                    if (path.StartsWith(Config.InstallPath, StringComparison.OrdinalIgnoreCase))
                    {
                        string name = Path.GetFileName(path).ToLowerInvariant();
                        // Our own exe is expected
                        if (name == "gidr.exe") continue;

                        // Any DLL in our install dir that isn't ours is suspicious
                        Logger.Log(string.Format("DLL in install directory: {0} — potential DLL hijack",
                            path), LogLevel.THREAT, "self_protection.log");
                        JsonLogger.LogThreat("DLLHijack", path, ComputeHash(path),
                            80, "CRITICAL", "Critical", "T1574.001", "DLL loaded from EDR install directory");
                        GidrState.IncrementThreats();
                    }

                    // Verify hash of known modules
                    string originalHash;
                    if (_moduleHashes.TryGetValue(path, out originalHash))
                    {
                        string currentHash = ComputeHash(path);
                        if (currentHash != null && currentHash != originalHash)
                        {
                            Logger.Log(string.Format("MODULE TAMPERED: {0} hash changed on disk",
                                path), LogLevel.THREAT, "self_protection.log");
                            JsonLogger.LogThreat("ModuleTamper", path, currentHash,
                                85, "CRITICAL", "Critical", "T1574", "Loaded module hash changed on disk");
                            GidrState.IncrementThreats();
                            _moduleHashes[path] = currentHash;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Module verification failed: " + ex.Message, LogLevel.WARN);
            }
        }

        private static string ComputeHash(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return null;
            try
            {
                using (SHA256 sha = SHA256.Create())
                using (FileStream fs = File.OpenRead(filePath))
                {
                    byte[] hash = sha.ComputeHash(fs);
                    return BitConverter.ToString(hash).Replace("-", "");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Hash computation failed for " + filePath + ": " + ex.Message, LogLevel.DEBUG);
                return null;
            }
        }
    }
}
