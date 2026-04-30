using System;
using System.Runtime.InteropServices;
using System.Text;
using GEdr.Core;

namespace GEdr.Engine
{
    /// <summary>
    /// AMSI (Antimalware Scan Interface) integration with tamper detection.
    /// 
    /// AMSI provides access to deobfuscated script content before execution.
    /// PowerShell, VBScript, JScript, and Office macros all call AMSI.
    /// 
    /// Includes integrity verification: checks that AmsiScanBuffer hasn't been
    /// patched in memory (common bypass technique).
    /// 
    /// Note: Full AMSI provider registration requires a COM DLL registered
    /// in the system. This module provides the scanning capability that can
    /// be called from our process monitor when we intercept script content.
    /// 
    /// For direct AMSI scanning, we use AmsiScanBuffer to check content
    /// against Windows Defender and any other registered AMSI providers.
    /// We also scan the content ourselves with YARA and pattern matching.
    /// </summary>
    public static class AmsiScanner
    {
        private static IntPtr _amsiContext = IntPtr.Zero;
        private static IntPtr _amsiSession = IntPtr.Zero;
        private static bool _available;

        // AMSI result enum
        public const int AMSI_RESULT_CLEAN = 0;
        public const int AMSI_RESULT_NOT_DETECTED = 1;
        public const int AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000;
        public const int AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4FFF;
        public const int AMSI_RESULT_DETECTED = 32768;

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll")]
        private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr amsiSession);

        [DllImport("amsi.dll")]
        private static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length,
            string contentName, IntPtr amsiSession, out int result);

        [DllImport("amsi.dll")]
        private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr amsiSession);

        [DllImport("amsi.dll")]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandleA(string moduleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        public static bool IsAvailable { get { return _available; } }
        private static byte[] _originalAmsiPrologue;
        private static IntPtr _amsiScanBufferAddr = IntPtr.Zero;

        public static void Initialize()
        {
            try
            {
                int hr = AmsiInitialize("GEdr", out _amsiContext);
                if (hr == 0 && _amsiContext != IntPtr.Zero)
                {
                    hr = AmsiOpenSession(_amsiContext, out _amsiSession);
                    if (hr == 0)
                    {
                        _available = true;
                        SnapshotAmsiPrologue();
                        Logger.Log("AMSI scanner initialized (integrity baseline captured)");
                        return;
                    }
                }
                Logger.Log("AMSI initialization failed (HRESULT: " + hr + ")", LogLevel.WARN);
            }
            catch (DllNotFoundException)
            {
                Logger.Log("AMSI not available (amsi.dll not found - requires Windows 10+)", LogLevel.WARN);
            }
            catch (Exception ex)
            {
                Logger.Log("AMSI initialization error: " + ex.Message, LogLevel.WARN);
            }
        }

        public static void Shutdown()
        {
            try
            {
                if (_amsiSession != IntPtr.Zero && _amsiContext != IntPtr.Zero)
                    AmsiCloseSession(_amsiContext, _amsiSession);
                if (_amsiContext != IntPtr.Zero)
                    AmsiUninitialize(_amsiContext);
            }
            catch { }
        }

        /// <summary>
        /// Scan a content buffer via AMSI (leverages all registered providers including Defender).
        /// Returns true if malicious content was detected.
        /// </summary>
        public static AmsiScanResult ScanContent(string content, string contentName)
        {
            AmsiScanResult result = new AmsiScanResult();
            result.ContentName = contentName;

            if (!_available || string.IsNullOrEmpty(content))
            {
                result.IsMalicious = false;
                return result;
            }

            // Verify AMSI hasn't been patched before trusting its results
            VerifyIntegrity();

            try
            {
                byte[] buffer = Encoding.Unicode.GetBytes(content);
                int amsiResult;
                int hr = AmsiScanBuffer(_amsiContext, buffer, (uint)buffer.Length,
                    contentName, _amsiSession, out amsiResult);

                if (hr == 0)
                {
                    result.RawResult = amsiResult;
                    result.IsMalicious = amsiResult >= AMSI_RESULT_DETECTED;
                    result.IsBlocked = amsiResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START
                        && amsiResult <= AMSI_RESULT_BLOCKED_BY_ADMIN_END;

                    if (result.IsMalicious)
                    {
                        Logger.Log(string.Format("AMSI detection: {0} (result: {1})",
                            contentName, amsiResult), LogLevel.THREAT, "amsi_detections.log");
                        EdrState.IncrementThreats();
                        JsonLogger.LogThreat("AMSI", contentName, null,
                            90, "CRITICAL", "Critical", "T1059", "AMSI flagged content as malicious");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("AMSI scan error: " + ex.Message, LogLevel.WARN);
            }

            // Also run our own pattern matching on the content
            ScanContentPatterns(content, contentName, result);

            return result;
        }

        /// <summary>
        /// Scan a file's content via AMSI (for scripts).
        /// </summary>
        public static AmsiScanResult ScanFile(string filePath)
        {
            try
            {
                if (!System.IO.File.Exists(filePath))
                    return new AmsiScanResult { ContentName = filePath };

                // Only scan text-based files
                long size = new System.IO.FileInfo(filePath).Length;
                if (size > 5 * 1024 * 1024) // Skip files > 5MB
                    return new AmsiScanResult { ContentName = filePath };

                string content = System.IO.File.ReadAllText(filePath);
                return ScanContent(content, filePath);
            }
            catch
            {
                return new AmsiScanResult { ContentName = filePath };
            }
        }

        /// <summary>
        /// Snapshot the first 16 bytes of AmsiScanBuffer for tamper detection.
        /// Common AMSI bypass patches these bytes to: mov eax, 0x80070057; ret
        /// </summary>
        private static void SnapshotAmsiPrologue()
        {
            try
            {
                IntPtr hAmsi = GetModuleHandleA("amsi.dll");
                if (hAmsi == IntPtr.Zero) return;
                _amsiScanBufferAddr = GetProcAddress(hAmsi, "AmsiScanBuffer");
                if (_amsiScanBufferAddr == IntPtr.Zero) return;

                _originalAmsiPrologue = new byte[16];
                Marshal.Copy(_amsiScanBufferAddr, _originalAmsiPrologue, 0, 16);
            }
            catch { }
        }

        /// <summary>
        /// Verify AmsiScanBuffer hasn't been patched in memory.
        /// Returns true if AMSI is intact, false if tampered.
        /// </summary>
        public static bool VerifyIntegrity()
        {
            if (_amsiScanBufferAddr == IntPtr.Zero || _originalAmsiPrologue == null)
                return true; // Can't verify, assume OK

            try
            {
                byte[] current = new byte[16];
                Marshal.Copy(_amsiScanBufferAddr, current, 0, 16);

                for (int i = 0; i < 16; i++)
                {
                    if (current[i] != _originalAmsiPrologue[i])
                    {
                        // AMSI has been patched!
                        Logger.Log(string.Format(
                            "AMSI TAMPERED! AmsiScanBuffer prologue modified at byte {0}: expected 0x{1:X2}, found 0x{2:X2}",
                            i, _originalAmsiPrologue[i], current[i]),
                            LogLevel.THREAT, "amsi_detections.log");
                        EdrState.IncrementThreats();
                        JsonLogger.LogThreat("AMSI-Tamper", "amsi.dll!AmsiScanBuffer", null,
                            95, "CRITICAL", "Critical", "T1562.001", "AMSI bypass detected - prologue patched");

                        // Attempt to restore original bytes
                        try
                        {
                            // Need to change page protection first
                            uint oldProtect;
                            VirtualProtect(_amsiScanBufferAddr, (UIntPtr)16, 0x40 /* PAGE_EXECUTE_READWRITE */, out oldProtect);
                            Marshal.Copy(_originalAmsiPrologue, 0, _amsiScanBufferAddr, 16);
                            VirtualProtect(_amsiScanBufferAddr, (UIntPtr)16, oldProtect, out oldProtect);
                            Logger.Log("AMSI restored: AmsiScanBuffer prologue repaired", LogLevel.ACTION);
                        }
                        catch (Exception ex)
                        {
                            Logger.Log("AMSI restore failed: " + ex.Message, LogLevel.ERROR);
                        }

                        return false;
                    }
                }
                return true;
            }
            catch { return true; }
        }

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        /// <summary>
        /// Our own pattern matching on script content (supplements AMSI).
        /// Catches things AMSI might miss if Defender definitions are outdated.
        /// </summary>
        private static void ScanContentPatterns(string content, string name, AmsiScanResult result)
        {
            if (string.IsNullOrEmpty(content)) return;
            string lower = content.ToLowerInvariant();

            // PowerShell attack patterns
            string[][] patterns = new string[][]
            {
                new string[] { "invoke-mimikatz",       "Mimikatz",             "T1003",    "90" },
                new string[] { "invoke-kerberoast",     "Kerberoasting",        "T1558.003","80" },
                new string[] { "invoke-bloodhound",     "BloodHound",           "T1087",    "75" },
                new string[] { "invoke-sharphound",     "SharpHound",           "T1087",    "75" },
                new string[] { "invoke-rubeus",         "Rubeus",               "T1558",    "80" },
                new string[] { "invoke-seatbelt",       "Seatbelt",             "T1082",    "60" },
                new string[] { "invoke-powershellmafia","PowerShellMafia",      "T1059.001","70" },
                new string[] { "get-gpppassword",       "GPP Password",         "T1552.006","80" },
                new string[] { "invoke-psexec",         "PsExec",               "T1570",    "70" },
                new string[] { "invoke-wmiexec",        "WMIExec",              "T1047",    "70" },
                new string[] { "invoke-smbexec",        "SMBExec",              "T1021.002","70" },
                new string[] { "invoke-dcomexec",       "DCOMExec",             "T1021.003","70" },
                new string[] { "new-inmemorypemodule",  "Reflective PE Load",   "T1620",    "85" },
                new string[] { "[system.reflection.assembly]::load", "Assembly.Load", "T1620", "75" },
                new string[] { "sekurlsa::logonpasswords", "Mimikatz sekurlsa", "T1003.001","95" },
                new string[] { "token::elevate",        "Mimikatz token",       "T1134",    "90" },
                new string[] { "lsadump::sam",          "Mimikatz SAM dump",    "T1003.002","90" },
                new string[] { "kerberos::golden",      "Golden ticket",        "T1558.001","95" },
                new string[] { "amsiutils",             "AMSI bypass attempt",  "T1562.001","80" },
                new string[] { "amsiinitfailed",        "AMSI bypass",          "T1562.001","85" },
                new string[] { "amsi.dll",              "AMSI manipulation",    "T1562.001","60" },
            };

            for (int i = 0; i < patterns.Length; i++)
            {
                if (lower.Contains(patterns[i][0]))
                {
                    int score = int.Parse(patterns[i][3]);
                    if (!result.IsMalicious) result.IsMalicious = true;
                    result.PatternMatches.Add(string.Format("{0} [{1}] (score:{2})",
                        patterns[i][1], patterns[i][2], score));

                    Logger.Log(string.Format("Script pattern: {0} in {1} [{2}]",
                        patterns[i][1], name, patterns[i][2]),
                        LogLevel.THREAT, "amsi_detections.log");
                    EdrState.IncrementThreats();
                }
            }
        }
    }

    public class AmsiScanResult
    {
        public string ContentName;
        public bool IsMalicious;
        public bool IsBlocked;
        public int RawResult;
        public System.Collections.Generic.List<string> PatternMatches;

        public AmsiScanResult()
        {
            PatternMatches = new System.Collections.Generic.List<string>();
        }
    }
}
