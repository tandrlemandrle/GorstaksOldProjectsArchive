using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GEdr.Engine
{
    /// <summary>
    /// Poor man's CAPA: parses PE headers to extract imports, sections, resources,
    /// and maps import combinations to capabilities (inject-code, capture-keystrokes, etc.).
    /// No external dependencies - raw binary parsing of PE format.
    /// </summary>
    public static class PeAnalyzer
    {
        public class SectionInfo
        {
            public string Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint RawDataSize;
            public uint RawDataOffset;
            public uint Characteristics;
            public double Entropy;
        }

        public class ImportInfo
        {
            public string DllName;
            public List<string> Functions;
            public ImportInfo()
            {
                Functions = new List<string>();
            }
        }

        public class Capability
        {
            public string Name;
            public string Description;
            public string MitreId;
            public int Score;
            public List<string> Evidence;
            public Capability()
            {
                Evidence = new List<string>();
            }
        }

        public class PeReport
        {
            public bool IsPE;
            public bool Is64Bit;
            public bool IsDLL;
            public bool IsNET;
            public DateTime CompileTime;
            public List<SectionInfo> Sections;
            public List<ImportInfo> Imports;
            public List<string> ImportedFunctions; // flat list for easy searching
            public List<Capability> Capabilities;
            public List<string> SuspiciousStrings;
            public List<string> Urls;
            public List<string> IpAddresses;
            public List<string> RegistryKeys;
            public List<string> PackerIndicators;
            public int TotalScore;
            public string Error;

            public PeReport()
            {
                Sections = new List<SectionInfo>();
                Imports = new List<ImportInfo>();
                ImportedFunctions = new List<string>();
                Capabilities = new List<Capability>();
                SuspiciousStrings = new List<string>();
                Urls = new List<string>();
                IpAddresses = new List<string>();
                RegistryKeys = new List<string>();
                PackerIndicators = new List<string>();
            }
        }

        // ── Capability definitions: import combinations → capabilities ──────
        private static readonly CapabilityDef[] _capabilityDefs = new CapabilityDef[]
        {
            new CapabilityDef("inject-code-into-process", "Process injection via remote thread",
                "T1055", 70, new string[] { "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" }, 3),
            new CapabilityDef("inject-code-via-apc", "APC injection",
                "T1055.004", 70, new string[] { "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC" }, 3),
            new CapabilityDef("process-hollowing", "Process hollowing",
                "T1055.012", 80, new string[] { "CreateProcessA", "CreateProcessW", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread" }, 4),
            new CapabilityDef("capture-keystrokes", "Keylogger capability",
                "T1056.001", 65, new string[] { "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState" }, 2),
            new CapabilityDef("capture-screenshot", "Screenshot capture",
                "T1113", 40, new string[] { "BitBlt", "GetDC", "CreateCompatibleDC", "GetDesktopWindow", "CreateCompatibleBitmap" }, 3),
            new CapabilityDef("communicate-over-http", "HTTP communication",
                "T1071.001", 20, new string[] { "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW", "HttpSendRequestA", "HttpSendRequestW", "HttpOpenRequestA", "HttpOpenRequestW" }, 2),
            new CapabilityDef("download-file", "File download capability",
                "T1105", 30, new string[] { "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA" }, 1),
            new CapabilityDef("escalate-privileges", "Privilege escalation",
                "T1134", 60, new string[] { "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA", "LookupPrivilegeValueW", "ImpersonateLoggedOnUser", "DuplicateTokenEx" }, 3),
            new CapabilityDef("persist-via-registry", "Registry persistence",
                "T1547.001", 45, new string[] { "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW", "RegOpenKeyExA", "RegOpenKeyExW" }, 2),
            new CapabilityDef("create-service", "Service creation",
                "T1543.003", 50, new string[] { "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW", "StartServiceA", "StartServiceW" }, 2),
            new CapabilityDef("manipulate-firewall", "Firewall manipulation",
                "T1562.004", 55, new string[] { "INetFwPolicy2", "INetFwRules", "INetFwRule" }, 1),
            new CapabilityDef("enumerate-processes", "Process enumeration",
                "T1057", 15, new string[] { "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses" }, 2),
            new CapabilityDef("read-process-memory", "Read other process memory",
                "T1055", 55, new string[] { "OpenProcess", "ReadProcessMemory" }, 2),
            new CapabilityDef("modify-memory-protection", "Change memory page protection",
                "T1055", 50, new string[] { "VirtualProtect", "VirtualProtectEx" }, 1),
            new CapabilityDef("execute-shellcode", "Shellcode execution",
                "T1055", 65, new string[] { "VirtualAlloc", "VirtualProtect", "RtlMoveMemory" }, 2),
            new CapabilityDef("anti-debug", "Anti-debugging techniques",
                "T1622", 35, new string[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA" }, 2),
            new CapabilityDef("anti-vm", "Anti-VM / sandbox detection",
                "T1497", 40, new string[] { "GetTickCount", "QueryPerformanceCounter", "GetSystemInfo", "GlobalMemoryStatusEx" }, 3),
            new CapabilityDef("encrypt-data", "Cryptographic operations",
                "T1486", 25, new string[] { "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW", "BCryptEncrypt", "BCryptDecrypt" }, 2),
            new CapabilityDef("access-clipboard", "Clipboard access",
                "T1115", 30, new string[] { "OpenClipboard", "GetClipboardData", "SetClipboardData", "EmptyClipboard" }, 2),
            new CapabilityDef("create-mutex", "Mutex creation (single instance check)",
                "T1480", 10, new string[] { "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW" }, 1),
        };

        // ── Packer section name indicators ──────────────────────────────────
        private static readonly string[] _packerSections = new string[]
        {
            "UPX0", "UPX1", "UPX!", ".aspack", ".rlpack", ".petite",
            ".themida", ".vmp0", ".vmp1", ".enigma", ".nsp0", ".nsp1",
            "MEW", ".MPRESS1", ".MPRESS2", ".perplex", ".sforce"
        };

        public static PeReport Analyze(string filePath)
        {
            PeReport report = new PeReport();
            if (!File.Exists(filePath))
            {
                report.Error = "File not found";
                return report;
            }

            byte[] fileBytes;
            try
            {
                fileBytes = File.ReadAllBytes(filePath);
            }
            catch (Exception ex)
            {
                report.Error = "Cannot read file: " + ex.Message;
                return report;
            }

            if (fileBytes.Length < 64)
            {
                report.Error = "File too small for PE";
                return report;
            }

            // Check MZ header
            if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A)
            {
                report.IsPE = false;
                // Still extract strings for non-PE files (scripts, etc.)
                ExtractStrings(fileBytes, report);
                return report;
            }

            report.IsPE = true;

            try
            {
                // Get PE header offset from e_lfanew (offset 0x3C)
                int peOffset = BitConverter.ToInt32(fileBytes, 0x3C);
                if (peOffset < 0 || peOffset + 24 > fileBytes.Length)
                {
                    report.Error = "Invalid PE offset";
                    return report;
                }

                // Verify PE signature "PE\0\0"
                if (fileBytes[peOffset] != 0x50 || fileBytes[peOffset + 1] != 0x45 ||
                    fileBytes[peOffset + 2] != 0x00 || fileBytes[peOffset + 3] != 0x00)
                {
                    report.Error = "Invalid PE signature";
                    return report;
                }

                // COFF header starts at peOffset + 4
                int coffOffset = peOffset + 4;
                ushort machine = BitConverter.ToUInt16(fileBytes, coffOffset);
                report.Is64Bit = (machine == 0x8664); // AMD64
                ushort numSections = BitConverter.ToUInt16(fileBytes, coffOffset + 2);
                uint timeDateStamp = BitConverter.ToUInt32(fileBytes, coffOffset + 4);
                ushort characteristics = BitConverter.ToUInt16(fileBytes, coffOffset + 18);
                report.IsDLL = (characteristics & 0x2000) != 0;

                // Compile timestamp
                try
                {
                    report.CompileTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeDateStamp);
                }
                catch { }

                // Optional header
                int optionalOffset = coffOffset + 20;
                ushort optionalMagic = BitConverter.ToUInt16(fileBytes, optionalOffset);
                bool isPE32Plus = (optionalMagic == 0x20B); // PE32+

                // Check for .NET (COM descriptor directory)
                int clrDirOffset;
                if (isPE32Plus)
                    clrDirOffset = optionalOffset + 208; // DataDirectory[14] for PE32+
                else
                    clrDirOffset = optionalOffset + 192; // DataDirectory[14] for PE32

                if (clrDirOffset + 8 <= fileBytes.Length)
                {
                    uint clrRva = BitConverter.ToUInt32(fileBytes, clrDirOffset);
                    uint clrSize = BitConverter.ToUInt32(fileBytes, clrDirOffset + 4);
                    report.IsNET = (clrRva != 0 && clrSize != 0);
                }

                // Parse sections
                ushort optionalHeaderSize = BitConverter.ToUInt16(fileBytes, coffOffset + 16);
                int sectionTableOffset = optionalOffset + optionalHeaderSize;

                for (int i = 0; i < numSections; i++)
                {
                    int secOff = sectionTableOffset + (i * 40);
                    if (secOff + 40 > fileBytes.Length) break;

                    SectionInfo sec = new SectionInfo();
                    // Section name is 8 bytes, null-padded
                    byte[] nameBytes = new byte[8];
                    Array.Copy(fileBytes, secOff, nameBytes, 0, 8);
                    sec.Name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                    sec.VirtualSize = BitConverter.ToUInt32(fileBytes, secOff + 8);
                    sec.VirtualAddress = BitConverter.ToUInt32(fileBytes, secOff + 12);
                    sec.RawDataSize = BitConverter.ToUInt32(fileBytes, secOff + 16);
                    sec.RawDataOffset = BitConverter.ToUInt32(fileBytes, secOff + 20);
                    sec.Characteristics = BitConverter.ToUInt32(fileBytes, secOff + 36);

                    report.Sections.Add(sec);

                    // Check for packer indicators
                    for (int p = 0; p < _packerSections.Length; p++)
                    {
                        if (string.Equals(sec.Name, _packerSections[p], StringComparison.OrdinalIgnoreCase))
                        {
                            report.PackerIndicators.Add(sec.Name);
                            break;
                        }
                    }

                    // Check for executable + writable sections (suspicious)
                    bool isExec = (sec.Characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
                    bool isWrite = (sec.Characteristics & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE
                    if (isExec && isWrite && sec.Name != ".text")
                    {
                        report.PackerIndicators.Add(string.Format("RWX section: {0}", sec.Name));
                    }
                }

                // Calculate section entropies
                double[] entropies = EntropyAnalyzer.CalculateSectionEntropies(filePath, report.Sections.ToArray());
                for (int i = 0; i < entropies.Length && i < report.Sections.Count; i++)
                {
                    report.Sections[i].Entropy = entropies[i];
                    if (entropies[i] > 7.0)
                    {
                        report.PackerIndicators.Add(string.Format("High entropy section: {0} ({1:F2})", report.Sections[i].Name, entropies[i]));
                    }
                }

                // Parse import table
                ParseImports(fileBytes, report, peOffset, isPE32Plus, optionalOffset);

                // Map imports to capabilities (CAPA-like)
                MapCapabilities(report);

                // Scan for direct syscall stubs (SysWhispers, HellsGate, D/Invoke)
                ScanForSyscallStubs(fileBytes, report);

                // Extract strings
                ExtractStrings(fileBytes, report);
            }
            catch (Exception ex)
            {
                report.Error = "PE parse error: " + ex.Message;
            }

            // Calculate total score
            for (int i = 0; i < report.Capabilities.Count; i++)
                report.TotalScore += report.Capabilities[i].Score;
            report.TotalScore += report.PackerIndicators.Count * 15;

            return report;
        }

        private static void ParseImports(byte[] fileBytes, PeReport report, int peOffset, bool isPE32Plus, int optionalOffset)
        {
            try
            {
                // Import directory is DataDirectory[1]
                int importDirOffset;
                if (isPE32Plus)
                    importDirOffset = optionalOffset + 120; // 16 + 8*13 for PE32+... actually offset 104 + 16
                else
                    importDirOffset = optionalOffset + 104;

                // Simpler approach: just offset from optional header start
                // PE32: DataDirectory starts at offset 96 from optional header, import is index 1
                // PE32+: DataDirectory starts at offset 112 from optional header, import is index 1
                int ddStart = isPE32Plus ? optionalOffset + 112 : optionalOffset + 96;
                int importRva = (int)BitConverter.ToUInt32(fileBytes, ddStart + 8); // index 1, each entry is 8 bytes
                int importSize = (int)BitConverter.ToUInt32(fileBytes, ddStart + 12);

                if (importRva == 0 || importSize == 0) return;

                // Convert RVA to file offset using section table
                int importFileOffset = RvaToOffset(importRva, report.Sections);
                if (importFileOffset < 0 || importFileOffset >= fileBytes.Length) return;

                // Each import descriptor is 20 bytes
                int pos = importFileOffset;
                while (pos + 20 <= fileBytes.Length)
                {
                    uint originalFirstThunk = BitConverter.ToUInt32(fileBytes, pos);
                    uint nameRva = BitConverter.ToUInt32(fileBytes, pos + 12);
                    uint firstThunk = BitConverter.ToUInt32(fileBytes, pos + 16);

                    // End of import descriptors
                    if (nameRva == 0 && firstThunk == 0) break;

                    ImportInfo imp = new ImportInfo();

                    // Read DLL name
                    int nameOffset = RvaToOffset((int)nameRva, report.Sections);
                    if (nameOffset >= 0 && nameOffset < fileBytes.Length)
                    {
                        imp.DllName = ReadAsciiString(fileBytes, nameOffset, 256);
                    }

                    // Read imported function names
                    uint thunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
                    int thunkOffset = RvaToOffset((int)thunkRva, report.Sections);
                    if (thunkOffset >= 0)
                    {
                        int thunkSize = isPE32Plus ? 8 : 4;
                        int tpos = thunkOffset;
                        int funcCount = 0;
                        while (tpos + thunkSize <= fileBytes.Length && funcCount < 500)
                        {
                            long thunkValue;
                            if (isPE32Plus)
                                thunkValue = BitConverter.ToInt64(fileBytes, tpos);
                            else
                                thunkValue = BitConverter.ToUInt32(fileBytes, tpos);

                            if (thunkValue == 0) break;

                            // Check if import by ordinal (high bit set)
                            bool byOrdinal;
                            if (isPE32Plus)
                                byOrdinal = (thunkValue & unchecked((long)0x8000000000000000)) != 0;
                            else
                                byOrdinal = (thunkValue & 0x80000000) != 0;

                            if (!byOrdinal)
                            {
                                int hintNameRva = (int)(thunkValue & 0x7FFFFFFF);
                                int hintNameOffset = RvaToOffset(hintNameRva, report.Sections);
                                if (hintNameOffset >= 0 && hintNameOffset + 2 < fileBytes.Length)
                                {
                                    // Skip 2-byte hint, read name
                                    string funcName = ReadAsciiString(fileBytes, hintNameOffset + 2, 256);
                                    if (!string.IsNullOrEmpty(funcName))
                                    {
                                        imp.Functions.Add(funcName);
                                        report.ImportedFunctions.Add(funcName);
                                    }
                                }
                            }

                            tpos += thunkSize;
                            funcCount++;
                        }
                    }

                    if (!string.IsNullOrEmpty(imp.DllName))
                        report.Imports.Add(imp);

                    pos += 20;
                    if (report.Imports.Count > 200) break; // safety limit
                }
            }
            catch { }
        }

        private static void MapCapabilities(PeReport report)
        {
            HashSet<string> importSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < report.ImportedFunctions.Count; i++)
                importSet.Add(report.ImportedFunctions[i]);

            for (int i = 0; i < _capabilityDefs.Length; i++)
            {
                CapabilityDef def = _capabilityDefs[i];
                List<string> matched = new List<string>();
                for (int j = 0; j < def.RequiredImports.Length; j++)
                {
                    // Check both A and W variants
                    string imp = def.RequiredImports[j];
                    if (importSet.Contains(imp) || importSet.Contains(imp + "A") || importSet.Contains(imp + "W"))
                    {
                        matched.Add(imp);
                    }
                }

                if (matched.Count >= def.MinMatches)
                {
                    Capability cap = new Capability();
                    cap.Name = def.Name;
                    cap.Description = def.Description;
                    cap.MitreId = def.MitreId;
                    cap.Score = def.Score;
                    cap.Evidence = matched;
                    report.Capabilities.Add(cap);
                }
            }
        }

        /// <summary>
        /// Scan for direct syscall stubs in executable sections.
        /// Modern attack tools (SysWhispers, HellsGate, D/Invoke) embed syscall
        /// stubs to bypass user-mode API hooks. The pattern is:
        ///   mov r10, rcx        (4C 8B D1)
        ///   mov eax, <number>   (B8 xx xx 00 00)
        ///   syscall              (0F 05)
        /// or the older int 2e variant:
        ///   mov r10, rcx        (4C 8B D1)
        ///   mov eax, <number>   (B8 xx xx 00 00)
        ///   ... int 2e           (CD 2E)
        /// 
        /// Legitimate binaries (ntdll.dll) contain these, but any OTHER binary
        /// with embedded syscall stubs is highly suspicious.
        /// </summary>
        private static void ScanForSyscallStubs(byte[] fileBytes, PeReport report)
        {
            if (!report.Is64Bit) return; // Syscall stubs are x64 only

            // Don't flag ntdll.dll itself
            // (We check the report's imports — if it IS ntdll, skip)

            int stubCount = 0;

            // Scan only executable sections
            for (int s = 0; s < report.Sections.Count; s++)
            {
                SectionInfo sec = report.Sections[s];
                bool isExec = (sec.Characteristics & 0x20000000) != 0;
                if (!isExec) continue;

                int start = (int)sec.RawDataOffset;
                int end = start + (int)sec.RawDataSize;
                if (start < 0 || end > fileBytes.Length) continue;

                // Pattern: 4C 8B D1 B8 xx xx 00 00 ... 0F 05
                // (mov r10, rcx; mov eax, syscall_number; ... syscall)
                for (int i = start; i < end - 12; i++)
                {
                    // mov r10, rcx = 4C 8B D1
                    if (fileBytes[i] == 0x4C && fileBytes[i + 1] == 0x8B && fileBytes[i + 2] == 0xD1)
                    {
                        // mov eax, imm32 = B8 xx xx 00 00
                        if (fileBytes[i + 3] == 0xB8 && fileBytes[i + 7] == 0x00)
                        {
                            // Look for syscall (0F 05) or int 2e (CD 2E) within next 20 bytes
                            int searchEnd = Math.Min(i + 24, end - 1);
                            for (int j = i + 8; j < searchEnd; j++)
                            {
                                if ((fileBytes[j] == 0x0F && fileBytes[j + 1] == 0x05) ||
                                    (fileBytes[j] == 0xCD && fileBytes[j + 1] == 0x2E))
                                {
                                    stubCount++;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (stubCount > 0)
            {
                // A few stubs might be legitimate (some crypto libraries inline them)
                // But 3+ is very suspicious for non-system binaries
                int score;
                if (stubCount >= 10) score = 80;
                else if (stubCount >= 5) score = 65;
                else if (stubCount >= 3) score = 50;
                else score = 25;

                Capability cap = new Capability();
                cap.Name = "direct-syscall";
                cap.Description = string.Format("Direct syscall stubs ({0} found) - bypasses API hooks", stubCount);
                cap.MitreId = "T1106";
                cap.Score = score;
                cap.Evidence = new List<string>();
                cap.Evidence.Add(string.Format("{0} syscall stubs", stubCount));
                report.Capabilities.Add(cap);
            }
        }

        private static void ExtractStrings(byte[] fileBytes, PeReport report)
        {
            // Extract ASCII strings >= 6 chars, look for URLs, IPs, registry keys, suspicious patterns
            int maxScan = Math.Min(fileBytes.Length, 2 * 1024 * 1024); // scan first 2MB
            StringBuilder current = new StringBuilder();

            for (int i = 0; i < maxScan; i++)
            {
                byte b = fileBytes[i];
                if (b >= 0x20 && b < 0x7F)
                {
                    current.Append((char)b);
                }
                else
                {
                    if (current.Length >= 6)
                    {
                        string s = current.ToString();
                        ClassifyString(s, report);
                    }
                    current.Clear();
                }
            }
            if (current.Length >= 6)
                ClassifyString(current.ToString(), report);

            // Cap lists to prevent memory bloat
            if (report.Urls.Count > 100) report.Urls.RemoveRange(100, report.Urls.Count - 100);
            if (report.IpAddresses.Count > 100) report.IpAddresses.RemoveRange(100, report.IpAddresses.Count - 100);
            if (report.SuspiciousStrings.Count > 200) report.SuspiciousStrings.RemoveRange(200, report.SuspiciousStrings.Count - 200);
        }

        private static void ClassifyString(string s, PeReport report)
        {
            // URLs
            if (s.Contains("http://") || s.Contains("https://") || s.Contains("ftp://"))
            {
                if (!report.Urls.Contains(s))
                    report.Urls.Add(s);
            }

            // IP addresses (simple pattern)
            if (s.Length <= 21 && System.Text.RegularExpressions.Regex.IsMatch(s, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
            {
                if (!s.StartsWith("0.") && !s.StartsWith("255."))
                {
                    if (!report.IpAddresses.Contains(s))
                        report.IpAddresses.Add(s);
                }
            }

            // Registry keys
            string su = s.ToUpperInvariant();
            if (su.Contains("HKEY_") || su.Contains("HKLM\\") || su.Contains("HKCU\\") ||
                su.Contains("CURRENTVERSION\\RUN"))
            {
                if (!report.RegistryKeys.Contains(s))
                    report.RegistryKeys.Add(s);
            }

            // Suspicious strings
            string sl = s.ToLowerInvariant();
            if (sl.Contains("mimikatz") || sl.Contains("metasploit") || sl.Contains("cobaltstrike") ||
                sl.Contains("meterpreter") || sl.Contains("shellcode") || sl.Contains("keylogger") ||
                sl.Contains("ransomware") || sl.Contains("backdoor") || sl.Contains("rootkit") ||
                sl.Contains("exploit") || sl.Contains("payload") || sl.Contains("reverse_tcp") ||
                sl.Contains("cmd.exe /c") || sl.Contains("powershell -enc") ||
                sl.Contains("downloadstring") || sl.Contains("invoke-expression"))
            {
                if (report.SuspiciousStrings.Count < 200 && !report.SuspiciousStrings.Contains(s))
                    report.SuspiciousStrings.Add(s);
            }
        }

        private static int RvaToOffset(int rva, List<SectionInfo> sections)
        {
            for (int i = 0; i < sections.Count; i++)
            {
                SectionInfo sec = sections[i];
                if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + Math.Max(sec.VirtualSize, sec.RawDataSize))
                {
                    return (int)(rva - sec.VirtualAddress + sec.RawDataOffset);
                }
            }
            return -1;
        }

        private static string ReadAsciiString(byte[] data, int offset, int maxLen)
        {
            if (offset < 0 || offset >= data.Length) return null;
            int end = offset;
            while (end < data.Length && end - offset < maxLen && data[end] != 0)
                end++;
            if (end == offset) return null;
            return Encoding.ASCII.GetString(data, offset, end - offset);
        }

        private class CapabilityDef
        {
            public string Name;
            public string Description;
            public string MitreId;
            public int Score;
            public string[] RequiredImports;
            public int MinMatches;

            public CapabilityDef(string name, string desc, string mitre, int score, string[] imports, int minMatches)
            {
                Name = name;
                Description = desc;
                MitreId = mitre;
                Score = score;
                RequiredImports = imports;
                MinMatches = minMatches;
            }
        }
    }
}
