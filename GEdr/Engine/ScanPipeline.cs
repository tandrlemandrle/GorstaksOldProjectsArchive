using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using GEdr.Core;
using GEdr.Response;

namespace GEdr.Engine
{
    /// <summary>
    /// VirusTotal-like multi-engine scan pipeline.
    /// Each file goes through: Hash reputation -> Signature check -> PE analysis (CAPA) -> YARA -> Entropy -> Verdict.
    /// Each engine votes with a score, combined score determines final verdict.
    /// Results are cached by file path + last-write-time to avoid re-scanning unchanged files.
    /// </summary>

    // Cached scan verdict (lightweight, not the full ScanResult)
    internal class CachedVerdict
    {
        public int TotalScore;
        public string Verdict;
        public ThreatSeverity Severity;
        public DateTime CachedAt;
        public DateTime FileWriteTime;
    }
    public class ScanResult
    {
        // File info
        public string FilePath;
        public string FileName;
        public long FileSize;
        public string SHA256;
        public string MD5;
        public string SHA1;

        // Signature
        public bool IsSigned;
        public string SignerName;

        // Entropy
        public double FileEntropy;
        public string EntropyVerdict;

        // Hash reputation
        public ReputationResult Reputation;

        // PE analysis (CAPA-like)
        public PeAnalyzer.PeReport PeReport;

        // YARA matches
        public List<YaraMatch> YaraMatches;

        // Combined verdict
        public int TotalScore;
        public string Verdict; // CLEAN, SUSPICIOUS, MALICIOUS, CRITICAL
        public ThreatSeverity Severity;
        public List<string> Reasons;

        public ScanResult()
        {
            YaraMatches = new List<YaraMatch>();
            Reasons = new List<string>();
        }
    }

    public static class ScanPipeline
    {
        // Cache: path -> cached verdict (avoids re-scanning unchanged files in monitor mode)
        private static readonly ConcurrentDictionary<string, CachedVerdict> _cache
            = new ConcurrentDictionary<string, CachedVerdict>(StringComparer.OrdinalIgnoreCase);
        private const int MaxCacheSize = 10000;
        private const int CacheTtlMinutes = 30;

        // Skip files larger than this (VHDX, PST, ISO won't contain scannable malware)
        public const long MaxScanFileSize = 100 * 1024 * 1024; // 100 MB

        // Known LOLBins (Living Off The Land Binaries) — signed Microsoft tools
        // that can be abused for code execution, download, or persistence.
        private static readonly string[] _lolBins = new string[]
        {
            "msbuild.exe", "installutil.exe", "regsvcs.exe", "regasm.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "cmstp.exe",
            "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe",
            "odbcconf.exe", "ieexec.exe", "msconfig.exe", "dnscmd.exe",
            "ftp.exe", "presentationhost.exe", "syncappvpublishingserver.exe",
            "control.exe", "csc.exe", "vbc.exe", "jsc.exe",
            "xwizard.exe", "infdefaultinstall.exe", "pcalua.exe",
            "scriptrunner.exe", "bash.exe", "wsl.exe",
            "forfiles.exe", "pcwrun.exe", "atbroker.exe",
        };

        /// <summary>Run the full analysis pipeline on a single file.</summary>
        public static ScanResult ScanFile(string filePath)
        {
            ScanResult result = new ScanResult();
            result.FilePath = filePath;
            result.FileName = Path.GetFileName(filePath);

            if (!File.Exists(filePath))
            {
                result.Verdict = "ERROR";
                result.Reasons.Add("File not found");
                return result;
            }

            try
            {
                FileInfo fi = new FileInfo(filePath);
                result.FileSize = fi.Length;

                // Skip oversized files
                if (fi.Length > MaxScanFileSize)
                {
                    result.Verdict = "SKIPPED";
                    result.Severity = ThreatSeverity.Low;
                    result.Reasons.Add(string.Format("File too large ({0:N0} MB, limit {1} MB)",
                        fi.Length / (1024 * 1024), MaxScanFileSize / (1024 * 1024)));
                    Logger.Log(string.Format("Skipped oversized file: {0} ({1:N0} bytes)", filePath, fi.Length), LogLevel.DEBUG);
                    return result;
                }

                // Check cache
                CachedVerdict cached;
                if (_cache.TryGetValue(filePath, out cached))
                {
                    if (cached.FileWriteTime == fi.LastWriteTimeUtc
                        && (DateTime.UtcNow - cached.CachedAt).TotalMinutes < CacheTtlMinutes)
                    {
                        result.TotalScore = cached.TotalScore;
                        result.Verdict = cached.Verdict;
                        result.Severity = cached.Severity;
                        result.Reasons.Add("CACHED");
                        return result;
                    }
                }
            }
            catch { }

            // ── Engine 1: Hashes ─────────────────────────────────────────────
            result.SHA256 = HashReputation.ComputeSha256(filePath);
            result.MD5 = HashReputation.ComputeMd5(filePath);
            result.SHA1 = HashReputation.ComputeSha1(filePath);

            // ── Engine 2: Hash Reputation (CIRCL, Cymru, MalwareBazaar) ──────
            if (!string.IsNullOrEmpty(result.SHA256))
            {
                result.Reputation = HashReputation.GetReputation(result.SHA256);
                if (result.Reputation.IsMalicious)
                {
                    result.TotalScore += result.Reputation.Confidence;
                    result.Reasons.Add(string.Format("Hash reputation: {0} (confidence {1}%)", result.Reputation.Source, result.Reputation.Confidence));
                }
            }

            // ── Engine 3: Authenticode Signature ─────────────────────────────
            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                X509Certificate2 cert2 = new X509Certificate2(cert);
                result.IsSigned = cert2.Verify();
                result.SignerName = cert2.Subject;
            }
            catch
            {
                result.IsSigned = false;
            }

            if (!result.IsSigned)
            {
                result.TotalScore += 10;
                result.Reasons.Add("Unsigned binary");
            }

            // ── Trusted Publisher Check ──────────────────────────────────────
            // Signed binaries from known OS/AV vendors get CAPA analysis for
            // informational purposes but their capability scores are zeroed out
            // to prevent false positives on legitimate system binaries.
            bool isTrustedPublisher = false;
            if (result.IsSigned && !string.IsNullOrEmpty(result.SignerName))
            {
                isTrustedPublisher = IsTrustedSigner(result.SignerName);
            }

            // ── Engine 4: Entropy Analysis ───────────────────────────────────
            result.FileEntropy = EntropyAnalyzer.CalculateFileEntropy(filePath);
            result.EntropyVerdict = EntropyAnalyzer.EntropyVerdict(result.FileEntropy);

            if (result.FileEntropy >= 7.5)
            {
                result.TotalScore += 25;
                result.Reasons.Add(string.Format("High entropy: {0:F2} ({1})", result.FileEntropy, result.EntropyVerdict));
            }
            else if (result.FileEntropy >= 7.0)
            {
                result.TotalScore += 10;
                result.Reasons.Add(string.Format("Elevated entropy: {0:F2}", result.FileEntropy));
            }

            // ── Engine 5: PE Analysis (CAPA-like) ────────────────────────────
            result.PeReport = PeAnalyzer.Analyze(filePath);

            if (result.PeReport.IsPE)
            {
                // Add capability scores (skip scoring for trusted publishers)
                for (int i = 0; i < result.PeReport.Capabilities.Count; i++)
                {
                    PeAnalyzer.Capability cap = result.PeReport.Capabilities[i];
                    if (!isTrustedPublisher)
                    {
                        result.TotalScore += cap.Score;
                    }
                    result.Reasons.Add(string.Format("PE capability: {0} [{1}] (score {2}{3}, evidence: {4})",
                        cap.Name, cap.MitreId, cap.Score,
                        isTrustedPublisher ? " TRUSTED-SKIP" : "",
                        string.Join("+", cap.Evidence.ToArray())));
                }

                // Packer indicators
                for (int i = 0; i < result.PeReport.PackerIndicators.Count; i++)
                {
                    if (!isTrustedPublisher)
                        result.TotalScore += 15;
                    result.Reasons.Add("Packer: " + result.PeReport.PackerIndicators[i]);
                }

                // Suspicious strings
                if (result.PeReport.SuspiciousStrings.Count > 0)
                {
                    int strScore = Math.Min(result.PeReport.SuspiciousStrings.Count * 5, 30);
                    if (!isTrustedPublisher)
                        result.TotalScore += strScore;
                    result.Reasons.Add(string.Format("Suspicious strings: {0} found", result.PeReport.SuspiciousStrings.Count));
                }

                // URLs to raw IPs (not domains) are suspicious
                int rawIpUrls = 0;
                for (int i = 0; i < result.PeReport.Urls.Count; i++)
                {
                    string url = result.PeReport.Urls[i];
                    // Check if URL contains raw IP (http://1.2.3.4/...)
                    if (System.Text.RegularExpressions.Regex.IsMatch(url, @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                        rawIpUrls++;
                }
                if (rawIpUrls > 0)
                {
                    if (!isTrustedPublisher)
                        result.TotalScore += rawIpUrls * 10;
                    result.Reasons.Add(string.Format("URLs to raw IPs: {0}", rawIpUrls));
                }
            }

            // ── Engine 6: YARA Rule Scanning ─────────────────────────────────
            if (YaraEngine.IsAvailable)
            {
                result.YaraMatches = YaraEngine.ScanFile(filePath);
                for (int i = 0; i < result.YaraMatches.Count; i++)
                {
                    YaraMatch ym = result.YaraMatches[i];
                    result.TotalScore += ym.Score;
                    result.Reasons.Add(string.Format("YARA: {0} ({1}, score {2}{3})",
                        ym.RuleName, ym.RuleFile, ym.Score,
                        string.IsNullOrEmpty(ym.MitreId) ? "" : ", " + ym.MitreId));
                }
            }

            // ── Engine 7: LOLBin Detection (even for trusted publishers) ──────
            // Trusted publisher bypass prevents false positives on system binaries,
            // but attackers abuse signed Microsoft LOLBins. Check original filename
            // against known LOLBin list regardless of trust status.
            if (result.PeReport != null && result.PeReport.IsPE)
            {
                string origName = null;
                try
                {
                    System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
                    origName = (fvi.OriginalFilename ?? fvi.InternalName ?? "").ToLowerInvariant();
                }
                catch { }
                if (string.IsNullOrEmpty(origName))
                    origName = Path.GetFileName(filePath).ToLowerInvariant();

                // Check if this is a known LOLBin
                for (int lb = 0; lb < _lolBins.Length; lb++)
                {
                    if (origName.Contains(_lolBins[lb]))
                    {
                        result.Reasons.Add(string.Format("LOLBin: {0} (signed abuse vector)", _lolBins[lb]));
                        // Don't add score here — score comes from command-line analysis
                        // But flag it so the process monitor knows to scrutinize arguments
                        break;
                    }
                }
            }

            // ── Engine 8: AMSI scan for script files ─────────────────────────
            if (AmsiScanner.IsAvailable)
            {
                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                if (ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".wsf" || ext == ".hta")
                {
                    AmsiScanResult amsi = AmsiScanner.ScanFile(filePath);
                    if (amsi.IsMalicious)
                    {
                        result.TotalScore += 80;
                        result.Reasons.Add("AMSI: Malicious script content detected");
                        for (int a = 0; a < amsi.PatternMatches.Count; a++)
                            result.Reasons.Add("AMSI pattern: " + amsi.PatternMatches[a]);
                    }
                }
            }

            // ── Final Verdict ────────────────────────────────────────────────
            // Check allowlist before applying verdict
            if (Config.IsAllowlisted(result.FilePath, result.SHA256, result.SignerName))
            {
                result.Verdict = "CLEAN";
                result.Severity = ThreatSeverity.Low;
                result.Reasons.Add("ALLOWLISTED");
                return result;
            }

            if (result.TotalScore >= Config.RuntimeAutoKillThreshold)
            {
                result.Verdict = "CRITICAL";
                result.Severity = ThreatSeverity.Critical;
            }
            else if (result.TotalScore >= Config.RuntimeAutoQuarantineThreshold)
            {
                result.Verdict = "MALICIOUS";
                result.Severity = ThreatSeverity.High;
            }
            else if (result.TotalScore >= Config.RuntimeAlertThreshold)
            {
                result.Verdict = "SUSPICIOUS";
                result.Severity = ThreatSeverity.Medium;
            }
            else
            {
                result.Verdict = "CLEAN";
                result.Severity = ThreatSeverity.Low;
            }

            EdrState.IncrementScanned();
            if (result.TotalScore >= Config.RuntimeAlertThreshold)
                EdrState.IncrementThreats();

            // Structured JSON logging
            JsonLogger.LogScanResult(result);

            // Cache the result
            try
            {
                if (_cache.Count > MaxCacheSize) _cache.Clear(); // simple eviction
                FileInfo cfi = new FileInfo(filePath);
                CachedVerdict cv = new CachedVerdict();
                cv.TotalScore = result.TotalScore;
                cv.Verdict = result.Verdict;
                cv.Severity = result.Severity;
                cv.CachedAt = DateTime.UtcNow;
                cv.FileWriteTime = cfi.LastWriteTimeUtc;
                _cache[filePath] = cv;
            }
            catch { }

            return result;
        }

        /// <summary>Print a scan result to console in VT-like format.</summary>
        public static void PrintResult(ScanResult r)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
            Console.WriteLine("=== SCAN: {0} ===", r.FileName);
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  Path:    {0}", r.FilePath);
            Console.WriteLine("  Size:    {0:N0} bytes", r.FileSize);
            Console.WriteLine("  SHA256:  {0}", r.SHA256 ?? "N/A");
            Console.WriteLine("  MD5:     {0}", r.MD5 ?? "N/A");
            Console.WriteLine("  SHA1:    {0}", r.SHA1 ?? "N/A");

            // Signature
            if (r.IsSigned)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  Signed:  YES ({0})", TruncateSubject(r.SignerName));
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  Signed:  NO");
            }

            // Entropy
            ConsoleColor entColor = r.FileEntropy >= 7.5 ? ConsoleColor.Red
                : r.FileEntropy >= 7.0 ? ConsoleColor.Yellow : ConsoleColor.Gray;
            Console.ForegroundColor = entColor;
            Console.WriteLine("  Entropy: {0:F2} ({1})", r.FileEntropy, r.EntropyVerdict);

            // Hash reputation
            if (r.Reputation != null && r.Reputation.IsMalicious)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  Hash:    MALICIOUS ({0}, confidence {1}%)", r.Reputation.Source, r.Reputation.Confidence);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("  Hash:    Not found in threat databases");
            }

            // PE info
            if (r.PeReport != null && r.PeReport.IsPE)
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("  PE:      {0} {1}{2}",
                    r.PeReport.Is64Bit ? "x64" : "x86",
                    r.PeReport.IsDLL ? "DLL" : "EXE",
                    r.PeReport.IsNET ? " (.NET)" : "");
                Console.WriteLine("  Compile: {0:yyyy-MM-dd HH:mm:ss} UTC", r.PeReport.CompileTime);
                Console.WriteLine("  Imports: {0} DLLs, {1} functions", r.PeReport.Imports.Count, r.PeReport.ImportedFunctions.Count);
                Console.WriteLine("  Sections: {0}", r.PeReport.Sections.Count);

                // Section details
                for (int i = 0; i < r.PeReport.Sections.Count; i++)
                {
                    PeAnalyzer.SectionInfo sec = r.PeReport.Sections[i];
                    ConsoleColor secColor = sec.Entropy > 7.0 ? ConsoleColor.Red
                        : sec.Entropy > 6.5 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
                    Console.ForegroundColor = secColor;
                    Console.WriteLine("    {0,-8} size:{1,8}  entropy:{2:F2}", sec.Name, sec.RawDataSize, sec.Entropy);
                }

                // Capabilities (CAPA-like)
                if (r.PeReport.Capabilities.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("  --- Capabilities (CAPA-like) ---");
                    for (int i = 0; i < r.PeReport.Capabilities.Count; i++)
                    {
                        PeAnalyzer.Capability cap = r.PeReport.Capabilities[i];
                        ConsoleColor capColor = cap.Score >= 60 ? ConsoleColor.Red
                            : cap.Score >= 40 ? ConsoleColor.Yellow : ConsoleColor.Cyan;
                        Console.ForegroundColor = capColor;
                        Console.WriteLine("    [{0}] {1} (score:{2}) via {3}",
                            cap.MitreId, cap.Name, cap.Score, string.Join("+", cap.Evidence.ToArray()));
                    }
                }

                // Packer indicators
                if (r.PeReport.PackerIndicators.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    for (int i = 0; i < r.PeReport.PackerIndicators.Count; i++)
                        Console.WriteLine("  Packer:  {0}", r.PeReport.PackerIndicators[i]);
                }

                // Suspicious strings (first 10)
                if (r.PeReport.SuspiciousStrings.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    int show = Math.Min(r.PeReport.SuspiciousStrings.Count, 10);
                    Console.WriteLine("  Suspicious strings ({0} total):", r.PeReport.SuspiciousStrings.Count);
                    for (int i = 0; i < show; i++)
                    {
                        string s = r.PeReport.SuspiciousStrings[i];
                        if (s.Length > 80) s = s.Substring(0, 80) + "...";
                        Console.WriteLine("    \"{0}\"", s);
                    }
                }

                // URLs (first 5)
                if (r.PeReport.Urls.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    int show = Math.Min(r.PeReport.Urls.Count, 5);
                    Console.WriteLine("  URLs ({0} total):", r.PeReport.Urls.Count);
                    for (int i = 0; i < show; i++)
                    {
                        string u = r.PeReport.Urls[i];
                        if (u.Length > 100) u = u.Substring(0, 100) + "...";
                        Console.WriteLine("    {0}", u);
                    }
                }
            }

            // YARA matches
            if (r.YaraMatches.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("  --- YARA Matches ---");
                for (int i = 0; i < r.YaraMatches.Count; i++)
                {
                    YaraMatch ym = r.YaraMatches[i];
                    Console.WriteLine("    {0} ({1}) score:{2} severity:{3}{4}",
                        ym.RuleName, ym.RuleFile, ym.Score, ym.Severity,
                        string.IsNullOrEmpty(ym.MitreId) ? "" : " mitre:" + ym.MitreId);
                }
            }

            // Final verdict
            Console.WriteLine();
            ConsoleColor verdictColor;
            switch (r.Verdict)
            {
                case "CRITICAL": verdictColor = ConsoleColor.Red; break;
                case "MALICIOUS": verdictColor = ConsoleColor.Red; break;
                case "SUSPICIOUS": verdictColor = ConsoleColor.Yellow; break;
                default: verdictColor = ConsoleColor.Green; break;
            }
            Console.ForegroundColor = verdictColor;
            Console.WriteLine("  VERDICT: {0} (score: {1})", r.Verdict, r.TotalScore);
            Console.ForegroundColor = ConsoleColor.Gray;

            // Reasons summary
            if (r.Reasons.Count > 0 && r.TotalScore >= Config.AlertThreshold)
            {
                Console.WriteLine("  Reasons:");
                for (int i = 0; i < r.Reasons.Count; i++)
                    Console.WriteLine("    - {0}", r.Reasons[i]);
            }

            Console.ResetColor();
            Console.WriteLine();
        }

        private static string TruncateSubject(string subject)
        {
            if (string.IsNullOrEmpty(subject)) return "unknown";
            // Extract CN= value
            int cnIdx = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (cnIdx >= 0)
            {
                string cn = subject.Substring(cnIdx + 3);
                int commaIdx = cn.IndexOf(',');
                if (commaIdx > 0) cn = cn.Substring(0, commaIdx);
                return cn.Trim();
            }
            if (subject.Length > 60) return subject.Substring(0, 60) + "...";
            return subject;
        }

        /// <summary>
        /// Check if a certificate subject belongs to a trusted OS/AV publisher.
        /// These binaries legitimately use privileged APIs and should not be
        /// scored on PE capabilities alone.
        /// </summary>
        private static bool IsTrustedSigner(string subject)
        {
            if (string.IsNullOrEmpty(subject)) return false;
            string upper = subject.ToUpperInvariant();
            string[] trustedNames = new string[] {
                "MICROSOFT CORPORATION",
                "MICROSOFT WINDOWS",
                "MICROSOFT CODE SIGNING",
                "WINDOWS DEFENDER",
                "INTEL(",
                "NVIDIA",
                "AMD INC",
                "ADVANCED MICRO DEVICES",
                "GOOGLE LLC",
                "GOOGLE INC",
                "MOZILLA CORPORATION",
                "APPLE INC",
                "ADOBE",
                "ORACLE",
                "VMWARE",
                "CITRIX",
                "CROWDSTRIKE",
                "SYMANTEC",
                "MCAFEE",
                "ESET",
                "KASPERSKY",
                "BITDEFENDER",
                "MALWAREBYTES",
                "SOPHOS",
                "TREND MICRO",
                "PALO ALTO",
                "SENTINELONE",
                "CARBON BLACK"
            };
            for (int i = 0; i < trustedNames.Length; i++)
            {
                if (upper.Contains(trustedNames[i]))
                    return true;
            }
            return false;
        }
    }
}
