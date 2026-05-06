using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Detection
{
    /// <summary>
    /// Indicator of Compromise (IoC) scanner.
    /// Matches files, processes, and network connections against:
    /// - Known malicious file hashes (MD5/SHA1/SHA256)
    /// - Known malicious IP addresses and CIDR ranges
    /// - Known malicious domains
    /// - MITRE ATT&CK technique IDs
    /// 
    /// Sources: user-supplied IoC lists, threat intel feeds, internal detections.
    /// </summary>
    public static class IoCScanner
    {
        // In-memory caches for fast lookup
        private static readonly HashSet<string> _maliciousHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> _maliciousIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> _maliciousDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, string> _hashToName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private static readonly object _cacheLock = new object();
        private static DateTime _lastReload = DateTime.MinValue;

        /// <summary>
        /// Built-in high-confidence IoCs (known malware families, common attack tools).
        /// These are always loaded even without external feeds.
        /// </summary>
        static IoCScanner()
        {
            LoadBuiltinIoCs();
        }

        private static void LoadBuiltinIoCs()
        {
            // Known Mimikatz variants (example hashes - these would be updated from threat intel)
            // In production, these come from MISP, VirusTotal, or internal intelligence
            AddMaliciousHash("" /* placeholder - real deployment loads from file */,
                "Mimikatz-Variant", "CredentialDumping");

            // Common Cobalt Strike beacon hashes (example)
            AddMaliciousHash("",
                "CobaltStrike-Beacon", "C2-Beacon");

            // Known malicious IPs (examples - would be populated from feeds)
            // These are placeholder examples only
        }

        /// <summary>
        /// Reload IoCs from disk (called periodically or on config change).
        /// </summary>
        public static void ReloadIoCs()
        {
            lock (_cacheLock)
            {
                if ((DateTime.Now - _lastReload).TotalMinutes < 5)
                    return; // Rate limit reloads

                string iocPath = Path.Combine(Config.InstallPath, "iocs.txt");
                if (!File.Exists(iocPath))
                {
                    // Create template file
                    try
                    {
                        File.WriteAllText(iocPath, GetDefaultIoCTemplate());
                    }
                    catch { }
                    return;
                }

                try
                {
                    _maliciousHashes.Clear();
                    _maliciousIPs.Clear();
                    _maliciousDomains.Clear();
                    _hashToName.Clear();

                    LoadBuiltinIoCs(); // Always keep builtins

                    string[] lines = File.ReadAllLines(iocPath);
                    foreach (string line in lines)
                    {
                        ParseIoCLine(line);
                    }

                    _lastReload = DateTime.Now;
                    Logger.Log(string.Format("IoC cache reloaded: {0} hashes, {1} IPs, {2} domains",
                        _maliciousHashes.Count, _maliciousIPs.Count, _maliciousDomains.Count),
                        LogLevel.INFO);
                }
                catch (Exception ex)
                {
                    Logger.Log("IoC reload failed: " + ex.Message, LogLevel.ERROR);
                }
            }
        }

        /// <summary>
        /// Check if a file hash is known malicious.
        /// </summary>
        public static bool IsMaliciousHash(string hash, out string threatName, out string technique)
        {
            threatName = null;
            technique = null;

            if (string.IsNullOrEmpty(hash)) return false;

            // Normalize hash
            hash = hash.Replace("-", "").ToUpperInvariant();

            lock (_cacheLock)
            {
                if (_maliciousHashes.Contains(hash))
                {
                    _hashToName.TryGetValue(hash, out threatName);
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Check if an IP address is known malicious.
        /// </summary>
        public static bool IsMaliciousIP(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;

            lock (_cacheLock)
            {
                // Direct match
                if (_maliciousIPs.Contains(ipAddress))
                    return true;

                // CIDR range check (simplified - full implementation would use IPNetwork library)
                foreach (string cidr in _maliciousIPs.Where(i => i.Contains("/")))
                {
                    if (IsIpInCidr(ipAddress, cidr))
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Check if a domain is known malicious or matches malicious patterns.
        /// </summary>
        public static bool IsMaliciousDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain)) return false;

            domain = domain.ToLowerInvariant();

            lock (_cacheLock)
            {
                // Direct match
                if (_maliciousDomains.Contains(domain))
                    return true;

                // Parent domain match (e.g., evil.com matches sub.evil.com)
                foreach (string badDomain in _maliciousDomains)
                {
                    if (domain.EndsWith("." + badDomain) || domain == badDomain)
                        return true;
                }
            }

            // DGA (Domain Generation Algorithm) detection
            if (DetectDGA(domain))
                return true;

            return false;
        }

        /// <summary>
        /// Scan a process for IoC matches (hash of executable).
        /// </summary>
        public static void ScanProcess(int pid, string processName, string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return;

            try
            {
                string hash = ComputeSHA256(exePath);
                string threatName, technique;

                if (IsMaliciousHash(hash, out threatName, out technique))
                {
                    Logger.Log(string.Format("IoC MATCH: {0} in {1} (PID:{2}) - {3}",
                        threatName, exePath, pid, hash),
                        LogLevel.THREAT, "ioc_hits.log");

                    ThreatInfo threat = new ThreatInfo();
                    threat.ThreatType = "IoC:" + threatName;
                    threat.ThreatPath = exePath;
                    threat.ProcessId = pid;
                    threat.ProcessName = processName;
                    threat.Severity = ThreatSeverity.Critical;
                    threat.Confidence = 95;
                    threat.Details["Hash"] = hash;
                    threat.Details["Technique"] = technique;
                    threat.Details["IoCSource"] = "hash-match";

                    ResponseQueue.Enqueue(threat);
                    GidrState.IncrementThreats();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("IoC scan error for PID " + pid + ": " + ex.Message, LogLevel.DEBUG);
            }
        }

        /// <summary>
        /// Scheduled job entry - reload IoCs periodically.
        /// </summary>
        public static void Maintenance()
        {
            ReloadIoCs();
        }

        private static void ParseIoCLine(string line)
        {
            line = line.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                return;

            // Format: type:value:metadata
            // hash:sha256:ThreatName:Technique
            // ip:1.2.3.4:Description
            // domain:evil.com:Description

            string[] parts = line.Split(':');
            if (parts.Length < 2) return;

            string type = parts[0].ToLower();
            string value = parts[1];

            switch (type)
            {
                case "hash":
                    string name = parts.Length > 2 ? parts[2] : "Unknown";
                    string tech = parts.Length > 3 ? parts[3] : "T1204";
                    AddMaliciousHash(value, name, tech);
                    break;

                case "ip":
                    _maliciousIPs.Add(value);
                    break;

                case "domain":
                    _maliciousDomains.Add(value.ToLower());
                    break;
            }
        }

        private static void AddMaliciousHash(string hash, string name, string technique)
        {
            if (string.IsNullOrEmpty(hash)) return;
            hash = hash.Replace("-", "").ToUpperInvariant();
            _maliciousHashes.Add(hash);
            _hashToName[hash] = name + "|" + technique;
        }

        private static bool IsIpInCidr(string ip, string cidr)
        {
            try
            {
                string[] parts = cidr.Split('/');
                string baseIp = parts[0];
                int prefix = int.Parse(parts[1]);

                uint ipNum = IpToUint(ip);
                uint baseNum = IpToUint(baseIp);
                uint mask = uint.MaxValue << (32 - prefix);

                return (ipNum & mask) == (baseNum & mask);
            }
            catch
            {
                return false;
            }
        }

        private static uint IpToUint(string ip)
        {
            string[] octets = ip.Split('.');
            return (uint.Parse(octets[0]) << 24) |
                   (uint.Parse(octets[1]) << 16) |
                   (uint.Parse(octets[2]) << 8) |
                   uint.Parse(octets[3]);
        }

        private static bool DetectDGA(string domain)
        {
            // Simple DGA detection heuristics
            // Real implementation would use ML or entropy analysis

            string[] parts = domain.Split('.');
            if (parts.Length < 2) return false;

            string subdomain = parts[0];

            // High entropy check (random-looking strings)
            double entropy = CalculateEntropy(subdomain);
            if (entropy > 4.0 && subdomain.Length > 10)
                return true;

            // Consonant-heavy check (DGAs often avoid vowels)
            int consonants = subdomain.Count(c => "bcdfghjklmnpqrstvwxyz".Contains(c));
            double ratio = (double)consonants / subdomain.Length;
            if (ratio > 0.8 && subdomain.Length > 8)
                return true;

            return false;
        }

        private static double CalculateEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;

            var charCounts = new Dictionary<char, int>();
            foreach (char c in s)
            {
                if (!charCounts.ContainsKey(c)) charCounts[c] = 0;
                charCounts[c]++;
            }

            double entropy = 0;
            int len = s.Length;
            foreach (var count in charCounts.Values)
            {
                double freq = (double)count / len;
                entropy -= freq * Math.Log(freq, 2);
            }

            return entropy;
        }

        private static string ComputeSHA256(string filePath)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream fs = File.OpenRead(filePath))
            {
                byte[] hash = sha.ComputeHash(fs);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        private static string GetDefaultIoCTemplate()
        {
            return @"# GIDR IoC List
# Format: type:value:name:technique
# Lines starting with # are comments

# Example malicious hashes (add your threat intelligence here)
# hash:AABBCC...:Mimikatz:T1003
# hash:112233...:CobaltStrike:T1071

# Example malicious IPs
# ip:192.0.2.100:Known-C2-Server
# ip:203.0.113.0/24:Bad-Actor-Range

# Example malicious domains
# domain:evil-c2.com:Malware-Domain
# domain:phishing-bank.example:Phishing
";
        }
    }
}
