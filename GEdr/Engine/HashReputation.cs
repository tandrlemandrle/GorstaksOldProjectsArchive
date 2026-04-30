using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using GEdr.Core;

namespace GEdr.Engine
{
    public class ReputationResult
    {
        public string Hash;
        public bool IsMalicious;
        public int Confidence;
        public string Source = "";
    }

    /// <summary>
    /// Local hash cache + remote API lookups (CIRCL, Cymru, MalwareBazaar).
    /// Cache format: sha256,True|False,timestamp per line.
    /// </summary>
    public static class HashReputation
    {
        private static readonly ConcurrentDictionary<string, bool> _cache
            = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        private static readonly Regex _lineRegex
            = new Regex(@"^([0-9a-fA-F]{64}),(True|False),(.+)$", RegexOptions.Compiled);

        public static int CacheCount { get { return _cache.Count; } }

        public static void LoadDatabase()
        {
            string path = Config.HashDatabaseFile;
            if (!File.Exists(path))
            {
                try
                {
                    string dir = Path.GetDirectoryName(path);
                    if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    File.WriteAllText(path, "");
                    Logger.Log("Created new hash database file");
                }
                catch { }
                return;
            }

            try
            {
                int count = 0;
                foreach (string line in File.ReadLines(path))
                {
                    Match m = _lineRegex.Match(line);
                    if (!m.Success) continue;

                    string hash = m.Groups[1].Value;
                    bool safe = bool.Parse(m.Groups[2].Value);
                    string timestamp = m.Groups[3].Value;

                    DateTime entryDate;
                    if (DateTime.TryParse(timestamp, out entryDate))
                    {
                        if (entryDate < DateTime.Now.AddDays(-Config.DatabaseCleanupDays))
                            continue;
                    }

                    _cache[hash] = safe;
                    count++;
                    if (count >= Config.MaxDatabaseEntries) break;
                }
                Logger.Log(string.Format("Loaded {0} entries from hash database", count));
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to load hash database: " + ex.Message, LogLevel.WARN);
                _cache.Clear();
            }
        }

        public static void SaveToDatabase(string sha256, bool isSafe)
        {
            if (string.IsNullOrEmpty(sha256)) return;
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string entry = string.Format("{0},{1},{2}", sha256, isSafe, timestamp);
            try
            {
                File.AppendAllText(Config.HashDatabaseFile, entry + Environment.NewLine);
                _cache[sha256] = isSafe;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to save to hash database: " + ex.Message, LogLevel.WARN);
            }
        }

        /// <summary>Check cache only. Returns null if not cached.</summary>
        public static bool? LookupCache(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return null;
            bool val;
            if (_cache.TryGetValue(sha256, out val)) return val;
            return null;
        }

        public static string ComputeSha256(string filePath)
        {
            try
            {
                using (SHA256 sha = SHA256.Create())
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hash = sha.ComputeHash(stream);
                    StringBuilder sb = new StringBuilder(64);
                    for (int i = 0; i < hash.Length; i++)
                        sb.Append(hash[i].ToString("X2"));
                    return sb.ToString();
                }
            }
            catch { return null; }
        }

        public static string ComputeMd5(string filePath)
        {
            try
            {
                using (MD5 md5 = MD5.Create())
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hash = md5.ComputeHash(stream);
                    StringBuilder sb = new StringBuilder(32);
                    for (int i = 0; i < hash.Length; i++)
                        sb.Append(hash[i].ToString("X2"));
                    return sb.ToString();
                }
            }
            catch { return null; }
        }

        public static string ComputeSha1(string filePath)
        {
            try
            {
                using (SHA1 sha1 = SHA1.Create())
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hash = sha1.ComputeHash(stream);
                    StringBuilder sb = new StringBuilder(40);
                    for (int i = 0; i < hash.Length; i++)
                        sb.Append(hash[i].ToString("X2"));
                    return sb.ToString();
                }
            }
            catch { return null; }
        }

        /// <summary>CIRCL hashlookup - returns true if hash is known-good.</summary>
        public static bool CheckCirclKnownGood(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            try
            {
                string url = Config.CirclHashLookupUrl + "/" + sha256;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = 8000;
                req.Method = "GET";
                req.UserAgent = "GEdr/2.0";
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    if (resp.StatusCode == HttpStatusCode.OK)
                    {
                        Logger.Log("CIRCL known-good match: " + sha256);
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>Team Cymru malware hash registry - returns true if known malicious.</summary>
        public static bool CheckCymruMalware(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            try
            {
                string url = Config.CymruApiUrl + "/" + sha256;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = 8000;
                req.Method = "GET";
                req.UserAgent = "GEdr/2.0";
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
                {
                    string body = reader.ReadToEnd();
                    if (body.Contains("\"detections\""))
                    {
                        Match match = Regex.Match(body, "\"detections\"\\s*:\\s*(\\d+)");
                        int det;
                        if (match.Success && int.TryParse(match.Groups[1].Value, out det))
                        {
                            if (det >= Config.CymruDetectionThreshold)
                            {
                                Logger.Log(string.Format("CYMRU malware match: {0} (detections: {1})", sha256, det), LogLevel.THREAT);
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>MalwareBazaar lookup - returns true if hash is known malware.</summary>
        public static bool CheckMalwareBazaar(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(Config.MalwareBazaarApiUrl);
                req.Timeout = 10000;
                req.Method = "POST";
                req.ContentType = "application/x-www-form-urlencoded";
                req.UserAgent = "GEdr/2.0";
                string postData = "query=get_info&hash=" + sha256;
                byte[] data = Encoding.UTF8.GetBytes(postData);
                req.ContentLength = data.Length;
                using (Stream stream = req.GetRequestStream())
                    stream.Write(data, 0, data.Length);

                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
                {
                    string body = reader.ReadToEnd();
                    if (body.Contains("\"query_status\":\"ok\"") || body.Contains("\"query_status\": \"ok\""))
                    {
                        Logger.Log("MalwareBazaar match: " + sha256, LogLevel.THREAT);
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>Full reputation pipeline: cache -> EICAR -> CIRCL -> Cymru -> MalwareBazaar.</summary>
        public static ReputationResult GetReputation(string sha256)
        {
            ReputationResult result = new ReputationResult();
            result.Hash = sha256;
            if (string.IsNullOrEmpty(sha256)) return result;

            // Cache check
            bool? cached = LookupCache(sha256);
            if (cached.HasValue)
            {
                result.IsMalicious = !cached.Value;
                result.Confidence = 100;
                result.Source = "Cache";
                return result;
            }

            // EICAR test file
            if (string.Equals(sha256, "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F", StringComparison.OrdinalIgnoreCase))
            {
                result.IsMalicious = true;
                result.Confidence = 100;
                result.Source = "LocalDB:EICAR";
                SaveToDatabase(sha256, false);
                return result;
            }

            // CIRCL known-good
            if (CheckCirclKnownGood(sha256))
            {
                SaveToDatabase(sha256, true);
                return result;
            }

            // Cymru
            if (CheckCymruMalware(sha256))
            {
                result.IsMalicious = true;
                result.Confidence = 40;
                result.Source = "Cymru";
                SaveToDatabase(sha256, false);
                return result;
            }

            // MalwareBazaar
            if (CheckMalwareBazaar(sha256))
            {
                result.IsMalicious = true;
                result.Confidence = 50;
                result.Source = "MalwareBazaar";
                SaveToDatabase(sha256, false);
                return result;
            }

            return result;
        }
    }
}
