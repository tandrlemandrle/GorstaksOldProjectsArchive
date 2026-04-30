using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace GEdr.Core
{
    /// <summary>
    /// Loads configuration from config.json alongside the executable.
    /// Falls back to hard-coded defaults if the file is missing or malformed.
    /// 
    /// JSON parsing is done manually to avoid System.Web or NuGet dependencies.
    /// Only flat key-value pairs and simple arrays are supported.
    /// </summary>
    public static class ConfigLoader
    {
        private static Dictionary<string, string> _values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static Dictionary<string, List<string>> _arrays = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        public static string ConfigFilePath
        {
            get { return Path.Combine(Config.InstallPath, "config.json"); }
        }

        /// <summary>Load config.json if it exists. Safe to call multiple times.</summary>
        public static void Load()
        {
            string path = ConfigFilePath;
            if (!File.Exists(path))
            {
                Logger.Log("No config.json found, using defaults");
                return;
            }

            try
            {
                string json = File.ReadAllText(path);
                Parse(json);
                ApplyToConfig();
                Logger.Log(string.Format("Loaded config.json ({0} settings, {1} arrays)", _values.Count, _arrays.Count));
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("Failed to parse config.json: {0} — using defaults", ex.Message), LogLevel.WARN);
            }
        }

        /// <summary>Create a default config.json with all current settings.</summary>
        public static void CreateDefault()
        {
            string path = ConfigFilePath;
            if (File.Exists(path)) return;

            List<string> lines = new List<string>();
            lines.Add("{");
            lines.Add("  // ── Threat Scoring Thresholds ──");
            lines.Add(string.Format("  \"autoKillThreshold\": {0},", Config.AutoKillThreshold));
            lines.Add(string.Format("  \"autoQuarantineThreshold\": {0},", Config.AutoQuarantineThreshold));
            lines.Add(string.Format("  \"autoBlockThreshold\": {0},", Config.AutoBlockThreshold));
            lines.Add(string.Format("  \"alertThreshold\": {0},", Config.AlertThreshold));
            lines.Add("");
            lines.Add("  // ── Response Toggles ──");
            lines.Add(string.Format("  \"autoKillThreats\": {0},", Config.AutoKillThreats.ToString().ToLower()));
            lines.Add(string.Format("  \"autoQuarantine\": {0},", Config.AutoQuarantine.ToString().ToLower()));
            lines.Add("");
            lines.Add("  // ── Database ──");
            lines.Add(string.Format("  \"maxDatabaseEntries\": {0},", Config.MaxDatabaseEntries));
            lines.Add(string.Format("  \"databaseCleanupDays\": {0},", Config.DatabaseCleanupDays));
            lines.Add(string.Format("  \"cymruDetectionThreshold\": {0},", Config.CymruDetectionThreshold));
            lines.Add("");
            lines.Add("  // ── Logging ──");
            lines.Add("  \"jsonLogging\": true,");
            lines.Add("");
            lines.Add("  // ── Scan Exclusions (paths that are never scanned) ──");
            lines.Add("  \"exclusionPaths\": [");
            lines.Add("  ],");
            lines.Add("");
            lines.Add("  // ── Allowlisted Hashes (SHA256, never flagged) ──");
            lines.Add("  \"allowlistHashes\": [");
            lines.Add("  ],");
            lines.Add("");
            lines.Add("  // ── Allowlisted Paths (files/folders, never flagged) ──");
            lines.Add("  \"allowlistPaths\": [");
            lines.Add("  ],");
            lines.Add("");
            lines.Add("  // ── Allowlisted Signers (certificate CN substrings) ──");
            lines.Add("  \"allowlistSigners\": [");
            lines.Add("  ],");
            lines.Add("");
            lines.Add("  // ── Additional Protected Processes ──");
            lines.Add("  \"additionalProtectedProcesses\": [");
            lines.Add("  ],");
            lines.Add("");
            lines.Add("  // ── Additional YARA Rule Directories ──");
            lines.Add("  \"extraRulePaths\": [");
            lines.Add("  ]");
            lines.Add("}");

            try
            {
                File.WriteAllText(path, string.Join(Environment.NewLine, lines.ToArray()));
                Logger.Log("Created default config.json");
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to create config.json: " + ex.Message, LogLevel.WARN);
            }
        }

        private static void ApplyToConfig()
        {
            // Thresholds
            Config.RuntimeAutoKillThreshold = GetInt("autoKillThreshold", Config.AutoKillThreshold);
            Config.RuntimeAutoQuarantineThreshold = GetInt("autoQuarantineThreshold", Config.AutoQuarantineThreshold);
            Config.RuntimeAutoBlockThreshold = GetInt("autoBlockThreshold", Config.AutoBlockThreshold);
            Config.RuntimeAlertThreshold = GetInt("alertThreshold", Config.AlertThreshold);

            // Toggles
            Config.AutoKillThreats = GetBool("autoKillThreats", Config.AutoKillThreats);
            Config.AutoQuarantine = GetBool("autoQuarantine", Config.AutoQuarantine);

            // Database
            Config.RuntimeMaxDatabaseEntries = GetInt("maxDatabaseEntries", Config.MaxDatabaseEntries);
            Config.RuntimeDatabaseCleanupDays = GetInt("databaseCleanupDays", Config.DatabaseCleanupDays);
            Config.RuntimeCymruDetectionThreshold = GetInt("cymruDetectionThreshold", Config.CymruDetectionThreshold);

            // Logging
            Config.JsonLogging = GetBool("jsonLogging", false);

            // Additional exclusion paths
            List<string> extraExclusions = GetArray("exclusionPaths");
            if (extraExclusions != null)
            {
                for (int i = 0; i < extraExclusions.Count; i++)
                    Config.ExclusionPaths.Add(extraExclusions[i]);
            }

            // Allowlists
            List<string> hashes = GetArray("allowlistHashes");
            if (hashes != null)
            {
                for (int i = 0; i < hashes.Count; i++)
                    Config.AllowlistHashes.Add(hashes[i].ToUpperInvariant());
            }

            List<string> paths = GetArray("allowlistPaths");
            if (paths != null)
            {
                for (int i = 0; i < paths.Count; i++)
                    Config.AllowlistPaths.Add(paths[i]);
            }

            List<string> signers = GetArray("allowlistSigners");
            if (signers != null)
            {
                for (int i = 0; i < signers.Count; i++)
                    Config.AllowlistSigners.Add(signers[i]);
            }

            // Additional protected processes
            List<string> procs = GetArray("additionalProtectedProcesses");
            if (procs != null)
            {
                for (int i = 0; i < procs.Count; i++)
                    Config.ProtectedProcesses.Add(procs[i]);
            }

            // Extra YARA rule paths
            List<string> rulePaths = GetArray("extraRulePaths");
            if (rulePaths != null)
            {
                for (int i = 0; i < rulePaths.Count; i++)
                    Config.ExtraRulePaths.Add(rulePaths[i]);
            }
        }

        // ── Simple JSON parser (no external dependencies) ────────────────

        private static void Parse(string json)
        {
            _values.Clear();
            _arrays.Clear();

            // Strip comments (// style)
            json = Regex.Replace(json, @"//[^\n]*", "");

            // Match simple key-value pairs: "key": value
            MatchCollection kvMatches = Regex.Matches(json,
                "\"([^\"]+)\"\\s*:\\s*(?:\"([^\"]*)\"|(-?\\d+\\.?\\d*)|true|false)");
            for (int i = 0; i < kvMatches.Count; i++)
            {
                Match m = kvMatches[i];
                string key = m.Groups[1].Value;
                // Check for boolean
                string raw = m.Value;
                if (raw.Contains(": true") || raw.Contains(":true"))
                    _values[key] = "true";
                else if (raw.Contains(": false") || raw.Contains(":false"))
                    _values[key] = "false";
                else if (m.Groups[2].Success)
                    _values[key] = m.Groups[2].Value;
                else if (m.Groups[3].Success)
                    _values[key] = m.Groups[3].Value;
            }

            // Match arrays: "key": [ "val1", "val2" ]
            MatchCollection arrMatches = Regex.Matches(json,
                "\"([^\"]+)\"\\s*:\\s*\\[([^\\]]*)\\]", RegexOptions.Singleline);
            for (int i = 0; i < arrMatches.Count; i++)
            {
                Match m = arrMatches[i];
                string key = m.Groups[1].Value;
                string body = m.Groups[2].Value;
                List<string> items = new List<string>();
                MatchCollection itemMatches = Regex.Matches(body, "\"([^\"]+)\"");
                for (int j = 0; j < itemMatches.Count; j++)
                    items.Add(itemMatches[j].Groups[1].Value);
                _arrays[key] = items;
            }
        }

        private static int GetInt(string key, int defaultValue)
        {
            string val;
            if (_values.TryGetValue(key, out val))
            {
                int result;
                if (int.TryParse(val, out result)) return result;
            }
            return defaultValue;
        }

        private static bool GetBool(string key, bool defaultValue)
        {
            string val;
            if (_values.TryGetValue(key, out val))
                return string.Equals(val, "true", StringComparison.OrdinalIgnoreCase);
            return defaultValue;
        }

        private static string GetString(string key, string defaultValue)
        {
            string val;
            if (_values.TryGetValue(key, out val)) return val;
            return defaultValue;
        }

        private static List<string> GetArray(string key)
        {
            List<string> val;
            if (_arrays.TryGetValue(key, out val)) return val;
            return null;
        }
    }
}
