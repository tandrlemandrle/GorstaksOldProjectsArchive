using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using GEdr.Core;

namespace GEdr.Engine
{
    public class YaraMatch
    {
        public string RuleName;
        public string RuleFile;
        public string Meta; // raw meta string from yara output
        public int Score;
        public string Severity;
        public string MitreId;
    }

    /// <summary>
    /// Invokes yara.exe against files and parses the output.
    /// Supports scanning single files, directories, and process memory (via pid).
    /// </summary>
    public static class YaraEngine
    {
        private static string _yaraExe;
        private static bool _available;

        // Regex to parse YARA meta from our rules: severity, score, mitre
        private static readonly Regex _metaSeverity = new Regex("severity\\s*=\\s*\"([^\"]+)\"", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex _metaScore = new Regex("score\\s*=\\s*(\\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex _metaMitre = new Regex("mitre\\s*=\\s*\"([^\"]+)\"", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static bool IsAvailable { get { return _available; } }

        public static void Initialize()
        {
            // Try yara64.exe first, then yara.exe
            if (File.Exists(Config.YaraExePath))
            {
                _yaraExe = Config.YaraExePath;
                _available = true;
            }
            else
            {
                string yara32 = Path.Combine(Config.ToolsPath, "yara.exe");
                if (File.Exists(yara32))
                {
                    _yaraExe = yara32;
                    _available = true;
                }
                else
                {
                    // Check PATH
                    string pathYara = FindInPath("yara64.exe");
                    if (pathYara == null) pathYara = FindInPath("yara.exe");
                    if (pathYara != null)
                    {
                        _yaraExe = pathYara;
                        _available = true;
                    }
                }
            }

            if (_available)
                Logger.Log("YARA engine ready: " + _yaraExe);
            else
                Logger.Log("YARA engine NOT available - rule scanning disabled", LogLevel.WARN);
        }

        /// <summary>Scan a single file against all rules in the Rules directory.</summary>
        public static List<YaraMatch> ScanFile(string filePath)
        {
            List<YaraMatch> matches = new List<YaraMatch>();
            if (!_available) return matches;
            if (!File.Exists(filePath)) return matches;

            // Collect rule files from built-in path + extra paths from config
            List<string> allRuleFiles = new List<string>();
            if (Directory.Exists(Config.RulesPath))
                allRuleFiles.AddRange(Directory.GetFiles(Config.RulesPath, "*.yar", SearchOption.AllDirectories));
            for (int p = 0; p < Config.ExtraRulePaths.Count; p++)
            {
                string extra = Config.ExtraRulePaths[p];
                if (Directory.Exists(extra))
                    allRuleFiles.AddRange(Directory.GetFiles(extra, "*.yar", SearchOption.AllDirectories));
            }
            if (allRuleFiles.Count == 0) return matches;

            EdrState.IncrementYaraMatches(); // track that YARA was invoked

            for (int i = 0; i < allRuleFiles.Count; i++)
            {
                try
                {
                    List<YaraMatch> fileMatches = RunYara(allRuleFiles[i], filePath);
                    matches.AddRange(fileMatches);
                }
                catch (Exception ex)
                {
                    Logger.Log(string.Format("YARA scan error with {0}: {1}", Path.GetFileName(allRuleFiles[i]), ex.Message), LogLevel.WARN);
                }
            }

            return matches;
        }

        /// <summary>Scan a process by PID (yara -p pid).</summary>
        public static List<YaraMatch> ScanProcess(int pid)
        {
            List<YaraMatch> matches = new List<YaraMatch>();
            if (!_available) return matches;

            List<string> allRuleFiles = GetAllRuleFiles();
            for (int i = 0; i < allRuleFiles.Count; i++)
            {
                try
                {
                    string args = string.Format("\"{0}\" {1}", allRuleFiles[i], pid);
                    string output = ExecuteYara(args, 30000);
                    if (!string.IsNullOrEmpty(output))
                    {
                        ParseOutput(output, allRuleFiles[i], matches);
                    }
                }
                catch { }
            }
            return matches;
        }

        /// <summary>Get total count of rule files across all paths.</summary>
        public static int RuleFileCount
        {
            get { return GetAllRuleFiles().Count; }
        }

        private static List<string> GetAllRuleFiles()
        {
            List<string> files = new List<string>();
            if (Directory.Exists(Config.RulesPath))
                files.AddRange(Directory.GetFiles(Config.RulesPath, "*.yar", SearchOption.AllDirectories));
            for (int i = 0; i < Config.ExtraRulePaths.Count; i++)
            {
                string extra = Config.ExtraRulePaths[i];
                if (Directory.Exists(extra))
                    files.AddRange(Directory.GetFiles(extra, "*.yar", SearchOption.AllDirectories));
            }
            return files;
        }

        private static List<YaraMatch> RunYara(string ruleFile, string targetFile)
        {
            List<YaraMatch> matches = new List<YaraMatch>();

            // yara.exe -s -m rules.yar targetfile
            // -s = print matching strings
            // -m = print metadata
            string args = string.Format("-m \"{0}\" \"{1}\"", ruleFile, targetFile);
            string output = ExecuteYara(args, 60000);

            if (string.IsNullOrEmpty(output)) return matches;

            ParseOutput(output, ruleFile, matches);
            return matches;
        }

        private static void ParseOutput(string output, string ruleFile, List<YaraMatch> matches)
        {
            // YARA output format with -m:
            // RuleName [meta1=val1,meta2=val2] target_path
            // or just: RuleName target_path
            string[] lines = output.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (string.IsNullOrEmpty(line)) continue;
                if (line.StartsWith("error") || line.StartsWith("warning")) continue;

                // Extract rule name (first token before space or [)
                int spaceIdx = line.IndexOf(' ');
                int bracketIdx = line.IndexOf('[');
                int nameEnd;
                if (bracketIdx > 0 && (bracketIdx < spaceIdx || spaceIdx < 0))
                    nameEnd = bracketIdx;
                else if (spaceIdx > 0)
                    nameEnd = spaceIdx;
                else
                    continue;

                string ruleName = line.Substring(0, nameEnd).Trim();
                if (string.IsNullOrEmpty(ruleName)) continue;

                YaraMatch match = new YaraMatch();
                match.RuleName = ruleName;
                match.RuleFile = Path.GetFileName(ruleFile);

                // Extract metadata if present
                if (bracketIdx > 0)
                {
                    int bracketEnd = line.IndexOf(']', bracketIdx);
                    if (bracketEnd > bracketIdx)
                    {
                        match.Meta = line.Substring(bracketIdx + 1, bracketEnd - bracketIdx - 1);
                    }
                }

                // Try to get score/severity from the rule file itself (more reliable than -m output)
                ReadRuleMeta(ruleFile, ruleName, match);

                matches.Add(match);
                EdrState.IncrementYaraMatches();
            }
        }

        private static void ReadRuleMeta(string ruleFile, string ruleName, YaraMatch match)
        {
            // Parse the .yar file to find the rule's meta block
            try
            {
                string content = File.ReadAllText(ruleFile);
                // Find "rule RuleName" then its meta block
                int ruleIdx = content.IndexOf("rule " + ruleName, StringComparison.OrdinalIgnoreCase);
                if (ruleIdx < 0) return;

                int metaIdx = content.IndexOf("meta:", ruleIdx);
                if (metaIdx < 0) return;

                // Read until "strings:" or "condition:"
                int endIdx = content.IndexOf("strings:", metaIdx);
                int endIdx2 = content.IndexOf("condition:", metaIdx);
                if (endIdx < 0) endIdx = int.MaxValue;
                if (endIdx2 < 0) endIdx2 = int.MaxValue;
                int metaEnd = Math.Min(endIdx, endIdx2);
                if (metaEnd == int.MaxValue) metaEnd = Math.Min(content.Length, metaIdx + 1000);

                string metaBlock = content.Substring(metaIdx, metaEnd - metaIdx);

                Match sevMatch = _metaSeverity.Match(metaBlock);
                if (sevMatch.Success) match.Severity = sevMatch.Groups[1].Value;

                Match scoreMatch = _metaScore.Match(metaBlock);
                int score;
                if (scoreMatch.Success && int.TryParse(scoreMatch.Groups[1].Value, out score))
                    match.Score = score;

                Match mitreMatch = _metaMitre.Match(metaBlock);
                if (mitreMatch.Success) match.MitreId = mitreMatch.Groups[1].Value;
            }
            catch { }

            // Defaults if not found
            if (string.IsNullOrEmpty(match.Severity)) match.Severity = "medium";
            if (match.Score == 0) match.Score = 50;
        }

        private static string ExecuteYara(string arguments, int timeoutMs)
        {
            ProcessStartInfo psi = new ProcessStartInfo(_yaraExe, arguments);
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            using (Process p = Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit(timeoutMs);

                if (!string.IsNullOrEmpty(stderr) && stderr.Contains("error"))
                {
                    Logger.Log("YARA stderr: " + stderr.Substring(0, Math.Min(stderr.Length, 200)), LogLevel.WARN);
                }

                return stdout;
            }
        }

        private static string FindInPath(string exeName)
        {
            string pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrEmpty(pathEnv)) return null;
            string[] paths = pathEnv.Split(';');
            for (int i = 0; i < paths.Length; i++)
            {
                string full = Path.Combine(paths[i].Trim(), exeName);
                if (File.Exists(full)) return full;
            }
            return null;
        }
    }
}
