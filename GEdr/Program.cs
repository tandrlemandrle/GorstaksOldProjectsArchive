using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.ServiceProcess;
using System.Threading;
using GEdr.Core;
using GEdr.Detection;
using GEdr.Engine;
using GEdr.Monitors;
using GEdr.Response;

namespace GEdr
{
    /// <summary>
    /// Gorstak EDR - Phase 1: Scanner
    /// Poor man's CAPA + VirusTotal pipeline.
    /// 
    /// Usage:
    ///   GEdr.exe scan file.exe           Scan a single file
    ///   GEdr.exe scan C:\path\           Scan all executables in a directory
    ///   GEdr.exe scan C:\path\ -r        Scan recursively
    ///   GEdr.exe bootstrap               Download YARA + VC++ redist
    ///   GEdr.exe info                    Show engine status
    /// </summary>
    class Program
    {
        const string EDR_VERSION = "6.0.0";

        // Verbosity: 0=quiet, 1=normal, 2=verbose
        internal static int Verbosity = 1;

        static int Main(string[] args)
        {
            try
            {
                // Detect if running as a Windows service (no console, started by SCM)
                // When SCM starts the exe, args will be "monitor" and there's no console window
                if (!Environment.UserInteractive)
                {
                    // Running as a service — hand off to ServiceBase
                    System.ServiceProcess.ServiceBase.Run(new Core.GEdrService());
                    return 0;
                }

                // Parse global flags before anything else
                List<string> cleanArgs = new List<string>();
                for (int i = 0; i < args.Length; i++)
                {
                    string a = args[i].ToLowerInvariant();
                    if (a == "--quiet" || a == "-q") Verbosity = 0;
                    else if (a == "--verbose") Verbosity = 2;
                    else cleanArgs.Add(args[i]);
                }
                args = cleanArgs.ToArray();

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                Config.EnsureDirectories();
                ConfigLoader.Load();
                JsonLogger.Initialize();

                // Admin check for commands that need it
                if (args.Length > 0)
                {
                    string cmd = args[0].ToLowerInvariant();
                    if (cmd == "monitor" || cmd == "bootstrap")
                    {
                        if (!IsAdministrator())
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("ERROR: '{0}' requires administrator privileges.", cmd);
                            Console.ForegroundColor = ConsoleColor.Gray;
                            Console.WriteLine("Right-click the terminal -> Run as administrator");
                            Console.ResetColor();
                            return 1;
                        }
                    }
                }

                if (args.Length == 0)
                {
                    PrintUsage();
                    return 0;
                }

                string command = args[0].ToLowerInvariant();

                switch (command)
                {
                    case "scan":
                        return CmdScan(args);

                    case "monitor":
                        return CmdMonitor(args);

                    case "bootstrap":
                        return CmdBootstrap();

                    case "config":
                        return CmdConfig();

                    case "info":
                        return CmdInfo();

                    case "hash":
                        return CmdHash(args);

                    case "restore":
                        return CmdRestore(args);

                    case "report":
                        return CmdReport();

                    case "health":
                        return CmdHealth();

                    case "--help":
                    case "-h":
                    case "help":
                        PrintUsage();
                        return 0;

                    case "--version":
                    case "-v":
                    case "version":
                        PrintVersion();
                        return 0;

                    default:
                        // If first arg is a file/directory path, treat as scan
                        if (File.Exists(args[0]) || Directory.Exists(args[0]))
                        {
                            string[] newArgs = new string[args.Length + 1];
                            newArgs[0] = "scan";
                            Array.Copy(args, 0, newArgs, 1, args.Length);
                            return CmdScan(newArgs);
                        }
                        Console.WriteLine("Unknown command: {0}", command);
                        PrintUsage();
                        return 1;
                }
            }
            catch (Exception ex)
            {
                string crashLog = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "GEdr_crash.log");
                try
                {
                    File.AppendAllText(crashLog, string.Format(
                        "[{0}] FATAL: {1}\n{2}\n\n",
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), ex.Message, ex.StackTrace));
                }
                catch { }

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("  FATAL ERROR: {0}", ex.Message);
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("  Crash log written to: {0}", crashLog);
                Console.WriteLine("  Please report this issue at:");
                Console.WriteLine("  https://github.com/gorstak/GEdr/issues");
                Console.ResetColor();
                Console.WriteLine();
                return 99;
            }
        }

        static int CmdScan(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: GEdr.exe scan <file_or_directory> [-r] [--no-action] [--quiet] [--verbose]");
                return 1;
            }

            string target = args[1];
            bool recursive = false;
            bool autoRespond = true;
            bool outputJson = false;

            for (int i = 2; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if (a == "-r" || a == "--recursive") recursive = true;
                if (a == "--no-action") autoRespond = false;
                if (a == "--output-json") outputJson = true;
            }

            // Initialize engines
            HashReputation.LoadDatabase();
            YaraEngine.Initialize();

            if (!YaraEngine.IsAvailable && Verbosity > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[*] YARA not found. Run 'GEdr.exe bootstrap' to download it.");
                Console.WriteLine("[*] Continuing without YARA rule scanning...");
                Console.ResetColor();
            }

            if (Verbosity > 0) PrintBanner();

            if (File.Exists(target))
            {
                ScanResult result = ScanFileWithRetry(target);
                if (outputJson)
                    PrintResultJson(result);
                else if (Verbosity > 0)
                    ScanPipeline.PrintResult(result);
                if (autoRespond) ThreatActions.AutoRespond(result);
                return result.Severity >= ThreatSeverity.High ? 2 : 0;
            }
            else if (Directory.Exists(target))
            {
                SearchOption opt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                string[] extensions = new string[] {
                    "*.exe", "*.dll", "*.sys", "*.scr", "*.com",
                    "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js", "*.hta",
                    "*.msi", "*.ocx", "*.cpl", "*.drv"
                };

                int totalFiles = 0;
                int threats = 0;
                int suspicious = 0;
                int skipped = 0;
                DateTime scanStart = DateTime.Now;

                if (Verbosity > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("[*] Scanning directory: {0} {1}", target, recursive ? "(recursive)" : "");
                    Console.ResetColor();
                }

                for (int e = 0; e < extensions.Length; e++)
                {
                    string[] files;
                    try
                    {
                        files = Directory.GetFiles(target, extensions[e], opt);
                    }
                    catch { continue; }

                    for (int f = 0; f < files.Length; f++)
                    {
                        string filePath = files[f];
                        if (Config.IsExcludedPath(filePath)) continue;

                        totalFiles++;
                        try
                        {
                            ScanResult result = ScanFileWithRetry(filePath);

                            if (result.Verdict == "SKIPPED")
                            {
                                skipped++;
                                if (Verbosity >= 2)
                                    Logger.Log(string.Format("Skipped: {0} ({1})", filePath,
                                        result.Reasons.Count > 0 ? result.Reasons[0] : "unknown"), LogLevel.DEBUG);
                                continue;
                            }

                            if (result.TotalScore >= Config.RuntimeAutoQuarantineThreshold)
                            {
                                threats++;
                                if (outputJson) PrintResultJson(result);
                                else if (Verbosity > 0) ScanPipeline.PrintResult(result);
                                if (autoRespond) ThreatActions.AutoRespond(result);
                            }
                            else if (result.TotalScore >= Config.RuntimeAlertThreshold)
                            {
                                suspicious++;
                                if (outputJson) PrintResultJson(result);
                                else if (Verbosity > 0) ScanPipeline.PrintResult(result);
                            }
                            else if (Verbosity > 0)
                            {
                                // Progress indicator
                                if (totalFiles % 50 == 0)
                                {
                                    double elapsed = (DateTime.Now - scanStart).TotalSeconds;
                                    double rate = elapsed > 0 ? totalFiles / elapsed : 0;
                                    Console.ForegroundColor = ConsoleColor.DarkGray;
                                    Console.Write("\r[*] Scanned {0} files ({1:F0}/sec) | {2} threats, {3} suspicious...",
                                        totalFiles, rate, threats, suspicious);
                                    Console.ResetColor();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Log(string.Format("Scan error for {0}: {1}", filePath, ex.Message), LogLevel.ERROR);
                        }
                    }
                }

                double totalElapsed = (DateTime.Now - scanStart).TotalSeconds;

                if (Verbosity > 0)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine("=== Scan Complete ===");
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine("  Files scanned:  {0}", totalFiles);
                    if (skipped > 0) Console.WriteLine("  Skipped:        {0} (oversized)", skipped);
                    Console.ForegroundColor = threats > 0 ? ConsoleColor.Red : ConsoleColor.Green;
                    Console.WriteLine("  Threats found:  {0}", threats);
                    Console.ForegroundColor = suspicious > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
                    Console.WriteLine("  Suspicious:     {0}", suspicious);
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine("  YARA matches:   {0}", EdrState.YaraMatches);
                    Console.WriteLine("  Quarantined:    {0}", EdrState.FilesQuarantined);
                    Console.WriteLine("  Duration:       {0:F1}s ({1:F0} files/sec)", totalElapsed,
                        totalElapsed > 0 ? totalFiles / totalElapsed : 0);
                    Console.ResetColor();
                    Console.WriteLine();
                }

                return threats > 0 ? 2 : 0;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Target not found: {0}", target);
                Console.ResetColor();
                return 1;
            }
        }

        /// <summary>Scan with retry on sharing violations (locked files).</summary>
        static ScanResult ScanFileWithRetry(string filePath)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    return ScanPipeline.ScanFile(filePath);
                }
                catch (IOException)
                {
                    if (attempt < 2) Thread.Sleep(200);
                }
            }
            ScanResult err = new ScanResult();
            err.FilePath = filePath;
            err.FileName = Path.GetFileName(filePath);
            err.Verdict = "ERROR";
            err.Reasons.Add("File locked after 3 retries");
            return err;
        }

        /// <summary>Print a scan result as a single JSON line (for --output-json).</summary>
        static void PrintResultJson(ScanResult r)
        {
            string reasons = "";
            if (r.Reasons.Count > 0)
                reasons = string.Join("; ", r.Reasons.ToArray()).Replace("\"", "'");
            Console.WriteLine("{{\"file\":\"{0}\",\"score\":{1},\"verdict\":\"{2}\",\"sha256\":\"{3}\",\"signed\":{4},\"reasons\":\"{5}\"}}",
                (r.FilePath ?? "").Replace("\\", "\\\\").Replace("\"", "\\\""),
                r.TotalScore,
                r.Verdict ?? "UNKNOWN",
                r.SHA256 ?? "",
                r.IsSigned ? "true" : "false",
                reasons);
        }

        static int CmdBootstrap()
        {
            PrintBanner();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] Bootstrapping dependencies...");
            Console.ResetColor();

            bool ok = Bootstrapper.EnsureDependencies();

            if (ok)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Bootstrap complete. All dependencies ready.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] Bootstrap completed with warnings. Check logs.");
            }
            Console.ResetColor();
            return ok ? 0 : 1;
        }

        static int CmdConfig()
        {
            PrintBanner();
            string path = ConfigLoader.ConfigFilePath;
            if (File.Exists(path))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("config.json already exists: {0}", path);
                Console.ResetColor();
            }
            else
            {
                ConfigLoader.CreateDefault();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Created default config.json: {0}", path);
                Console.ResetColor();
            }
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("Edit config.json to customize:");
            Console.WriteLine("  - Threat scoring thresholds");
            Console.WriteLine("  - Auto-kill and auto-quarantine toggles");
            Console.WriteLine("  - Allowlisted hashes, paths, and signers");
            Console.WriteLine("  - Additional YARA rule directories");
            Console.WriteLine("  - Additional protected processes");
            Console.WriteLine("  - Scan exclusion paths");
            Console.WriteLine("  - JSON structured logging");
            Console.ResetColor();
            Console.WriteLine();
            return 0;
        }

        static int CmdRestore(string[] args)
        {
            PrintBanner();
            if (!Directory.Exists(Config.QuarantinePath))
            {
                Console.WriteLine("Quarantine folder not found.");
                return 1;
            }

            string[] files = Directory.GetFiles(Config.QuarantinePath);
            if (files.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Quarantine is empty.");
                Console.ResetColor();
                return 0;
            }

            // List mode: GEdr.exe restore
            if (args.Length < 2 || args[1] == "--list")
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("Quarantined files ({0}):", files.Length);
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine();
                for (int i = 0; i < files.Length; i++)
                {
                    string name = Path.GetFileName(files[i]);
                    FileInfo fi = new FileInfo(files[i]);
                    // Format: ticks_originalname.exe
                    int sep = name.IndexOf('_');
                    string original = sep > 0 ? name.Substring(sep + 1) : name;
                    Console.WriteLine("  [{0}] {1}  ({2:N0} bytes, quarantined {3})",
                        i, original, fi.Length, fi.CreationTime.ToString("yyyy-MM-dd HH:mm"));
                }
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("To restore: GEdr.exe restore <index> <destination_path>");
                Console.WriteLine("To delete:  GEdr.exe restore --purge <index>");
                Console.ResetColor();
                return 0;
            }

            // Purge mode: GEdr.exe restore --purge <index>
            if (args[1] == "--purge")
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: GEdr.exe restore --purge <index>");
                    return 1;
                }
                int idx;
                if (!int.TryParse(args[2], out idx) || idx < 0 || idx >= files.Length)
                {
                    Console.WriteLine("Invalid index. Use 'GEdr.exe restore' to list files.");
                    return 1;
                }
                File.Delete(files[idx]);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Deleted quarantined file: {0}", Path.GetFileName(files[idx]));
                Console.ResetColor();
                return 0;
            }

            // Restore mode: GEdr.exe restore <index> <destination>
            {
                int idx;
                if (!int.TryParse(args[1], out idx) || idx < 0 || idx >= files.Length)
                {
                    Console.WriteLine("Invalid index. Use 'GEdr.exe restore' to list files.");
                    return 1;
                }
                string dest;
                if (args.Length >= 3)
                {
                    dest = args[2];
                }
                else
                {
                    // Restore to current directory with original name
                    string name = Path.GetFileName(files[idx]);
                    int sep = name.IndexOf('_');
                    string original = sep > 0 ? name.Substring(sep + 1) : name;
                    dest = Path.Combine(Directory.GetCurrentDirectory(), original);
                }
                File.Move(files[idx], dest);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Restored: {0}", dest);
                Console.ResetColor();
                Logger.Log(string.Format("Restored from quarantine: {0} -> {1}", files[idx], dest), LogLevel.ACTION);
                return 0;
            }
        }

        static int CmdReport()
        {
            PrintBanner();
            string logFile = Path.Combine(Config.LogPath, "gedr_log.txt");
            if (!File.Exists(logFile))
            {
                Console.WriteLine("No log file found. Run 'GEdr.exe monitor' first.");
                return 1;
            }

            DateTime cutoff = DateTime.Now.AddHours(-24);
            int threats = 0;
            int actions = 0;
            int warnings = 0;
            int errors = 0;
            System.Collections.Generic.List<string> recentThreats = new System.Collections.Generic.List<string>();

            try
            {
                foreach (string line in File.ReadLines(logFile))
                {
                    // Parse timestamp from [yyyy-MM-dd HH:mm:ss.fff]
                    if (line.Length < 25 || line[0] != '[') continue;
                    string tsStr = line.Substring(1, 23);
                    DateTime ts;
                    if (!DateTime.TryParse(tsStr, out ts)) continue;
                    if (ts < cutoff) continue;

                    if (line.Contains("[THREAT]"))
                    {
                        threats++;
                        if (recentThreats.Count < 20) recentThreats.Add(line);
                    }
                    else if (line.Contains("[ACTION]")) actions++;
                    else if (line.Contains("[WARN]")) warnings++;
                    else if (line.Contains("[ERROR]")) errors++;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error reading log: {0}", ex.Message);
                return 1;
            }

            // Quarantine count
            int quarantined = 0;
            if (Directory.Exists(Config.QuarantinePath))
                quarantined = Directory.GetFiles(Config.QuarantinePath).Length;

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("=== GEdr Report (last 24 hours) ===");
            Console.WriteLine("  Generated: {0}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            Console.WriteLine();
            Console.ForegroundColor = threats > 0 ? ConsoleColor.Red : ConsoleColor.Green;
            Console.WriteLine("  Threats:     {0}", threats);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  Actions:     {0}", actions);
            Console.WriteLine("  Warnings:    {0}", warnings);
            Console.ForegroundColor = errors > 0 ? ConsoleColor.Red : ConsoleColor.Gray;
            Console.WriteLine("  Errors:      {0}", errors);
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  Quarantined: {0} files total", quarantined);
            Console.WriteLine();

            if (recentThreats.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("  Recent threats:");
                Console.ForegroundColor = ConsoleColor.Gray;
                for (int i = 0; i < recentThreats.Count; i++)
                {
                    string t = recentThreats[i];
                    if (t.Length > 120) t = t.Substring(0, 120) + "...";
                    Console.WriteLine("    {0}", t);
                }
            }

            Console.ResetColor();
            Console.WriteLine();

            // Also write JSON report if json logging is enabled
            if (Config.JsonLogging)
            {
                string reportPath = Path.Combine(Config.ReportsPath, string.Format("report_{0}.json", DateTime.Now.ToString("yyyyMMdd_HHmmss")));
                try
                {
                    string json = string.Format(
                        "{{\"generated\":\"{0}\",\"period\":\"24h\",\"threats\":{1},\"actions\":{2},\"warnings\":{3},\"errors\":{4},\"quarantined\":{5}}}",
                        DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), threats, actions, warnings, errors, quarantined);
                    if (!Directory.Exists(Config.ReportsPath)) Directory.CreateDirectory(Config.ReportsPath);
                    File.WriteAllText(reportPath, json);
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("  JSON report: {0}", reportPath);
                    Console.ResetColor();
                }
                catch { }
            }

            return 0;
        }

        static int CmdHash(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: GEdr.exe hash <file>");
                return 1;
            }

            string filePath = args[1];
            if (!File.Exists(filePath))
            {
                Console.WriteLine("File not found: {0}", filePath);
                return 1;
            }

            string sha256 = HashReputation.ComputeSha256(filePath);
            string md5 = HashReputation.ComputeMd5(filePath);
            string sha1 = HashReputation.ComputeSha1(filePath);

            Console.WriteLine("File:   {0}", filePath);
            Console.WriteLine("SHA256: {0}", sha256 ?? "ERROR");
            Console.WriteLine("MD5:    {0}", md5 ?? "ERROR");
            Console.WriteLine("SHA1:   {0}", sha1 ?? "ERROR");

            // Check reputation
            if (!string.IsNullOrEmpty(sha256))
            {
                Console.WriteLine();
                Console.WriteLine("[*] Checking reputation...");
                HashReputation.LoadDatabase();
                ReputationResult rep = HashReputation.GetReputation(sha256);
                if (rep.IsMalicious)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] MALICIOUS: {0} (confidence {1}%)", rep.Source, rep.Confidence);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Not found in threat databases");
                }
                Console.ResetColor();
            }

            return 0;
        }

        static int CmdInfo()
        {
            PrintBanner();
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("Install path:  {0}", Config.InstallPath);
            Console.WriteLine("Rules path:    {0}", Config.RulesPath);
            Console.WriteLine("Tools path:    {0}", Config.ToolsPath);
            Console.WriteLine("Log path:      {0}", Config.LogPath);
            Console.WriteLine("Quarantine:    {0}", Config.QuarantinePath);
            Console.WriteLine();

            // YARA status
            YaraEngine.Initialize();
            if (YaraEngine.IsAvailable)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("YARA:          AVAILABLE");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("YARA:          NOT FOUND (run 'GEdr.exe bootstrap')");
            }

            // Rule count
            int ruleFiles = 0;
            if (Directory.Exists(Config.RulesPath))
                ruleFiles = Directory.GetFiles(Config.RulesPath, "*.yar", SearchOption.AllDirectories).Length;
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("Rule files:    {0}", ruleFiles);

            // Hash DB
            HashReputation.LoadDatabase();
            Console.WriteLine("Hash DB:       {0} entries", HashReputation.CacheCount);

            // Config
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("Config:        {0}", File.Exists(ConfigLoader.ConfigFilePath) ? "config.json loaded" : "defaults (run 'GEdr.exe config' to create)");
            Console.WriteLine("JSON logging:  {0}", Config.JsonLogging ? "ENABLED" : "DISABLED");
            Console.WriteLine("Allowlist:     {0} hashes, {1} paths, {2} signers",
                Config.AllowlistHashes.Count, Config.AllowlistPaths.Count, Config.AllowlistSigners.Count);
            Console.WriteLine("Extra rules:   {0} directories", Config.ExtraRulePaths.Count);
            Console.WriteLine("Thresholds:    kill={0} quarantine={1} block={2} alert={3}",
                Config.RuntimeAutoKillThreshold, Config.RuntimeAutoQuarantineThreshold,
                Config.RuntimeAutoBlockThreshold, Config.RuntimeAlertThreshold);

            // Quarantine count
            int quarantined = 0;
            if (Directory.Exists(Config.QuarantinePath))
                quarantined = Directory.GetFiles(Config.QuarantinePath).Length;
            Console.WriteLine("Quarantined:   {0} files", quarantined);

            Console.ResetColor();
            Console.WriteLine();
            return 0;
        }

        static int CmdMonitor(string[] args)
        {
            PrintBanner();

            // Parse monitor-specific flags
            bool noDelay = false;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--no-delay") noDelay = true;
                if (args[i] == "--dry-run") Config.DryRun = true;
            }

            if (Config.DryRun)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[*] DRY-RUN MODE: Threats will be logged but no actions taken");
                Console.ResetColor();
            }
            if (!noDelay)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("[*] Waiting 15 seconds for system processes to stabilize...");
                Console.ResetColor();
                Thread.Sleep(15000);
            }

            // Ctrl+C handler
            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e) {
                e.Cancel = true;
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[*] Shutting down...");
                Console.ResetColor();
                cts.Cancel();
            };

            // Run the shared monitor logic (same code used by the Windows service)
            GEdr.Core.GEdrMonitor.Run(cts.Token, serviceMode: false);
            return 0;
        }

        static int CmdHealth()
        {
            PrintBanner();
            int issues = 0;

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("=== GEdr Health Check ===");
            Console.WriteLine();

            // Admin
            bool admin = IsAdministrator();
            PrintCheck("Administrator", admin, admin ? "Running elevated" : "NOT elevated - limited functionality");
            if (!admin) issues++;

            // Config
            bool configExists = File.Exists(ConfigLoader.ConfigFilePath);
            PrintCheck("config.json", configExists, configExists ? ConfigLoader.ConfigFilePath : "Not found (using defaults)");

            // YARA
            YaraEngine.Initialize();
            PrintCheck("YARA engine", YaraEngine.IsAvailable, YaraEngine.IsAvailable ? "Ready" : "Not found (run 'GEdr.exe bootstrap')");
            if (!YaraEngine.IsAvailable) issues++;

            // Rules
            int ruleCount = 0;
            if (Directory.Exists(Config.RulesPath))
                ruleCount = Directory.GetFiles(Config.RulesPath, "*.yar", SearchOption.AllDirectories).Length;
            PrintCheck("YARA rules", ruleCount > 0, string.Format("{0} rule files", ruleCount));
            if (ruleCount == 0) issues++;

            // Directories
            string[] dirs = new string[] { Config.LogPath, Config.QuarantinePath, Config.DatabasePath, Config.RulesPath, Config.ToolsPath };
            string[] names = new string[] { "Logs", "Quarantine", "Data", "Rules", "Tools" };
            for (int i = 0; i < dirs.Length; i++)
            {
                bool exists = Directory.Exists(dirs[i]);
                PrintCheck(names[i] + " directory", exists, exists ? dirs[i] : "MISSING");
                if (!exists) issues++;
            }

            // PID file (stale check)
            if (File.Exists(Config.PidFilePath))
            {
                try
                {
                    string pidStr = File.ReadAllText(Config.PidFilePath).Trim();
                    int pid;
                    if (int.TryParse(pidStr, out pid))
                    {
                        bool running = false;
                        try { Process.GetProcessById(pid); running = true; } catch { }
                        if (running)
                            PrintCheck("Monitor process", true, string.Format("PID {0} is running", pid));
                        else
                        {
                            PrintCheck("Monitor process", false, string.Format("Stale PID file (PID {0} not running)", pid));
                            File.Delete(Config.PidFilePath);
                        }
                    }
                }
                catch { }
            }
            else
            {
                PrintCheck("Monitor process", false, "Not running");
            }

            // WMI
            bool wmiOk = false;
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process WHERE ProcessId = 4"))
                using (ManagementObjectCollection c = s.Get())
                {
                    wmiOk = c.Count > 0;
                }
            }
            catch { }
            PrintCheck("WMI access", wmiOk, wmiOk ? "Working" : "FAILED - process monitoring will use polling");
            if (!wmiOk) issues++;

            Console.WriteLine();
            if (issues == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("All checks passed.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("{0} issue(s) found.", issues);
            }
            Console.ResetColor();
            Console.WriteLine();
            return issues > 0 ? 1 : 0;
        }

        static void PrintCheck(string name, bool ok, string detail)
        {
            Console.ForegroundColor = ok ? ConsoleColor.Green : ConsoleColor.Red;
            Console.Write("  [{0}] ", ok ? "OK" : "!!"); 
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("{0,-20} {1}", name, detail);
        }

        static void RegisterJob(JobScheduler scheduler, string name, Action execute, int interval, ref int loaded)
        {
            try
            {
                scheduler.Register(name, execute, interval);
                loaded++;
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("Failed to register {0}: {1}", name, ex.Message), LogLevel.ERROR);
            }
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  Gorstak EDR v{0} - Unified Endpoint Defense", EDR_VERSION);
            Console.WriteLine("  CAPA-like PE Analysis + YARA + Hash Reputation");
            Console.WriteLine();
            Console.ResetColor();
        }

        static void PrintVersion()
        {
            string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string buildDate = "unknown";
            try
            {
                if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                    buildDate = File.GetLastWriteTime(exePath).ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch { }
            Console.WriteLine("Gorstak EDR v{0}", EDR_VERSION);
            Console.WriteLine("Build date: {0}", buildDate);
            Console.WriteLine("Runtime:    .NET {0}", Environment.Version);
            Console.WriteLine("Platform:   {0}", Environment.Is64BitProcess ? "x64" : "x86");
        }

        static bool IsAdministrator()
        {
            try
            {
                System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                System.Security.Principal.WindowsPrincipal principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        static void EmitHeartbeat()
        {
            Logger.Stability(string.Format("Heartbeat: PID={0} threats={1} scanned={2} quarantined={3} uptime={4}",
                Process.GetCurrentProcess().Id, EdrState.ThreatCount, EdrState.FilesScanned,
                EdrState.FilesQuarantined, (DateTime.Now - Process.GetCurrentProcess().StartTime).ToString(@"d\.hh\:mm\:ss")));
            JsonLogger.LogEvent("INFO", "heartbeat", string.Format(
                "pid={0} threats={1} scanned={2} quarantined={3}",
                Process.GetCurrentProcess().Id, EdrState.ThreatCount,
                EdrState.FilesScanned, EdrState.FilesQuarantined));
        }

        static void AmsiIntegrityCheck()
        {
            if (AmsiScanner.IsAvailable)
                AmsiScanner.VerifyIntegrity();
        }

        static void PrintUsage()
        {
            PrintBanner();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Usage:");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  GEdr.exe scan <file>              Scan a single file");
            Console.WriteLine("  GEdr.exe scan <directory>         Scan directory (executables)");
            Console.WriteLine("  GEdr.exe scan <directory> -r      Scan directory recursively");
            Console.WriteLine("  GEdr.exe scan <target> --no-action  Scan without auto-quarantine");
            Console.WriteLine("  GEdr.exe scan <target> --output-json Output results as JSON lines");
            Console.WriteLine("  GEdr.exe monitor                  Real-time EDR monitoring mode");
            Console.WriteLine("  GEdr.exe monitor --dry-run        Monitor without killing/quarantining");
            Console.WriteLine("  GEdr.exe monitor --no-delay       Skip 15s startup delay");
            Console.WriteLine("  GEdr.exe hash <file>              Compute hashes + check reputation");
            Console.WriteLine("  GEdr.exe bootstrap                Download YARA + VC++ redist");
            Console.WriteLine("  GEdr.exe config                   Create/show config.json");
            Console.WriteLine("  GEdr.exe restore                  List quarantined files");
            Console.WriteLine("  GEdr.exe restore <id> [dest]      Restore a quarantined file");
            Console.WriteLine("  GEdr.exe report                   24-hour threat summary");
            Console.WriteLine("  GEdr.exe health                   System health check");
            Console.WriteLine("  GEdr.exe info                     Show engine status");
            Console.WriteLine("  GEdr.exe --version                Show version info");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("Exit codes: 0=clean, 1=error, 2=threats found, 99=crash");
            Console.WriteLine();
            Console.WriteLine("Global flags:");
            Console.WriteLine("  --quiet, -q       Suppress non-essential output");
            Console.WriteLine("  --verbose          Show debug-level detail");
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}
