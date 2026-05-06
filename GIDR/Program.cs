using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using GIDR.Core;
using GIDR.Detection;
using GIDR.Monitors;
using GIDR.Response;

namespace GIDR
{
    /// <summary>
    /// GIDR - Gorstaks Intrusion Detection and Response
    /// Behavioral EDR - detects malware by actions, not signatures.
    /// 
    /// Usage:
    ///   GIDR.exe monitor                 Start behavioral monitoring
    ///   GIDR.exe info                    Show engine status
    /// </summary>
    class Program
    {
        const string GIDR_VERSION = "6.3.0";

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
                    System.ServiceProcess.ServiceBase.Run(new Core.GIDRService());
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
                    case "monitor":
                        return CmdMonitor(args);

                    case "config":
                        return CmdConfig();

                    case "bootstrap":
                        return CmdBootstrap();

                    case "info":
                        return CmdInfo();

                    case "restore":
                        return CmdRestore(args);

                    case "report":
                        return CmdReport();

                    case "health":
                        return CmdHealth();

                    case "hunt":
                        return CmdHunt(args);

                    case "scan":
                        return CmdScan(args);

                    case "isolate":
                        return CmdIsolate(args);

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
                        Console.WriteLine("Unknown command: {0}", command);
                        PrintUsage();
                        return 1;
                }
            }
            catch (Exception ex)
            {
                string crashLog = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "GIDR_crash.log");
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
                Console.WriteLine("  https://github.com/gorstak/GIDR/issues");
                Console.ResetColor();
                Console.WriteLine();
                return 99;
            }
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

            // List mode: GIDR.exe restore
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
                Console.WriteLine("To restore: GIDR.exe restore <index> <destination_path>");
                Console.WriteLine("To delete:  GIDR.exe restore --purge <index>");
                Console.ResetColor();
                return 0;
            }

            // Purge mode: GIDR.exe restore --purge <index>
            if (args[1] == "--purge")
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: GIDR.exe restore --purge <index>");
                    return 1;
                }
                int idx;
                if (!int.TryParse(args[2], out idx) || idx < 0 || idx >= files.Length)
                {
                    Console.WriteLine("Invalid index. Use 'GIDR.exe restore' to list files.");
                    return 1;
                }
                File.Delete(files[idx]);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Deleted quarantined file: {0}", Path.GetFileName(files[idx]));
                Console.ResetColor();
                return 0;
            }

            // Restore mode: GIDR.exe restore <index> <destination>
            {
                int idx;
                if (!int.TryParse(args[1], out idx) || idx < 0 || idx >= files.Length)
                {
                    Console.WriteLine("Invalid index. Use 'GIDR.exe restore' to list files.");
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
            string logFile = Path.Combine(Config.LogPath, "gidr_log.txt");
            if (!File.Exists(logFile))
            {
                Console.WriteLine("No log file found. Run 'GIDR.exe monitor' first.");
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
            Console.WriteLine("=== GIDR Report (last 24 hours) ===");
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

            // Detection engines status
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Mode:          BEHAVIORAL DETECTION (EDR)");
            Console.WriteLine("Detectors:     MemoryExec, C2Network, CredentialDump, AudioHijack, Ransomware, Persistence");
            Console.ForegroundColor = ConsoleColor.Gray;

            // Config
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("Config:        {0}", File.Exists(ConfigLoader.ConfigFilePath) ? "config.json loaded" : "defaults (run 'GIDR.exe config' to create)");
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
            GIDR.Core.GIDRMonitor.Run(cts.Token, serviceMode: false);
            return 0;
        }

        static int CmdHealth()
        {
            PrintBanner();
            int issues = 0;

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("=== GIDR Health Check ===");
            Console.WriteLine();

            // Admin
            bool admin = IsAdministrator();
            PrintCheck("Administrator", admin, admin ? "Running elevated" : "NOT elevated - limited functionality");
            if (!admin) issues++;

            // Config
            bool configExists = File.Exists(ConfigLoader.ConfigFilePath);
            PrintCheck("config.json", configExists, configExists ? ConfigLoader.ConfigFilePath : "Not found (using defaults)");

            // Detection engines
            PrintCheck("Behavioral Detection", true, "Active (EDR mode - no signatures)");

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

        // Bootstrap command - download and install YARA + dependencies
        static int CmdBootstrap()
        {
            PrintBanner();
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: 'bootstrap' requires administrator privileges.");
                Console.ResetColor();
                return 1;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] Bootstrapping GIDR dependencies...");
            Console.WriteLine();
            Console.ResetColor();

            // Ensure directories exist
            Config.EnsureDirectories();

            bool success = Bootstrap.RunFullBootstrap();

            Console.WriteLine();
            if (success && File.Exists(Config.YaraExePath))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Bootstrap complete. YARA is ready.");
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("You can now run:");
                Console.WriteLine("  GIDR.exe hunt          - Hunt suspicious locations");
                Console.WriteLine("  GIDR.exe scan <path>   - Scan specific paths");
                Console.WriteLine("  GIDR.exe monitor       - Start real-time monitoring");
                Console.ResetColor();
                return 0;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] Bootstrap incomplete. Some features may be unavailable.");
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("Check logs for details. YARA can be manually installed to:");
                Console.WriteLine("  " + Config.ToolsPath);
                Console.ResetColor();
                return 1;
            }
        }

        // IDR: Manual hunting mode - scan suspicious locations on demand
        static int CmdHunt(string[] args)
        {
            PrintBanner();
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: 'hunt' requires administrator privileges.");
                Console.ResetColor();
                return 1;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] Starting YARA hunt mode on suspicious locations...");
            Console.ResetColor();

            // Force immediate hunt
            YaraScanner.HuntSuspiciousLocations();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Hunt complete. Check logs for results.");
            Console.ResetColor();
            return 0;
        }

        // IDR: Scan specific path with YARA
        static int CmdScan(string[] args)
        {
            PrintBanner();
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: GIDR.exe scan <path> [rule-file]");
                Console.WriteLine("Example: GIDR.exe scan C:\\ suspicious.yar");
                return 1;
            }

            string path = args[1];
            string ruleFile = args.Length > 2 ? args[2] : null;

            if (!Directory.Exists(path) && !File.Exists(path))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Path not found: " + path);
                Console.ResetColor();
                return 1;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] Scanning: {0}", path);
            if (ruleFile != null)
                Console.WriteLine("[*] Rule file: {0}", ruleFile);
            Console.ResetColor();

            bool found = YaraScanner.ScanPath(path, ruleFile);

            if (found)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] YARA matches found - check yara_detections.log");
                Console.ResetColor();
                return 2; // Exit code 2 = threats found
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] No YARA matches found.");
                Console.ResetColor();
                return 0;
            }
        }

        // IDR: Host isolation command
        static int CmdIsolate(string[] args)
        {
            PrintBanner();
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: 'isolate' requires administrator privileges.");
                Console.ResetColor();
                return 1;
            }

            // Check for restore option
            if (args.Length > 1 && args[1] == "--restore")
            {
                if (IncidentResponse.RestoreNetwork())
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Network connectivity restored.");
                    Console.ResetColor();
                    return 0;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Failed to restore network. Check logs.");
                    Console.ResetColor();
                    return 1;
                }
            }

            if (IncidentResponse.IsHostIsolated)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] Host is already isolated.");
                Console.WriteLine("    Run 'GIDR.exe isolate --restore' to restore network.");
                Console.ResetColor();
                return 0;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[!] WARNING: This will block all outbound network traffic!");
            Console.WriteLine("    Only localhost (127.0.0.1) will remain accessible.");
            Console.WriteLine();
            Console.WriteLine("    Use case: Contain a compromised host during incident response.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Type 'ISOLATE' to confirm: ");
            Console.ResetColor();

            string confirm = Console.ReadLine();
            if (confirm != "ISOLATE")
            {
                Console.WriteLine("Cancelled.");
                return 0;
            }

            if (IncidentResponse.IsolateHost("Manual isolation via command line"))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Host isolated successfully.");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("    Run 'GIDR.exe isolate --restore' when ready to restore network.");
                Console.ResetColor();
                return 0;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Failed to isolate host. Check logs.");
                Console.ResetColor();
                return 1;
            }
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
            Console.WriteLine("  GIDR - Gorstaks Intrusion Detection and Response v{0} - Unified Endpoint Defense", GIDR_VERSION);
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
            Console.WriteLine("GIDR - Gorstaks Intrusion Detection and Response v{0}", GIDR_VERSION);
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
                Process.GetCurrentProcess().Id, GidrState.ThreatCount, GidrState.FilesScanned,
                GidrState.FilesQuarantined, (DateTime.Now - Process.GetCurrentProcess().StartTime).ToString(@"d\.hh\:mm\:ss")));
            JsonLogger.LogEvent("INFO", "heartbeat", string.Format(
                "pid={0} threats={1} scanned={2} quarantined={3}",
                Process.GetCurrentProcess().Id, GidrState.ThreatCount,
                GidrState.FilesScanned, GidrState.FilesQuarantined));
        }

        static void PrintUsage()
        {
            PrintBanner();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Usage:");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  GIDR.exe bootstrap                Download/install YARA + dependencies");
            Console.WriteLine("  GIDR.exe monitor                  Real-time behavioral IDR monitoring");
            Console.WriteLine("  GIDR.exe monitor --dry-run        Monitor without killing/quarantining");
            Console.WriteLine("  GIDR.exe monitor --no-delay       Skip 15s startup delay");
            Console.WriteLine("  GIDR.exe config                   Create/show config.json");
            Console.WriteLine("  GIDR.exe restore                  List quarantined files");
            Console.WriteLine("  GIDR.exe restore <id> [dest]      Restore a quarantined file");
            Console.WriteLine("  GIDR.exe report                   24-hour threat summary");
            Console.WriteLine("  GIDR.exe health                   System health check");
            Console.WriteLine("  GIDR.exe info                     Show engine status");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("IDR (Incident Detection & Response):");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  GIDR.exe hunt                     Hunt suspicious locations with YARA");
            Console.WriteLine("  GIDR.exe scan <path> [rule]       Scan file/folder with YARA rules");
            Console.WriteLine("  GIDR.exe isolate                  Isolate host (block outbound)");
            Console.WriteLine("  GIDR.exe isolate --restore        Restore network connectivity");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Information:");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  GIDR.exe --version                Show version info");
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
