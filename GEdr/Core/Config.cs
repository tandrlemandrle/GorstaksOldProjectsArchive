using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace GEdr.Core
{
    public static class Config
    {
        public static readonly string ScriptGuid = "539EF6B5-578B-4AF3-A5C7-FD564CB9C8FB";
        public static readonly string InstallPath;
        public static readonly string LogPath;
        public static readonly string QuarantinePath;
        public static readonly string DatabasePath;
        public static readonly string ReportsPath;
        public static readonly string WhitelistPath;
        public static readonly string HashDatabaseFile;
        public static readonly string PidFilePath;
        public static readonly string StabilityLogPath;
        public static readonly string RulesPath;
        public static readonly string YaraExePath;
        public static readonly string ToolsPath;

        public const string EDRName = "Gorstak-EDR";
        public const string CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256";
        public const string CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash";
        public const string MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/";
        public const int CymruDetectionThreshold = 60;
        public const int MaxDatabaseEntries = 50000;
        public const int DatabaseCleanupDays = 30;

        public const string YaraDownloadUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.0/yara-v4.5.0-2326-win64.zip";
        public const string YaraDownloadUrl32 = "https://github.com/VirusTotal/yara/releases/download/v4.5.0/yara-v4.5.0-2326-win32.zip";
        public const string VcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
        public const string VcRedistUrl32 = "https://aka.ms/vs/17/release/vc_redist.x86.exe";

        public static bool AutoKillThreats = true;
        public static bool AutoQuarantine = true;

        public const int AutoKillThreshold = 80;
        public const int AutoQuarantineThreshold = 70;
        public const int AutoBlockThreshold = 60;
        public const int AlertThreshold = 40;

        // Runtime-overridable thresholds (set by config.json, fall back to const defaults)
        public static int RuntimeAutoKillThreshold = AutoKillThreshold;
        public static int RuntimeAutoQuarantineThreshold = AutoQuarantineThreshold;
        public static int RuntimeAutoBlockThreshold = AutoBlockThreshold;
        public static int RuntimeAlertThreshold = AlertThreshold;
        public static int RuntimeMaxDatabaseEntries = MaxDatabaseEntries;
        public static int RuntimeDatabaseCleanupDays = DatabaseCleanupDays;
        public static int RuntimeCymruDetectionThreshold = CymruDetectionThreshold;

        // Logging
        public static bool JsonLogging = false;

        // Dry-run mode: log actions but don't quarantine/kill/block
        public static bool DryRun = false;

        // Allowlists (populated from config.json)
        public static readonly HashSet<string> AllowlistHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static readonly HashSet<string> AllowlistPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static readonly HashSet<string> AllowlistSigners = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Extra YARA rule directories (populated from config.json)
        public static readonly List<string> ExtraRulePaths = new List<string>();

        public static readonly HashSet<string> ProtectedProcesses;
        public static readonly HashSet<string> ExclusionPaths;

        static Config()
        {
            string loc = Assembly.GetExecutingAssembly().Location;
            InstallPath = string.IsNullOrEmpty(loc)
                ? AppDomain.CurrentDomain.BaseDirectory
                : Path.GetDirectoryName(loc);

            LogPath = Path.Combine(InstallPath, "Logs");
            QuarantinePath = Path.Combine(InstallPath, "Quarantine");
            DatabasePath = Path.Combine(InstallPath, "Data");
            ReportsPath = Path.Combine(InstallPath, "Reports");
            WhitelistPath = Path.Combine(DatabasePath, "whitelist.json");
            HashDatabaseFile = Path.Combine(DatabasePath, "known_files.db");
            PidFilePath = Path.Combine(DatabasePath, "gedr.pid");
            StabilityLogPath = Path.Combine(LogPath, "stability_log.txt");
            RulesPath = Path.Combine(InstallPath, "Rules");
            ToolsPath = Path.Combine(InstallPath, "Tools");
            YaraExePath = Path.Combine(ToolsPath, "yara64.exe");

            ExclusionPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ExclusionPaths.Add(InstallPath);
            ExclusionPaths.Add(LogPath);
            ExclusionPaths.Add(QuarantinePath);
            ExclusionPaths.Add(ReportsPath);
            ExclusionPaths.Add(DatabasePath);

            ProtectedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] prot = new string[] {
                "System","smss","csrss","wininit","winlogon","services","lsass",
                "svchost","dwm","explorer","taskhostw","sihost","fontdrvhost",
                "RuntimeBroker","MsMpEng","Idle","Registry","conhost","ctfmon",
                "SecurityHealthService","NisSrv","audiodg","dasHost","WUDFHost",
                "SearchHost","StartMenuExperienceHost","ShellExperienceHost",
                "TextInputHost","spoolsv","SearchIndexer","WmiPrvSE","dllhost",
                "chrome","firefox","msedge","brave","opera",
                "powershell","pwsh","WindowsTerminal","cmd",
                "VSSVC","MpCmdRun","MpSigStub","MpDefenderCoreService",
                "wuaucltcore","wuauserv","TrustedInstaller","TiWorker",
                "msiexec","netsh","sc","bcdedit","wusa","mpcmdrun",
                "AM_Delta_Patch","MsMpEngCP","smartscreen","MDCoreSvc",
                "SearchProtocolHost","SearchFilterHost","SearchIndexer",
                "backgroundTaskHost","CompPkgSrv","SystemSettings",
                "SettingSyncHost","PhoneExperienceHost","WidgetService",
                "Widgets","GameBarPresenceWriter","SecurityHealthSystray",
                "UserOOBEBroker","LockApp","LogonUI","consent",
                "git","git-remote-https","ssh","ssh-agent","gpg-agent",
                "schtasks","tasklist","systeminfo","whoami","hostname",
                "wmiprvse","WmiApSrv","msdtc","wlanext","WaaSMedicAgent"
            };
            for (int i = 0; i < prot.Length; i++)
                ProtectedProcesses.Add(prot[i]);
        }

        public static void EnsureDirectories()
        {
            string[] dirs = new string[] { LogPath, QuarantinePath, DatabasePath, ReportsPath, RulesPath, ToolsPath };
            for (int i = 0; i < dirs.Length; i++)
            {
                if (!Directory.Exists(dirs[i]))
                    Directory.CreateDirectory(dirs[i]);
            }
        }

        public static bool IsExcludedPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (string ex in ExclusionPaths)
            {
                if (path.StartsWith(ex, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static bool IsProtectedProcess(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            string clean = name.Replace(".exe", "");
            if (ProtectedProcesses.Contains(clean)) return true;
            // Prefix match for versioned names like AM_Delta_Patch_1.449.341.0
            if (clean.StartsWith("AM_Delta_Patch", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        /// <summary>Check if a file is allowlisted by hash, path, or signer.</summary>
        public static bool IsAllowlisted(string filePath, string sha256, string signerName)
        {
            // Hash allowlist
            if (!string.IsNullOrEmpty(sha256) && AllowlistHashes.Contains(sha256.ToUpperInvariant()))
                return true;

            // Path allowlist (prefix match)
            if (!string.IsNullOrEmpty(filePath))
            {
                foreach (string allowed in AllowlistPaths)
                {
                    if (filePath.StartsWith(allowed, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            // Signer allowlist (substring match on certificate subject)
            if (!string.IsNullOrEmpty(signerName))
            {
                string upper = signerName.ToUpperInvariant();
                foreach (string signer in AllowlistSigners)
                {
                    if (upper.Contains(signer.ToUpperInvariant()))
                        return true;
                }
            }

            return false;
        }
    }
}
