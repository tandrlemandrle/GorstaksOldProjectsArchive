using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace GIDR.Core
{
    /// <summary>
    /// Bootstrap utilities for downloading and installing dependencies:
    /// - YARA scanner (from GitHub releases)
    /// - Visual C++ Redistributables (if needed)
    /// </summary>
    public static class Bootstrap
    {
        private static readonly object _bootstrapLock = new object();
        private static bool _isBootstrapping = false;

        /// <summary>
        /// Check if YARA is available, download and extract if not.
        /// Called by the bootstrap command or on first run.
        /// </summary>
        public static bool EnsureYara()
        {
            if (File.Exists(Config.YaraExePath))
            {
                Logger.Log("YARA already available: " + Config.YaraExePath, LogLevel.INFO);
                return true;
            }

            lock (_bootstrapLock)
            {
                if (_isBootstrapping)
                {
                    Logger.Log("Bootstrap already in progress, waiting...", LogLevel.INFO);
                    return false;
                }

                _isBootstrapping = true;
                try
                {
                    return DownloadAndExtractYara();
                }
                finally
                {
                    _isBootstrapping = false;
                }
            }
        }

        private static bool DownloadAndExtractYara()
        {
            string zipPath = null;
            string extractPath = null;

            try
            {
                // Determine architecture
                bool is64Bit = Environment.Is64BitProcess;
                string downloadUrl = is64Bit ? Config.YaraDownloadUrl : Config.YaraDownloadUrl32;
                string yaraExeName = is64Bit ? "yara64.exe" : "yara32.exe";

                Logger.Log(string.Format("Downloading YARA from {0}...", downloadUrl), LogLevel.INFO);

                // Ensure Tools directory exists
                if (!Directory.Exists(Config.ToolsPath))
                    Directory.CreateDirectory(Config.ToolsPath);

                // Download to temp location
                zipPath = Path.Combine(Path.GetTempPath(), string.Format("yara_{0}.zip", Guid.NewGuid()));
                extractPath = Path.Combine(Path.GetTempPath(), string.Format("yara_extract_{0}", Guid.NewGuid()));

                // Download with TLS 1.2 (GitHub requirement)
                using (WebClient client = new WebClient())
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    client.DownloadProgressChanged += (s, e) =>
                    {
                        if (e.ProgressPercentage % 25 == 0) // Log at 0%, 25%, 50%, 75%, 100%
                        {
                            Logger.Log(string.Format("YARA download: {0}%", e.ProgressPercentage), LogLevel.INFO);
                        }
                    };
                    client.DownloadFile(downloadUrl, zipPath);
                }

                Logger.Log("YARA download complete, extracting...", LogLevel.INFO);

                // Extract
                ZipFile.ExtractToDirectory(zipPath, extractPath);

                // Find yara.exe in extracted folder (might be nested)
                string[] yaraFiles = Directory.GetFiles(extractPath, "yara*.exe", SearchOption.AllDirectories);
                if (yaraFiles.Length == 0)
                {
                    Logger.Log("YARA executable not found in downloaded archive", LogLevel.ERROR);
                    return false;
                }

                // Copy to Tools directory
                string sourceYara = yaraFiles[0]; // Use first match
                string destYara = Path.Combine(Config.ToolsPath, yaraExeName);
                File.Copy(sourceYara, destYara, true);

                // Also copy yarac.exe (compiler) if present
                string sourceDir = Path.GetDirectoryName(sourceYara);
                string yaracPath = Path.Combine(sourceDir, "yarac.exe");
                if (File.Exists(yaracPath))
                {
                    File.Copy(yaracPath, Path.Combine(Config.ToolsPath, "yarac.exe"), true);
                }

                Logger.Log("YARA installed successfully: " + destYara, LogLevel.INFO);

                // Test YARA works
                if (TestYara())
                {
                    Logger.Log("YARA test successful", LogLevel.INFO);
                    return true;
                }
                else
                {
                    Logger.Log("YARA installed but test failed - may need VC++ Redist", LogLevel.WARN);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("YARA bootstrap failed: " + ex.Message, LogLevel.ERROR);
                return false;
            }
            finally
            {
                // Cleanup
                try
                {
                    if (zipPath != null && File.Exists(zipPath))
                        File.Delete(zipPath);
                    if (extractPath != null && Directory.Exists(extractPath))
                        Directory.Delete(extractPath, true);
                }
                catch { }
            }
        }

        private static bool TestYara()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Config.YaraExePath, "--version");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process proc = Process.Start(psi))
                {
                    proc.WaitForExit(10000);
                    return proc.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Install Visual C++ Redistributables if YARA fails to run.
        /// This is a silent installation.
        /// </summary>
        public static bool InstallVcRedist()
        {
            string installerPath = null;

            try
            {
                bool is64Bit = Environment.Is64BitProcess;
                string downloadUrl = is64Bit ? Config.VcRedistUrl : Config.VcRedistUrl32;
                string vcName = is64Bit ? "vc_redist.x64.exe" : "vc_redist.x86.exe";

                Logger.Log(string.Format("Downloading VC++ Redist from {0}...", downloadUrl), LogLevel.INFO);

                installerPath = Path.Combine(Path.GetTempPath(), vcName);

                // Download
                using (WebClient client = new WebClient())
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    client.DownloadFile(downloadUrl, installerPath);
                }

                Logger.Log("Installing VC++ Redistributables (silent)...", LogLevel.INFO);

                // Silent install: /install /quiet /norestart
                ProcessStartInfo psi = new ProcessStartInfo(installerPath, "/install /quiet /norestart");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process proc = Process.Start(psi))
                {
                    proc.WaitForExit(60000); // 60 second timeout

                    if (proc.ExitCode == 0)
                    {
                        Logger.Log("VC++ Redistributables installed successfully", LogLevel.INFO);

                        // Re-test YARA
                        if (TestYara())
                        {
                            Logger.Log("YARA now working after VC++ Redist install", LogLevel.INFO);
                            return true;
                        }
                    }
                    else
                    {
                        string error = proc.StandardError.ReadToEnd();
                        Logger.Log("VC++ Redist install failed: " + error, LogLevel.ERROR);
                        return false;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log("VC++ Redist bootstrap failed: " + ex.Message, LogLevel.ERROR);
                return false;
            }
            finally
            {
                try
                {
                    if (installerPath != null && File.Exists(installerPath))
                        File.Delete(installerPath);
                }
                catch { }
            }
        }

        /// <summary>
        /// Full bootstrap - ensure all dependencies are ready.
        /// Called by 'GIDR.exe bootstrap' command.
        /// </summary>
        public static bool RunFullBootstrap()
        {
            Logger.Log("Starting full bootstrap process...", LogLevel.INFO);

            bool yaraOk = EnsureYara();

            if (!yaraOk)
            {
                Logger.Log("YARA bootstrap failed, attempting VC++ Redist install...", LogLevel.WARN);

                if (InstallVcRedist())
                {
                    // Try YARA again after VC++ install
                    yaraOk = EnsureYara();
                }
            }

            // Summary
            Logger.Log("Bootstrap complete:", LogLevel.INFO);
            Logger.Log("  YARA: " + (File.Exists(Config.YaraExePath) ? "AVAILABLE" : "UNAVAILABLE"), LogLevel.INFO);

            // Also create default rules if needed
            CreateDefaultRules();

            return yaraOk;
        }

        /// <summary>
        /// Create default YARA rule templates if no rules exist.
        /// </summary>
        public static void CreateDefaultRules()
        {
            try
            {
                if (!Directory.Exists(Config.RulesPath))
                    Directory.CreateDirectory(Config.RulesPath);

                // Check if any .yar files exist
                string[] existingRules = Directory.GetFiles(Config.RulesPath, "*.yar");
                if (existingRules.Length > 0)
                    return; // Rules already exist

                Logger.Log("Creating default YARA rule templates...", LogLevel.INFO);

                // Create a basic rule template
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("// GIDR Default YARA Rules - Template");
                sb.AppendLine("// Replace with your own rules or download from:");
                sb.AppendLine("// https://github.com/Yara-Rules/rules");
                sb.AppendLine();
                sb.AppendLine("rule SuspiciousStrings");
                sb.AppendLine("{");
                sb.AppendLine("    meta:");
                sb.AppendLine("        description = \"Detects common suspicious strings in binaries\"");
                sb.AppendLine("        author = \"GIDR\"");
                sb.AppendLine("        severity = \"medium\"");
                sb.AppendLine("    strings:");
                sb.AppendLine("        $mimikatz = \"mimikatz\" nocase");
                sb.AppendLine("        $powershell = \"powershell -enc\" nocase");
                sb.AppendLine("        $reflection = \"[Reflection.Assembly]::Load\" nocase");
                sb.AppendLine("        $invoke_expr = \"Invoke-Expression\" nocase");
                sb.AppendLine("        $downloadstring = \"DownloadString\" nocase");
                sb.AppendLine("        $virtualalloc = \"VirtualAlloc\" nocase");
                sb.AppendLine("        $createremotethread = \"CreateRemoteThread\" nocase");
                sb.AppendLine("        $shellcode_pattern = { 4D 5A } // MZ header");
                sb.AppendLine("    condition:");
                sb.AppendLine("        any of them");
                sb.AppendLine("}");
                sb.AppendLine();
                sb.AppendLine("rule CredentialDumpingIndicator");
                sb.AppendLine("{");
                sb.AppendLine("    meta:");
                sb.AppendLine("        description = \"Indicators of credential dumping tools\"");
                sb.AppendLine("        author = \"GIDR\"");
                sb.AppendLine("        severity = \"high\"");
                sb.AppendLine("    strings:");
                sb.AppendLine("        $lsass_access = \"lsass.exe\" nocase");
                sb.AppendLine("        $sam_hive = \"SAM\" nocase");
                sb.AppendLine("        $security_hive = \"SECURITY\" nocase");
                sb.AppendLine("        $wdigest = \"wdigest.dll\" nocase");
                sb.AppendLine("        $sekurlsa = \"sekurlsa\" nocase");
                sb.AppendLine("    condition:");
                sb.AppendLine("        2 of them");
                sb.AppendLine("}");

                string rulePath = Path.Combine(Config.RulesPath, "gidr_default.yar");
                File.WriteAllText(rulePath, sb.ToString());

                Logger.Log("Default YARA rules created: " + rulePath, LogLevel.INFO);
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to create default rules: " + ex.Message, LogLevel.WARN);
            }
        }

        /// <summary>
        /// Auto-bootstrap on first scan attempt.
        /// Non-blocking - returns immediately if already bootstrapped.
        /// </summary>
        public static bool AutoBootstrap()
        {
            if (File.Exists(Config.YaraExePath))
                return true;

            // Don't block - run bootstrap in background
            Thread bootstrapThread = new Thread(() =>
            {
                EnsureYara();
            });
            bootstrapThread.IsBackground = true;
            bootstrapThread.Name = "GIDR-Bootstrap";
            bootstrapThread.Start();

            return false; // Not immediately available
        }
    }
}
