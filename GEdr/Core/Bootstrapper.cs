using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using Microsoft.Win32;

namespace GEdr.Core
{
    public static class Bootstrapper
    {
        public static bool EnsureDependencies()
        {
            Config.EnsureDirectories();
            bool ok = true;

            if (!EnsureVcRedist())
                Logger.Log("VC++ Redist check failed - YARA may not work", LogLevel.WARN);

            if (!EnsureYara())
            {
                Logger.Log("YARA not available - detection capability reduced", LogLevel.ERROR);
                ok = false;
            }

            EnsureRules();
            return ok;
        }

        private static bool EnsureYara()
        {
            if (File.Exists(Config.YaraExePath)) { Logger.Log("YARA found: " + Config.YaraExePath); return true; }
            string yara32 = Path.Combine(Config.ToolsPath, "yara.exe");
            if (File.Exists(yara32)) { Logger.Log("YARA (32-bit) found: " + yara32); return true; }

            Logger.Log("Downloading YARA...", LogLevel.INFO);
            string zipPath = Path.Combine(Config.ToolsPath, "yara.zip");
            try
            {
                bool is64 = IntPtr.Size == 8;
                string url = is64 ? Config.YaraDownloadUrl : Config.YaraDownloadUrl32;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                using (WebClient wc = new WebClient()) { wc.DownloadFile(url, zipPath); }
                Logger.Log("Extracting YARA...");
                ZipFile.ExtractToDirectory(zipPath, Config.ToolsPath);
                try { File.Delete(zipPath); } catch { }

                if (File.Exists(Config.YaraExePath) || File.Exists(yara32))
                {
                    Logger.Log("YARA installed successfully");
                    return true;
                }

                // Search subdirectories
                foreach (string f in Directory.GetFiles(Config.ToolsPath, "yara*.exe", SearchOption.AllDirectories))
                {
                    string dest = Path.Combine(Config.ToolsPath, Path.GetFileName(f));
                    if (!string.Equals(f, dest, StringComparison.OrdinalIgnoreCase))
                        File.Copy(f, dest, true);
                }
                return File.Exists(Config.YaraExePath) || File.Exists(yara32);
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to download YARA: " + ex.Message, LogLevel.ERROR);
                try { File.Delete(zipPath); } catch { }
                return false;
            }
        }

        private static bool EnsureVcRedist()
        {
            if (IsVcRedistInstalled()) { Logger.Log("VC++ Redistributable found"); return true; }

            Logger.Log("VC++ Redistributable not found - downloading...", LogLevel.INFO);
            string exePath = Path.Combine(Config.ToolsPath, "vc_redist.exe");
            try
            {
                bool is64 = IntPtr.Size == 8;
                string url = is64 ? Config.VcRedistUrl : Config.VcRedistUrl32;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                using (WebClient wc = new WebClient()) { wc.DownloadFile(url, exePath); }
                Logger.Log("Installing VC++ Redistributable (silent)...");
                ProcessStartInfo psi = new ProcessStartInfo(exePath, "/install /quiet /norestart");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                Process p = Process.Start(psi);
                p.WaitForExit(120000);
                try { File.Delete(exePath); } catch { }
                return p.ExitCode == 0 || p.ExitCode == 3010;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to install VC++ Redist: " + ex.Message, LogLevel.WARN);
                try { File.Delete(exePath); } catch { }
                return false;
            }
        }

        private static bool IsVcRedistInstalled()
        {
            string[] keys = new string[] {
                @"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
                @"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86",
                @"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
            };
            for (int i = 0; i < keys.Length; i++)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keys[i]))
                    {
                        if (key != null)
                        {
                            object val = key.GetValue("Installed");
                            if (val != null && Convert.ToInt32(val) == 1) return true;
                        }
                    }
                }
                catch { }
            }
            string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            return File.Exists(Path.Combine(sys32, "vcruntime140.dll"));
        }

        private static bool EnsureRules()
        {
            if (!Directory.Exists(Config.RulesPath)) Directory.CreateDirectory(Config.RulesPath);
            return Directory.GetFiles(Config.RulesPath, "*.yar").Length > 0;
        }
    }
}
