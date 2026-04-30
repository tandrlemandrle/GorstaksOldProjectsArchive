using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using GEdr.Core;

namespace GEdr.Response
{
    public static class ThreatActions
    {
        // MoveFileEx flag: delete file on next reboot
        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

        public static bool IsFileSigned(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                X509Certificate2 cert2 = new X509Certificate2(cert);
                return cert2.Verify();
            }
            catch { return false; }
        }

        public static bool Quarantine(string filePath, string reason)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
            if (Config.IsExcludedPath(filePath)) return false;

            if (Config.DryRun)
            {
                Logger.Log(string.Format("[DRY-RUN] Would quarantine: {0} (Reason: {1})", filePath, reason), LogLevel.ACTION);
                JsonLogger.LogAction("quarantine-dryrun", filePath, true, reason);
                return false;
            }

            try
            {
                string fileName = Path.GetFileName(filePath);
                string dest = Path.Combine(Config.QuarantinePath,
                    string.Format("{0}_{1}", DateTime.Now.Ticks, fileName));
                if (!Directory.Exists(Config.QuarantinePath))
                    Directory.CreateDirectory(Config.QuarantinePath);

                // Try move first (fastest, works if file isn't locked)
                try
                {
                    File.Move(filePath, dest);
                    EdrState.IncrementQuarantined();
                    Logger.Log(string.Format("Quarantined: {0} -> {1} (Reason: {2})", filePath, dest, reason), LogLevel.ACTION);
                    JsonLogger.LogAction("quarantine", filePath, true, reason);
                    return true;
                }
                catch (IOException)
                {
                    // File is locked — fall back to copy + schedule delete on reboot
                }

                // Copy the file to quarantine (works even if source is locked for read)
                try
                {
                    File.Copy(filePath, dest, true);
                }
                catch (IOException)
                {
                    // Can't even copy — try reading with FileShare.ReadWrite
                    using (FileStream src = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (FileStream dst = new FileStream(dest, FileMode.Create, FileAccess.Write))
                    {
                        byte[] buf = new byte[65536];
                        int read;
                        while ((read = src.Read(buf, 0, buf.Length)) > 0)
                            dst.Write(buf, 0, read);
                    }
                }

                // Schedule the original for deletion on next reboot
                bool pendingDelete = MoveFileEx(filePath, null, MOVEFILE_DELAY_UNTIL_REBOOT);

                EdrState.IncrementQuarantined();
                if (pendingDelete)
                {
                    Logger.Log(string.Format("Quarantined (locked): {0} -> {1} (original scheduled for deletion on reboot)",
                        filePath, dest, reason), LogLevel.ACTION);
                    JsonLogger.LogAction("quarantine-locked", filePath, true,
                        reason + " | copied to quarantine, original pending delete on reboot");
                }
                else
                {
                    Logger.Log(string.Format("Quarantined (copy only): {0} -> {1} (original still in place, locked by process)",
                        filePath, dest), LogLevel.ACTION);
                    JsonLogger.LogAction("quarantine-copy", filePath, true,
                        reason + " | copied to quarantine, original locked");
                }
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("Quarantine failed for {0}: {1}", filePath, ex.Message), LogLevel.ERROR);
                JsonLogger.LogAction("quarantine", filePath, false, ex.Message);
                return false;
            }
        }

        public static bool TerminateProcess(int pid, string processName)
        {
            if (pid <= 0) return false;
            if (pid == Process.GetCurrentProcess().Id) return false;
            if (Config.IsProtectedProcess(processName))
            {
                Logger.Log(string.Format("BLOCKED: Refusing to terminate protected process: {0} (PID: {1})", processName, pid), LogLevel.WARN);
                return false;
            }

            if (Config.DryRun)
            {
                Logger.Log(string.Format("[DRY-RUN] Would terminate: {0} (PID: {1})", processName, pid), LogLevel.ACTION);
                JsonLogger.LogAction("terminate-dryrun", processName, true, string.Format("PID: {0}", pid));
                return false;
            }

            try
            {
                Process proc = Process.GetProcessById(pid);
                proc.Kill();
                EdrState.IncrementTerminated();
                Logger.Log(string.Format("Terminated: {0} (PID: {1})", processName, pid), LogLevel.ACTION);
                JsonLogger.LogAction("terminate", processName, true, string.Format("PID: {0}", pid));
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("Failed to terminate {0} (PID: {1}): {2}", processName, pid, ex.Message), LogLevel.ERROR);
                JsonLogger.LogAction("terminate", processName, false, ex.Message);
                return false;
            }
        }

        public static bool BlockIP(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;
            if (Config.DryRun)
            {
                Logger.Log(string.Format("[DRY-RUN] Would block IP: {0}", ipAddress), LogLevel.ACTION);
                return false;
            }
            try
            {
                string ruleName = string.Format("GEdr_Block_{0}", ipAddress.Replace('.', '_').Replace(':', '_'));
                ProcessStartInfo psi = new ProcessStartInfo("netsh.exe",
                    string.Format("advfirewall firewall add rule name=\"{0}\" dir=out action=block remoteip={1}", ruleName, ipAddress));
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                p.WaitForExit(10000);
                if (p.ExitCode == 0)
                {
                    Logger.Log(string.Format("Blocked IP: {0}", ipAddress), LogLevel.ACTION);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("Failed to block IP {0}: {1}", ipAddress, ex.Message), LogLevel.ERROR);
            }
            return false;
        }

        /// <summary>Auto-respond to a scan result based on verdict.</summary>
        public static void AutoRespond(Engine.ScanResult result)
        {
            if (result == null) return;

            switch (result.Verdict)
            {
                case "CRITICAL":
                    if (Config.AutoQuarantine && File.Exists(result.FilePath))
                    {
                        Quarantine(result.FilePath, "CRITICAL: score " + result.TotalScore);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("  ACTION: Quarantined -> {0}", Config.QuarantinePath);
                        Console.ResetColor();
                    }
                    break;

                case "MALICIOUS":
                    if (Config.AutoQuarantine && File.Exists(result.FilePath))
                    {
                        Quarantine(result.FilePath, "MALICIOUS: score " + result.TotalScore);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("  ACTION: Quarantined -> {0}", Config.QuarantinePath);
                        Console.ResetColor();
                    }
                    break;

                case "SUSPICIOUS":
                    Logger.Log(string.Format("SUSPICIOUS file: {0} (score {1})", result.FilePath, result.TotalScore), LogLevel.WARN);
                    break;
            }
        }
    }
}
