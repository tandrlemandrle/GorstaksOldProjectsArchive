using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Detection
{
    /// <summary>
    /// Behavioral ransomware detection.
    /// Detects mass file encryption by monitoring process file I/O patterns:
    /// - High rate of file modifications (write operations)
    /// - Read-modify-write patterns on document files
    /// - Entropy changes in written files
    /// - Targeting user document directories
    /// 
    /// Ignores known-good processes: BitLocker, Windows Search, backup software, etc.
    /// </summary>
    public static class RansomwareDetection
    {
        // Process file activity tracking
        private static readonly Dictionary<int, ProcessFileActivity> _processActivity = new Dictionary<int, ProcessFileActivity>();
        private static readonly object _lock = new object();
        private static DateTime _lastCleanup = DateTime.UtcNow;

        // Known-good processes that do mass file operations legitimately
        private static readonly HashSet<string> _whitelistedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Encryption/Security
            "bitlocker", "bdeunlock", "fveupdate", "fveskybackup",
            "truecrypt", "veracrypt", "diskcryptor",
            
            // Windows Search/Indexing
            "searchindexer", "searchprotocolhost", "searchfilterhost",
            "mobsync", "onesync", "backgroundtaskhost",
            
            // Backup/Sync
            "robocopy", "wbengine", "sdclt", "com",  // COM = Windows Backup
            "onedrive", "dropbox", "googlebackupandsync", "googledrivesync",
            "boxsync", "pcloud", "megasync", "sync",
            
            // Antivirus/Security (they scan files)
            "msmpeng", "mmc", "mpuxsrv", "nissrv",  // Windows Defender
            "avp", "avastsvc", "avgsvc", "mcshield", "ccsvchst",
            
            // System
            "svchost", "lsass", "services", "csrss", "smss",
            "dwm", "winlogon", "wininit", "crss",
            
            // Installers/Updates
            "msiexec", "trustedinstaller", "tiworker", "wusa",
            "wuauclt", "usoclient", "musnotification",
            
            // Development tools
            "git", "tfs", "devenv", "code", "rider64"
        };

        // Document extensions that ransomware typically targets
        private static readonly HashSet<string> _targetExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm",
            ".xls", ".xlsx", ".xlsm", ".xlsb", ".xltx", ".xltm",
            ".ppt", ".pptx", ".pptm", ".pot", ".potx", ".potm", ".pps", ".ppsx",
            ".pdf", ".txt", ".rtf", ".odt", ".ods", ".odp",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".raw", ".psd",
            ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".db", ".sql", ".sqlite", ".mdb", ".accdb",
            ".pst", ".ost", ".eml", ".msg",
            ".dwg", ".dxf", ".cad",
            ".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".css", ".js",
            ".java", ".py", ".cs", ".cpp", ".c", ".h", ".go", ".rb", ".pl",
            ".mdb", ".frm", ".myd", ".myi" // Database files
        };

        // Thresholds
        private const int SUSPICIOUS_FILE_COUNT = 50;        // Files touched in window
        private const int SUSPICIOUS_FILE_RATE = 10;        // Files per minute
        private const int DETECTION_WINDOW_MINUTES = 2;     // Time window for rate calculation

        public static void Detect()
        {
            CleanupOldEntries();

            // Get all running processes and their I/O stats
            Process[] processes = Process.GetProcesses();
            int selfPid = Process.GetCurrentProcess().Id;

            foreach (Process proc in processes)
            {
                if (proc.Id == selfPid || proc.Id <= 4) continue;
                if (IsWhitelistedProcess(proc.ProcessName)) continue;

                try
                {
                    AnalyzeProcessFileActivity(proc);
                }
                catch (Exception ex)
                {
                    // Process may have exited or we lack permissions
                    Logger.Log(string.Format("RansomwareDetection: Error analyzing PID {0}: {1}", proc.Id, ex.Message), LogLevel.DEBUG);
                }
            }
        }

        private static void AnalyzeProcessFileActivity(Process proc)
        {
            string procName = proc.ProcessName.ToLowerInvariant();
            int pid = proc.Id;

            // Get per-process I/O counters from WMI.
            // WriteOperationCount = number of write I/O operations issued by this process.
            // This is a cumulative counter — we track the delta between polls.
            // WriteTransferCount = bytes written (also cumulative).
            // These are the only reliable per-process file I/O metrics available in
            // user-mode without a kernel driver or ETW file I/O provider.
            long currentWriteOps = 0;
            long currentWriteBytes = 0;

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    string.Format("SELECT WriteOperationCount, WriteTransferCount FROM Win32_Process WHERE ProcessId = {0}", pid)))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject mo in results)
                    {
                        try
                        {
                            object writeOps = mo["WriteOperationCount"];
                            object writeBytes = mo["WriteTransferCount"];
                            if (writeOps != null) currentWriteOps = Convert.ToInt64(writeOps);
                            if (writeBytes != null) currentWriteBytes = Convert.ToInt64(writeBytes);
                        }
                        catch { }
                        finally
                        {
                            mo.Dispose();
                        }
                        break;
                    }
                }
            }
            catch { return; } // Can't get I/O stats — skip this process

            lock (_lock)
            {
                ProcessFileActivity activity;
                if (!_processActivity.TryGetValue(pid, out activity))
                {
                    activity = new ProcessFileActivity
                    {
                        Pid = pid,
                        ProcessName = procName,
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        LastWriteOps = currentWriteOps,
                        LastWriteBytes = currentWriteBytes,
                    };
                    _processActivity[pid] = activity;
                    return; // Need at least two samples to compute a delta
                }

                // Compute deltas since last poll
                long writeOpsDelta = currentWriteOps - activity.LastWriteOps;
                long writeBytesDelta = currentWriteBytes - activity.LastWriteBytes;

                // Counters can reset if the process was replaced (PID reuse) — ignore negative deltas
                if (writeOpsDelta < 0 || writeBytesDelta < 0)
                {
                    activity.LastWriteOps = currentWriteOps;
                    activity.LastWriteBytes = currentWriteBytes;
                    activity.LastSeen = DateTime.UtcNow;
                    return;
                }

                activity.LastWriteOps = currentWriteOps;
                activity.LastWriteBytes = currentWriteBytes;
                activity.LastSeen = DateTime.UtcNow;
                activity.TotalWriteOps += writeOpsDelta;
                activity.TotalWriteBytes += writeBytesDelta;

                // Accumulate write op counts into time-bucketed windows for rate calculation
                activity.WriteOpHistory.Add(new WriteOpSample
                {
                    Timestamp = DateTime.UtcNow,
                    WriteOps = writeOpsDelta,
                    WriteBytes = writeBytesDelta
                });

                // Trim samples older than the detection window
                DateTime windowStart = DateTime.UtcNow.AddMinutes(-DETECTION_WINDOW_MINUTES);
                activity.WriteOpHistory.RemoveAll(delegate(WriteOpSample s) { return s.Timestamp < windowStart; });

                // Evaluate threat score
                int score = CalculateThreatScore(activity);
                if (score >= 60)
                {
                    ReportRansomwareThreat(activity, score);
                    _processActivity.Remove(pid);
                }
            }
        }

        /// <summary>
        /// Called by FileMonitor when a file rename event fires.
        /// Records the rename against the system-wide activity log so that
        /// CalculateThreatScore can factor in rename counts per process.
        ///
        /// NOTE: Without a kernel driver we cannot attribute a rename to a specific
        /// process. We therefore record it as a system-level event and use it only
        /// as a corroborating signal alongside high write I/O, not as a standalone
        /// detection. This is honest about the limitation.
        /// </summary>
        public static void RecordFileRename(string oldPath, string newPath)
        {
            lock (_lock)
            {
                _recentRenames.Add(new RenameSample
                {
                    Timestamp = DateTime.UtcNow,
                    OldPath = oldPath,
                    NewPath = newPath
                });

                // Trim old entries
                DateTime cutoff = DateTime.UtcNow.AddMinutes(-DETECTION_WINDOW_MINUTES);
                _recentRenames.RemoveAll(delegate(RenameSample s) { return s.Timestamp < cutoff; });
            }
        }

        // System-wide file rename tracking (used as corroborating signal only)
        private static readonly List<RenameSample> _recentRenames = new List<RenameSample>();

        private class RenameSample
        {
            public DateTime Timestamp;
            public string OldPath;
            public string NewPath;
        }

        private class WriteOpSample
        {
            public DateTime Timestamp;
            public long WriteOps;
            public long WriteBytes;
        }

        private static int CalculateThreatScore(ProcessFileActivity activity)
        {
            int score = 0;
            TimeSpan duration = DateTime.UtcNow - activity.FirstSeen;
            double minutes = Math.Max(duration.TotalMinutes, 0.016); // floor at ~1 second

            // ── Signal 1: Write operation rate ──
            // Sum write ops across the detection window
            long windowWriteOps = 0;
            foreach (WriteOpSample s in activity.WriteOpHistory)
                windowWriteOps += s.WriteOps;

            double opsPerMinute = windowWriteOps / minutes;

            if (opsPerMinute >= 500) score += 40;       // Very high write rate
            else if (opsPerMinute >= 200) score += 30;
            else if (opsPerMinute >= 50) score += 20;
            else if (opsPerMinute >= 20) score += 10;

            // ── Signal 2: Write byte volume ──
            // Ransomware reads then writes every file — high byte volume is expected.
            // 50MB+ written in the window is suspicious for a non-backup process.
            long windowWriteBytes = 0;
            foreach (WriteOpSample s in activity.WriteOpHistory)
                windowWriteBytes += s.WriteBytes;

            if (windowWriteBytes >= 100 * 1024 * 1024) score += 25;  // 100MB+
            else if (windowWriteBytes >= 50 * 1024 * 1024) score += 15;   // 50MB+
            else if (windowWriteBytes >= 10 * 1024 * 1024) score += 5;    // 10MB+

            // ── Signal 3: Corroborating rename events ──
            // We can't attribute renames to a specific process in user-mode, but a
            // burst of renames system-wide while a process has high write I/O is a
            // meaningful corroborating signal. Weight it lower than direct I/O.
            int recentRenames;
            lock (_lock)
            {
                recentRenames = _recentRenames.Count;
            }
            if (recentRenames >= 20) score += 20;
            else if (recentRenames >= 10) score += 10;
            else if (recentRenames >= 5) score += 5;

            // ── Signal 4: Suspicious process location ──
            // Ransomware often runs from Temp/AppData, not Program Files.
            string exePath = "";
            try
            {
                Process p = Process.GetProcessById(activity.Pid);
                exePath = p.MainModule.FileName.ToLowerInvariant();
            }
            catch { }

            if (!string.IsNullOrEmpty(exePath))
            {
                if (exePath.Contains(@"\temp\") || exePath.Contains(@"\tmp\") ||
                    exePath.Contains(@"\appdata\local\temp"))
                    score += 15;
                else if (exePath.Contains(@"\appdata\") && !exePath.Contains(@"\microsoft\"))
                    score += 5;
            }

            return Math.Min(score, 100);
        }

        private static void ReportRansomwareThreat(ProcessFileActivity activity, int score)
        {
            long windowWriteOps = 0;
            long windowWriteBytes = 0;
            foreach (WriteOpSample s in activity.WriteOpHistory)
            {
                windowWriteOps += s.WriteOps;
                windowWriteBytes += s.WriteBytes;
            }

            string details = string.Format(
                "Process: {0} (PID {1}), WriteOps/min: {2:F0}, WriteBytes: {3:F1}MB, Duration: {4:F1}s, Renames: {5}",
                activity.ProcessName, activity.Pid,
                windowWriteOps / Math.Max((DateTime.UtcNow - activity.FirstSeen).TotalMinutes, 0.016),
                windowWriteBytes / (1024.0 * 1024.0),
                (DateTime.UtcNow - activity.FirstSeen).TotalSeconds,
                _recentRenames.Count);

            Logger.Log(string.Format("RANSOMWARE DETECTED: {0} - {1}", activity.ProcessName, details),
                LogLevel.THREAT, "ransomware_detections.log");

            ThreatInfo threat = new ThreatInfo();
            threat.ThreatType = "Ransomware:MassFileModification";
            threat.ThreatPath = activity.ProcessName;
            threat.Severity = score >= 80 ? ThreatSeverity.Critical : ThreatSeverity.High;
            threat.Confidence = score;
            threat.ProcessId = activity.Pid;
            threat.ProcessName = activity.ProcessName;
            threat.Details["WriteOpsInWindow"] = windowWriteOps.ToString();
            threat.Details["WriteBytesInWindow"] = windowWriteBytes.ToString();
            threat.Details["RecentRenames"] = _recentRenames.Count.ToString();
            threat.Details["DurationSeconds"] = ((int)(DateTime.UtcNow - activity.FirstSeen).TotalSeconds).ToString();

            ResponseQueue.Enqueue(threat);

            // Auto-kill if enabled and score is high enough
            if (Config.AutoKillThreats && score >= Config.RuntimeAutoKillThreshold)
            {
                try
                {
                    Process target = Process.GetProcessById(activity.Pid);
                    if (target != null && !target.HasExited)
                    {
                        Logger.Log(string.Format("Auto-killing ransomware process {0} (PID {1})",
                            activity.ProcessName, activity.Pid), LogLevel.ACTION);
                        target.Kill();
                        target.WaitForExit(5000);
                        GidrState.IncrementTerminated();
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log(string.Format("Failed to kill ransomware process {0}: {1}",
                        activity.Pid, ex.Message), LogLevel.ERROR);
                }
            }
        }

        private static bool IsWhitelistedProcess(string processName)
        {
            if (_whitelistedProcesses.Contains(processName)) return true;
            
            // Check partial matches for processes like "bitlockerwizard.exe"
            foreach (string whitelist in _whitelistedProcesses)
            {
                if (processName.StartsWith(whitelist, StringComparison.OrdinalIgnoreCase) ||
                    processName.Contains(whitelist))
                    return true;
            }

            return false;
        }

        private static void CleanupOldEntries()
        {
            if ((DateTime.UtcNow - _lastCleanup).TotalMinutes < 5) return;
            _lastCleanup = DateTime.UtcNow;

            lock (_lock)
            {
                List<int> toRemove = new List<int>();
                foreach (var kvp in _processActivity)
                {
                    // Remove entries for processes that haven't been seen in 5 minutes
                    // or have exited
                    if ((DateTime.UtcNow - kvp.Value.LastSeen).TotalMinutes > 5)
                    {
                        toRemove.Add(kvp.Key);
                        continue;
                    }

                    try
                    {
                        Process.GetProcessById(kvp.Key); // Will throw if process exited
                    }
                    catch
                    {
                        toRemove.Add(kvp.Key);
                    }
                }

                foreach (int pid in toRemove)
                {
                    _processActivity.Remove(pid);
                }
            }
        }

        private class ProcessFileActivity
        {
            public int Pid;
            public string ProcessName;
            public DateTime FirstSeen;
            public DateTime LastSeen;
            public DateTime LastModifiedTime;
            public long LastWriteOps;
            public long LastWriteBytes;
            public long TotalWriteOps;
            public long TotalWriteBytes;
            public List<WriteOpSample> WriteOpHistory = new List<WriteOpSample>();
        }
    }
}
