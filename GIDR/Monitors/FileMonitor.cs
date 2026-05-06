using System;
using System.Collections.Generic;
using System.IO;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Monitors
{
    /// <summary>
    /// FileSystemWatcher on all drives. When a new executable/script is created or modified,
    /// feeds it through the scan pipeline.
    /// Ported from GorstaksEDR Start-FileMonitor + Antivirus.ps1 Start-RealtimeFileMonitor.
    /// </summary>
    public static class FileMonitor
    {
        private static readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private static readonly HashSet<string> _scanExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta",
            ".scr", ".msi", ".sys", ".com", ".ocx", ".cpl", ".drv"
        };

        // Debounce: don't scan the same file twice within 5 seconds
        private static readonly Dictionary<string, DateTime> _recentScans = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static readonly object _lock = new object();

        public static int WatcherCount { get { return _watchers.Count; } }

        public static void Initialize()
        {
            // Watch all fixed drives
            DriveInfo[] drives = DriveInfo.GetDrives();
            for (int i = 0; i < drives.Length; i++)
            {
                if (drives[i].DriveType != DriveType.Fixed) continue;
                if (!drives[i].IsReady) continue;

                string root = drives[i].RootDirectory.FullName;
                if (Config.IsExcludedPath(root)) continue;

                try
                {
                    FileSystemWatcher watcher = new FileSystemWatcher();
                    watcher.Path = root;
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
                    watcher.Created += OnFileEvent;
                    watcher.Changed += OnFileEvent;
                    watcher.Renamed += OnRenameEvent;
                    watcher.Error += OnWatcherError;
                    watcher.InternalBufferSize = 65536; // 64KB buffer
                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                    Logger.Log(string.Format("FileMonitor: watching {0}", root));
                }
                catch (Exception ex)
                {
                    Logger.Log(string.Format("FileMonitor: failed to watch {0}: {1}", root, ex.Message), LogLevel.WARN);
                }
            }

            Logger.Log(string.Format("FileMonitor: {0} watchers active", _watchers.Count));
        }

        public static void Shutdown()
        {
            for (int i = 0; i < _watchers.Count; i++)
            {
                try
                {
                    _watchers[i].EnableRaisingEvents = false;
                    _watchers[i].Dispose();
                }
                catch { }
            }
            _watchers.Clear();
        }

        private static void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            // Behavioral detection only - we don't scan files on creation.
            // Ransomware detection is handled by RansomwareDetection.cs via process behavior monitoring.
            // File rename detection (for known ransomware extensions) is handled in OnRenameEvent.
            // This method is kept for future expansion if needed.
        }

        private static void OnRenameEvent(object sender, RenamedEventArgs e)
        {
            // Check if renamed to a ransomware extension
            try
            {
                string newExt = Path.GetExtension(e.FullPath);
                if (!string.IsNullOrEmpty(newExt))
                {
                    // Check against known ransomware extensions
                    HashSet<string> ransomExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ".encrypted",".locked",".crypt",".crypto",".enc",".locky",".cerber",
                        ".zepto",".thor",".aesir",".zzzzz",".micro",".xxx",".ttt",".ecc",
                        ".wncry",".wcry",".wnry",".petya",".dharma",".wallet"
                    };

                    if (ransomExts.Contains(newExt))
                    {
                        Logger.Log(string.Format("FileMonitor: RANSOMWARE rename detected: {0} -> {1}",
                            e.OldFullPath, e.FullPath), LogLevel.THREAT, "ransomware_detections.log");

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "RansomwareRename";
                        threat.ThreatPath = e.FullPath;
                        threat.Severity = ThreatSeverity.Critical;
                        threat.Confidence = 80;
                        threat.Details["OldPath"] = e.OldFullPath;
                        threat.Details["NewPath"] = e.FullPath;
                        ResponseQueue.Enqueue(threat);
                    }

                    // Feed all renames into RansomwareDetection as a corroborating signal.
                    // We can't attribute the rename to a specific process here, but the
                    // detection module uses the system-wide rename rate alongside per-process
                    // write I/O to build a composite score.
                    Detection.RansomwareDetection.RecordFileRename(e.OldFullPath, e.FullPath);
                }
            }
            catch { }
        }

        private static void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Logger.Log("FileMonitor watcher error: " + e.GetException().Message, LogLevel.WARN);
        }

        /// <summary>Periodic cleanup of debounce cache (called by scheduler).</summary>
        public static void CleanupCache()
        {
            lock (_lock)
            {
                if (_recentScans.Count < 500) return;
                List<string> toRemove = new List<string>();
                foreach (KeyValuePair<string, DateTime> kvp in _recentScans)
                {
                    if ((DateTime.UtcNow - kvp.Value).TotalMinutes > 5)
                        toRemove.Add(kvp.Key);
                }
                for (int i = 0; i < toRemove.Count; i++)
                    _recentScans.Remove(toRemove[i]);
            }
        }
    }
}
