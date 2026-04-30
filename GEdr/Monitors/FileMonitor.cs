using System;
using System.Collections.Generic;
using System.IO;
using GEdr.Core;
using GEdr.Engine;
using GEdr.Response;

namespace GEdr.Monitors
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
            try
            {
                string path = e.FullPath;
                if (string.IsNullOrEmpty(path)) return;
                if (Config.IsExcludedPath(path)) return;

                string ext = Path.GetExtension(path);
                if (string.IsNullOrEmpty(ext)) return;
                if (!_scanExtensions.Contains(ext)) return;

                // Debounce
                lock (_lock)
                {
                    DateTime lastScan;
                    if (_recentScans.TryGetValue(path, out lastScan))
                    {
                        if ((DateTime.UtcNow - lastScan).TotalSeconds < 5) return;
                    }
                    _recentScans[path] = DateTime.UtcNow;
                }

                // Small delay to let the file finish writing
                System.Threading.Thread.Sleep(500);

                if (!File.Exists(path)) return;

                // Retry on sharing violations
                ScanResult result = null;
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    try
                    {
                        result = ScanPipeline.ScanFile(path);
                        break;
                    }
                    catch (IOException)
                    {
                        if (attempt < 2) System.Threading.Thread.Sleep(200);
                    }
                }
                if (result == null) return;
                if (result.Verdict == "SKIPPED") return;

                if (result.TotalScore >= Config.AlertThreshold)
                {
                    Logger.Log(string.Format("FileMonitor: {0} score:{1} verdict:{2}",
                        Path.GetFileName(path), result.TotalScore, result.Verdict), LogLevel.THREAT, "file_monitor.log");

                    ScanPipeline.PrintResult(result);

                    if (Config.AutoQuarantine && result.Severity >= ThreatSeverity.High)
                        ThreatActions.Quarantine(path, "FileMonitor: " + result.Verdict);

                    ThreatInfo threat = new ThreatInfo();
                    threat.ThreatType = "FileCreated:" + result.Verdict;
                    threat.ThreatPath = path;
                    threat.Severity = result.Severity;
                    threat.Confidence = result.TotalScore;
                    ResponseQueue.Enqueue(threat);
                }
            }
            catch { }
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
