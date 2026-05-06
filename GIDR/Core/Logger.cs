using System;
using System.Diagnostics;
using System.IO;

namespace GIDR.Core
{
    public enum LogLevel { DEBUG, INFO, WARN, THREAT, ACTION, ERROR }

    public static class Logger
    {
        private static readonly object _lock = new object();
        private static bool _eventSourceCreated;

        private const long MaxLogSize = 5 * 1024 * 1024; // 5 MB
        private const int MaxLogFiles = 5;

        public static void Log(string message, LogLevel level, string logFile)
        {
            string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string entry = string.Format("[{0}] [{1}] {2}", ts, level, message);
            lock (_lock)
            {
                try
                {
                    if (!Directory.Exists(Config.LogPath))
                        Directory.CreateDirectory(Config.LogPath);
                    string fullPath = Path.Combine(Config.LogPath, logFile);
                    RotateIfNeeded(fullPath);
                    File.AppendAllText(fullPath, entry + Environment.NewLine);
                }
                catch { }
            }
            WriteEventLog(message, level);
            if (level >= LogLevel.WARN)
            {
                ConsoleColor color;
                switch (level)
                {
                    case LogLevel.ERROR: color = ConsoleColor.Red; break;
                    case LogLevel.THREAT: color = ConsoleColor.Magenta; break;
                    default: color = ConsoleColor.Yellow; break;
                }
                WriteConsole(entry, color);
            }
        }

        public static void Log(string message, LogLevel level) { Log(message, level, "gidr_log.txt"); }
        public static void Log(string message) { Log(message, LogLevel.INFO, "gidr_log.txt"); }

        public static void Stability(string message, LogLevel level)
        {
            string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string entry = string.Format("[{0}] [{1}] [STABILITY] {2}", ts, level, message);
            lock (_lock)
            {
                try
                {
                    string dir = Path.GetDirectoryName(Config.StabilityLogPath);
                    if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    File.AppendAllText(Config.StabilityLogPath, entry + Environment.NewLine);
                }
                catch { }
            }
        }

        public static void Stability(string message) { Stability(message, LogLevel.INFO); }

        private static void RotateIfNeeded(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;
                FileInfo fi = new FileInfo(filePath);
                if (fi.Length < MaxLogSize) return;

                // Rotate: log.4 -> delete, log.3 -> log.4, ... log -> log.1
                for (int i = MaxLogFiles - 1; i >= 1; i--)
                {
                    string src = filePath + "." + i;
                    string dst = filePath + "." + (i + 1);
                    if (File.Exists(dst)) File.Delete(dst);
                    if (File.Exists(src)) File.Move(src, dst);
                }
                string first = filePath + ".1";
                if (File.Exists(first)) File.Delete(first);
                File.Move(filePath, first);
            }
            catch { }
        }

        private static void WriteEventLog(string message, LogLevel level)
        {
            // Skip EventLog entirely if not admin — it blocks on SourceExists check
            if (!_eventSourceCreated)
            {
                try
                {
                    // Quick check: if we can't open the registry key, we're not admin
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\EventLog\Application", false))
                    {
                        if (key == null) return;
                    }
                    if (!EventLog.SourceExists(Config.EDRName))
                        EventLog.CreateEventSource(Config.EDRName, "Application");
                    _eventSourceCreated = true;
                }
                catch { return; }
            }
            try
            {
                int eid;
                switch (level)
                {
                    case LogLevel.ERROR: eid = 1001; break;
                    case LogLevel.WARN: eid = 1002; break;
                    case LogLevel.THREAT: eid = 1003; break;
                    case LogLevel.ACTION: eid = 1004; break;
                    default: eid = 1000; break;
                }
                EventLog.WriteEntry(Config.EDRName, message, EventLogEntryType.Information, eid);
            }
            catch { }
        }

        private static void WriteConsole(string text, ConsoleColor color)
        {
            try
            {
                ConsoleColor prev = Console.ForegroundColor;
                Console.ForegroundColor = color;
                Console.WriteLine(text);
                Console.ForegroundColor = prev;
            }
            catch { }
        }
    }
}
