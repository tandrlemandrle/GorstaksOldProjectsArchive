using System;
using System.IO;

namespace GIDR.Core
{
    /// <summary>
    /// Structured JSON lines logger. Writes one JSON object per line to gidr_events.jsonl.
    /// Designed for SIEM ingestion (Elastic, Splunk, Graylog) or simple parsing.
    /// 
    /// Enabled via config.json: "jsonLogging": true
    /// </summary>
    public static class JsonLogger
    {
        private static readonly object _lock = new object();
        private static string _logFile;

        public static void Initialize()
        {
            _logFile = Path.Combine(Config.LogPath, "gidr_events.jsonl");
        }

        /// <summary>Log a simple event.</summary>
        public static void LogEvent(string level, string category, string message)
        {
            if (!Config.JsonLogging) return;
            string json = string.Format(
                "{{\"timestamp\":\"{0}\",\"level\":\"{1}\",\"category\":\"{2}\",\"message\":{3}}}",
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                EscapeJson(level),
                EscapeJson(category),
                QuoteJson(message));
            WriteLine(json);
        }

        /// <summary>Log a threat detection event with full context.</summary>
        public static void LogThreat(string source, string filePath, string sha256,
            int score, string verdict, string severity, string mitreId, string evidence)
        {
            if (!Config.JsonLogging) return;
            string json = string.Format(
                "{{\"timestamp\":\"{0}\",\"level\":\"THREAT\",\"category\":\"detection\"," +
                "\"source\":{1},\"filePath\":{2},\"sha256\":{3}," +
                "\"score\":{4},\"verdict\":{5},\"severity\":{6}," +
                "\"mitreId\":{7},\"evidence\":{8}}}",
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                QuoteJson(source),
                QuoteJson(filePath),
                QuoteJson(sha256),
                score,
                QuoteJson(verdict),
                QuoteJson(severity),
                QuoteJson(mitreId),
                QuoteJson(evidence));
            WriteLine(json);
        }

        /// <summary>Log a process event (creation, termination, suspicious).</summary>
        public static void LogProcess(string action, string processName, int pid,
            string exePath, string commandLine, int score, string verdict)
        {
            if (!Config.JsonLogging) return;
            string json = string.Format(
                "{{\"timestamp\":\"{0}\",\"level\":\"THREAT\",\"category\":\"process\"," +
                "\"action\":{1},\"processName\":{2},\"pid\":{3}," +
                "\"exePath\":{4},\"commandLine\":{5}," +
                "\"score\":{6},\"verdict\":{7}}}",
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                QuoteJson(action),
                QuoteJson(processName),
                pid,
                QuoteJson(exePath),
                QuoteJson(commandLine),
                score,
                QuoteJson(verdict));
            WriteLine(json);
        }

        /// <summary>Log a network event.</summary>
        public static void LogNetwork(string action, string remoteAddress, int remotePort,
            int score, string details)
        {
            if (!Config.JsonLogging) return;
            string json = string.Format(
                "{{\"timestamp\":\"{0}\",\"level\":\"THREAT\",\"category\":\"network\"," +
                "\"action\":{1},\"remoteAddress\":{2},\"remotePort\":{3}," +
                "\"score\":{4},\"details\":{5}}}",
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                QuoteJson(action),
                QuoteJson(remoteAddress),
                remotePort,
                score,
                QuoteJson(details));
            WriteLine(json);
        }

        /// <summary>Log a response action (quarantine, terminate, block).</summary>
        public static void LogAction(string action, string target, bool success, string details)
        {
            if (!Config.JsonLogging) return;
            string json = string.Format(
                "{{\"timestamp\":\"{0}\",\"level\":\"ACTION\",\"category\":\"response\"," +
                "\"action\":{1},\"target\":{2},\"success\":{3},\"details\":{4}}}",
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                QuoteJson(action),
                QuoteJson(target),
                success ? "true" : "false",
                QuoteJson(details));
            WriteLine(json);
        }

        private static void WriteLine(string json)
        {
            lock (_lock)
            {
                try
                {
                    if (!Directory.Exists(Config.LogPath))
                        Directory.CreateDirectory(Config.LogPath);
                    File.AppendAllText(_logFile, json + "\n");
                }
                catch { }
            }
        }

        private static string EscapeJson(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"")
                    .Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
        }

        private static string QuoteJson(string s)
        {
            if (s == null) return "null";
            return "\"" + EscapeJson(s) + "\"";
        }
    }
}
