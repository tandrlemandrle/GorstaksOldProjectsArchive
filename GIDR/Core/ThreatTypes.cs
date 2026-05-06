using System;
using System.Collections.Generic;

namespace GIDR.Core
{
    public enum ThreatSeverity { Low, Medium, High, Critical }

    public class ThreatInfo
    {
        public string ThreatType;
        public string ThreatPath;
        public ThreatSeverity Severity;
        public DateTime Timestamp;
        public int ProcessId;
        public string ProcessName;
        public string CommandLine;
        public List<string> DetectionMethods;
        public int Confidence;
        public string YaraRule;
        public Dictionary<string, string> Details;

        public ThreatInfo()
        {
            Timestamp = DateTime.UtcNow;
            DetectionMethods = new List<string>();
            Details = new Dictionary<string, string>();
        }
    }

    public static class ResponseQueue
    {
        private static readonly Queue<ThreatInfo> _queue = new Queue<ThreatInfo>();
        private static readonly object _lock = new object();
        private const int MaxSize = 1000;

        public static void Enqueue(ThreatInfo threat)
        {
            lock (_lock)
            {
                if (_queue.Count >= MaxSize) _queue.Dequeue();
                _queue.Enqueue(threat);
            }
        }

        public static ThreatInfo Dequeue()
        {
            lock (_lock) { return _queue.Count > 0 ? _queue.Dequeue() : null; }
        }

        public static int Count
        {
            get { lock (_lock) { return _queue.Count; } }
        }
    }

    public static class GidrState
    {
        private static readonly object _lock = new object();
        private static int _threatCount;
        private static int _filesScanned;
        private static int _filesQuarantined;
        private static int _processesTerminated;
        private static int _yaraMatches;

        public static int ThreatCount { get { lock (_lock) return _threatCount; } }
        public static int FilesScanned { get { lock (_lock) return _filesScanned; } }
        public static int FilesQuarantined { get { lock (_lock) return _filesQuarantined; } }
        public static int ProcessesTerminated { get { lock (_lock) return _processesTerminated; } }
        public static int YaraMatches { get { lock (_lock) return _yaraMatches; } }

        public static void IncrementThreats() { lock (_lock) _threatCount++; }
        public static void IncrementScanned() { lock (_lock) _filesScanned++; }
        public static void IncrementQuarantined() { lock (_lock) _filesQuarantined++; }
        public static void IncrementTerminated() { lock (_lock) _processesTerminated++; }
        public static void IncrementYaraMatches() { lock (_lock) _yaraMatches++; }
    }
}
