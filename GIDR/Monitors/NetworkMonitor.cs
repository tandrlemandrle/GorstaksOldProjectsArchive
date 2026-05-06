using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Monitors
{
    /// <summary>
    /// Network intrusion detection monitor.
    /// 
    /// Detects exactly:
    ///   - C2 beaconing (regular-interval outbound connections)
    ///   - Reverse shells: cmd/powershell/interpreters with outbound connections
    ///   - Connections to known C2 ports
    ///
    /// Does NOT detect: legitimate apps, browsers, etc. Only attack behaviors.
    /// </summary>
    public static class NetworkMonitor
    {
        // Beacon tracking: "ip:port" -> list of observation timestamps
        private static readonly Dictionary<string, List<DateTime>> _beaconHistory
            = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);

        // Track bytes sent per process for exfiltration detection
        private static readonly Dictionary<int, long> _prevBytesSent = new Dictionary<int, long>();

        // Track which PIDs we've already alerted on (avoid spam)
        private static readonly HashSet<string> _alertedConnections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static DateTime _lastAlertCleanup = DateTime.UtcNow;

        // Thread safety locks
        private static readonly object _beaconLock = new object();
        private static readonly object _alertLock = new object();
        private static readonly object _bytesLock = new object();

        private static readonly Dictionary<int, PortDef> _suspiciousPorts = new Dictionary<int, PortDef>();

        static NetworkMonitor()
        {
            _suspiciousPorts[4444]  = new PortDef(50, "Metasploit default");
            _suspiciousPorts[5555]  = new PortDef(40, "Common backdoor/ADB");
            _suspiciousPorts[6666]  = new PortDef(30, "IRC/trojan");
            _suspiciousPorts[6667]  = new PortDef(30, "IRC");
            _suspiciousPorts[6697]  = new PortDef(30, "IRC SSL");
            _suspiciousPorts[9999]  = new PortDef(20, "Common trojan");
            _suspiciousPorts[31337] = new PortDef(40, "Elite backdoor");
            _suspiciousPorts[12345] = new PortDef(30, "NetBus trojan");
            _suspiciousPorts[54321] = new PortDef(30, "Back Orifice");
            _suspiciousPorts[1337]  = new PortDef(25, "Leet port");
            _suspiciousPorts[8443]  = new PortDef(15, "Alt HTTPS (C2 common)");
            _suspiciousPorts[4443]  = new PortDef(20, "Alt HTTPS (C2 common)");
        }

        public static void Execute()
        {
            try
            {
                // Clean up old alerts every 10 minutes (thread-safe)
                lock (_alertLock)
                {
                    if ((DateTime.UtcNow - _lastAlertCleanup).TotalMinutes > 10)
                    {
                        _alertedConnections.Clear();
                        _lastAlertCleanup = DateTime.UtcNow;
                    }
                }

                // Get TCP connections with owning PIDs
                List<TcpConnectionInfo> connections = GetTcpConnectionsWithPids();
                DateTime now = DateTime.UtcNow;
                int selfPid = Process.GetCurrentProcess().Id;

                for (int c = 0; c < connections.Count; c++)
                {
                    TcpConnectionInfo conn = connections[c];
                    if (conn.State != "ESTABLISHED") continue;
                    if (conn.OwningPid <= 4 || conn.OwningPid == selfPid) continue;

                    string remote = conn.RemoteAddress;
                    if (remote == "127.0.0.1" || remote == "::1" || remote == "0.0.0.0") continue;
                    if (remote.StartsWith("192.168.") || remote.StartsWith("10.") || remote.StartsWith("169.254.")) continue;

                    int remotePort = conn.RemotePort;
                    int score = 0;
                    List<string> reasons = new List<string>();
                    string processName = GetProcessName(conn.OwningPid);
                    string alertKey = string.Format("{0}:{1}:{2}", conn.OwningPid, remote, remotePort);

                    // Skip if already alerted (thread-safe check)
                    lock (_alertLock)
                    {
                        if (_alertedConnections.Contains(alertKey)) continue;
                    }

                    // ── Check 1: Suspicious port ──
                    PortDef portDef;
                    if (_suspiciousPorts.TryGetValue(remotePort, out portDef))
                    {
                        score += portDef.Score;
                        reasons.Add(string.Format("Port {0}: {1}", remotePort, portDef.Reason));
                    }

                    // ── Check 2: Reverse shell detection ──
                    // Shell/interpreter processes with outbound connections = likely reverse shell
                    string procLower = (processName ?? "").ToLowerInvariant().Replace(".exe", "");
                    string[] shellProcesses = new string[]
                    {
                        "cmd", "powershell", "pwsh",           // Native shells
                        "wscript", "cscript",                  // VBScript/JavaScript
                        "mshta",                               // HTML Applications
                        "rundll32",                            // DLL execution
                        "regsvr32",                            // COM scriptlets
                        "certutil",                            // Download+decode
                        "bitsadmin",                           // BITS transfers
                        "wmic",                                // WMI execution
                        "msbuild",                             // .NET inline tasks
                        "installutil", "regasm", "regsvcs",    // .NET assembly execution
                        "ieexec",                              // IE execution
                        "msxsl",                               // XSL transforms
                        "winrm", "wsmprovhost",                // WinRM shells
                        "bash", "wsl", "wslhost"               // WSL shells
                    };

                    for (int s = 0; s < shellProcesses.Length; s++)
                    {
                        if (procLower == shellProcesses[s])
                        {
                            // Shell process with outbound connection to non-standard port
                            if (remotePort != 80 && remotePort != 443 && remotePort != 22)
                            {
                                score += 75;
                                reasons.Add(string.Format("Reverse shell: {0} -> {1}:{2}", processName, remote, remotePort));
                            }
                            else if (procLower == "mshta" || procLower == "regsvr32" || procLower == "rundll32")
                            {
                                // These should NEVER have direct internet connections
                                score += 80;
                                reasons.Add(string.Format("Abused LOLBAS: {0} -> {1}:{2}", processName, remote, remotePort));
                            }
                            break;
                        }
                    }

                    // ── Check 4: Beacon detection (C2) ──
                    string beaconKey = string.Format("{0}:{1}:{2}", conn.OwningPid, remote, remotePort);
                    List<DateTime> history;
                    lock (_beaconLock)
                    {
                        if (!_beaconHistory.TryGetValue(beaconKey, out history))
                        {
                            history = new List<DateTime>();
                            _beaconHistory[beaconKey] = history;
                        }
                        history.Add(now);
                        history.RemoveAll(delegate(DateTime t) { return (now - t).TotalMinutes > 30; });

                        if (history.Count >= 4)
                        {
                            history.Sort();
                            List<double> intervals = new List<double>();
                            for (int i = 1; i < history.Count; i++)
                                intervals.Add((history[i] - history[i - 1]).TotalSeconds);

                            if (intervals.Count >= 3)
                            {
                                double sum = 0;
                                for (int i = 0; i < intervals.Count; i++) sum += intervals[i];
                                double avg = sum / intervals.Count;

                                double varSum = 0;
                                for (int i = 0; i < intervals.Count; i++)
                                    varSum += (intervals[i] - avg) * (intervals[i] - avg);
                                double stdDev = Math.Sqrt(varSum / intervals.Count);

                                if (stdDev < avg * 0.25 && avg > 10 && avg < 3600)
                                {
                                    score += 55;
                                    reasons.Add(string.Format("C2 beacon: avg={0:F0}s jitter={1:F1}% count={2} from {3}",
                                        avg, (stdDev / avg) * 100, history.Count, processName));
                                    history.Clear();
                                }
                            }
                        }
                    } // Close the beacon lock here

                    // ── Enqueue if threshold met ──
                    if (score >= 40)
                    {
                        lock (_alertLock)
                        {
                            _alertedConnections.Add(alertKey);
                        }

                        ThreatSeverity sev = score >= 80 ? ThreatSeverity.Critical
                            : score >= 60 ? ThreatSeverity.High : ThreatSeverity.Medium;

                        Logger.Log(string.Format("Network: {0} (PID:{1}) -> {2}:{3} score:{4} | {5}",
                            processName, conn.OwningPid, remote, remotePort, score,
                            string.Join("; ", reasons.ToArray())),
                            LogLevel.THREAT, "network_detections.log");

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "NetworkAnomaly";
                        threat.ThreatPath = string.Format("{0}:{1}", remote, remotePort);
                        threat.Severity = sev;
                        threat.ProcessId = conn.OwningPid;
                        threat.ProcessName = processName;
                        threat.Confidence = score;
                        for (int i = 0; i < reasons.Count; i++)
                            threat.DetectionMethods.Add(reasons[i]);

                        ResponseQueue.Enqueue(threat);
                    }
                }

                // Cleanup old beacon entries
                List<string> deadKeys = new List<string>();
                foreach (KeyValuePair<string, List<DateTime>> kvp in _beaconHistory)
                {
                    if (kvp.Value.Count == 0) deadKeys.Add(kvp.Key);
                }
                for (int i = 0; i < deadKeys.Count; i++)
                    _beaconHistory.Remove(deadKeys[i]);
            }
            catch (Exception ex)
            {
                Logger.Log("NetworkMonitor error: " + ex.Message, LogLevel.ERROR);
            }
        }

        // ── Get TCP connections with owning PIDs via GetExtendedTcpTable ──
        // Native API is faster and more reliable than parsing netstat output
        private static List<TcpConnectionInfo> GetTcpConnectionsWithPids()
        {
            List<TcpConnectionInfo> result = new List<TcpConnectionInfo>();

            // Get IPv4 connections
            GetIPv4Connections(result);

            // Get IPv6 connections
            GetIPv6Connections(result);

            return result;
        }

        private static void GetIPv4Connections(List<TcpConnectionInfo> result)
        {
            IntPtr tcpTable = IntPtr.Zero;
            try
            {
                uint size = 0;
                int ret = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, true,
                    NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

                if (ret != 0 && ret != 122) return;

                tcpTable = Marshal.AllocHGlobal((int)size);
                ret = NativeMethods.GetExtendedTcpTable(tcpTable, ref size, true,
                    NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

                if (ret != 0) return;

                uint numEntries = (uint)Marshal.ReadInt32(tcpTable);
                int rowSize = Marshal.SizeOf(typeof(NativeMethods.MIB_TCPROW_OWNER_PID));
                IntPtr rowPtr = IntPtr.Add(tcpTable, 4);

                for (int i = 0; i < numEntries; i++)
                {
                    NativeMethods.MIB_TCPROW_OWNER_PID row =
                        (NativeMethods.MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(
                            rowPtr, typeof(NativeMethods.MIB_TCPROW_OWNER_PID));

                    if (row.dwState == NativeMethods.MIB_TCP_STATE_ESTABLISHED)
                    {
                        TcpConnectionInfo conn = new TcpConnectionInfo();
                        conn.RemoteAddress = NativeMethods.ConvertIPv4Address(row.dwRemoteAddr);
                        conn.RemotePort = NativeMethods.ntohs((ushort)row.dwRemotePort);
                        conn.State = "ESTABLISHED";
                        conn.OwningPid = (int)row.dwOwningPid;
                        result.Add(conn);
                    }
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("IPv4 connection enumeration error: " + ex.Message, LogLevel.WARN);
            }
            finally
            {
                if (tcpTable != IntPtr.Zero)
                    Marshal.FreeHGlobal(tcpTable);
            }
        }

        private static void GetIPv6Connections(List<TcpConnectionInfo> result)
        {
            IntPtr tcpTable = IntPtr.Zero;
            try
            {
                uint size = 0;
                int ret = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, true,
                    NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

                if (ret != 0 && ret != 122) return;

                tcpTable = Marshal.AllocHGlobal((int)size);
                ret = NativeMethods.GetExtendedTcpTable(tcpTable, ref size, true,
                    NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

                if (ret != 0) return;

                uint numEntries = (uint)Marshal.ReadInt32(tcpTable);
                int rowSize = Marshal.SizeOf(typeof(NativeMethods.MIB_TCP6ROW_OWNER_PID));
                IntPtr rowPtr = IntPtr.Add(tcpTable, 4);

                for (int i = 0; i < numEntries; i++)
                {
                    NativeMethods.MIB_TCP6ROW_OWNER_PID row =
                        (NativeMethods.MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(
                            rowPtr, typeof(NativeMethods.MIB_TCP6ROW_OWNER_PID));

                    if (row.dwState == NativeMethods.MIB_TCP_STATE_ESTABLISHED)
                    {
                        TcpConnectionInfo conn = new TcpConnectionInfo();
                        conn.RemoteAddress = NativeMethods.ConvertIPv6Address(row.ucRemoteAddr);
                        conn.RemotePort = NativeMethods.ntohs((ushort)row.dwRemotePort);
                        conn.State = "ESTABLISHED";
                        conn.OwningPid = (int)row.dwOwningPid;
                        result.Add(conn);
                    }
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("IPv6 connection enumeration error: " + ex.Message, LogLevel.WARN);
            }
            finally
            {
                if (tcpTable != IntPtr.Zero)
                    Marshal.FreeHGlobal(tcpTable);
            }
        }

        private static string GetProcessName(int pid)
        {
            try
            {
                Process p = Process.GetProcessById(pid);
                return p.ProcessName;
            }
            catch { return "unknown"; }
        }

        private static string GetProcessPath(int pid)
        {
            try
            {
                Process p = Process.GetProcessById(pid);
                return p.MainModule.FileName;
            }
            catch
            {
                // Fallback to WMI for access-denied processes
                try
                {
                    ProcessInfo info = WmiHelper.GetProcess(pid);
                    return info != null ? info.ExecutablePath : null;
                }
                catch { return null; }
            }
        }

        private class TcpConnectionInfo
        {
            public string RemoteAddress;
            public int RemotePort;
            public string State;
            public int OwningPid;
        }

        private class PortDef
        {
            public int Score;
            public string Reason;
            public PortDef(int s, string r) { Score = s; Reason = r; }
        }
    }
}
