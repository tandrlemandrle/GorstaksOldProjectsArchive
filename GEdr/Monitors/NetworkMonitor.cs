using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using GEdr.Core;
using GEdr.Response;

namespace GEdr.Monitors
{
    /// <summary>
    /// Periodic network connection analysis: suspicious ports, beacon detection
    /// (regular interval connections), connections to raw IPs, DNS port abuse.
    /// Ported from Invoke-NetworkAnomalyDetection + Invoke-BeaconDetection.
    /// </summary>
    public static class NetworkMonitor
    {
        // Beacon tracking: endpoint -> list of observation timestamps
        private static readonly Dictionary<string, List<DateTime>> _beaconHistory
            = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);

        private static readonly Dictionary<int, PortDef> _suspiciousPorts = new Dictionary<int, PortDef>();
        private static readonly string[] _maliciousRanges = new string[] { "5.8.18.", "5.8.48.", "91.92.", "91.215." };

        // Known legitimate IP ranges that should never be flagged or blocked
        private static readonly string[][] _allowedNetworkRanges = new string[][]
        {
            new string[] { "185.199.",   "GitHub Pages/CDN" },
            new string[] { "140.82.112.", "GitHub" },
            new string[] { "140.82.113.", "GitHub" },
            new string[] { "140.82.114.", "GitHub" },
            new string[] { "20.",        "Microsoft Azure/365" },
            new string[] { "13.",        "Microsoft Azure" },
            new string[] { "52.",        "Amazon AWS" },
            new string[] { "54.",        "Amazon AWS" },
            new string[] { "104.16.",    "Cloudflare" },
            new string[] { "104.17.",    "Cloudflare" },
            new string[] { "104.18.",    "Cloudflare" },
            new string[] { "104.19.",    "Cloudflare" },
            new string[] { "104.20.",    "Cloudflare" },
            new string[] { "104.21.",    "Cloudflare" },
            new string[] { "104.22.",    "Cloudflare" },
            new string[] { "104.23.",    "Cloudflare" },
            new string[] { "104.24.",    "Cloudflare" },
            new string[] { "104.25.",    "Cloudflare" },
            new string[] { "104.26.",    "Cloudflare" },
            new string[] { "104.27.",    "Cloudflare" },
            new string[] { "162.159.",   "Cloudflare" },
            new string[] { "172.64.",    "Cloudflare" },
            new string[] { "172.65.",    "Cloudflare" },
            new string[] { "172.66.",    "Cloudflare" },
            new string[] { "172.67.",    "Cloudflare" },
            new string[] { "146.66.",    "Steam/Valve" },
            new string[] { "155.133.",   "Steam/Valve" },
            new string[] { "142.250.",   "Google" },
            new string[] { "172.217.",   "Google" },
            new string[] { "216.58.",    "Google" },
            new string[] { "34.104.",    "Google Cloud" },
            new string[] { "35.186.",    "Google Cloud" },
            new string[] { "151.101.",   "Fastly CDN (Reddit, StackOverflow)" },
            new string[] { "199.232.",   "GitHub raw/assets" },
            new string[] { "192.0.73.",  "WordPress/Automattic" },
            new string[] { "192.0.78.",  "WordPress/Automattic" },
        };

        static NetworkMonitor()
        {
            _suspiciousPorts[4444]  = new PortDef(30, "Metasploit default");
            _suspiciousPorts[5555]  = new PortDef(30, "Common backdoor");
            _suspiciousPorts[6666]  = new PortDef(20, "IRC/trojan");
            _suspiciousPorts[9999]  = new PortDef(10, "Common trojan");
            _suspiciousPorts[31337] = new PortDef(20, "Elite backdoor");
            _suspiciousPorts[12345] = new PortDef(20, "NetBus trojan");
            _suspiciousPorts[54321] = new PortDef(20, "Back Orifice");
            _suspiciousPorts[1337]  = new PortDef(15, "Leet port");
        }

        public static void Execute()
        {
            try
            {
                TcpConnectionInformation[] connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                DateTime now = DateTime.UtcNow;

                for (int c = 0; c < connections.Length; c++)
                {
                    TcpConnectionInformation conn = connections[c];
                    if (conn.State != TcpState.Established) continue;

                    string remote = conn.RemoteEndPoint.Address.ToString();
                    if (remote == "127.0.0.1" || remote == "::1") continue;
                    if (remote.StartsWith("192.168.") || remote.StartsWith("10.") || remote.StartsWith("169.254.")) continue;

                    int remotePort = conn.RemoteEndPoint.Port;
                    int score = 0;
                    List<string> reasons = new List<string>();

                    // Suspicious port
                    PortDef portDef;
                    if (_suspiciousPorts.TryGetValue(remotePort, out portDef))
                    {
                        score += portDef.Score;
                        reasons.Add(string.Format("Port {0}: {1}", remotePort, portDef.Reason));
                    }

                    // Known malicious IP ranges
                    for (int r = 0; r < _maliciousRanges.Length; r++)
                    {
                        if (remote.StartsWith(_maliciousRanges[r]))
                        {
                            score += 25;
                            reasons.Add("Malicious IP range: " + _maliciousRanges[r]);
                            break;
                        }
                    }

                    // DNS port from unexpected source
                    if (remotePort == 53)
                    {
                        score += 25;
                        reasons.Add("DNS port connection (potential tunneling)");
                    }

                    // High ephemeral port
                    if (remotePort > 49152 && remotePort < 65535)
                    {
                        score += 5;
                        reasons.Add("High ephemeral port");
                    }

                    // Beacon tracking
                    string beaconKey = string.Format("{0}:{1}", remote, remotePort);
                    List<DateTime> history;
                    if (!_beaconHistory.TryGetValue(beaconKey, out history))
                    {
                        history = new List<DateTime>();
                        _beaconHistory[beaconKey] = history;
                    }
                    history.Add(now);

                    // Prune old entries
                    history.RemoveAll(delegate(DateTime t) { return (now - t).TotalMinutes > 30; });

                    // Beacon analysis: 4+ observations with regular intervals
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

                            // Low variance + reasonable interval = beacon
                            if (stdDev < avg * 0.2 && avg > 10 && avg < 3600)
                            {
                                score += 40;
                                reasons.Add(string.Format("Beacon pattern: avg={0:F0}s stddev={1:F1}s count={2}", avg, stdDev, history.Count));
                                history.Clear(); // reset after detection
                            }
                        }
                    }

                    if (score >= Config.AlertThreshold)
                    {
                        ThreatSeverity sev = score >= Config.AutoKillThreshold ? ThreatSeverity.Critical
                            : score >= Config.AutoQuarantineThreshold ? ThreatSeverity.High : ThreatSeverity.Medium;

                        Logger.Log(string.Format("Network: {0}:{1} score:{2} | {3}",
                            remote, remotePort, score, string.Join("; ", reasons.ToArray())),
                            LogLevel.THREAT, "network_detections.log");

                        ThreatInfo threat = new ThreatInfo();
                        threat.ThreatType = "NetworkAnomaly";
                        threat.ThreatPath = string.Format("{0}:{1}", remote, remotePort);
                        threat.Severity = sev;
                        threat.Confidence = score;
                        for (int i = 0; i < reasons.Count; i++)
                            threat.DetectionMethods.Add(reasons[i]);

                        ResponseQueue.Enqueue(threat);

                        if (score >= Config.AutoBlockThreshold)
                            ThreatActions.BlockIP(remote);
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

        private class PortDef
        {
            public int Score;
            public string Reason;
            public PortDef(int s, string r) { Score = s; Reason = r; }
        }
    }
}
