using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading;

namespace SystemMonitor
{
    public class SystemWatcher
    {
        public event EventHandler<AlertEventArgs> AlertRaised;

        private PerformanceCounter cpuCounter;
        private PerformanceCounter memCounter;
        private Thread monitorThread;
        private bool running = true;

        private HashSet<int> knownProcessIds = new HashSet<int>();
        private HashSet<string> knownConnections = new HashSet<string>();

        public SystemWatcher()
        {
            // CPU and Memory counters may not exist on stripped down systems; fallback to simple methods
            try
            {
                cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                memCounter = new PerformanceCounter("Memory", "% Committed Bytes In Use");
            }
            catch
            {
                cpuCounter = null;
                memCounter = null;
            }

            // Seed known processes
            foreach (var p in Process.GetProcesses())
                knownProcessIds.Add(p.Id);

            // Seed known network connections
            try
            {
                foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
                    knownConnections.Add($"{c.LocalEndPoint}-{c.RemoteEndPoint}");
            }
            catch { }

            monitorThread = new Thread(MonitorLoop) { IsBackground = true };
            monitorThread.Start();
        }

        public float GetCpuUsage()
        {
            if (cpuCounter != null)
            {
                try { return cpuCounter.NextValue(); }
                catch { }
            }
            // Fallback: use total processor time over short interval
            try
            {
                var proc = Process.GetCurrentProcess();
                var start = proc.TotalProcessorTime;
                Thread.Sleep(200);
                var end = proc.TotalProcessorTime;
                return (float)((end - start).TotalMilliseconds / 200.0 * 100 / Environment.ProcessorCount);
            }
            catch { return 0; }
        }

        public float GetMemoryUsage()
        {
            if (memCounter != null)
            {
                try { return memCounter.NextValue(); }
                catch { }
            }
            // Fallback: use WorkingSet vs total physical memory
            try
            {
                var total = new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory;
                var used = total - new Microsoft.VisualBasic.Devices.ComputerInfo().AvailablePhysicalMemory;
                return (float)((double)used / total * 100);
            }
            catch { return 0; }
        }

        private void MonitorLoop()
        {
            while (running)
            {
                DetectNewProcesses();
                DetectNetworkAnomalies();
                Thread.Sleep(3000);
            }
        }

        private void DetectNewProcesses()
        {
            foreach (var p in Process.GetProcesses())
            {
                if (!knownProcessIds.Contains(p.Id))
                {
                    knownProcessIds.Add(p.Id);
                    // Simple heuristic: if process name is suspicious
                    if (IsSuspiciousProcess(p))
                    {
                        OnAlertRaised(new AlertEventArgs($"Suspicious process detected: '{p.ProcessName}' (PID {p.Id})", p.ProcessName));
                    }
                }
            }
        }

        private bool IsSuspiciousProcess(Process p)
        {
            // Basic list; can be expanded. If process not in system folder, flag.
            try
            {
                string path = p.MainModule.FileName;
                if (!path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch { return true; } // Access denied -> treat as suspicious
            return false;
        }

        private void DetectNetworkAnomalies()
        {
            try
            {
                var current = new HashSet<string>();
                foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
                {
                    string key = $"{c.LocalEndPoint}-{c.RemoteEndPoint}";
                    current.Add(key);
                    if (!knownConnections.Contains(key))
                    {
                        // New connection
                        if (IsRemoteEndpointSuspicious(c.RemoteEndPoint.Address.ToString()))
                        {
                            OnAlertRaised(new AlertEventArgs($"New external connection to {c.RemoteEndPoint}"));
                        }
                    }
                }
                knownConnections = current;
            }
            catch { /* ignore on minimal systems */ }
        }

        private bool IsRemoteEndpointSuspicious(string ip)
        {
            // Very naive: flag non‑private IP ranges
            if (ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("172.16.") || ip.StartsWith("172.31."))
                return false;
            return true;
        }

        protected virtual void OnAlertRaised(AlertEventArgs e)
        {
            AlertRaised?.Invoke(this, e);
        }

        public void Stop()
        {
            running = false;
            monitorThread?.Join(1000);
        }
    }
}