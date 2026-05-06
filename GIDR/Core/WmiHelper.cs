using System;
using System.Collections.Generic;
using System.Management;

namespace GIDR.Core
{
    public class ProcessInfo
    {
        public int ProcessId;
        public string Name;
        public string ExecutablePath;
        public string CommandLine;
        public int ParentProcessId;
    }

    public static class WmiHelper
    {
        public static List<ProcessInfo> GetProcesses()
        {
            List<ProcessInfo> result = new List<ProcessInfo>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process"))
                using (ManagementObjectCollection collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        try
                        {
                            ProcessInfo pi = new ProcessInfo();
                            pi.ProcessId = Convert.ToInt32(obj["ProcessId"]);
                            pi.Name = (obj["Name"] != null) ? obj["Name"].ToString() : "";
                            pi.ExecutablePath = (obj["ExecutablePath"] != null) ? obj["ExecutablePath"].ToString() : null;
                            pi.CommandLine = (obj["CommandLine"] != null) ? obj["CommandLine"].ToString() : null;
                            pi.ParentProcessId = Convert.ToInt32(obj["ParentProcessId"] ?? 0);
                            result.Add(pi);
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("WMI process enumeration failed: " + ex.Message, LogLevel.WARN);
            }
            return result;
        }

        public static ProcessInfo GetProcess(int pid)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    string.Format("SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", pid)))
                using (ManagementObjectCollection collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        ProcessInfo pi = new ProcessInfo();
                        pi.ProcessId = Convert.ToInt32(obj["ProcessId"]);
                        pi.Name = (obj["Name"] != null) ? obj["Name"].ToString() : "";
                        pi.ExecutablePath = (obj["ExecutablePath"] != null) ? obj["ExecutablePath"].ToString() : null;
                        pi.CommandLine = (obj["CommandLine"] != null) ? obj["CommandLine"].ToString() : null;
                        pi.ParentProcessId = Convert.ToInt32(obj["ParentProcessId"] ?? 0);
                        return pi;
                    }
                }
            }
            catch { }
            return null;
        }

        public static List<Dictionary<string, string>> GetWmiEventFilters()
        {
            List<Dictionary<string, string>> result = new List<Dictionary<string, string>>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    new ManagementScope(@"\\.\root\subscription"),
                    new ObjectQuery("SELECT * FROM __EventFilter")))
                using (ManagementObjectCollection collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        Dictionary<string, string> d = new Dictionary<string, string>();
                        d["Name"] = (obj["Name"] != null) ? obj["Name"].ToString() : "";
                        d["Query"] = (obj["Query"] != null) ? obj["Query"].ToString() : "";
                        result.Add(d);
                    }
                }
            }
            catch { }
            return result;
        }

        public static List<Dictionary<string, string>> GetWmiCommandConsumers()
        {
            List<Dictionary<string, string>> result = new List<Dictionary<string, string>>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    new ManagementScope(@"\\.\root\subscription"),
                    new ObjectQuery("SELECT * FROM CommandLineEventConsumer")))
                using (ManagementObjectCollection collection = searcher.Get())
                {
                    foreach (ManagementObject obj in collection)
                    {
                        Dictionary<string, string> d = new Dictionary<string, string>();
                        d["Name"] = (obj["Name"] != null) ? obj["Name"].ToString() : "";
                        d["CommandLineTemplate"] = (obj["CommandLineTemplate"] != null) ? obj["CommandLineTemplate"].ToString() : "";
                        result.Add(d);
                    }
                }
            }
            catch { }
            return result;
        }
    }
}
