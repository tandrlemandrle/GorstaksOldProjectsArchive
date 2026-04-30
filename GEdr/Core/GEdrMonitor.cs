using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using GEdr.Detection;
using GEdr.Engine;
using GEdr.Monitors;
using GEdr.Response;

namespace GEdr.Core
{
    /// <summary>
    /// Shared monitor logic used by both console mode and Windows service mode.
    /// </summary>
    public static class GEdrMonitor
    {
        public static void Run(CancellationToken token, bool serviceMode = false)
        {
            // Initialize engines
            HashReputation.LoadDatabase();
            YaraEngine.Initialize();

            if (!YaraEngine.IsAvailable && !serviceMode)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[*] YARA not found. Run 'GEdr.exe bootstrap' first for full detection.");
                Console.WriteLine("[*] Continuing without YARA...");
                Console.ResetColor();
            }

            // Write PID file
            try
            {
                string pidDir = Path.GetDirectoryName(Config.PidFilePath);
                if (!Directory.Exists(pidDir)) Directory.CreateDirectory(pidDir);
                File.WriteAllText(Config.PidFilePath, Process.GetCurrentProcess().Id.ToString());
            }
            catch { }

            // Initialize real-time monitors
            if (!serviceMode)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("[*] Starting real-time monitors...");
                Console.ResetColor();
            }

            SelfProtection.Initialize();
            ProcessMonitor.Initialize();
            FileMonitor.Initialize();
            EtwMonitor.Initialize();
            AmsiScanner.Initialize();

            if (!serviceMode)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] ProcessMonitor active");
                Console.WriteLine("[+] FileMonitor active ({0} watchers)", FileMonitor.WatcherCount);
                Console.WriteLine("[+] EtwMonitor {0}", EtwMonitor.IsAvailable ? "active (zero-gap process events)" : "unavailable");
                Console.WriteLine("[+] AMSI scanner {0}", AmsiScanner.IsAvailable ? "active" : "unavailable");
                Console.ResetColor();
            }

            // Register scheduled jobs
            JobScheduler scheduler = new JobScheduler();
            int loaded = 0;

            RegisterJob(scheduler, "NetworkMonitor", new Action(NetworkMonitor.Execute), 30, ref loaded);
            RegisterJob(scheduler, "ResponseEngine", new Action(ResponseEngine.Execute), 10, ref loaded);
            RegisterJob(scheduler, "ProcessPoll", new Action(ProcessMonitor.Poll), 5, ref loaded);
            RegisterJob(scheduler, "FileMonitorCleanup", new Action(FileMonitor.CleanupCache), 300, ref loaded);

            RegisterJob(scheduler, "PersistenceRegistry", new Action(PersistenceDetection.RegistryPersistence), 120, ref loaded);
            RegisterJob(scheduler, "PersistenceScheduledTasks", new Action(PersistenceDetection.ScheduledTasks), 120, ref loaded);
            RegisterJob(scheduler, "PersistenceWMI", new Action(PersistenceDetection.WmiPersistence), 120, ref loaded);
            RegisterJob(scheduler, "PersistenceStartup", new Action(PersistenceDetection.StartupFolder), 120, ref loaded);
            RegisterJob(scheduler, "ProcessHollowing", new Action(ProcessDetection.ProcessHollowing), 30, ref loaded);
            RegisterJob(scheduler, "TokenManipulation", new Action(ProcessDetection.TokenManipulation), 60, ref loaded);
            RegisterJob(scheduler, "SuspiciousParentChild", new Action(ProcessDetection.SuspiciousParentChild), 45, ref loaded);
            RegisterJob(scheduler, "FilelessDetection", new Action(ProcessDetection.FilelessDetection), 20, ref loaded);
            RegisterJob(scheduler, "MemoryScanning", new Action(ProcessDetection.MemoryScanning), 90, ref loaded);
            RegisterJob(scheduler, "DllHijacking", new Action(DllDetection.DllHijacking), 90, ref loaded);
            RegisterJob(scheduler, "ElfCatcher", new Action(DllDetection.ElfCatcher), 30, ref loaded);
            RegisterJob(scheduler, "ReflectiveDll", new Action(DllDetection.ReflectiveDllInjection), 30, ref loaded);
            RegisterJob(scheduler, "KeystrokeInjection", new Action(DllDetection.KeystrokeInjection), 30, ref loaded);
            RegisterJob(scheduler, "RootkitDetection", new Action(SystemDetection.RootkitDetection), 180, ref loaded);
            RegisterJob(scheduler, "DriverWatcher", new Action(SystemDetection.DriverWatcher), 60, ref loaded);
            RegisterJob(scheduler, "BCDSecurity", new Action(SystemDetection.BCDSecurity), 300, ref loaded);
            RegisterJob(scheduler, "ServiceMonitoring", new Action(SystemDetection.ServiceMonitoring), 60, ref loaded);
            RegisterJob(scheduler, "EventLogMonitoring", new Action(SystemDetection.EventLogMonitoring), 60, ref loaded);
            RegisterJob(scheduler, "FirewallMonitoring", new Action(SystemDetection.FirewallRuleMonitoring), 120, ref loaded);
            RegisterJob(scheduler, "USBMonitoring", new Action(SystemDetection.USBMonitoring), 20, ref loaded);
            RegisterJob(scheduler, "ShadowCopyMonitoring", new Action(SystemDetection.ShadowCopyMonitoring), 30, ref loaded);
            RegisterJob(scheduler, "ClipboardMonitoring", new Action(SystemDetection.ClipboardMonitoring), 30, ref loaded);
            RegisterJob(scheduler, "DNSExfiltration", new Action(SystemDetection.DNSExfiltrationDetection), 30, ref loaded);
            RegisterJob(scheduler, "LocalProxy", new Action(SystemDetection.LocalProxyDetection), 60, ref loaded);
            RegisterJob(scheduler, "ScriptHost", new Action(SystemDetection.ScriptHostDetection), 60, ref loaded);
            RegisterJob(scheduler, "ScriptContentScan", new Action(SystemDetection.ScriptContentScan), 120, ref loaded);
            RegisterJob(scheduler, "CredentialProtection", new Action(SystemDetection.CredentialProtection), 300, ref loaded);
            RegisterJob(scheduler, "MemoryAcquisition", new Action(SystemDetection.MemoryAcquisitionDetection), 90, ref loaded);
            RegisterJob(scheduler, "Honeypot", new Action(SystemDetection.HoneypotMonitoring), 30, ref loaded);
            RegisterJob(scheduler, "ScriptBlockLogging", new Action(SystemDetection.ScriptBlockLoggingCheck), 86400, ref loaded);
            RegisterJob(scheduler, "CrudePayloadGuard", new Action(SystemDetection.CrudePayloadGuard), 60, ref loaded);
            RegisterJob(scheduler, "LateralMovement", new Action(SystemDetection.LateralMovementDetection), 30, ref loaded);
            RegisterJob(scheduler, "DataExfiltration", new Action(SystemDetection.DataExfiltrationDetection), 30, ref loaded);
            RegisterJob(scheduler, "QuarantineManagement", new Action(SystemDetection.QuarantineManagement), 300, ref loaded);

            RegisterJob(scheduler, "CVEMitigation", new Action(HardeningDetection.CVEMitigationPatcher), 3600, ref loaded);
            RegisterJob(scheduler, "ASRRules", new Action(HardeningDetection.ASRRulesEnforcement), 86400, ref loaded);
            RegisterJob(scheduler, "DNSSecureConfig", new Action(HardeningDetection.DNSSecureConfig), 86400, ref loaded);
            RegisterJob(scheduler, "C2BlockList", new Action(HardeningDetection.C2BlockList), 3600, ref loaded);
            RegisterJob(scheduler, "MitreMapping", new Action(HardeningDetection.MitreMapping), 300, ref loaded);
            RegisterJob(scheduler, "COMMonitoring", new Action(HardeningDetection.COMMonitoring), 120, ref loaded);
            RegisterJob(scheduler, "BrowserExtensions", new Action(HardeningDetection.BrowserExtensionMonitoring), 300, ref loaded);
            RegisterJob(scheduler, "ProcessAuditing", new Action(ProcessDetection.ProcessAuditing), 86400, ref loaded);
            RegisterJob(scheduler, "NamedPipeDetection", new Action(PipeDetection.ScanNamedPipes), 60, ref loaded);
            RegisterJob(scheduler, "PPIDSpoofing", new Action(ProcessDetection.ParentPidSpoofing), 45, ref loaded);
            RegisterJob(scheduler, "ShortLivedProcess", new Action(ProcessDetection.ShortLivedProcessDetection), 3, ref loaded);
            RegisterJob(scheduler, "ServiceTamper", new Action(ProcessDetection.ServiceTamperDetection), 10, ref loaded);
            RegisterJob(scheduler, "EtwIntegrity", new Action(EtwMonitor.IntegrityCheck), 300, ref loaded);
            RegisterJob(scheduler, "AccountProtocol", new Action(AccountTamperDetection.ProtocolHandlerAbuse), 15, ref loaded);
            RegisterJob(scheduler, "COMAutoApproval", new Action(AccountTamperDetection.COMAutoApprovalMonitor), 60, ref loaded);
            RegisterJob(scheduler, "SuspiciousGUID", new Action(AccountTamperDetection.SuspiciousGuidExecution), 10, ref loaded);
            RegisterJob(scheduler, "CredentialProviders", new Action(AccountTamperDetection.CredentialProviderMonitor), 300, ref loaded);

            Logger.Stability(string.Format("EDR monitor started: {0} jobs, {1} file watchers, service={2}",
                scheduler.JobCount, FileMonitor.WatcherCount, serviceMode));

            // Enter main loop
            scheduler.Run(token);

            // Cleanup
            SelfProtection.Shutdown();
            EtwMonitor.Shutdown();
            AmsiScanner.Shutdown();
            ProcessMonitor.Shutdown();
            FileMonitor.Shutdown();
            try { File.Delete(Config.PidFilePath); } catch { }

            Logger.Stability("EDR monitor stopped");
        }

        private static void RegisterJob(JobScheduler scheduler, string name, Action execute, int interval, ref int loaded)
        {
            try
            {
                scheduler.Register(name, execute, interval);
                loaded++;
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("Failed to register {0}: {1}", name, ex.Message), LogLevel.ERROR);
            }
        }
    }
}
