using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using GIDR.Detection;
using GIDR.Monitors;
using GIDR.Response;

namespace GIDR.Core
{
    /// <summary>
    /// Shared monitor logic used by both console mode and Windows service mode.
    /// </summary>
    public static class GIDRMonitor
    {
        public static void Run(CancellationToken token, bool serviceMode = false)
        {
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
            EtwMonitor.Initialize();
            FileMonitor.Initialize();

            if (!serviceMode)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] ProcessMonitor active");
                Console.WriteLine("[+] EtwMonitor {0}", EtwMonitor.IsAvailable ? "active (zero-gap process events)" : "unavailable");
                Console.WriteLine("[+] FileMonitor active ({0} drive watchers)", FileMonitor.WatcherCount);
                Console.ResetColor();
            }

            // Register scheduled jobs
            JobScheduler scheduler = new JobScheduler();
            int loaded = 0;

            RegisterJob(scheduler, "ResponseEngine", new Action(ResponseEngine.Execute), 10, ref loaded);
            RegisterJob(scheduler, "ProcessPoll", new Action(ProcessMonitor.Poll), 5, ref loaded);

            // Core intrusion detection - hackers trying to:
            RegisterJob(scheduler, "C2Network", new Action(NetworkMonitor.Execute), 30, ref loaded);           // C2, reverse shells
            RegisterJob(scheduler, "MemoryExecution", new Action(MemoryExecutionDetection.Detect), 20, ref loaded); // Fileless, reflective DLL, hollowing, download cradles
            RegisterJob(scheduler, "AudioHijack", new Action(AudioHijackDetection.Detect), 15, ref loaded);        // Mic access
            RegisterJob(scheduler, "CredentialDump", new Action(CredentialDumpDetection.Detect), 15, ref loaded); // LSASS/SAM dumping
            RegisterJob(scheduler, "Ransomware", new Action(RansomwareDetection.Detect), 10, ref loaded);          // Mass file encryption (ignores BitLocker/known apps)

            // Module validation - heavy operation, runs on dedicated thread
            RegisterJob(scheduler, "ModuleValidation", new Action(ModuleValidationDetection.ValidateModules), 60, ref loaded, useDedicatedThread: true);

            // IDR: YARA scanning (quarantine check)
            RegisterJob(scheduler, "YaraQuarantine", new Action(YaraScanner.ScanQuarantine), 300, ref loaded);

            // IDR: IoC maintenance (reload threat intel)
            RegisterJob(scheduler, "IoCMaintenance", new Action(IoCScanner.Maintenance), 300, ref loaded);

            // Housekeeping
            RegisterJob(scheduler, "FileMonitorCleanup", new Action(FileMonitor.CleanupCache), 300, ref loaded);
            RegisterJob(scheduler, "EtwIntegrityCheck", new Action(EtwMonitor.IntegrityCheck), 120, ref loaded);

            Logger.Stability(string.Format("EDR monitor started: {0} jobs, service={1}",
                scheduler.JobCount, serviceMode));

            // Enter main loop
            scheduler.Run(token);

            // Cleanup
            SelfProtection.Shutdown();
            EtwMonitor.Shutdown();
            FileMonitor.Shutdown();
            ProcessMonitor.Shutdown();
            try { File.Delete(Config.PidFilePath); } catch { }

            Logger.Stability("EDR monitor stopped");
        }

        private static void RegisterJob(JobScheduler scheduler, string name, Action execute, int interval, ref int loaded, bool useDedicatedThread = false)
        {
            try
            {
                scheduler.Register(name, execute, interval, useDedicatedThread);
                loaded++;
            }
            catch (Exception ex)
            {
                Logger.Log(string.Format("Failed to register {0}: {1}", name, ex.Message), LogLevel.ERROR);
            }
        }
    }
}
