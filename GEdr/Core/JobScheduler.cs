using System;
using System.Collections.Generic;
using System.Threading;

namespace GEdr.Core
{
    public class ManagedJob
    {
        public string Name;
        public Action Execute;
        public int IntervalSeconds;
        public bool Enabled;
        public int MaxRestartAttempts;
        public int RestartDelaySeconds;

        // Runtime state
        public int RestartAttempts;
        public DateTime NextRunUtc;
        public DateTime LastBackoffUtc;
        public bool InBackoff;
        public Exception LastError;

        public ManagedJob()
        {
            Enabled = true;
            MaxRestartAttempts = 3;
            RestartDelaySeconds = 5;
            NextRunUtc = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Single-threaded cooperative job scheduler. Runs detection modules on configured
    /// intervals with failure recovery and exponential backoff.
    /// Ported from Antivirus.ps1 Register-ManagedJob / Invoke-ManagedJobsTick / Monitor-Jobs.
    /// </summary>
    public class JobScheduler
    {
        private readonly Dictionary<string, ManagedJob> _jobs
            = new Dictionary<string, ManagedJob>(StringComparer.OrdinalIgnoreCase);

        private int _consecutiveErrors;
        private const int MaxConsecutiveErrors = 10;

        public int JobCount { get { return _jobs.Count; } }

        public void Register(string name, Action execute, int intervalSeconds)
        {
            ManagedJob job = new ManagedJob();
            job.Name = name;
            job.Execute = execute;
            job.IntervalSeconds = Math.Max(1, intervalSeconds);
            _jobs[name] = job;
            Logger.Log(string.Format("Registered job: {0} ({1}s)", name, intervalSeconds));
        }

        public void Tick()
        {
            DateTime now = DateTime.UtcNow;
            foreach (KeyValuePair<string, ManagedJob> kvp in _jobs)
            {
                ManagedJob job = kvp.Value;
                if (!job.Enabled) continue;
                if (job.InBackoff && now < job.LastBackoffUtc.AddMinutes(5)) continue;
                if (job.InBackoff) job.InBackoff = false; // backoff expired
                if (now < job.NextRunUtc) continue;

                try
                {
                    job.Execute();
                    job.RestartAttempts = 0;
                    job.LastError = null;
                    job.NextRunUtc = DateTime.UtcNow.AddSeconds(job.IntervalSeconds);
                }
                catch (Exception ex)
                {
                    job.LastError = ex;
                    job.RestartAttempts++;
                    Logger.Log(string.Format("Job '{0}' failed ({1}/{2}): {3}",
                        job.Name, job.RestartAttempts, job.MaxRestartAttempts, ex.Message), LogLevel.WARN);

                    if (job.RestartAttempts >= job.MaxRestartAttempts)
                    {
                        job.RestartAttempts = 0;
                        job.InBackoff = true;
                        job.LastBackoffUtc = DateTime.UtcNow;
                        Logger.Log(string.Format("Job '{0}' backing off 5 minutes", job.Name), LogLevel.ERROR);
                    }
                    else
                    {
                        job.NextRunUtc = DateTime.UtcNow.AddSeconds(job.RestartDelaySeconds);
                    }
                }
            }
        }

        /// <summary>Main monitoring loop. Blocks until cancelled.</summary>
        public void Run(CancellationToken ct)
        {
            Logger.Stability("Entering main monitoring loop");
            int iteration = 0;
            DateTime lastStabilityCheck = DateTime.Now;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    iteration++;
                    Tick();
                    _consecutiveErrors = 0;

                    // Stability check every 5 minutes
                    if ((DateTime.Now - lastStabilityCheck).TotalMinutes >= 5)
                    {
                        int enabled = 0;
                        int backoff = 0;
                        foreach (ManagedJob j in _jobs.Values)
                        {
                            if (j.Enabled && !j.InBackoff) enabled++;
                            else if (j.Enabled && j.InBackoff) backoff++;
                        }
                        Logger.Stability(string.Format("Stability: {0} enabled, {1} backoff, iteration {2}", enabled, backoff, iteration));
                        lastStabilityCheck = DateTime.Now;
                    }

                    // Heartbeat every ~12 seconds
                    if (iteration % 12 == 0)
                    {
                        int enabled = 0;
                        int backoff = 0;
                        foreach (ManagedJob j in _jobs.Values)
                        {
                            if (j.Enabled && !j.InBackoff) enabled++;
                            else if (j.Enabled && j.InBackoff) backoff++;
                        }
                        try
                        {
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.WriteLine("[EDR] {0} enabled / {1} backoff | Threats:{2} Scanned:{3} YARA:{4}",
                                enabled, backoff, EdrState.ThreatCount, EdrState.FilesScanned, EdrState.YaraMatches);
                            Console.ResetColor();
                        }
                        catch { }
                    }

                    Thread.Sleep(1000);
                }
                catch (Exception ex)
                {
                    _consecutiveErrors++;
                    Logger.Stability(string.Format("Monitor error: {0}", ex.Message), LogLevel.WARN);

                    if (_consecutiveErrors >= MaxConsecutiveErrors)
                    {
                        Logger.Stability("Too many errors, triggering recovery", LogLevel.ERROR);
                        Recovery();
                        _consecutiveErrors = 0;
                    }
                    Thread.Sleep(5000);
                }
            }
            Logger.Stability("Monitoring loop exited");
        }

        private void Recovery()
        {
            Logger.Stability("Starting recovery sequence", LogLevel.WARN);
            foreach (ManagedJob j in _jobs.Values)
            {
                j.RestartAttempts = 0;
                j.InBackoff = false;
                j.NextRunUtc = DateTime.UtcNow.AddSeconds(10);
            }
            Thread.Sleep(10000);
            Logger.Stability("Recovery complete");
        }
    }
}
