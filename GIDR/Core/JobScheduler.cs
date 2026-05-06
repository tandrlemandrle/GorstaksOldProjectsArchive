using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace GIDR.Core
{
    public class ManagedJob
    {
        public string Name;
        public Action Execute;
        public int IntervalSeconds;
        public bool Enabled;
        public int MaxRestartAttempts;
        public int RestartDelaySeconds;
        public bool UseDedicatedThread; // For long-running/heavy jobs

        // Runtime state
        public int RestartAttempts;
        public DateTime NextRunUtc;
        public DateTime LastBackoffUtc;
        public bool InBackoff;
        public Exception LastError;
        public bool IsRunning;
        public Task CurrentTask;
        public readonly object StateLock = new object();

        public ManagedJob()
        {
            Enabled = true;
            MaxRestartAttempts = 3;
            RestartDelaySeconds = 5;
            NextRunUtc = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Concurrent job scheduler with parallel execution. Runs detection modules on configured
    /// intervals with failure recovery, exponential backoff, and dedicated threads for heavy jobs.
    /// Prevents slow jobs from blocking others.
    /// </summary>
    public class JobScheduler
    {
        private readonly ConcurrentDictionary<string, ManagedJob> _jobs
            = new ConcurrentDictionary<string, ManagedJob>(StringComparer.OrdinalIgnoreCase);

        private int _consecutiveErrors;
        private const int MaxConsecutiveErrors = 10;
        private readonly SemaphoreSlim _maxParallelism;

        public JobScheduler(int maxParallelJobs = 4)
        {
            _maxParallelism = new SemaphoreSlim(maxParallelJobs, maxParallelJobs);
        }

        public int JobCount { get { return _jobs.Count; } }

        public void Register(string name, Action execute, int intervalSeconds, bool useDedicatedThread = false)
        {
            ManagedJob job = new ManagedJob();
            job.Name = name;
            job.Execute = execute;
            job.IntervalSeconds = Math.Max(1, intervalSeconds);
            job.UseDedicatedThread = useDedicatedThread;
            _jobs[name] = job;
            Logger.Log(string.Format("Registered job: {0} ({1}s, dedicated={2})", name, intervalSeconds, useDedicatedThread));
        }

        /// <summary>Tick all jobs that are due - executes concurrently</summary>
        public void Tick()
        {
            DateTime now = DateTime.UtcNow;
            List<Task> pendingTasks = new List<Task>();

            foreach (ManagedJob job in _jobs.Values)
            {
                bool shouldRun = false;
                lock (job.StateLock)
                {
                    if (!job.Enabled) continue;
                    if (job.InBackoff && now < job.LastBackoffUtc.AddMinutes(5)) continue;
                    if (job.InBackoff) job.InBackoff = false; // backoff expired
                    if (now < job.NextRunUtc) continue;
                    if (job.IsRunning) continue; // Skip if still running from previous cycle

                    shouldRun = true;
                    job.IsRunning = true;
                }

                if (shouldRun)
                {
                    if (job.UseDedicatedThread)
                    {
                        // Run on dedicated thread for long-running jobs
                        Thread thread = new Thread(() => ExecuteJob(job));
                        thread.IsBackground = true;
                        thread.Name = "GIDR-Job-" + job.Name;
                        thread.Start();
                    }
                    else
                    {
                        // Run on thread pool with parallelism limit
                        Task task = Task.Run(async () =>
                        {
                            await _maxParallelism.WaitAsync();
                            try
                            {
                                ExecuteJob(job);
                            }
                            finally
                            {
                                _maxParallelism.Release();
                            }
                        });
                        pendingTasks.Add(task);
                    }
                }
            }

            // Don't block - let tasks run concurrently
            // We only wait if we need to throttle
        }

        private void ExecuteJob(ManagedJob job)
        {
            try
            {
                job.Execute();
                lock (job.StateLock)
                {
                    job.RestartAttempts = 0;
                    job.LastError = null;
                    job.NextRunUtc = DateTime.UtcNow.AddSeconds(job.IntervalSeconds);
                    job.IsRunning = false;
                }
            }
            catch (Exception ex)
            {
                lock (job.StateLock)
                {
                    job.LastError = ex;
                    job.RestartAttempts++;
                    job.IsRunning = false;

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
            Logger.Stability("Entering main monitoring loop (concurrent execution)");
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
                        int enabled = 0, running = 0, backoff = 0;
                        foreach (ManagedJob j in _jobs.Values)
                        {
                            lock (j.StateLock)
                            {
                                if (j.Enabled && !j.InBackoff && !j.IsRunning) enabled++;
                                else if (j.IsRunning) running++;
                                else if (j.Enabled && j.InBackoff) backoff++;
                            }
                        }
                        Logger.Stability(string.Format("Stability: {0} ready, {1} running, {2} backoff, iteration {3}",
                            enabled, running, backoff, iteration));
                        lastStabilityCheck = DateTime.Now;
                    }

                    // Heartbeat every ~12 seconds
                    if (iteration % 12 == 0)
                    {
                        int enabled = 0, running = 0, backoff = 0;
                        foreach (ManagedJob j in _jobs.Values)
                        {
                            lock (j.StateLock)
                            {
                                if (j.Enabled && !j.InBackoff && !j.IsRunning) enabled++;
                                else if (j.IsRunning) running++;
                                else if (j.Enabled && j.InBackoff) backoff++;
                            }
                        }
                        try
                        {
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.WriteLine("[EDR] {0} ready / {1} run / {2} back | Threats:{3} Scanned:{4} YARA:{5}",
                                enabled, running, backoff, GidrState.ThreatCount, GidrState.FilesScanned, GidrState.YaraMatches);
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
                lock (j.StateLock)
                {
                    j.RestartAttempts = 0;
                    j.InBackoff = false;
                    j.IsRunning = false;
                    j.NextRunUtc = DateTime.UtcNow.AddSeconds(10);
                }
            }
            Thread.Sleep(10000);
            Logger.Stability("Recovery complete");
        }
    }
}
