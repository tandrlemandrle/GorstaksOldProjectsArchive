using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using GIDR.Core;

namespace GIDR.Response
{
    /// <summary>
    /// When a behavioral threat is detected, traces the entire attack chain
    /// back to the root process and forward to all children. Kills every
    /// process in the chain and quarantines every file they touched.
    ///
    /// Flow:
    ///   1. Bad behavior detected on PID X
    ///   2. Walk parent chain: X → parent → grandparent → ... → root
    ///   3. Find the "attack root" — the first non-system, non-protected ancestor
    ///   4. Walk forward from root: collect all children, grandchildren, etc.
    ///   5. Kill every process in the chain (bottom-up so children die first)
    ///   6. Quarantine every executable in the chain
    ///   7. Scan for persistence artifacts the chain may have created
    /// </summary>
    public static class ChainTracer
    {
        // Max depth to prevent infinite loops on circular parent references
        private const int MaxChainDepth = 30;

        // Lock for thread-safe process killing to prevent race conditions
        private static readonly object _killLock = new object();

        /// <summary>
        /// Processes that should never be treated as the attack root even if they are
        /// not in Config.ProtectedProcesses. These are high-value user applications that
        /// are frequently abused as launch pads (e.g. a browser download executing malware)
        /// but killing the entire browser process tree is never the right response.
        ///
        /// When one of these is the highest non-protected ancestor, FindAttackRoot skips
        /// it and uses the next descendant as the root instead — so only the malicious
        /// child subtree is killed, not the browser/office app itself.
        /// </summary>
        private static readonly HashSet<string> _neverAttackRoot = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Browsers
            "chrome", "firefox", "msedge", "iexplore", "opera", "brave", "vivaldi",
            "chromium", "waterfox", "palemoon",
            // Office / productivity
            "winword", "excel", "powerpnt", "outlook", "onenote", "access", "publisher",
            "visio", "project", "teams", "slack", "discord", "zoom", "skype",
            // Terminals / shells that are legitimate parents
            "windowsterminal", "wt",
            // Explorer (already in ProtectedProcesses but belt-and-suspenders)
            "explorer",
        };

        /// <summary>
        /// Trace the attack chain from a detected threat, kill all processes,
        /// quarantine all executables, and clean up persistence.
        /// Returns a summary of everything that was done.
        /// </summary>
        public static ChainResponse TraceAndNuke(ThreatInfo trigger)
        {
            ChainResponse response = new ChainResponse();
            response.TriggeredBy = trigger;
            response.Timestamp = DateTime.Now;

            int triggerPid = trigger.ProcessId;
            if (triggerPid <= 0)
            {
                Logger.Log("ChainTracer: no PID to trace", LogLevel.WARN);
                return response;
            }

            // ── Step 1: Build the ancestor chain (walk up to root) ──
            List<ChainNode> ancestors = WalkAncestors(triggerPid);
            response.AncestorChain = ancestors;

            // ── Step 2: Find the attack root ──
            // The attack root is the highest ancestor that is NOT a system/protected process.
            // e.g., if chain is: explorer → cmd → powershell → mimikatz
            //   explorer is protected, so attack root = cmd
            ChainNode attackRoot = FindAttackRoot(ancestors);
            if (attackRoot == null)
            {
                // Couldn't find a non-protected root — just target the trigger process
                attackRoot = FindNodeByPid(ancestors, triggerPid);
            }
            response.AttackRoot = attackRoot;

            Logger.Log(string.Format("ChainTracer: attack root = {0} (PID:{1}), trigger = PID:{2}",
                attackRoot != null ? attackRoot.Name : "?",
                attackRoot != null ? attackRoot.PID : 0,
                triggerPid), LogLevel.THREAT, "chain_tracer.log");

            // ── Step 3: Collect all descendants of the attack root ──
            List<ChainNode> descendants = new List<ChainNode>();
            if (attackRoot != null)
            {
                CollectDescendants(attackRoot.PID, descendants, 0);
            }
            response.Descendants = descendants;

            // ── Step 4: Build the full kill list (root + all descendants) ──
            // Deduplicate and exclude protected processes
            Dictionary<int, ChainNode> killList = new Dictionary<int, ChainNode>();
            if (attackRoot != null && !Config.IsProtectedProcess(attackRoot.Name))
            {
                killList[attackRoot.PID] = attackRoot;
            }
            for (int i = 0; i < descendants.Count; i++)
            {
                ChainNode d = descendants[i];
                if (!Config.IsProtectedProcess(d.Name) && d.PID != Process.GetCurrentProcess().Id)
                {
                    killList[d.PID] = d;
                }
            }

            // ── Step 5: Kill processes (children first, then parents) ──
            // Sort by depth descending so we kill leaves before parents
            List<ChainNode> sortedKills = new List<ChainNode>(killList.Values);
            sortedKills.Sort((a, b) => b.Depth.CompareTo(a.Depth));

            // Use a kill lock to prevent race conditions during rapid process operations
            lock (_killLock)
            {
                for (int i = 0; i < sortedKills.Count; i++)
                {
                    ChainNode node = sortedKills[i];
                    try
                    {
                        // Verify process still exists and matches expected name before killing
                        // This prevents killing a new process that reused the PID
                        Process proc = Process.GetProcessById(node.PID);
                        if (proc != null && !proc.HasExited)
                        {
                            // Verify process name matches to avoid killing wrong process
                            string actualName = proc.ProcessName;
                            if (!string.Equals(actualName, node.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                Logger.Log(string.Format("ChainTracer: PID {0} name mismatch (expected {1}, got {2}) - skipping kill",
                                    node.PID, node.Name, actualName), LogLevel.WARN, "chain_tracer.log");
                                continue;
                            }

                            proc.Kill();
                            response.ProcessesKilled.Add(string.Format("{0} (PID:{1})", node.Name, node.PID));
                            Logger.Log(string.Format("ChainTracer: KILLED {0} (PID:{1}, depth:{2})",
                                node.Name, node.PID, node.Depth), LogLevel.ACTION, "chain_tracer.log");
                        }
                    }
                    catch (ArgumentException)
                    {
                        // Process already exited - expected, no action needed
                    }
                    catch (InvalidOperationException)
                    {
                        // Process has exited between check and kill - expected, no action needed
                    }
                    catch (Exception ex)
                    {
                        Logger.Log(string.Format("ChainTracer: failed to kill {0} (PID:{1}): {2}",
                            node.Name, node.PID, ex.Message), LogLevel.WARN, "chain_tracer.log");
                    }
                }
            }

            // ── Step 6: Quarantine all executables from the chain ──
            HashSet<string> quarantined = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<ChainNode> allNodes = new List<ChainNode>();
            allNodes.AddRange(killList.Values);

            for (int i = 0; i < allNodes.Count; i++)
            {
                string exePath = allNodes[i].ExePath;
                if (string.IsNullOrEmpty(exePath)) continue;
                if (quarantined.Contains(exePath)) continue;
                if (!File.Exists(exePath)) continue;
                if (Config.IsExcludedPath(exePath)) continue;

                // Don't quarantine system binaries (cmd.exe, powershell.exe, etc.)
                // They're legitimate tools that were abused — quarantining them breaks the OS
                if (IsSystemBinary(exePath)) continue;

                bool ok = ThreatActions.Quarantine(exePath,
                    string.Format("ChainTracer: part of attack chain rooted at {0} (PID:{1})",
                        attackRoot != null ? attackRoot.Name : "?",
                        attackRoot != null ? attackRoot.PID : 0));
                if (ok)
                {
                    quarantined.Add(exePath);
                    response.FilesQuarantined.Add(exePath);
                }
            }

            // ── Step 7: Hunt for persistence the attacker may have created ──
            HuntPersistence(killList, response);

            // ── Step 8: Block any suspicious network connections from the chain ──
            HuntNetworkConnections(killList, response);

            // ── Log the full chain summary ──
            LogChainSummary(response);

            return response;
        }

        /// <summary>Walk the parent chain from a PID up to the root.</summary>
        private static List<ChainNode> WalkAncestors(int startPid)
        {
            List<ChainNode> chain = new List<ChainNode>();
            HashSet<int> visited = new HashSet<int>();
            int currentPid = startPid;
            int depth = 0;

            while (currentPid > 4 && depth < MaxChainDepth && !visited.Contains(currentPid))
            {
                visited.Add(currentPid);
                ChainNode node = GetProcessInfo(currentPid);
                if (node == null) break;
                node.Depth = depth;
                chain.Add(node);
                currentPid = node.ParentPID;
                depth++;
            }

            // Reverse so chain[0] is the oldest ancestor
            chain.Reverse();
            // Re-assign depth so root = 0
            for (int i = 0; i < chain.Count; i++)
                chain[i].Depth = i;

            return chain;
        }

        /// <summary>Find the highest non-protected ancestor (the attack root).</summary>
        private static ChainNode FindAttackRoot(List<ChainNode> ancestors)
        {
            // Walk from the top (oldest ancestor) down.
            // Skip protected processes AND processes in _neverAttackRoot (browsers, office apps).
            // The first process that passes both checks is the attack root.
            //
            // Example: explorer(protected) → chrome(neverRoot) → cmd → powershell → malware
            //   Result: cmd is the attack root — only cmd+children are killed, chrome survives.
            //
            // Example: explorer(protected) → cmd → powershell → malware
            //   Result: cmd is the attack root — correct.
            for (int i = 0; i < ancestors.Count; i++)
            {
                ChainNode node = ancestors[i];
                string nameNoExt = node.Name.Replace(".exe", "");

                if (Config.IsProtectedProcess(node.Name)) continue;
                if (IsSystemBinary(node.ExePath)) continue;
                if (_neverAttackRoot.Contains(nameNoExt)) continue;

                return node;
            }

            // All ancestors are protected/neverRoot — fall back to the trigger process itself.
            // This means we only kill the detected process, not a broader tree.
            return ancestors.Count > 0 ? ancestors[ancestors.Count - 1] : null;
        }

        /// <summary>Recursively collect all child processes of a given PID.</summary>
        private static void CollectDescendants(int parentPid, List<ChainNode> result, int depth)
        {
            if (depth > MaxChainDepth) return;

            try
            {
                // Use WMI to find children
                string query = string.Format("SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process WHERE ParentProcessId = {0}", parentPid);
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        int childPid = Convert.ToInt32(obj["ProcessId"]);
                        if (childPid == Process.GetCurrentProcess().Id) continue;
                        if (childPid <= 4) continue;

                        ChainNode child = new ChainNode();
                        child.PID = childPid;
                        child.Name = (obj["Name"] ?? "").ToString();
                        child.ExePath = (obj["ExecutablePath"] ?? "").ToString();
                        child.CommandLine = (obj["CommandLine"] ?? "").ToString();
                        child.ParentPID = parentPid;
                        child.Depth = depth;
                        result.Add(child);

                        // Recurse into children
                        CollectDescendants(childPid, result, depth + 1);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("CollectDescendants WMI error: " + ex.Message, LogLevel.WARN);
            }
        }

        /// <summary>Get process info for a single PID via WMI.</summary>
        private static ChainNode GetProcessInfo(int pid)
        {
            try
            {
                string query = string.Format("SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", pid);
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        ChainNode node = new ChainNode();
                        node.PID = pid;
                        node.Name = (obj["Name"] ?? "").ToString();
                        node.ExePath = (obj["ExecutablePath"] ?? "").ToString();
                        node.CommandLine = (obj["CommandLine"] ?? "").ToString();
                        node.ParentPID = Convert.ToInt32(obj["ParentProcessId"] ?? 0);
                        return node;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("GetProcessInfo WMI error for PID " + pid + ": " + ex.Message, LogLevel.WARN);
            }
            return null;
        }

        private static ChainNode FindNodeByPid(List<ChainNode> nodes, int pid)
        {
            for (int i = 0; i < nodes.Count; i++)
            {
                if (nodes[i].PID == pid) return nodes[i];
            }
            return null;
        }

        /// <summary>Check if a path is a Windows system binary that shouldn't be quarantined.</summary>
        private static bool IsSystemBinary(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string lower = path.ToLowerInvariant();
            return lower.StartsWith(@"c:\windows\") ||
                   lower.StartsWith(@"c:\program files\windowsapps\") ||
                   lower.StartsWith(@"c:\programdata\microsoft\");
        }

        /// <summary>
        /// Hunt for persistence mechanisms the attack chain may have created.
        /// Checks Run keys, scheduled tasks, and startup folder for entries
        /// pointing to executables from the killed chain.
        /// </summary>
        private static void HuntPersistence(Dictionary<int, ChainNode> killList, ChainResponse response)
        {
            // Collect all executable paths from the chain
            HashSet<string> chainPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ChainNode node in killList.Values)
            {
                if (!string.IsNullOrEmpty(node.ExePath) && !IsSystemBinary(node.ExePath))
                    chainPaths.Add(node.ExePath);
            }
            if (chainPaths.Count == 0) return;

            // Check HKCU\...\Run and HKLM\...\Run
            string[] runKeys = new string[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            };

            foreach (string keyPath in runKeys)
            {
                try
                {
                    // HKCU
                    using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, true))
                    {
                        if (key != null) CleanRunKey(key, keyPath, "HKCU", chainPaths, response);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("HuntPersistence HKCU registry error for " + keyPath + ": " + ex.Message, LogLevel.WARN);
                }

                try
                {
                    // HKLM
                    using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, true))
                    {
                        if (key != null) CleanRunKey(key, keyPath, "HKLM", chainPaths, response);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("HuntPersistence HKLM registry error for " + keyPath + ": " + ex.Message, LogLevel.WARN);
                }
            }

            // Check scheduled tasks
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", "/query /fo CSV /nh /v");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);

                if (!string.IsNullOrEmpty(output))
                {
                    string[] lines = output.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 0; i < lines.Length; i++)
                    {
                        string line = lines[i];
                        foreach (string chainPath in chainPaths)
                        {
                            if (line.IndexOf(chainPath, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                // Extract task name (first CSV field)
                                string taskName = ExtractCsvField(line, 0);
                                if (!string.IsNullOrEmpty(taskName))
                                {
                                    try
                                    {
                                        Process del = Process.Start(new ProcessStartInfo("schtasks.exe",
                                            string.Format("/delete /tn \"{0}\" /f", taskName))
                                        { CreateNoWindow = true, UseShellExecute = false });
                                        del.WaitForExit(5000);
                                        response.PersistenceRemoved.Add(string.Format("ScheduledTask: {0}", taskName));
                                        Logger.Log(string.Format("ChainTracer: removed scheduled task: {0}", taskName),
                                            LogLevel.ACTION, "chain_tracer.log");
                                    }
                                    catch (Exception ex)
                                    {
                                        Logger.Log("Failed to delete scheduled task " + taskName + ": " + ex.Message, LogLevel.WARN);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Scheduled task enumeration error: " + ex.Message, LogLevel.WARN);
            }

            // Check startup folder
            try
            {
                string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(startupFolder))
                {
                    string[] files = Directory.GetFiles(startupFolder);
                    for (int i = 0; i < files.Length; i++)
                    {
                        // Read .lnk target or check if the file itself is from the chain
                        string fileName = files[i];
                        foreach (string chainPath in chainPaths)
                        {
                            string chainFileName = Path.GetFileNameWithoutExtension(chainPath);
                            if (Path.GetFileName(fileName).IndexOf(chainFileName, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                try
                                {
                                    File.Delete(fileName);
                                    response.PersistenceRemoved.Add(string.Format("StartupFile: {0}", fileName));
                                    Logger.Log(string.Format("ChainTracer: removed startup file: {0}", fileName),
                                        LogLevel.ACTION, "chain_tracer.log");
                                }
                                catch (Exception ex)
                                {
                                    Logger.Log("Failed to delete startup file " + fileName + ": " + ex.Message, LogLevel.WARN);
                                }
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Startup folder enumeration error: " + ex.Message, LogLevel.WARN);
            }
        }

        /// <summary>Check a Run registry key for entries pointing to chain executables.</summary>
        private static void CleanRunKey(Microsoft.Win32.RegistryKey key, string keyPath, string hive,
            HashSet<string> chainPaths, ChainResponse response)
        {
            string[] valueNames = key.GetValueNames();
            for (int i = 0; i < valueNames.Length; i++)
            {
                string val = (key.GetValue(valueNames[i]) ?? "").ToString();
                foreach (string chainPath in chainPaths)
                {
                    if (val.IndexOf(chainPath, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        val.IndexOf(Path.GetFileName(chainPath), StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        try
                        {
                            key.DeleteValue(valueNames[i], false);
                            string entry = string.Format("{0}\\{1}\\{2}", hive, keyPath, valueNames[i]);
                            response.PersistenceRemoved.Add(entry);
                            Logger.Log(string.Format("ChainTracer: removed persistence: {0}", entry),
                                LogLevel.ACTION, "chain_tracer.log");
                        }
                        catch (Exception ex)
                        {
                            Logger.Log("Failed to remove registry value " + valueNames[i] + ": " + ex.Message, LogLevel.WARN);
                        }
                        break;
                    }
                }
            }
        }

        /// <summary>Find and block network connections from the attack chain.</summary>
        private static void HuntNetworkConnections(Dictionary<int, ChainNode> killList, ChainResponse response)
        {
            try
            {
                // Get all TCP connections and find ones owned by chain processes
                ProcessStartInfo psi = new ProcessStartInfo("netstat.exe", "-ano -p TCP");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);

                if (string.IsNullOrEmpty(output)) return;

                HashSet<string> blockedIPs = new HashSet<string>();
                string[] lines = output.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    // Parse: TCP  local_addr  remote_addr  state  PID
                    string[] parts = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5 || parts[0] != "TCP") continue;

                    int ownerPid;
                    if (!int.TryParse(parts[parts.Length - 1], out ownerPid)) continue;
                    if (!killList.ContainsKey(ownerPid)) continue;

                    // Extract remote IP
                    string remoteAddr = parts[2];
                    int colonIdx = remoteAddr.LastIndexOf(':');
                    if (colonIdx <= 0) continue;
                    string ip = remoteAddr.Substring(0, colonIdx);

                    // Skip local/loopback
                    if (ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" || ip == "::1") continue;
                    if (ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("172.")) continue;

                    if (blockedIPs.Contains(ip)) continue;
                    blockedIPs.Add(ip);

                    ThreatActions.BlockIP(ip);
                    response.IPsBlocked.Add(ip);
                    Logger.Log(string.Format("ChainTracer: blocked attacker IP: {0} (from {1} PID:{2})",
                        ip, killList[ownerPid].Name, ownerPid), LogLevel.ACTION, "chain_tracer.log");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("HuntNetworkConnections error: " + ex.Message, LogLevel.WARN);
            }
        }

        private static void LogChainSummary(ChainResponse response)
        {
            Logger.Log("═══════════════════════════════════════════════", LogLevel.THREAT, "chain_tracer.log");
            Logger.Log(string.Format("CHAIN TRACE COMPLETE at {0}", response.Timestamp), LogLevel.THREAT, "chain_tracer.log");
            Logger.Log(string.Format("  Trigger: {0} (PID:{1})",
                response.TriggeredBy.ThreatType, response.TriggeredBy.ProcessId), LogLevel.THREAT, "chain_tracer.log");
            Logger.Log(string.Format("  Attack root: {0} (PID:{1})",
                response.AttackRoot != null ? response.AttackRoot.Name : "?",
                response.AttackRoot != null ? response.AttackRoot.PID : 0), LogLevel.THREAT, "chain_tracer.log");

            if (response.AncestorChain.Count > 0)
            {
                string chainStr = "";
                for (int i = 0; i < response.AncestorChain.Count; i++)
                {
                    if (i > 0) chainStr += " -> ";
                    chainStr += response.AncestorChain[i].Name;
                }
                Logger.Log(string.Format("  Chain: {0}", chainStr), LogLevel.THREAT, "chain_tracer.log");
            }

            Logger.Log(string.Format("  Processes killed: {0}", response.ProcessesKilled.Count), LogLevel.THREAT, "chain_tracer.log");
            for (int i = 0; i < response.ProcessesKilled.Count; i++)
                Logger.Log(string.Format("    - {0}", response.ProcessesKilled[i]), LogLevel.ACTION, "chain_tracer.log");

            Logger.Log(string.Format("  Files quarantined: {0}", response.FilesQuarantined.Count), LogLevel.THREAT, "chain_tracer.log");
            for (int i = 0; i < response.FilesQuarantined.Count; i++)
                Logger.Log(string.Format("    - {0}", response.FilesQuarantined[i]), LogLevel.ACTION, "chain_tracer.log");

            Logger.Log(string.Format("  Persistence removed: {0}", response.PersistenceRemoved.Count), LogLevel.THREAT, "chain_tracer.log");
            for (int i = 0; i < response.PersistenceRemoved.Count; i++)
                Logger.Log(string.Format("    - {0}", response.PersistenceRemoved[i]), LogLevel.ACTION, "chain_tracer.log");

            Logger.Log(string.Format("  IPs blocked: {0}", response.IPsBlocked.Count), LogLevel.THREAT, "chain_tracer.log");
            for (int i = 0; i < response.IPsBlocked.Count; i++)
                Logger.Log(string.Format("    - {0}", response.IPsBlocked[i]), LogLevel.ACTION, "chain_tracer.log");

            Logger.Log("═══════════════════════════════════════════════", LogLevel.THREAT, "chain_tracer.log");

            // Also write a JSON summary
            JsonLogger.LogEvent("RESPONSE", "chain-trace", string.Format(
                "root={0} killed={1} quarantined={2} persistence={3} ips={4}",
                response.AttackRoot != null ? response.AttackRoot.Name : "?",
                response.ProcessesKilled.Count,
                response.FilesQuarantined.Count,
                response.PersistenceRemoved.Count,
                response.IPsBlocked.Count));
        }

        private static string ExtractCsvField(string line, int index)
        {
            // Simple CSV field extraction (handles quoted fields)
            int fieldIdx = 0;
            int pos = 0;
            bool inQuotes = false;
            int fieldStart = 0;

            while (pos <= line.Length)
            {
                if (pos == line.Length || (!inQuotes && line[pos] == ','))
                {
                    if (fieldIdx == index)
                    {
                        string field = line.Substring(fieldStart, pos - fieldStart).Trim().Trim('"');
                        return field;
                    }
                    fieldIdx++;
                    fieldStart = pos + 1;
                }
                else if (line[pos] == '"')
                {
                    inQuotes = !inQuotes;
                }
                pos++;
            }
            return null;
        }
    }

    /// <summary>A node in the process chain.</summary>
    public class ChainNode
    {
        public int PID;
        public string Name;
        public string ExePath;
        public string CommandLine;
        public int ParentPID;
        public int Depth;
    }

    /// <summary>Summary of a chain trace response.</summary>
    public class ChainResponse
    {
        public ThreatInfo TriggeredBy;
        public DateTime Timestamp;
        public List<ChainNode> AncestorChain = new List<ChainNode>();
        public ChainNode AttackRoot;
        public List<ChainNode> Descendants = new List<ChainNode>();
        public List<string> ProcessesKilled = new List<string>();
        public List<string> FilesQuarantined = new List<string>();
        public List<string> PersistenceRemoved = new List<string>();
        public List<string> IPsBlocked = new List<string>();
    }
}
