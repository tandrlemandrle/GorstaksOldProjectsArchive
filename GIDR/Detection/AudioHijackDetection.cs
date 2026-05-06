using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using GIDR.Core;
using GIDR.Response;

namespace GIDR.Detection
{
    /// <summary>
    /// Detects audio output to normal mic or webcam mic.
    /// </summary>
    public static class AudioHijackDetection
    {
        private static readonly HashSet<string> _processedSessions = new HashSet<string>();
        private static DateTime _lastCheck = DateTime.MinValue;

        // Windows audio APIs
        [DllImport("winmm.dll", SetLastError = true)]
        private static extern int waveOutGetNumDevs();

        [DllImport("winmm.dll", SetLastError = true)]
        private static extern int waveInGetNumDevs();

        /// <summary>
        /// Main entry: detect audio output to normal mic or webcam mic.
        /// Called periodically by the monitor scheduler.
        /// </summary>
        public static void Detect()
        {
            // Rate limit checks to every 10 seconds
            if ((DateTime.Now - _lastCheck).TotalSeconds < 10) return;
            _lastCheck = DateTime.Now;

            AudioOutputToMic();
        }

        /// <summary>
        /// Detect audio output redirected to normal mic or webcam mic.
        /// </summary>
        private static void AudioOutputToMic()
        {
            int selfPid = Process.GetCurrentProcess().Id;
            Process[] procs = Process.GetProcesses();

            for (int i = 0; i < procs.Length; i++)
            {
                if (procs[i].Id == selfPid || procs[i].Id <= 4) continue;

                try
                {
                    bool hasAudioOutput = false;
                    bool hasMicInput = false;

                    ProcessModuleCollection modules = procs[i].Modules;
                    for (int m = 0; m < modules.Count; m++)
                    {
                        string modName = Path.GetFileName(modules[m].FileName).ToLowerInvariant();

                        // Audio output indicators
                        if (modName.Contains("audioses.dll") || modName.Contains("audioeng.dll") ||
                            modName.Contains("mmdevapi.dll") || modName.Contains("audioclient.dll"))
                        {
                            hasAudioOutput = true;
                        }

                        // Microphone input indicators
                        if (modName.Contains("portaudio") || modName.Contains("naudio") ||
                            modName.Contains("directsound") || modName.Contains("winmm.dll") ||
                            modName.Contains("mfreadwrite.dll") || modName.Contains("mf.dll"))
                        {
                            hasMicInput = true;
                        }
                    }

                    // Get command line for analysis
                    string cmdLine = "";
                    try
                    {
                        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                            string.Format("SELECT CommandLine FROM Win32_Process WHERE ProcessId = {0}", procs[i].Id)))
                        using (ManagementObjectCollection results = searcher.Get())
                        {
                            foreach (ManagementObject obj in results)
                            {
                                cmdLine = obj["CommandLine"] != null ? obj["CommandLine"].ToString() : "";
                                break;
                            }
                        }
                    }
                    catch { }

                    string cmdLower = cmdLine.ToLowerInvariant();

                    // Detect: audio output to mic or webcam mic
                    bool outputToMic = cmdLower.Contains("-output=mic") || cmdLower.Contains("-output mic") ||
                                       cmdLower.Contains("--output-mic") || cmdLower.Contains("-out=mic") ||
                                       cmdLower.Contains("playback=mic") || cmdLower.Contains("playback mic") ||
                                       cmdLower.Contains("-to=mic") || cmdLower.Contains("-to mic") ||
                                       cmdLower.Contains("-redirect=mic") || cmdLower.Contains("-redirect mic") ||
                                       cmdLower.Contains("-sink=mic") || cmdLower.Contains("-sink mic") ||
                                       cmdLower.Contains("audioout=mic") || cmdLower.Contains("audioout mic") ||
                                       cmdLower.Contains("virtualmic") || cmdLower.Contains("mic=loopback") ||
                                       cmdLower.Contains("stereomix") || cmdLower.Contains("whatuh") ||
                                       cmdLower.Contains("cable output") || cmdLower.Contains("vb-audio") ||
                                       cmdLower.Contains("voiceoutput") || cmdLower.Contains("outputdevice=mic") ||
                                       cmdLower.Contains("render=mic") || cmdLower.Contains("endpoint=mic");

                    // Has both audio output and mic input components
                    if (hasAudioOutput && hasMicInput && outputToMic)
                    {
                        string sessionKey = string.Format("AudioOutputToMic:{0}:{1:HHmm}", procs[i].Id, DateTime.Now);
                        if (!_processedSessions.Contains(sessionKey))
                        {
                            _processedSessions.Add(sessionKey);

                            Logger.Log(string.Format("AUDIO OUTPUT TO MIC: {0} PID:{1} detected outputting audio to microphone device. Cmd:{2}",
                                procs[i].ProcessName, procs[i].Id, Truncate(cmdLine, 200)),
                                LogLevel.THREAT, "audio_hijack.log");
                            GidrState.IncrementThreats();

                            ThreatInfo threat = new ThreatInfo();
                            threat.ThreatType = "AudioHijack";
                            threat.ThreatPath = GetProcessPath(procs[i]);
                            threat.Severity = ThreatSeverity.High;
                            threat.ProcessId = procs[i].Id;
                            threat.ProcessName = procs[i].ProcessName;
                            threat.Confidence = 85;
                            ResponseQueue.Enqueue(threat);
                        }
                    }
                }
                catch { }
            }
        }

        private static string GetProcessPath(Process proc)
        {
            try
            {
                return proc.MainModule.FileName;
            }
            catch
            {
                return string.Format("pid:{0}", proc.Id);
            }
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...";
        }
    }
}
