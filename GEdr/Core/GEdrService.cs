using System;
using System.ServiceProcess;
using System.Threading;

namespace GEdr.Core
{
    /// <summary>
    /// Windows Service wrapper for GEdr monitor mode.
    /// Allows GEdr.exe to run as both a console application and a Windows service.
    /// When started by SCM, this class handles the service lifecycle.
    /// When started from command line, Program.cs runs the monitor loop directly.
    /// </summary>
    public class GEdrService : ServiceBase
    {
        private Thread _monitorThread;
        private CancellationTokenSource _cts;

        public GEdrService()
        {
            ServiceName = "GEdr";
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            _cts = new CancellationTokenSource();
            _monitorThread = new Thread(RunMonitor);
            _monitorThread.IsBackground = true;
            _monitorThread.Name = "GEdr-Monitor";
            _monitorThread.Start();
        }

        protected override void OnStop()
        {
            Logger.Stability("Service stop requested");
            if (_cts != null) _cts.Cancel();
            if (_monitorThread != null) _monitorThread.Join(10000);
        }

        private void RunMonitor()
        {
            try
            {
                // Run the same monitor logic as the console version
                GEdrMonitor.Run(_cts.Token, serviceMode: true);
            }
            catch (Exception ex)
            {
                Logger.Log("Service monitor error: " + ex.Message, LogLevel.ERROR);
            }
        }
    }
}
