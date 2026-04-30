using System;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SystemMonitor
{
    public partial class MainForm : Form
    {
        private SystemWatcher watcher;
        private Timer uiTimer;
        private bool autoMode = false;

        private Label lblCpu;
        private Label lblMemory;
        private ListBox lstAlerts;
        private Button btnFix;
        private CheckBox chkAuto;

        public MainForm()
        {
            InitializeComponent();
            watcher = new SystemWatcher();
            watcher.AlertRaised += Watcher_AlertRaised;

            uiTimer = new Timer { Interval = 1000 };
            uiTimer.Tick += UiTimer_Tick;
            uiTimer.Start();
        }

        private void InitializeComponent()
        {
            this.Text = "System Monitor & IDS";
            this.Size = new Size(600, 400);
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;

            lblCpu = new Label { Location = new Point(20, 20), AutoSize = true };
            lblMemory = new Label { Location = new Point(20, 50), AutoSize = true };
            lstAlerts = new ListBox { Location = new Point(20, 90), Size = new Size(540, 180) };
            btnFix = new Button { Text = "Fix Selected", Location = new Point(20, 280), Size = new Size(120, 30) };
            chkAuto = new CheckBox { Text = "Automatic Mode", Location = new Point(160, 285), AutoSize = true };

            btnFix.Click += BtnFix_Click;
            chkAuto.CheckedChanged += ChkAuto_CheckedChanged;

            this.Controls.Add(lblCpu);
            this.Controls.Add(lblMemory);
            this.Controls.Add(lstAlerts);
            this.Controls.Add(btnFix);
            this.Controls.Add(chkAuto);
        }

        private void UiTimer_Tick(object sender, EventArgs e)
        {
            lblCpu.Text = $"CPU Usage: {watcher.GetCpuUsage():0.0}%";
            lblMemory.Text = $"Memory Usage: {watcher.GetMemoryUsage():0.0}%";
        }

        private void Watcher_AlertRaised(object sender, AlertEventArgs e)
        {
            // UI thread safety
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action<object, AlertEventArgs>(Watcher_AlertRaised), sender, e);
                return;
            }

            lstAlerts.Items.Add($"{DateTime.Now:T} - {e.Message}");
            if (autoMode)
            {
                PerformFix(e);
            }
        }

        private void BtnFix_Click(object sender, EventArgs e)
        {
            if (lstAlerts.SelectedItem == null) return;

            string selected = lstAlerts.SelectedItem.ToString();
            // Very simple parsing to get process name if present
            var procName = selected.Split('\'').Skip(1).FirstOrDefault();
            if (!string.IsNullOrEmpty(procName))
            {
                PerformFix(new AlertEventArgs($"Fixing process '{procName}'", procName));
                lstAlerts.Items.Remove(lstAlerts.SelectedItem);
            }
            else
            {
                MessageBox.Show("No actionable item selected.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void ChkAuto_CheckedChanged(object sender, EventArgs e)
        {
            autoMode = chkAuto.Checked;
        }

        private void PerformFix(AlertEventArgs alert)
        {
            try
            {
                if (!string.IsNullOrEmpty(alert.ProcessName))
                {
                    var procs = Process.GetProcessesByName(alert.ProcessName);
                    foreach (var p in procs)
                    {
                        p.Kill();
                    }
                    MessageBox.Show($"Killed process '{alert.ProcessName}'.", "Auto Fix", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to fix: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    public class AlertEventArgs : EventArgs
    {
        public string Message { get; }
        public string ProcessName { get; }

        public AlertEventArgs(string message, string processName = null)
        {
            Message = message;
            ProcessName = processName;
        }
    }
}