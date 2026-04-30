using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Ceprkac
{
    // ───────────────────────── colour palette (Chrome-dark inspired) ─────────
    internal static class Theme
    {
        public static readonly Color TitleBar      = Color.FromArgb(32, 33, 36);
        public static readonly Color TabBar        = Color.FromArgb(32, 33, 36);
        public static readonly Color ActiveTab     = Color.FromArgb(53, 54, 58);
        public static readonly Color InactiveTab   = Color.FromArgb(40, 41, 45);
        public static readonly Color TabHover      = Color.FromArgb(48, 49, 53);
        public static readonly Color Toolbar       = Color.FromArgb(53, 54, 58);
        public static readonly Color AddressBox    = Color.FromArgb(41, 42, 45);
        public static readonly Color BookmarkBar   = Color.FromArgb(53, 54, 58);
        public static readonly Color StatusBar     = Color.FromArgb(32, 33, 36);
        public static readonly Color ForeLight     = Color.White;
        public static readonly Color ForeDim       = Color.FromArgb(180, 184, 190);
        public static readonly Color Accent        = Color.FromArgb(138, 180, 248);
        public static readonly Color CloseHover    = Color.FromArgb(200, 60, 60);
        public static readonly Color Border        = Color.FromArgb(60, 64, 67);
    }

    // ───────────────────────── tab data model ───────────────────────────────
    internal sealed class BrowserTab
    {
        public string Title { get; set; } = "New Tab";
        public string Url { get; set; } = "";
        public WebView2 WebView { get; set; } = null!;
        public bool IsLoading { get; set; }
        public DateTime LastAutoFillAttempt { get; set; } = DateTime.MinValue;
    }

    // ───────────────────────── custom tab strip control ─────────────────────
    internal sealed class ChromeTabStrip : Control
    {
        public List<BrowserTab> Tabs { get; } = new();
        public int SelectedIndex { get; set; } = -1;
        public int HoverIndex { get; private set; } = -1;
        public int HoverCloseIndex { get; private set; } = -1;

        public event EventHandler<int>? TabClicked;
        public event EventHandler<int>? TabCloseClicked;
        public event EventHandler? NewTabClicked;

        private const int TabHeight = 34;
        private const int TabMaxWidth = 240;
        private const int TabMinWidth = 60;
        private const int CloseSize = 16;
        private const int NewTabBtnWidth = 28;
        private const int TopPadding = 6;
        private const int LeftPadding = 8;

        public ChromeTabStrip()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
            Height = TabHeight + TopPadding + 2;
            BackColor = Theme.TabBar;
            Font = new Font("Segoe UI", 8.5f);
        }

        private int GetTabWidth()
        {
            if (Tabs.Count == 0) return TabMaxWidth;
            int available = Width - LeftPadding - NewTabBtnWidth - 16;
            int w = available / Math.Max(Tabs.Count, 1);
            return Math.Max(TabMinWidth, Math.Min(TabMaxWidth, w));
        }

        private Rectangle GetTabRect(int index)
        {
            int w = GetTabWidth();
            int x = LeftPadding + index * (w + 1);
            return new Rectangle(x, TopPadding, w, TabHeight);
        }

        private Rectangle GetCloseRect(Rectangle tabRect)
        {
            int x = tabRect.Right - CloseSize - 8;
            int y = tabRect.Y + (tabRect.Height - CloseSize) / 2;
            return new Rectangle(x, y, CloseSize, CloseSize);
        }

        private Rectangle GetNewTabRect()
        {
            int w = GetTabWidth();
            int x = LeftPadding + Tabs.Count * (w + 1);
            return new Rectangle(x + 4, TopPadding + 4, NewTabBtnWidth, TabHeight - 8);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            g.Clear(Theme.TabBar);

            for (int i = 0; i < Tabs.Count; i++)
            {
                if (i == SelectedIndex) continue;
                DrawTab(g, i);
            }
            if (SelectedIndex >= 0 && SelectedIndex < Tabs.Count)
                DrawTab(g, SelectedIndex);

            // New tab button (+)
            var newRect = GetNewTabRect();
            using (var brush = new SolidBrush(Theme.InactiveTab))
            using (var path = RoundedRect(newRect, 8))
                g.FillPath(brush, path);
            using (var pen = new Pen(Theme.ForeLight, 1.5f))
            {
                int cx = newRect.X + newRect.Width / 2;
                int cy = newRect.Y + newRect.Height / 2;
                g.DrawLine(pen, cx - 5, cy, cx + 5, cy);
                g.DrawLine(pen, cx, cy - 5, cx, cy + 5);
            }

            // Bottom line under inactive area
            if (SelectedIndex >= 0 && SelectedIndex < Tabs.Count)
            {
                using var pen = new Pen(Theme.ActiveTab, 2);
                var selRect = GetTabRect(SelectedIndex);
                g.DrawLine(pen, 0, Height - 1, selRect.Left, Height - 1);
                g.DrawLine(pen, selRect.Right, Height - 1, Width, Height - 1);
            }
        }

        private void DrawTab(Graphics g, int index)
        {
            var rect = GetTabRect(index);
            bool active = index == SelectedIndex;
            bool hover = index == HoverIndex && !active;
            Color bg = active ? Theme.ActiveTab : (hover ? Theme.TabHover : Theme.InactiveTab);

            int radius = active ? 10 : 8;
            using (var path = RoundedRectTop(rect, radius))
            using (var brush = new SolidBrush(bg))
                g.FillPath(brush, path);

            var tab = Tabs[index];
            int textRight = rect.Right - CloseSize - 16;
            int textLeft = rect.X + 12;
            var textRect = new Rectangle(textLeft, rect.Y + 2, textRight - textLeft, rect.Height - 2);
            var textColor = active ? Theme.ForeLight : Theme.ForeDim;
            TextRenderer.DrawText(g, tab.Title, Font, textRect, textColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

            if (Tabs.Count > 1 || active)
            {
                var closeRect = GetCloseRect(rect);
                bool closeHover = index == HoverCloseIndex;
                if (closeHover)
                {
                    using var closeBrush = new SolidBrush(Theme.CloseHover);
                    g.FillEllipse(closeBrush, closeRect);
                }
                using var closePen = new Pen(closeHover ? Color.White : Theme.ForeDim, 1.2f);
                int m = 4;
                g.DrawLine(closePen, closeRect.X + m, closeRect.Y + m, closeRect.Right - m, closeRect.Bottom - m);
                g.DrawLine(closePen, closeRect.Right - m, closeRect.Y + m, closeRect.X + m, closeRect.Bottom - m);
            }

            if (tab.IsLoading)
            {
                using var loadPen = new Pen(Theme.Accent, 2);
                g.DrawLine(loadPen, rect.X + 4, rect.Bottom - 2, rect.X + 4 + (rect.Width - 8) / 3, rect.Bottom - 2);
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            int oldHover = HoverIndex, oldClose = HoverCloseIndex;
            HoverIndex = -1;
            HoverCloseIndex = -1;
            for (int i = 0; i < Tabs.Count; i++)
            {
                var rect = GetTabRect(i);
                if (rect.Contains(e.Location))
                {
                    HoverIndex = i;
                    if (GetCloseRect(rect).Contains(e.Location))
                        HoverCloseIndex = i;
                    break;
                }
            }
            if (oldHover != HoverIndex || oldClose != HoverCloseIndex) Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (HoverIndex != -1 || HoverCloseIndex != -1) { HoverIndex = -1; HoverCloseIndex = -1; Invalidate(); }
        }

        protected override void OnMouseClick(MouseEventArgs e)
        {
            base.OnMouseClick(e);
            if (GetNewTabRect().Contains(e.Location)) { NewTabClicked?.Invoke(this, EventArgs.Empty); return; }
            for (int i = 0; i < Tabs.Count; i++)
            {
                var rect = GetTabRect(i);
                if (!rect.Contains(e.Location)) continue;
                if (GetCloseRect(rect).Contains(e.Location)) TabCloseClicked?.Invoke(this, i);
                else TabClicked?.Invoke(this, i);
                return;
            }
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button == MouseButtons.Middle)
                for (int i = 0; i < Tabs.Count; i++)
                    if (GetTabRect(i).Contains(e.Location)) { TabCloseClicked?.Invoke(this, i); return; }
        }

        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            var path = new GraphicsPath();
            int d = radius * 2;
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        private static GraphicsPath RoundedRectTop(Rectangle r, int radius)
        {
            var path = new GraphicsPath();
            int d = radius * 2;
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddLine(r.Right, r.Bottom, r.X, r.Bottom);
            path.CloseFigure();
            return path;
        }
    }

    // ───────────────────────── bookmark data model (tree) ──────────────────
    internal sealed class BookmarkNode
    {
        public string Type { get; set; } = "link"; // "link" or "folder"
        public string Title { get; set; } = "";
        public string Href { get; set; } = "";
        public List<BookmarkNode> Children { get; set; } = new();
    }

    // ───────────────────────── main form ────────────────────────────────────
    public class MainForm : Form
    {
        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

        private readonly ChromeTabStrip tabStrip;
        private readonly ToolStrip navToolStrip;
        private readonly ToolStripTextBox addressBox;
        private readonly ToolStripButton goBtn;
        private readonly ToolStripButton backBtn;
        private readonly ToolStripButton fwdBtn;
        private readonly ToolStripButton refreshBtn;
        private readonly ToolStripButton bookmarkBtn;
        private readonly ToolStripDropDownButton menuBtn;
        private readonly ToolStrip bookmarksBar;
        private readonly Panel webViewPanel;
        private readonly ToolStripStatusLabel statusLabel;
        private readonly StatusStrip statusStrip;

        private readonly string appDataFolder;
        private readonly string bookmarksFile;
        private readonly string historyFile;
        private readonly string passwordsFile;
        private readonly string settingsFile;
        private readonly List<BookmarkNode> bookmarks = new();
        private readonly List<string> history = new();
        private readonly List<SavedCredential> savedPasswords = new();
        private string homePageUrl = "https://www.google.com";
        private string searchUrlTemplate = "https://www.google.com/search?q={0}";
        private CoreWebView2Environment? sharedEnvironment;

        private BrowserTab? ActiveTab => tabStrip.SelectedIndex >= 0 && tabStrip.SelectedIndex < tabStrip.Tabs.Count
            ? tabStrip.Tabs[tabStrip.SelectedIndex] : null;

        public MainForm()
        {
            Text = "Ceprkac";
            ClientSize = new Size(1280, 860);
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(600, 400);
            BackColor = Theme.TitleBar;

            try { Icon = new Icon(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Ceprkac.ico")); }
            catch { }

            appDataFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Ceprkac");
            bookmarksFile = Path.Combine(appDataFolder, "bookmarks.txt");
            historyFile = Path.Combine(appDataFolder, "history.txt");
            passwordsFile = Path.Combine(appDataFolder, "passwords.dat");
            settingsFile = Path.Combine(appDataFolder, "settings.txt");

            // Tab strip
            tabStrip = new ChromeTabStrip { Dock = DockStyle.Top };
            tabStrip.TabClicked += (_, i) => SwitchToTab(i);
            tabStrip.TabCloseClicked += (_, i) => CloseTab(i);
            tabStrip.NewTabClicked += (_, _) => AddNewTab(homePageUrl);

            // Toolbar using ToolStrip — reliable dark theme rendering
            navToolStrip = new ToolStrip
            {
                GripStyle = ToolStripGripStyle.Hidden,
                BackColor = Theme.Toolbar,
                ForeColor = Color.White,
                RenderMode = ToolStripRenderMode.System,
                Padding = new Padding(4, 4, 4, 4),
                AutoSize = false,
                Height = 40,
                Dock = DockStyle.Top,
            };

            backBtn = new ToolStripButton("◀") { ForeColor = Color.White, Font = new Font("Segoe UI", 11f), AutoSize = false, Width = 36 };
            fwdBtn = new ToolStripButton("▶") { ForeColor = Color.White, Font = new Font("Segoe UI", 11f), AutoSize = false, Width = 36 };
            refreshBtn = new ToolStripButton("⟳") { ForeColor = Color.White, Font = new Font("Segoe UI", 12f), AutoSize = false, Width = 36 };
            addressBox = new ToolStripTextBox { BackColor = Theme.AddressBox, ForeColor = Color.White, Font = new Font("Segoe UI", 10f), AutoSize = false, Width = 800 };
            addressBox.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.Handled = true; e.SuppressKeyPress = true; NavigateCurrentTab(addressBox.Text); } };
            goBtn = new ToolStripButton("→") { ForeColor = Color.White, Font = new Font("Segoe UI", 11f), AutoSize = false, Width = 36 };
            bookmarkBtn = new ToolStripButton("☆") { ForeColor = Color.White, Font = new Font("Segoe UI", 11f), AutoSize = false, Width = 36 };

            menuBtn = new ToolStripDropDownButton("≡") { ForeColor = Color.White, Font = new Font("Segoe UI", 12f), AutoSize = false, Width = 36, ShowDropDownArrow = false };
            menuBtn.DropDown.BackColor = Theme.ActiveTab;
            menuBtn.DropDown.ForeColor = Color.White;
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("New Tab", null, (_, _) => AddNewTab(homePageUrl)) { ShortcutKeys = Keys.Control | Keys.T, ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripSeparator());
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Add Bookmark", null, (_, _) => AddCurrentPageBookmark()) { ShortcutKeys = Keys.Control | Keys.D, ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Import Bookmarks...", null, (_, _) => ImportBookmarksHtml()) { ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Export Bookmarks...", null, (_, _) => ExportBookmarksHtml()) { ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Clear Bookmarks", null, (_, _) => ClearBookmarks()) { ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripSeparator());
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Clear History", null, (_, _) => ClearHistory()) { ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripSeparator());
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Import Passwords (CSV)...", null, (_, _) => ImportPasswordsCsv()) { ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Clear Saved Passwords", null, (_, _) => ClearPasswords()) { ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripSeparator());
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("DevTools", null, (_, _) => ActiveTab?.WebView.CoreWebView2?.OpenDevToolsWindow()) { ShortcutKeys = Keys.Control | Keys.I, ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Change Search Engine...", null, (_, _) => { ShowSearchEnginePicker(); }) { ForeColor = Color.White, BackColor = Theme.ActiveTab });
            menuBtn.DropDownItems.Add(new ToolStripSeparator());
            menuBtn.DropDownItems.Add(new ToolStripMenuItem("Exit", null, (_, _) => Close()) { ForeColor = Color.White, BackColor = Theme.ActiveTab });

            backBtn.Click += (_, _) => { var c = ActiveTab?.WebView.CoreWebView2; if (c?.CanGoBack == true) c.GoBack(); };
            fwdBtn.Click += (_, _) => { var c = ActiveTab?.WebView.CoreWebView2; if (c?.CanGoForward == true) c.GoForward(); };
            refreshBtn.Click += (_, _) => ActiveTab?.WebView.CoreWebView2?.Reload();
            goBtn.Click += (_, _) => NavigateCurrentTab(addressBox.Text);
            bookmarkBtn.Click += (_, _) => AddCurrentPageBookmark();

            navToolStrip.Items.AddRange(new ToolStripItem[] { backBtn, fwdBtn, refreshBtn, new ToolStripSeparator(), addressBox, goBtn, new ToolStripSeparator(), bookmarkBtn, menuBtn });
            navToolStrip.Resize += (_, _) => { addressBox.Width = navToolStrip.Width - 280; };

            // Bookmarks bar (ToolStrip for nested folder support)
            bookmarksBar = new ToolStrip
            {
                Dock = DockStyle.Top,
                GripStyle = ToolStripGripStyle.Hidden,
                BackColor = Theme.BookmarkBar,
                ForeColor = Color.White,
                RenderMode = ToolStripRenderMode.System,
                Padding = new Padding(4, 2, 4, 2),
                AutoSize = false,
                Height = 30,
                Font = new Font("Segoe UI", 8f),
            };

            // WebView panel
            webViewPanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.ActiveTab };

            // Status bar
            statusLabel = new ToolStripStatusLabel("Ready") { ForeColor = Theme.ForeDim };
            statusStrip = new StatusStrip { BackColor = Theme.StatusBar };
            statusStrip.Items.Add(statusLabel);

            // Layout (reverse dock order)
            Controls.Add(webViewPanel);
            Controls.Add(bookmarksBar);
            Controls.Add(navToolStrip);
            Controls.Add(tabStrip);
            Controls.Add(statusStrip);

            KeyPreview = true;
            KeyDown += MainForm_KeyDown;
            Load += (_, _) => InitializeAsync();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            try { int v = 1; DwmSetWindowAttribute(Handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref v, sizeof(int)); } catch { }
        }

        private void MainForm_KeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.T) { AddNewTab(homePageUrl); e.Handled = true; }
            else if (e.Control && e.KeyCode == Keys.W) { if (tabStrip.SelectedIndex >= 0) CloseTab(tabStrip.SelectedIndex); e.Handled = true; }
            else if (e.Control && e.KeyCode == Keys.L) { addressBox.Focus(); addressBox.SelectAll(); e.Handled = true; }
            else if (e.Control && e.KeyCode == Keys.Tab)
            {
                if (tabStrip.Tabs.Count > 1) SwitchToTab((tabStrip.SelectedIndex + 1) % tabStrip.Tabs.Count);
                e.Handled = true;
            }
            else if (e.Control && e.Shift && e.KeyCode == Keys.Tab)
            {
                if (tabStrip.Tabs.Count > 1) SwitchToTab((tabStrip.SelectedIndex - 1 + tabStrip.Tabs.Count) % tabStrip.Tabs.Count);
                e.Handled = true;
            }
        }

        private async void InitializeAsync()
        {
            try
            {
                Directory.CreateDirectory(appDataFolder);
                LoadSettings();
                if (!File.Exists(settingsFile))
                    ShowSearchEnginePicker();
                LoadBookmarks();
                LoadHistory();
                LoadPasswords();
                RefreshBookmarksBar();

                // Load or download ad blocklist
                await LoadOrUpdateBlocklistAsync();

                var userDataFolder = Path.Combine(appDataFolder, "WebView2UserData");
                Directory.CreateDirectory(userDataFolder);

                // Check if WebView2 runtime is available, install if missing
                if (!IsWebView2RuntimeInstalled())
                {
                    statusLabel.Text = "Installing WebView2 runtime...";
                    bool installed = await InstallWebView2RuntimeAsync();
                    if (!installed)
                    {
                        statusLabel.Text = "WebView2 installation failed.";
                        MessageBox.Show(this,
                            "WebView2 runtime could not be installed.\r\nPlease install it manually from:\r\nhttps://developer.microsoft.com/en-us/microsoft-edge/webview2/",
                            "WebView2 Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }

                sharedEnvironment = await CoreWebView2Environment.CreateAsync(null, userDataFolder);
                AddNewTab(homePageUrl);
            }
            catch (Exception ex)
            {
                statusLabel.Text = "Failed to initialize WebView2.";
                MessageBox.Show(this, $"WebView2 initialization failed:\r\n{ex.Message}\r\n\r\n{ex.StackTrace}",
                    "Initialization Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static bool IsWebView2RuntimeInstalled()
        {
            try
            {
                var version = CoreWebView2Environment.GetAvailableBrowserVersionString();
                return !string.IsNullOrEmpty(version);
            }
            catch { return false; }
        }

        private async Task<bool> InstallWebView2RuntimeAsync()
        {
            var bootstrapperPath = Path.Combine(Path.GetTempPath(), "MicrosoftEdgeWebview2Setup.exe");
            try
            {
                // Download the Evergreen Bootstrapper (~1.5MB)
                using (var http = new HttpClient())
                {
                    var bytes = await http.GetByteArrayAsync(
                        "https://go.microsoft.com/fwlink/p/?LinkId=2124703");
                    File.WriteAllBytes(bootstrapperPath, bytes);
                }

                // Run silent install
                var psi = new ProcessStartInfo
                {
                    FileName = bootstrapperPath,
                    Arguments = "/silent /install",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                var proc = Process.Start(psi);
                if (proc == null) return false;
                await Task.Run(() => proc.WaitForExit());

                return IsWebView2RuntimeInstalled();
            }
            catch { return false; }
            finally
            {
                try { File.Delete(bootstrapperPath); } catch { }
            }
        }

        private async void AddNewTab(string url, int? insertAfter = null)
        {
            if (sharedEnvironment == null) return;
            var webView = new WebView2 { Dock = DockStyle.Fill, Visible = false };
            var tab = new BrowserTab { Url = url, WebView = webView };

            int insertIndex = insertAfter.HasValue ? insertAfter.Value + 1
                : tabStrip.SelectedIndex >= 0 ? tabStrip.SelectedIndex + 1
                : tabStrip.Tabs.Count;

            tabStrip.Tabs.Insert(insertIndex, tab);
            webViewPanel.Controls.Add(webView);

            try
            {
                await webView.EnsureCoreWebView2Async(sharedEnvironment);
                var core = webView.CoreWebView2;
                if (core != null)
                {
                    core.NavigationStarting += (_, _) => { tab.IsLoading = true; if (ActiveTab == tab) statusLabel.Text = "Loading..."; tabStrip.Invalidate(); };
                    core.NavigationCompleted += (_, _) => { tab.IsLoading = false; UpdateTabState(tab); tabStrip.Invalidate(); TryAutoFillCredentials(tab); InjectAdElementHider(tab); };
                    core.DocumentTitleChanged += (_, _) => { tab.Title = core.DocumentTitle ?? "New Tab"; if (ActiveTab == tab) Text = tab.Title + " - Ceprkac"; tabStrip.Invalidate(); };
                    core.SourceChanged += (_, _) =>
                    {
                        tab.Url = core.Source ?? "";
                        if (ActiveTab == tab) addressBox.Text = tab.Url;
                        // Re-trigger autofill for multi-step logins (Google account picker → password page)
                        TryAutoFillCredentials(tab);
                    };
                    core.NewWindowRequested += (_, args) =>
                    {
                        var uri = (args.Uri ?? "").ToLower();
                        // Let auth/OAuth flows open as native WebView2 popups
                        // They need window.opener, COOP headers, and shared cookies
                        if (uri.Contains("accounts.google.com") || uri.Contains("/gsi/") ||
                            uri.Contains("appleid.apple.com") || uri.Contains("login.microsoftonline.com") ||
                            uri.Contains("api.twitter.com") || uri.Contains("twitter.com/i/oauth") ||
                            uri.Contains("x.com/i/oauth") || uri.Contains("/oauth") ||
                            uri.Contains("/auth/") || uri.Contains("/authorize") ||
                            uri.Contains("/signin") || uri.Contains("/sso") ||
                            uri.Contains("pay.google.com") || uri.Contains("payments.google.com") ||
                            uri.Contains("clerk.") || uri.Contains("suno.com") || uri.Contains("suno.ai"))
                        {
                            return; // Let WebView2 open native popup
                        }

                        // Block new windows to ad domains — don't create a tab at all
                        if (IsAdUrl(uri))
                        {
                            args.Handled = true;
                            adsBlockedCount++;
                            return;
                        }

                        args.Handled = true;
                        int idx = tabStrip.Tabs.IndexOf(tab);
                        AddNewTab(args.Uri ?? homePageUrl, idx >= 0 ? idx : (int?)null);
                    };
                    core.DownloadStarting += Core_DownloadStarting;

                    // Block navigations to ad domains — cancel and auto-close empty tabs
                    core.NavigationStarting += (_, navArgs) =>
                    {
                        var navUri = (navArgs.Uri ?? "").ToLower();
                        if (IsAdUrl(navUri))
                        {
                            navArgs.Cancel = true;
                            adsBlockedCount++;
                            // If this tab has no real content (was just opened for the ad), close it
                            var tabUrl = (tab.Url ?? "").ToLower();
                            bool isEmptyTab = string.IsNullOrEmpty(tabUrl) || tabUrl == "about:blank" ||
                                tabUrl.StartsWith("data:") || IsAdUrl(tabUrl);
                            if (isEmptyTab && tabStrip.Tabs.Count > 1)
                            {
                                _ = Task.Delay(100).ContinueWith(_ =>
                                {
                                    try { Invoke(() => { int ti = tabStrip.Tabs.IndexOf(tab); if (ti >= 0) CloseTab(ti); }); } catch { }
                                });
                            }
                            else
                            {
                                // Tab has real content — just go back
                                if (core.CanGoBack) core.GoBack();
                            }
                        }
                    };

                    // Handle window.close() from auth flows — close the tab
                    core.WindowCloseRequested += (_, _) =>
                    {
                        int tabIdx = tabStrip.Tabs.IndexOf(tab);
                        if (tabIdx >= 0) CloseTab(tabIdx);
                    };

                    // Auto-close tabs that show "close this window" auth completion messages
                    core.NavigationCompleted += (s2, e2) =>
                    {
                        var src = core.Source ?? "";
                        if (src.Contains("/callback") && (src.Contains("oauth") || src.Contains("auth")))
                        {
                            // Auth callback page — auto-close after a short delay
                            _ = Task.Delay(1500).ContinueWith(_ =>
                            {
                                try { Invoke(() => { int ti = tabStrip.Tabs.IndexOf(tab); if (ti >= 0) CloseTab(ti); }); } catch { }
                            });
                        }
                    };

                    // Ad blocker — network-level request blocking
                    SetupAdBlocker(core);
                }
                SwitchToTab(insertIndex);
                if (!string.IsNullOrWhiteSpace(url)) NavigateTab(tab, url);
            }
            catch (Exception ex)
            {
                statusLabel.Text = "Tab creation failed.";
                MessageBox.Show(this, $"Failed to create tab:\r\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SwitchToTab(int index)
        {
            if (index < 0 || index >= tabStrip.Tabs.Count) return;
            if (tabStrip.SelectedIndex >= 0 && tabStrip.SelectedIndex < tabStrip.Tabs.Count)
                tabStrip.Tabs[tabStrip.SelectedIndex].WebView.Visible = false;
            tabStrip.SelectedIndex = index;
            var tab = tabStrip.Tabs[index];
            tab.WebView.Visible = true;
            tab.WebView.BringToFront();
            addressBox.Text = tab.Url;
            Text = tab.Title + " - Ceprkac";
            UpdateTabState(tab);
            tabStrip.Invalidate();
        }

        private async void OpenOAuthPopup(string url, BrowserTab parentTab)
        {
            if (sharedEnvironment == null) return;

            var popup = new Form
            {
                Text = "Sign In",
                ClientSize = new Size(500, 650),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Theme.TitleBar,
                MinimizeBox = false,
                MaximizeBox = false,
            };

            // Dark title bar
            try
            {
                int v = 1;
                DwmSetWindowAttribute(popup.Handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref v, sizeof(int));
            }
            catch { }

            var popupWebView = new WebView2 { Dock = DockStyle.Fill };
            popup.Controls.Add(popupWebView);

            try
            {
                // Use a separate environment for OAuth popups — no ad blocking scripts
                var popupUserData = Path.Combine(appDataFolder, "WebView2OAuthData");
                Directory.CreateDirectory(popupUserData);
                var popupEnv = await CoreWebView2Environment.CreateAsync(null, popupUserData);
                await popupWebView.EnsureCoreWebView2Async(popupEnv);
                var popupCore = popupWebView.CoreWebView2;
                if (popupCore == null) { popup.Dispose(); return; }

                // No ad blocker on OAuth popups — auth providers get blocked otherwise

                // Auto-close when the OAuth flow completes (redirects back to the original site)
                string? parentDomain = null;
                try { parentDomain = new Uri(parentTab.Url).Host.ToLower(); } catch { }

                popupCore.NavigationStarting += (_, navArgs) =>
                {
                    try
                    {
                        var navHost = new Uri(navArgs.Uri).Host.ToLower();
                        // If navigating back to the parent site, the auth is done
                        if (parentDomain != null && navHost.Contains(parentDomain))
                        {
                            popup.BeginInvoke(() =>
                            {
                                popup.Close();
                                // Refresh the parent tab to pick up the auth
                                parentTab.WebView.CoreWebView2?.Reload();
                            });
                        }
                    }
                    catch { }
                };

                // Also auto-close if the popup tries to close itself (window.close())
                popupCore.WindowCloseRequested += (_, _) =>
                {
                    popup.BeginInvoke(() => popup.Close());
                };

                // Update popup title
                popupCore.DocumentTitleChanged += (_, _) =>
                {
                    popup.BeginInvoke(() => popup.Text = popupCore.DocumentTitle ?? "Sign In");
                };

                popupCore.Navigate(url);
                popup.ShowDialog(this);
            }
            catch { }
            finally
            {
                popupWebView.Dispose();
                popup.Dispose();
            }
        }

        private void CloseTab(int index)
        {
            if (index < 0 || index >= tabStrip.Tabs.Count) return;
            if (tabStrip.Tabs.Count == 1) { NavigateTab(tabStrip.Tabs[0], homePageUrl); return; }
            var tab = tabStrip.Tabs[index];
            tab.WebView.Visible = false;
            webViewPanel.Controls.Remove(tab.WebView);
            tab.WebView.Dispose();
            tabStrip.Tabs.RemoveAt(index);
            SwitchToTab(Math.Min(index, tabStrip.Tabs.Count - 1));
        }

        private void NavigateTab(BrowserTab tab, string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return;
            // If it's not a URL, treat as search query
            if ((!url.Contains("://") && !url.Contains(".")) || (url.Contains(" ") && !url.Contains("://")))
            {
                url = string.Format(searchUrlTemplate, Uri.EscapeDataString(url));
            }
            else if (!url.Contains("://"))
            {
                url = "https://" + url;
            }
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;
            tab.WebView.CoreWebView2?.Navigate(uri.ToString());
            tab.Url = uri.ToString();
            if (ActiveTab == tab) addressBox.Text = uri.ToString();
            AddToHistory(uri.ToString());
        }

        private void NavigateCurrentTab(string url) { if (ActiveTab != null) NavigateTab(ActiveTab, url); }

        private void UpdateTabState(BrowserTab tab)
        {
            if (ActiveTab != tab) return;
            var core = tab.WebView.CoreWebView2;
            backBtn.Enabled = core?.CanGoBack ?? false;
            backBtn.ForeColor = backBtn.Enabled ? Color.White : Theme.ForeDim;
            fwdBtn.Enabled = core?.CanGoForward ?? false;
            fwdBtn.ForeColor = fwdBtn.Enabled ? Color.White : Theme.ForeDim;
            addressBox.Text = tab.WebView.Source?.AbsoluteUri ?? addressBox.Text;
            statusLabel.Text = $"Ready | Ads blocked: {adsBlockedCount} | Domains: {BlockedAdDomains.Count}";
            var currentUrl = tab.WebView.Source?.AbsoluteUri ?? "";
            bookmarkBtn.Text = BookmarkExistsInTree(bookmarks, currentUrl) ? "★" : "☆";
        }

        private void Core_DownloadStarting(object? sender, CoreWebView2DownloadStartingEventArgs e)
        {
            var filename = Path.GetFileName(e.ResultFilePath) ?? "download";
            using var dialog = new SaveFileDialog { FileName = filename, Filter = "All Files|*.*", Title = "Save Download", RestoreDirectory = true };
            if (dialog.ShowDialog(this) != DialogResult.OK) { e.Cancel = true; statusLabel.Text = "Download canceled."; return; }
            e.ResultFilePath = dialog.FileName;
            statusLabel.Text = $"Downloading {Path.GetFileName(dialog.FileName)}...";
            var op = e.DownloadOperation;
            op.BytesReceivedChanged += (_, _) => Invoke(() =>
            {
                var total = op.TotalBytesToReceive; var recv = op.BytesReceived;
                statusLabel.Text = total > 0 ? $"Downloading {Path.GetFileName(dialog.FileName)} {recv:N0}/{total:N0} bytes"
                    : $"Downloading {Path.GetFileName(dialog.FileName)} {recv:N0} bytes";
            });
            op.StateChanged += (_, _) => Invoke(() =>
            {
                if (op.State == CoreWebView2DownloadState.Completed) statusLabel.Text = "Download complete.";
                else if (op.State == CoreWebView2DownloadState.Interrupted) statusLabel.Text = "Download interrupted.";
            });
        }

        private void AddressBar_KeyDown(object? sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter) { e.Handled = true; e.SuppressKeyPress = true; NavigateCurrentTab(addressBox.Text); }
        }

        // ── Bookmarks ──
        private void LoadBookmarks()
        {
            if (!File.Exists(bookmarksFile)) return;
            bookmarks.Clear();
            var stack = new Stack<List<BookmarkNode>>();
            stack.Push(bookmarks);
            foreach (var line in File.ReadAllLines(bookmarksFile).Where(l => !string.IsNullOrWhiteSpace(l)))
            {
                var parts = line.Split(new[] { '\t' }, 3);
                // Fallback for old pipe-delimited format
                if (parts.Length < 2) parts = line.Split(new[] { '|' }, 3);
                var current = stack.Peek();
                if (parts[0] == "FOLDER" && parts.Length >= 2)
                {
                    var folder = new BookmarkNode { Type = "folder", Title = parts[1] };
                    current.Add(folder);
                    stack.Push(folder.Children);
                }
                else if (parts[0] == "ENDFOLDER")
                {
                    if (stack.Count > 1) stack.Pop();
                }
                else if (parts[0] == "LINK" && parts.Length >= 3)
                {
                    current.Add(new BookmarkNode { Type = "link", Title = parts[1], Href = parts[2] });
                }
                else
                {
                    // Legacy flat format: Title|Url
                    var legacy = line.Split(new[] { '|' }, 2);
                    if (legacy.Length == 2)
                        current.Add(new BookmarkNode { Type = "link", Title = legacy[0], Href = legacy[1] });
                    else
                        current.Add(new BookmarkNode { Type = "link", Title = GetDisplayTitle(line), Href = line });
                }
            }
        }

        private void SaveBookmarks()
        {
            var lines = new List<string>();
            WriteBookmarkNodes(lines, bookmarks);
            File.WriteAllLines(bookmarksFile, lines);
        }

        private static void WriteBookmarkNodes(List<string> lines, List<BookmarkNode> nodes)
        {
            foreach (var node in nodes)
            {
                if (node.Type == "folder")
                {
                    lines.Add($"FOLDER\t{node.Title}");
                    WriteBookmarkNodes(lines, node.Children);
                    lines.Add("ENDFOLDER");
                }
                else
                {
                    lines.Add($"LINK\t{node.Title}\t{node.Href}");
                }
            }
        }

        private void AddCurrentPageBookmark()
        {
            var tab = ActiveTab; if (tab == null) return;
            var url = tab.WebView.Source?.AbsoluteUri ?? addressBox.Text;
            if (string.IsNullOrWhiteSpace(url)) return;
            if (RemoveBookmarkFromTree(bookmarks, url))
            {
                SaveBookmarks(); RefreshBookmarksBar(); bookmarkBtn.Text = "☆"; statusLabel.Text = "Bookmark removed.";
            }
            else
            {
                bookmarks.Insert(0, new BookmarkNode { Type = "link", Title = tab.Title ?? GetDisplayTitle(url), Href = url });
                SaveBookmarks(); RefreshBookmarksBar(); bookmarkBtn.Text = "★"; statusLabel.Text = "Bookmark added.";
            }
        }

        private void RefreshBookmarksBar()
        {
            bookmarksBar.Items.Clear();
            foreach (var node in bookmarks)
            {
                if (node.Type == "folder")
                {
                    var dropDown = new ToolStripDropDownButton(node.Title)
                    {
                        ForeColor = Theme.ForeLight,
                        Font = bookmarksBar.Font,
                        DisplayStyle = ToolStripItemDisplayStyle.Text,
                    };
                    dropDown.DropDown.BackColor = Theme.ActiveTab;
                    dropDown.DropDown.ForeColor = Color.White;
                    AddChildrenToMenu(dropDown.DropDownItems, node.Children);
                    bookmarksBar.Items.Add(dropDown);
                }
                else
                {
                    var btn = new ToolStripButton(node.Title)
                    {
                        ForeColor = Theme.ForeLight,
                        Font = bookmarksBar.Font,
                        DisplayStyle = ToolStripItemDisplayStyle.Text,
                        Tag = node.Href,
                    };
                    btn.Click += (_, _) => NavigateCurrentTab(node.Href);
                    bookmarksBar.Items.Add(btn);
                }
            }
        }

        private void AddChildrenToMenu(ToolStripItemCollection items, List<BookmarkNode> children)
        {
            foreach (var child in children)
            {
                if (child.Type == "folder")
                {
                    var sub = new ToolStripMenuItem(child.Title)
                    {
                        ForeColor = Color.White,
                        BackColor = Theme.ActiveTab,
                    };
                    AddChildrenToMenu(sub.DropDownItems, child.Children);
                    sub.DropDown.BackColor = Theme.ActiveTab;
                    sub.DropDown.ForeColor = Color.White;
                    items.Add(sub);
                }
                else
                {
                    var href = child.Href;
                    var item = new ToolStripMenuItem(child.Title)
                    {
                        ForeColor = Color.White,
                        BackColor = Theme.ActiveTab,
                    };
                    item.Click += (_, _) => NavigateCurrentTab(href);
                    items.Add(item);
                }
            }
        }

        private static bool BookmarkExistsInTree(List<BookmarkNode> nodes, string url)
        {
            foreach (var node in nodes)
            {
                if (node.Type == "link" && string.Equals(node.Href, url, StringComparison.OrdinalIgnoreCase))
                    return true;
                if (node.Type == "folder" && BookmarkExistsInTree(node.Children, url))
                    return true;
            }
            return false;
        }

        private static bool RemoveBookmarkFromTree(List<BookmarkNode> nodes, string url)
        {
            for (int i = 0; i < nodes.Count; i++)
            {
                if (nodes[i].Type == "link" && string.Equals(nodes[i].Href, url, StringComparison.OrdinalIgnoreCase))
                {
                    nodes.RemoveAt(i);
                    return true;
                }
                if (nodes[i].Type == "folder" && RemoveBookmarkFromTree(nodes[i].Children, url))
                    return true;
            }
            return false;
        }

        private void ClearBookmarks()
        {
            if (MessageBox.Show(this, "Clear all bookmarks?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            bookmarks.Clear(); SaveBookmarks(); RefreshBookmarksBar(); statusLabel.Text = "Bookmarks cleared.";
        }

        private void ImportBookmarksHtml()
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Import Bookmarks",
                Filter = "Bookmark Files (*.html;*.htm)|*.html;*.htm|All Files|*.*",
                RestoreDirectory = true,
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;

            try
            {
                var html = File.ReadAllText(dlg.FileName);
                var parsed = ParseBookmarksHtml(html);
                // If the top level is a single folder, unwrap it
                if (parsed.Count == 1 && parsed[0].Type == "folder")
                    parsed = parsed[0].Children;
                bookmarks.Clear();
                bookmarks.AddRange(parsed);
                SaveBookmarks();
                RefreshBookmarksBar();
                int count = CountLinks(bookmarks);
                statusLabel.Text = $"Imported {count} bookmarks.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Import failed:\r\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static List<BookmarkNode> ParseBookmarksHtml(string html)
        {
            // Find the first <DL> tag and parse recursively (Netscape bookmark format)
            int dlStart = html.IndexOf("<DL", StringComparison.OrdinalIgnoreCase);
            if (dlStart < 0) dlStart = html.IndexOf("<dl", StringComparison.Ordinal);
            if (dlStart >= 0)
                return ParseDL(html, ref dlStart);

            // Fallback: extract all <A> tags as flat links
            var result = new List<BookmarkNode>();
            int pos = 0;
            while (pos < html.Length)
            {
                int aStart = html.IndexOf("<A ", pos, StringComparison.OrdinalIgnoreCase);
                if (aStart < 0) aStart = html.IndexOf("<a ", pos, StringComparison.OrdinalIgnoreCase);
                if (aStart < 0) break;
                var (href, title, endPos) = ExtractATag(html, aStart);
                if (!string.IsNullOrWhiteSpace(href))
                    result.Add(new BookmarkNode { Type = "link", Title = title, Href = href });
                pos = endPos;
            }
            return result;
        }

        private static List<BookmarkNode> ParseDL(string html, ref int pos)
        {
            var nodes = new List<BookmarkNode>();
            // Skip past the opening <DL...> tag
            int tagEnd = html.IndexOf('>', pos);
            if (tagEnd < 0) return nodes;
            pos = tagEnd + 1;

            while (pos < html.Length)
            {
                // Skip whitespace and text
                int nextTag = html.IndexOf('<', pos);
                if (nextTag < 0) break;
                pos = nextTag;

                // Peek at the tag
                int closeAngle = html.IndexOf('>', pos);
                if (closeAngle < 0) break;
                string tag = html.Substring(pos, closeAngle - pos + 1);
                string tagUpper = tag.ToUpperInvariant();

                // End of this DL
                if (tagUpper.StartsWith("</DL"))
                {
                    pos = closeAngle + 1;
                    return nodes;
                }

                // Skip <DT>, <p>, <DD> opening tags
                if (tagUpper.StartsWith("<DT") || tagUpper.StartsWith("<P") || tagUpper.StartsWith("<DD"))
                {
                    pos = closeAngle + 1;
                    continue;
                }

                // Folder header: <H3...>title</H3>
                if (tagUpper.StartsWith("<H3") || tagUpper.StartsWith("<H1") || tagUpper.StartsWith("<H2"))
                {
                    pos = closeAngle + 1;
                    // Find closing </H3> (or </H1>, </H2>)
                    string closeTag = "</" + tag.Substring(1, 2) + ">";
                    int hEnd = html.IndexOf(closeTag, pos, StringComparison.OrdinalIgnoreCase);
                    if (hEnd < 0) { hEnd = html.IndexOf("</h3>", pos, StringComparison.OrdinalIgnoreCase); }
                    string folderTitle = "Folder";
                    if (hEnd > pos)
                    {
                        folderTitle = StripHtmlTags(html.Substring(pos, hEnd - pos)).Trim();
                        pos = hEnd + closeTag.Length;
                    }

                    // Look for the next <DL> which contains this folder's children
                    var children = new List<BookmarkNode>();
                    int searchLimit = Math.Min(pos + 200, html.Length);
                    int childDL = html.IndexOf("<DL", pos, searchLimit - pos, StringComparison.OrdinalIgnoreCase);
                    if (childDL < 0) childDL = html.IndexOf("<dl", pos, searchLimit - pos, StringComparison.OrdinalIgnoreCase);
                    if (childDL >= 0)
                    {
                        int dlPos = childDL;
                        children = ParseDL(html, ref dlPos);
                        pos = dlPos;
                    }

                    nodes.Add(new BookmarkNode { Type = "folder", Title = folderTitle, Children = children });
                    continue;
                }

                // Link: <A HREF="...">title</A>
                if (tagUpper.StartsWith("<A ") && tagUpper.Contains("HREF"))
                {
                    var (href, title, endPos) = ExtractATag(html, pos);
                    pos = endPos;
                    if (!string.IsNullOrWhiteSpace(href) && Uri.TryCreate(href, UriKind.Absolute, out _))
                        nodes.Add(new BookmarkNode { Type = "link", Title = string.IsNullOrWhiteSpace(title) ? GetDisplayTitle(href) : title, Href = href });
                    continue;
                }

                // Skip any other tag
                pos = closeAngle + 1;
            }
            return nodes;
        }

        private static (string href, string title, int endPos) ExtractATag(string html, int aStart)
        {
            int tagEnd = html.IndexOf('>', aStart);
            if (tagEnd < 0) return ("", "", aStart + 1);
            string tag = html.Substring(aStart, tagEnd - aStart + 1);

            string href = "";
            int hrefStart = tag.IndexOf("HREF=\"", StringComparison.OrdinalIgnoreCase);
            if (hrefStart < 0) hrefStart = tag.IndexOf("href=\"", StringComparison.Ordinal);
            if (hrefStart >= 0)
            {
                hrefStart = tag.IndexOf('"', hrefStart) + 1;
                int hrefEnd = tag.IndexOf('"', hrefStart);
                if (hrefEnd > hrefStart)
                    href = tag.Substring(hrefStart, hrefEnd - hrefStart).Trim();
            }

            string title = "";
            int aEnd = html.IndexOf("</A>", tagEnd, StringComparison.OrdinalIgnoreCase);
            if (aEnd < 0) aEnd = html.IndexOf("</a>", tagEnd, StringComparison.Ordinal);
            if (aEnd > tagEnd)
            {
                title = StripHtmlTags(html.Substring(tagEnd + 1, aEnd - tagEnd - 1)).Trim();
                return (href, title, aEnd + 4);
            }
            return (href, title, tagEnd + 1);
        }

        private static string StripHtmlTags(string s)
        {
            var sb = new StringBuilder();
            bool inTag = false;
            foreach (char c in s)
            {
                if (c == '<') { inTag = true; continue; }
                if (c == '>') { inTag = false; continue; }
                if (!inTag) sb.Append(c);
            }
            return sb.ToString();
        }

        private static int CountLinks(List<BookmarkNode> nodes)
        {
            int count = 0;
            foreach (var n in nodes)
            {
                if (n.Type == "link") count++;
                else if (n.Type == "folder") count += CountLinks(n.Children);
            }
            return count;
        }

        private void ExportBookmarksHtml()
        {
            using var dlg = new SaveFileDialog
            {
                Title = "Export Bookmarks",
                Filter = "Bookmark File (*.html)|*.html",
                FileName = "bookmarks.html",
                RestoreDirectory = true,
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;

            try
            {
                using var w = new StreamWriter(dlg.FileName, false, System.Text.Encoding.UTF8);
                w.WriteLine("<!DOCTYPE NETSCAPE-Bookmark-file-1>");
                w.WriteLine("<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">");
                w.WriteLine("<TITLE>Bookmarks</TITLE>");
                w.WriteLine("<H1>Bookmarks</H1>");
                w.WriteLine("<DL><p>");
                WriteBookmarksHtml(w, bookmarks, "    ");
                w.WriteLine("</DL><p>");
                int count = CountLinks(bookmarks);
                statusLabel.Text = $"Exported {count} bookmarks.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Export failed:\r\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void WriteBookmarksHtml(StreamWriter w, List<BookmarkNode> nodes, string indent)
        {
            foreach (var node in nodes)
            {
                if (node.Type == "folder")
                {
                    var safeTitle = System.Net.WebUtility.HtmlEncode(node.Title);
                    w.WriteLine($"{indent}<DT><H3>{safeTitle}</H3>");
                    w.WriteLine($"{indent}<DL><p>");
                    WriteBookmarksHtml(w, node.Children, indent + "    ");
                    w.WriteLine($"{indent}</DL><p>");
                }
                else
                {
                    var safeTitle = System.Net.WebUtility.HtmlEncode(node.Title);
                    var safeUrl = System.Net.WebUtility.HtmlEncode(node.Href);
                    w.WriteLine($"{indent}<DT><A HREF=\"{safeUrl}\">{safeTitle}</A>");
                }
            }
        }

        private static string GetDisplayTitle(string url)
        {
            try { return new Uri(url).Host; } catch { return url.Length > 30 ? url.Substring(0, 27) + "..." : url; }
        }

        // ── Settings ──
        private static readonly (string Name, string Home, string Search)[] SearchEngines = new[]
        {
            ("Google",      "https://www.google.com",       "https://www.google.com/search?q={0}"),
            ("Bing",        "https://www.bing.com",         "https://www.bing.com/search?q={0}"),
            ("DuckDuckGo",  "https://duckduckgo.com",       "https://duckduckgo.com/?q={0}"),
            ("Yahoo",       "https://search.yahoo.com",     "https://search.yahoo.com/search?p={0}"),
            ("Brave Search","https://search.brave.com",     "https://search.brave.com/search?q={0}"),
            ("Startpage",   "https://www.startpage.com",    "https://www.startpage.com/do/search?q={0}"),
        };

        private void LoadSettings()
        {
            if (!File.Exists(settingsFile)) return;
            try
            {
                foreach (var line in File.ReadAllLines(settingsFile))
                {
                    var parts = line.Split(new[] { '=' }, 2);
                    if (parts.Length != 2) continue;
                    switch (parts[0].Trim().ToLower())
                    {
                        case "homepage": homePageUrl = parts[1].Trim(); break;
                        case "searchurl": searchUrlTemplate = parts[1].Trim(); break;
                    }
                }
            }
            catch { }
        }

        private void SaveSettings()
        {
            try
            {
                File.WriteAllLines(settingsFile, new[]
                {
                    $"homepage={homePageUrl}",
                    $"searchurl={searchUrlTemplate}",
                });
            }
            catch { }
        }

        private void ShowSearchEnginePicker()
        {
            using var dlg = new Form
            {
                Text = "Choose Your Search Engine",
                ClientSize = new Size(360, 340),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                BackColor = Theme.ActiveTab,
                ForeColor = Color.White,
            };

            var label = new Label
            {
                Text = "Select your default search engine:",
                Location = new Point(20, 16),
                AutoSize = true,
                Font = new Font("Segoe UI", 10f),
                ForeColor = Color.White,
            };
            dlg.Controls.Add(label);

            var list = new ListBox
            {
                Location = new Point(20, 48),
                Size = new Size(320, 220),
                Font = new Font("Segoe UI", 11f),
                BackColor = Theme.TitleBar,
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
            };
            foreach (var (name, _, _) in SearchEngines)
                list.Items.Add(name);
            list.SelectedIndex = 0;
            dlg.Controls.Add(list);

            var okBtn = new Button
            {
                Text = "OK",
                Location = new Point(240, 280),
                Size = new Size(100, 36),
                FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Accent,
                ForeColor = Color.Black,
                Font = new Font("Segoe UI", 10f),
                DialogResult = DialogResult.OK,
            };
            okBtn.FlatAppearance.BorderSize = 0;
            dlg.Controls.Add(okBtn);
            dlg.AcceptButton = okBtn;

            if (dlg.ShowDialog(this) == DialogResult.OK && list.SelectedIndex >= 0)
            {
                var choice = SearchEngines[list.SelectedIndex];
                homePageUrl = choice.Home;
                searchUrlTemplate = choice.Search;
            }
            SaveSettings();
        }

        // ── History ──
        private void LoadHistory()
        {
            if (!File.Exists(historyFile)) return;
            history.Clear();
            var lines = File.ReadAllLines(historyFile).Where(l => !string.IsNullOrWhiteSpace(l)).Distinct().ToList();
            history.AddRange(lines.Count <= 100 ? lines : lines.GetRange(lines.Count - 100, 100));
        }

        private void SaveHistory() { File.WriteAllLines(historyFile, history); }

        private void AddToHistory(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return;
            history.RemoveAll(item => string.Equals(item, url, StringComparison.OrdinalIgnoreCase));
            history.Add(url);
            if (history.Count > 100) history.RemoveRange(0, history.Count - 100);
            SaveHistory();
        }

        private void ClearHistory()
        {
            if (MessageBox.Show(this, "Clear all history?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            history.Clear(); SaveHistory(); statusLabel.Text = "History cleared.";
        }

        // ── Ad Blocker (powered by GSecurity Ad Shield + EasyList + EasyPrivacy) ──
        private static readonly HashSet<string> BlockedAdDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            // Google Ads & Analytics
            "doubleclick.net","googleadservices.com","googlesyndication.com","adservice.google.com",
            "ads.google.com","google-analytics.com","googletagmanager.com","googletagservices.com",
            "pagead2.googlesyndication.com","pagead2.googleadservices.com",
            // Major ad networks
            "adnxs.com","taboola.com","outbrain.com","criteo.com","scorecardresearch.com","pubmatic.com",
            "rubiconproject.com","quantserve.com","quantcast.com","omniture.com","comscore.com",
            "krux.com","bluekai.com","exelate.com","adform.com","adroll.com","vungle.com","inmobi.com",
            "flurry.com","mixpanel.com","heap.io","amplitude.com","optimizely.com","bizible.com",
            "pardot.com","hubspot.com","marketo.com","eloqua.com","media.net","appnexus.com","adbrite.com",
            "admob.com","adsonar.com","zergnet.com","revcontent.com","mgid.com","adblade.com","adcolony.com",
            "chartbeat.com","newrelic.com","pingdom.net","kissmetrics.com","tradedesk.com","turn.com",
            "adscale.com","bannerflow.com","nativeads.com","contentad.com","displayads.com",
            "smartadserver.com","openx.net","casalemedia.com","indexww.com","sharethrough.com",
            "33across.com","triplelift.com","sovrn.com","lijit.com","bidswitch.net","yieldmo.com",
            "teads.tv","spotxchange.com","springserve.com","contextweb.com","liveintent.com",
            "adtech.de","adform.net","serving-sys.com","adsafeprotected.com","moatads.com",
            // Facebook / Meta
            "connect.facebook.net","pixel.facebook.com","analytics.facebook.com","ads.facebook.com","an.facebook.com",
            // Twitter / X
            "ads-twitter.com","static.ads-twitter.com","analytics.twitter.com","ads-api.twitter.com","advertising.twitter.com",
            // Reddit
            "pixel.reddit.com","rereddit.com","ads.reddit.com","events.reddit.com","events.redditmedia.com","d.reddit.com",
            // LinkedIn
            "ads.linkedin.com","analytics.pointdrive.linkedin.com",
            // TikTok
            "analytics.tiktok.com","ads.tiktok.com","ads-sg.tiktok.com","analytics-sg.tiktok.com",
            // Pinterest
            "ads.pinterest.com","log.pinterest.com","ads-dev.pinterest.com","analytics.pinterest.com",
            "trk.pinterest.com","trk2.pinterest.com","widgets.pinterest.com",
            // Amazon
            "amazon-adsystem.com","advertising-api-eu.amazon.com","amazonaax.com","amazonclix.com","assoc-amazon.com",
            // YouTube
            "youtubeads.googleapis.com","ads.youtube.com","analytics.youtube.com","video-stats.video.google.com",
            "youtube.cleverads.vn",
            // Yahoo
            "advertising.yahoo.com","ads.yahoo.com","adserver.yahoo.com","global.adserver.yahoo.com",
            "adspecs.yahoo.com","analytics.yahoo.com","analytics.query.yahoo.com","comet.yahoo.com",
            "log.fc.yahoo.com","ganon.yahoo.com","gemini.yahoo.com","beap.gemini.yahoo.com",
            "geo.yahoo.com","marketingsolutions.yahoo.com","pclick.yahoo.com",
            "ads.yap.yahoo.com","m.yap.yahoo.com","partnerads.ysm.yahoo.com",
            // Yandex
            "appmetrica.yandex.com","yandexadexchange.net","adfox.yandex.ru","adsdk.yandex.ru",
            "an.yandex.ru","awaps.yandex.ru","awsync.yandex.ru","bs.yandex.ru","bs-meta.yandex.ru",
            "clck.yandex.ru","informer.yandex.ru","kiks.yandex.ru","mc.yandex.ru","metrika.yandex.ru",
            "share.yandex.ru","offerwall.yandex.net",
            // Hotjar / Session recording
            "hotjar.com","api-hotjar.com","hotjar-analytics.com","fullstory.com","mouseflow.com",
            "luckyorange.com","luckyorange.net","freshmarketer.com",
            // Segment / Analytics
            "segment.io","segment.com","stats.wp.com",
            // Error trackers
            "notify.bugsnag.com","sessions.bugsnag.com","api.bugsnag.com","app.bugsnag.com",
            "browser.sentry-cdn.com","app.getsentry.com",
            // FastClick
            "fastclick.com","fastclick.net",
            // Samsung
            "samsungadhub.com","samsungads.com","smetrics.samsung.com","nmetrics.samsung.com",
            "analytics.samsungknox.com","bigdata.ssp.samsung.com","config.samsungads.com",
            // Apple metrics
            "metrics.apple.com","securemetrics.apple.com","supportmetrics.apple.com",
            "metrics.icloud.com","metrics.mzstatic.com","books-analytics-events.apple.com",
            "stocks-analytics-events.apple.com",
            // Xiaomi
            "api.ad.xiaomi.com","data.mistat.xiaomi.com","sdkconfig.ad.xiaomi.com",
            "globalapi.ad.xiaomi.com","tracking.miui.com","tracking.intl.miui.com",
            // Huawei
            "metrics.data.hicloud.com","logservice.hicloud.com","logbak.hicloud.com",
            // OPPO / Realme / OnePlus
            "adsfs.oppomobile.com","bdapi-in-ads.realmemobile.com",
            "analytics.oneplus.cn","click.oneplus.cn","click.oneplus.com","open.oneplus.net",
            // Missing from d3ward test
            "events.hotjar.io","extmaps-api.yandex.net","metrics2.data.hicloud.com",
            "logservice1.hicloud.com","iot-eu-logser.realme.com","click.googleanalytics.com",
            "grs.hicloud.com","udcm.yahoo.com","auction.unityads.unity3d.com",
            "config.unityads.unity3d.com","adserver.unityads.unity3d.com","webview.unityads.unity3d.com",
            "adfstat.yandex.ru","iadsdk.apple.com","appmetrica.yandex.ru",
            "business-api.tiktok.com","log.byteoversea.com","ads-api.tiktok.com",
            "iot-logser.realme.com","tracking.rus.miui.com","adtech.yahooinc.com",
            "bdapi-ads.realmemobile.com","ck.ads.oppomobile.com","data.ads.oppomobile.com",
            "adx.ads.oppomobile.com","data.mistat.india.xiaomi.com","data.mistat.rus.xiaomi.com",
            "notes-analytics-events.apple.com","weather-analytics-events.apple.com",
            "api-adservices.apple.com","samsung-com.112.2o7.net","analytics-api.samsunghealthcn.com",
            "unityads.unity3d.com","byteoversea.com","yahooinc.com",
            // S3-hosted ad/analytics buckets
            "adtago.s3.amazonaws.com","analyticsengine.s3.amazonaws.com",
            "analytics.s3.amazonaws.com","advice-ads.s3.amazonaws.com",
            // Adult site ad networks
            "trafficjunky.com","trafficjunky.net","trafficstars.com","tsyndicate.com",
            "exoclick.com","exosrv.com","exoticads.com","juicyads.com","realsrv.com",
            "adsrv.org","padsdel.com","tsyndicate.com","syndication.exoclick.com",
            "main.exoclick.com","static.exoclick.com","ads.trafficjunky.net",
            "cdn.trafficjunky.net","adsrv.eacdn.com","a.realsrv.com",
            "mc.yandex.ru","syndication.realsrv.com","s.magsrv.com","magsrv.com",
            // Additional missing
            "sdkconfig.ad.intl.xiaomi.com","iot-eu-logser.realme.com","iot-logser.realme.com",
            "bdapi-ads.realmemobile.com","analytics-api.samsunghealthcn.com",
        };

        private static readonly HashSet<string> AdBlockWhitelist = new(StringComparer.OrdinalIgnoreCase)
        {
            "discord.com", "discordapp.com", "discord.gg", "discord.media",
            "apple.com", "icloud.com",
            "ebay.com",
            "paypal.com",
            "mediafire.com",
            // Auth/OAuth providers
            "accounts.google.com", "accounts.youtube.com", "myaccount.google.com",
            "google.com", "www.google.com", "google.hr", "google.co.uk",
            "youtube.com", "www.youtube.com",
            "login.microsoftonline.com", "login.live.com", "login.microsoft.com",
            "appleid.apple.com", "idmsa.apple.com",
            "github.com", "auth0.com", "okta.com",
            "apis.google.com", "ssl.gstatic.com",
            "pay.google.com", "payments.google.com",
            "gog.com", "auth.gog.com", "login.gog.com",
            "suno.com", "suno.ai", "clerk.suno.com",
            // AI services
            "openai.com", "chat.openai.com", "chatgpt.com",
            "claude.ai", "anthropic.com",
            "gemini.google.com", "bard.google.com",
            "perplexity.ai", "you.com",
            "midjourney.com", "stability.ai",
            "huggingface.co", "replicate.com",
            "udio.com", "poe.com", "character.ai",
            "copilot.microsoft.com",
            // Banking & financial
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
            "usbank.com", "capitalone.com", "discover.com", "americanexpress.com",
            "hsbc.com", "barclays.com", "natwest.com", "lloydsbank.com",
            "revolut.com", "wise.com", "transferwise.com", "stripe.com",
            "squareup.com", "venmo.com", "zelle.com", "cash.app",
            "ing.com", "raiffeisen.hr", "pbz.hr", "zaba.hr", "erstebank.hr",
            "n26.com", "monzo.com", "starlingbank.com",
            // Gaming clients & stores
            "steampowered.com", "store.steampowered.com", "steamcommunity.com",
            "epicgames.com", "unrealengine.com",
            "gog.com", "gogalaxy.com",
            "ea.com", "origin.com",
            "ubisoft.com", "ubi.com",
            "blizzard.com", "battle.net", "battlenet.com.cn",
            "riotgames.com", "leagueoflegends.com",
            "xbox.com", "xboxlive.com",
            "playstation.com", "sonyentertainmentnetwork.com",
            "nintendo.com", "nintendo.net",
            "humblebundle.com", "itch.io", "indiegala.com",
            "twitch.tv",
        };

        private static bool IsAdBlockWhitelisted(string host)
        {
            while (host.Contains('.'))
            {
                if (AdBlockWhitelist.Contains(host)) return true;
                int dot = host.IndexOf('.');
                host = host.Substring(dot + 1);
            }
            return false;
        }

        /// <summary>
        /// Checks if a URL points to a known ad/tracking domain.
        /// Used to block navigations and new windows to ad destinations.
        /// </summary>
        private bool IsAdUrl(string url)
        {
            try
            {
                var uri = new Uri(url.Contains("://") ? url : "https://" + url);
                var host = uri.Host.ToLower();
                // Don't block whitelisted domains
                if (IsAdBlockWhitelisted(host)) return false;
                // Check against blocklist
                var checkHost = host;
                while (checkHost.Contains('.'))
                {
                    if (BlockedAdDomains.Contains(checkHost)) return true;
                    int dot = checkHost.IndexOf('.');
                    checkHost = checkHost.Substring(dot + 1);
                }
                // Check common ad URL patterns
                if (url.Contains("/pagead/") || url.Contains("/adclick") ||
                    url.Contains("/aclk?") || url.Contains("googleadservices.com") ||
                    url.Contains("doubleclick.net") || url.Contains("googlesyndication.com"))
                    return true;
            }
            catch { }
            return false;
        }

        private int adsBlockedCount = 0;

        private void SetupAdBlocker(CoreWebView2 core)
        {
            // Track whether the current page is whitelisted — avoids per-request URI parsing
            bool pageIsWhitelisted = false;
            core.SourceChanged += (_, _) =>
            {
                try { pageIsWhitelisted = IsAdBlockWhitelisted(new Uri(core.Source ?? "").Host.ToLower()); }
                catch { pageIsWhitelisted = false; }
            };

            // Register filters for resource types that serve ads — NOT All, which would
            // intercept upload streams and add IPC overhead on every data chunk
            var adResourceTypes = new[]
            {
                CoreWebView2WebResourceContext.Script,
                CoreWebView2WebResourceContext.Image,
                CoreWebView2WebResourceContext.Stylesheet,
                CoreWebView2WebResourceContext.XmlHttpRequest,  // covers XHR, Fetch, EventSource
                CoreWebView2WebResourceContext.Media,
                CoreWebView2WebResourceContext.Font,
            };
            foreach (var resourceType in adResourceTypes)
                core.AddWebResourceRequestedFilter("*://*", resourceType);
            core.WebResourceRequested += (_, args) =>
            {
                try
                {
                    // Fast path: skip all checks when on a whitelisted page (GitHub, Discord, etc.)
                    if (pageIsWhitelisted) return;

                    var uri = new Uri(args.Request.Uri);
                    var host = uri.Host.ToLower();
                    // Skip whitelisted request hosts
                    if (IsAdBlockWhitelisted(host)) return;
                    // Check if the host or any parent domain is in the block list
                    var checkHost = host;
                    while (checkHost.Contains('.'))
                    {
                        if (BlockedAdDomains.Contains(checkHost))
                        {
                            args.Response = core.Environment.CreateWebResourceResponse(null, 403, "Blocked", "");
                            adsBlockedCount++;
                            return;
                        }
                        int dot = checkHost.IndexOf('.');
                        checkHost = checkHost.Substring(dot + 1);
                    }
                }
                catch { }
            };

            // Inject YouTube ad blocker into main world via DevTools Protocol
            // Page.addScriptToEvaluateOnNewDocument runs in the main world BEFORE any page scripts
            _ = InjectYouTubeMainWorldBlocker(core);

            // Inject fetch/XHR blocker into main world via DevTools Protocol
            core.NavigationCompleted += (_, _) => InjectMainWorldBlocker(core);
        }

        private static async Task InjectYouTubeMainWorldBlocker(CoreWebView2 core)
        {
            try
            {
                // Page.addScriptToEvaluateOnNewDocument injects into the MAIN world
                // before any page scripts run — critical for intercepting ytInitialData.
                // The JS itself has a strict YouTube-only hostname guard + auth domain exclusion
                // so it completely no-ops on auth popups, OAuth flows, etc.
                string escapedJs = YouTubeMainWorldCode.Replace("\\", "\\\\").Replace("\"", "\\\"");
                string cdpParams = "{\"source\":\"" + escapedJs + "\"}";
                await core.CallDevToolsProtocolMethodAsync("Page.addScriptToEvaluateOnNewDocument", cdpParams);
            }
            catch
            {
                // Fallback to AddScriptToExecuteOnDocumentCreatedAsync with <script> tag injection
                _ = core.AddScriptToExecuteOnDocumentCreatedAsync(YouTubeMainWorldInjectorJs);
            }
        }

        private const string AdElementHiderJs = @"(function() {
            if (window.__ceprkacAdHider) return;
            window.__ceprkacAdHider = true;

            /* CSS-based hiding — catches ads before JS runs */
            var css = document.createElement('style');
            css.textContent = [
                'ins.adsbygoogle','[id*=""google_ads""]','[class*=""ad-slot""]','[class*=""advert""]',
                '[class*=""ad-banner""]','[class*=""ad-container""]','[class*=""ad-wrapper""]',
                '[class*=""sponsor""]','[class*=""ad-placement""]','[class*=""ad_""]',
                '[data-ad]','[data-adunit]','[data-ad-slot]','[data-google-query-id]',
                '.sponsored-content','.promoted','.ad-banner','.ad-container','.ad-wrapper',
                '.native-ad','.ad-unit','.ad-zone','.ad-area','.ad-block','.ad-box','.ad-frame',
                '.ad-header','.ad-footer','.ad-leaderboard','.ad-sidebar','.ad-skyscraper',
                '.ad-rectangle','.ad-interstitial','.ad-overlay','.ad-popup','.ad-modal',
                'div[id*=""taboola""]','div[id*=""outbrain""]','div[class*=""taboola""]',
                'div[class*=""outbrain""]','div[id*=""zergnet""]','div[id*=""revcontent""]',
                'div[id*=""mgid""]','div[class*=""mgid""]',
                'iframe[src*=""doubleclick""]','iframe[src*=""googlesyndication""]',
                'iframe[src*=""googletagmanager""]','iframe[id*=""google_ads""]','iframe[id*=""aswift""]',
                'iframe[src*=""ad""][width]','iframe[data-ad]',
                '.video-ad-overlay','.preroll-ad','.midroll-ad',
                'a[href*=""doubleclick.net""]','a[href*=""googleadservices""]',
                'div[aria-label=""Advertisement""]','div[aria-label=""advertisement""]',
                'section[aria-label=""Sponsored""]',
                /* Pornhub / adult site ads */
                '.adBanner','.ad-banner','#hd-rightColAd','#pb_ad','.advertisement',
                '.mgbox','[class*=""mgbox""]','div[id*=""snigelAdStack""]',
                '.trafficStars','[class*=""trafficStars""]','[id*=""trafficStars""]',
                '[class*=""exoclick""]','[id*=""exoclick""]',
                'iframe[src*=""trafficstars""]','iframe[src*=""exoclick""]',
                'iframe[src*=""trafficjunky""]','iframe[src*=""adsrv""]',
                'iframe[src*=""juicyads""]','iframe[src*=""exosrv""]',
                'iframe[src*=""tsyndicate""]','iframe[src*=""realsrv""]',
                'div[class*=""abovePlayer""]','div[id*=""adblock""]',
                '.removeAdMessage','#removeAdblockContainer',
                /* DuckDuckGo sponsored results and self-promo */
                '.result--ad','.is-ad','[data-testid=""ad""]','[data-testid=""result--ad""]',
                '.badge--ad','.result__extras__url--ad',
                '.ddg-extension-hide','.js-sidebar-ads','.sidebar-modules--ads',
                '.header-aside',
                /* Google sponsored results */
                '#tads','#tadsb','#bottomads','.commercial-unit-desktop-top',
                '.commercial-unit-desktop-rhs','.cu-container',
                'div[data-text-ad]','div[data-hveid] .uEierd',
                /* Bing sponsored results */
                '.b_ad','.b_adSlug','li.b_ad','#b_results > .b_ad',
                /* Yahoo sponsored results */
                '.searchCenterTopAds','.searchCenterBottomAds','.compDlink',
                /* Reddit promoted posts (GSecurity Ad Shield) */
                'shreddit-ad-post','[data-testid=""ad-post""]','[data-testid=""promoted-post""]',
                'div[data-promoted=""true""]','.promotedlink','.sponsorshipbox','.sponsor-logo',
                'faceplate-tracker[source=""ad""]','faceplate-tracker[noun=""ad""]',
                '[data-testid=""sidebar-ad""]','[data-testid=""subreddit-sidebar-ad""]',
                '.sidebar-ad','div[class*=""promotedlink""]','.premium-banner-outer',
                '[data-testid=""premium-upsell""]',
                'shreddit-experience-tree[bundlename*=""ad""]','shreddit-experience-tree[bundlename*=""Ad""]',
                '.thing.promoted','.thing.stickied.promotedlink',
                /* LinkedIn ads */
                '[data-ad-banner-id]','[data-is-sponsored=""true""]',
                '.ad-banner-container','.ads-container',
                /* Twitch ads */
                '[data-a-target=""video-ad-label""]','.video-ad','.advertisement-banner',
                '[data-test-selector=""ad-banner-default-id""]','.stream-display-ad',
                /* TikTok ads */
                '[class*=""DivAdBanner""]','[data-e2e=""ad""]'
            ].join(',') + '{display:none!important;height:0!important;min-height:0!important;overflow:hidden!important}';
            (document.head || document.documentElement).appendChild(css);

            /* DOM removal selectors */
            var sels = [
                'ins.adsbygoogle','iframe[src*=""doubleclick""]','iframe[src*=""googlesyndication""]',
                'iframe[src*=""googletagmanager""]','iframe[id*=""google_ads""]','iframe[id*=""aswift""]',
                'iframe[src*=""ad""][width]','iframe[data-ad]',
                '[id*=""google_ads""]','[class*=""ad-slot""]','[class*=""advert""]','[class*=""ad-banner""]',
                '[class*=""ad-container""]','[class*=""ad-wrapper""]','[class*=""sponsor""]',
                '[class*=""ad-placement""]','[class*=""ad_""]',
                '[data-ad]','[data-adunit]','[data-ad-slot]','[data-google-query-id]',
                '.sponsored-content','.promoted','.ad-banner','.ad-container','.ad-wrapper',
                '.native-ad','.ad-unit','.ad-zone','.ad-area','.ad-block','.ad-box','.ad-frame',
                '.ad-header','.ad-footer','.ad-leaderboard','.ad-sidebar','.ad-skyscraper',
                '.ad-rectangle','.ad-interstitial','.ad-overlay','.ad-popup','.ad-modal',
                'div[id*=""taboola""]','div[id*=""outbrain""]','div[class*=""taboola""]',
                'div[class*=""outbrain""]','div[id*=""zergnet""]','div[id*=""revcontent""]',
                'div[id*=""mgid""]','div[class*=""mgid""]',
                '.video-ad-overlay','.preroll-ad','.midroll-ad',
                'div[aria-label=""Advertisement""]','div[aria-label=""advertisement""]',
                /* Search engine sponsored results */
                '.result--ad','.is-ad','[data-testid=""ad""]','[data-testid=""result--ad""]',
                '.badge--ad','.ddg-extension-hide','.js-sidebar-ads','.header-aside',
                '#tads','#tadsb','#bottomads','.commercial-unit-desktop-top',
                '.commercial-unit-desktop-rhs','div[data-text-ad]',
                '.b_ad','.b_adSlug','li.b_ad',
                '.searchCenterTopAds','.searchCenterBottomAds',
                /* Reddit (GSecurity Ad Shield) */
                'shreddit-ad-post','[data-testid=""ad-post""]','[data-testid=""promoted-post""]',
                'div[data-promoted=""true""]','.promotedlink','.sponsorshipbox','.sponsor-logo',
                '#ad-frame','#ad_main',
                'faceplate-tracker[source=""ad""]','faceplate-tracker[noun=""ad""]',
                '[data-testid=""sidebar-ad""]','[data-testid=""subreddit-sidebar-ad""]',
                'shreddit-experience-tree[bundlename*=""ad""]','shreddit-experience-tree[bundlename*=""Ad""]',
                '.premium-banner-outer','[data-testid=""premium-upsell""]',
                /* LinkedIn */
                '[data-ad-banner-id]','[data-is-sponsored=""true""]',
                '.ad-banner-container','.ads-container',
                /* Twitch */
                '[data-a-target=""video-ad-label""]','.video-ad','.advertisement-banner',
                '[data-test-selector=""ad-banner-default-id""]','.stream-display-ad',
                /* TikTok */
                '[class*=""DivAdBanner""]','[data-e2e=""ad""]'
            ];
            function scrub() {
                for (var i = 0; i < sels.length; i++) {
                    try {
                        var els = document.querySelectorAll(sels[i]);
                        for (var j = 0; j < els.length; j++) {
                            if (els[j] && els[j].parentElement) els[j].remove();
                        }
                    } catch(e) {}
                }
                /* Reddit: walk feed posts and remove promoted ones */
                try {
                    document.querySelectorAll('article, [data-testid=""post-container""], .thing').forEach(function(post) {
                        var badges = post.querySelectorAll('span, faceplate-tracker, [slot=""credit-bar""], .tagline');
                        for (var k = 0; k < badges.length; k++) {
                            var text = (badges[k].textContent || '').trim().toLowerCase();
                            if (text === 'promoted' || text === 'sponsored') { post.remove(); break; }
                        }
                    });
                    document.querySelectorAll('shreddit-post').forEach(function(post) {
                        if (post.hasAttribute('is-promoted') || post.getAttribute('post-type') === 'promoted') post.remove();
                    });
                } catch(e) {}
                /* Facebook: hide sponsored articles */
                try {
                    document.querySelectorAll('div[role=""article""], div[role=""feed""] > div').forEach(function(article) {
                        var spans = article.querySelectorAll('span');
                        for (var k = 0; k < spans.length; k++) {
                            if ((spans[k].textContent || '').trim().toLowerCase() === 'sponsored') {
                                article.style.display = 'none'; break;
                            }
                        }
                    });
                } catch(e) {}
                /* Twitter/X: hide promoted tweets */
                try {
                    document.querySelectorAll('article, [data-testid=""placementTracking""]').forEach(function(el) {
                        var text = (el.textContent || '').toLowerCase();
                        if (/\bpromoted\b/.test(text) || /\bad\s*·/.test(text) || el.matches('[data-testid=""placementTracking""]')) {
                            el.style.display = 'none';
                        }
                    });
                } catch(e) {}
                /* Instagram: hide sponsored posts */
                try {
                    document.querySelectorAll('article').forEach(function(a) {
                        if (/\bsponsored\b/i.test(a.textContent || '')) a.style.display = 'none';
                    });
                    document.querySelectorAll('[data-testid=""reel-ad""]').forEach(function(el) { el.remove(); });
                } catch(e) {}
            }
            scrub();
            setInterval(scrub, 1500);
            new MutationObserver(scrub).observe(document.documentElement, {childList:true, subtree:true});
        })()";

        private const string YouTubeAdBlockerJs = @"(function() {
            if (window.__ceprkacYtAdBlock) return;
            window.__ceprkacYtAdBlock = true;
            var s = document.createElement('style');
            s.textContent = 'ytd-display-ad-renderer,ytd-ad-slot-renderer,ytd-promoted-video-renderer,ytd-promoted-sparkles-web-renderer,ytd-promoted-sparkles-text-search-renderer,ytd-banner-promo-renderer,ytd-statement-banner-renderer,ytd-in-feed-ad-layout-renderer,ytd-masthead-ad-renderer,ytd-primetime-promo-renderer,ytd-compact-promoted-video-renderer,ytd-action-companion-ad-renderer,ytd-mealbar-promo-renderer,ytd-enforcement-message-view-model,ytd-engagement-panel-section-list-renderer[target-id=engagement-panel-ads],#masthead-ad,#player-ads,.video-ads,.ytp-ad-module,.ytp-ad-overlay-container,.ytp-ad-player-overlay,.ytp-ad-action-interstitial,.ytp-ad-image-overlay,.ytp-ad-text-overlay,.ytp-ad-skip-ad-slot,.ad-showing .ytp-ad-module,ytd-search-pyv-renderer,ytd-movie-offer-module-renderer,tp-yt-paper-dialog:has(#dismiss-button),ytd-popup-container:has(a[href*=""/premium""]),ytd-rich-item-renderer:has(ytd-ad-slot-renderer),ytd-rich-item-renderer:has(ytd-display-ad-renderer),ytd-rich-item-renderer:has(ytd-promoted-video-renderer),ytd-rich-item-renderer:has(ytd-promoted-sparkles-web-renderer),ytd-rich-section-renderer:has(ytd-ad-slot-renderer){display:none!important}';
            (document.head||document.documentElement).appendChild(s);
            var adKeys=['adPlacements','adSlots','playerAds','adBreakHeartbeatParams','ad3Module','adSafetyReason','adLoggingData','showAdSlots','adBreakParams','adBreakStatus','adVideoId','adLayoutLoggingData','instreamAdPlayerOverlayRenderer','adPlacementConfig','adVideoStitcherConfig','promotedSparklesWebRenderer','promotedSparklesTextSearchRenderer','promotedVideoRenderer','sponsoredCardRenderer','adSlotRenderer','displayAdRenderer','inFeedAdLayoutRenderer','mastheadAdRenderer','compactPromotedVideoRenderer','actionCompanionAdRenderer','bannerPromoRenderer','statementBannerRenderer','primeTimePromoRenderer','searchPyvRenderer','movieOfferModuleRenderer','adPlacementRenderer','sparklesAdRenderer'];
            function stripAds(o,d){if(!o||typeof o!=='object'||d>12)return;for(var i=0;i<adKeys.length;i++)if(o.hasOwnProperty(adKeys[i]))delete o[adKeys[i]];var k=Object.keys(o);for(var j=0;j<k.length;j++){var key=k[j],val=o[key];if(Array.isArray(val)){for(var m=val.length-1;m>=0;m--){var item=val[m];if(item&&typeof item==='object'){var ik=Object.keys(item);for(var n=0;n<ik.length;n++){if(/^(ad|promoted|sponsor)/i.test(ik[n])){val.splice(m,1);break;}}}}}else if(val&&typeof val==='object')stripAds(val,d+1);}}
            var op=JSON.parse;JSON.parse=function(){var r=op.apply(this,arguments);try{if(r&&typeof r==='object')stripAds(r,0);}catch(e){}return r;};
            ['ytInitialPlayerResponse','ytInitialData','ytcfg'].forEach(function(p){var v=window[p];try{Object.defineProperty(window,p,{configurable:true,get:function(){return v;},set:function(n){if(n&&typeof n==='object')stripAds(n,0);v=n;}});if(v)window[p]=v;}catch(e){}});
            var adS=['.video-ads','.ytp-ad-module','.ytp-ad-overlay-container','.ytp-ad-player-overlay','.ytp-ad-action-interstitial','.ytp-ad-image-overlay','.ytp-ad-text-overlay','#player-ads','#masthead-ad','ytd-display-ad-renderer','ytd-ad-slot-renderer','ytd-promoted-video-renderer','ytd-promoted-sparkles-web-renderer','ytd-banner-promo-renderer','ytd-in-feed-ad-layout-renderer','ytd-mealbar-promo-renderer','ytd-enforcement-message-view-model','ytd-search-pyv-renderer','ytd-movie-offer-module-renderer','ytd-compact-promoted-video-renderer','ytd-action-companion-ad-renderer','ytd-primetime-promo-renderer','ytd-masthead-ad-renderer'];
            var skS=['.ytp-ad-skip-button','.ytp-skip-ad-button','.ytp-ad-skip-button-modern','.ytp-skip-ad-button__text','button[class*=""skip""]','.ytp-ad-overlay-close-button','.ytp-ad-skip-button-slot'];
            /* Localized sponsored/ad badge words — covers major YouTube UI languages */
            var sponsorWords=['sponsored','sponzorirano','gesponsert','sponsorisé','patrocinado','sponsorizzato','gesponsord','спонсируемая','スポンサー','赞助','광고','reklam','promowane','sponzorované','szponzorált','annonce','reklama','hirdetés','реклама','commandité','gesponsord','publicidad','pubblicità','anúncio','reklame','sponzorováno','sponzorované','sponzorirane','спонзорирано'];
            function isSponsoredText(t){t=t.trim().toLowerCase();for(var i=0;i<sponsorWords.length;i++){if(t===sponsorWords[i])return true;}return false;}
            function scrub(){for(var i=0;i<adS.length;i++)document.querySelectorAll(adS[i]).forEach(function(e){var p=e.closest('ytd-rich-item-renderer,ytd-rich-section-renderer,ytd-reel-shelf-renderer');if(p)p.remove();else e.remove();});for(var j=0;j<skS.length;j++)document.querySelectorAll(skS[j]).forEach(function(b){if(b.click)b.click();});/* Walk homepage rich grid items and remove sponsored cards by badge text */try{document.querySelectorAll('ytd-rich-item-renderer,ytd-rich-section-renderer').forEach(function(item){if(item.querySelector('ytd-ad-slot-renderer,ytd-display-ad-renderer,ytd-promoted-video-renderer,ytd-promoted-sparkles-web-renderer,ytd-in-feed-ad-layout-renderer')){item.remove();return;}var badges=item.querySelectorAll('span.ytd-badge-supported-renderer,ytd-badge-supported-renderer span,div.ytd-badge-supported-renderer,ytd-badge-supported-renderer,[class*=""badge""],.badge,.badge-style-type-ad,span[aria-label]');for(var k=0;k<badges.length;k++){if(isSponsoredText(badges[k].textContent||'')){item.remove();return;}}/* Check inline-block ad metadata text */var metas=item.querySelectorAll('#metadata-line span,#byline-container span,yt-formatted-string.ytd-channel-name');for(var m=0;m<metas.length;m++){if(isSponsoredText(metas[m].textContent||'')){item.remove();return;}}});}catch(e){}/* Walk search results for promoted items */try{document.querySelectorAll('ytd-video-renderer,ytd-compact-video-renderer').forEach(function(item){var badges=item.querySelectorAll('span.ytd-badge-supported-renderer,ytd-badge-supported-renderer span,[class*=""badge""]');for(var k=0;k<badges.length;k++){if(isSponsoredText(badges[k].textContent||'')){item.remove();return;}}});}catch(e){}var p=document.querySelector('.html5-video-player'),v=document.querySelector('video');if(p&&v&&(p.classList.contains('ad-showing')||p.classList.contains('ad-interrupting'))){if(Number.isFinite(v.duration)&&v.duration>0){v.currentTime=Math.max(0,v.duration-0.1);}v.muted=true;v.playbackRate=16;try{v.play();}catch(e){}p.classList.remove('ad-showing');p.classList.remove('ad-interrupting');p.classList.remove('ad-created');document.querySelectorAll('.ytp-ad-skip-button,.ytp-skip-ad-button,.ytp-ad-skip-button-modern').forEach(function(b){b.click();});setTimeout(function(){v.muted=false;v.playbackRate=1;},500);}document.querySelectorAll('ytd-rich-item-renderer').forEach(function(el){var hasAd=!!el.querySelector('ytd-ad-slot-renderer,ytd-display-ad-renderer,ytd-promoted-video-renderer,ytd-promoted-sparkles-web-renderer');if(hasAd){el.remove();return;}});document.querySelectorAll('tp-yt-paper-dialog').forEach(function(d){var t=(d.textContent||'').toLowerCase();if(t.includes('ad blocker')||t.includes('allow ads')){var b=d.querySelector('#dismiss-button,.dismiss-button,button');if(b&&b.click)b.click();d.remove();}});}
            scrub();setInterval(scrub,200);new MutationObserver(scrub).observe(document.documentElement,{childList:true,subtree:true});
        })()";

        // Main-world YouTube ad blocker — built at runtime to handle nested quotes cleanly
        // Raw main-world code (no <script> tag wrapper) for Page.addScriptToEvaluateOnNewDocument
        private static readonly string YouTubeMainWorldCode = BuildYouTubeMainWorldCode();
        // Fallback: wraps the main world code in a <script> tag for AddScriptToExecuteOnDocumentCreatedAsync
        private static readonly string YouTubeMainWorldInjectorJs = BuildYouTubeInjector();

        private static string BuildYouTubeMainWorldCode()
        {
            return
                "(function(){" +
                // Strict YouTube-only guard — never run on auth/OAuth domains
                "var h=location.hostname.toLowerCase();" +
                "if(h!=='youtube.com'&&h!=='www.youtube.com'&&h!=='m.youtube.com'&&h!=='music.youtube.com'&&!h.endsWith('.youtube.com'))return;" +
                // Extra safety: bail on any auth/OAuth page that might be in a YouTube subdomain
                "if(/accounts\\.google|login\\.microsoft|appleid\\.apple|auth0\\.com|clerk\\.|oauth/.test(h))return;" +
                "if(window.__ceprkacYtMain)return;window.__ceprkacYtMain=true;" +
                // Extended ad keys list
                "var adKeys=['adPlacements','adSlots','playerAds','adBreakHeartbeatParams','ad3Module'," +
                "'adSafetyReason','adLoggingData','showAdSlots','adBreakParams','adBreakStatus'," +
                "'adVideoId','adLayoutLoggingData','instreamAdPlayerOverlayRenderer'," +
                "'adPlacementConfig','adVideoStitcherConfig'," +
                "'promotedSparklesWebRenderer','promotedSparklesTextSearchRenderer'," +
                "'promotedVideoRenderer','sponsoredCardRenderer','adSlotRenderer'," +
                "'displayAdRenderer','inFeedAdLayoutRenderer','mastheadAdRenderer'," +
                "'compactPromotedVideoRenderer','actionCompanionAdRenderer'," +
                "'bannerPromoRenderer','statementBannerRenderer','primeTimePromoRenderer'," +
                "'searchPyvRenderer','movieOfferModuleRenderer','adPlacementRenderer','sparklesAdRenderer'];" +
                // Recursive strip function — deletes ad keys and splices ad items from arrays
                "function strip(o,d){if(!o||typeof o!=='object'||d>15)return;" +
                "for(var i=0;i<adKeys.length;i++)if(o.hasOwnProperty(adKeys[i]))delete o[adKeys[i]];" +
                "var k=Object.keys(o);for(var j=0;j<k.length;j++){" +
                "var key=k[j],val=o[key];" +
                "if(Array.isArray(val)){for(var m=val.length-1;m>=0;m--){" +
                "var item=val[m];if(item&&typeof item==='object'){" +
                "var ik=Object.keys(item);var isAd=false;" +
                "for(var n=0;n<ik.length;n++){" +
                "if(/^(ad|promoted|sponsor)/i.test(ik[n])){isAd=true;break;}}" +
                // Also check for adSlotRenderer or promotedVideoRenderer nested inside richItemRenderer
                "if(!isAd&&item.richItemRenderer&&item.richItemRenderer.content){" +
                "var ck=Object.keys(item.richItemRenderer.content);" +
                "for(var c=0;c<ck.length;c++){if(/^(ad|promoted|sponsor)/i.test(ck[c])){isAd=true;break;}}}" +
                // Check for badge text indicating sponsored content (BADGE_STYLE_TYPE_AD or localized label)
                "if(!isAd){try{var js=JSON.stringify(item);" +
                "if(/\"style\":\"BADGE_STYLE_TYPE_AD\"/.test(js)||" +
                "/\"label\":\"(?:Sponsored|Sponzorirano|Gesponsert|Sponsorisé|Patrocinado|Sponsorizzato|Gesponsord|Реклама|Рекламa|スポンサー|赞助|광고|Reklam|Promowane|Sponzorované|Szponzorált|Annonce|Reklama|Hirdetés|Commandité|Publicidad|Pubblicità|Anúncio|Reklame|Sponzorováno|Sponzorirane|Спонзорирано)\"/.test(js))" +
                "{isAd=true;}}catch(e){}}" +
                "if(isAd){val.splice(m,1);}" +
                "else{strip(item,d+1);}" +
                "}}" +
                "}else if(val&&typeof val==='object')strip(val,d+1);}}" +
                // Intercept JSON.parse — catches ytInitialData embedded in <script> tags
                "var op=JSON.parse;JSON.parse=function(){var r=op.apply(this,arguments);" +
                "try{if(r&&typeof r==='object')strip(r,0);}catch(e){}return r;};" +
                // Intercept ytInitialPlayerResponse, ytInitialData — catches direct assignments
                "['ytInitialPlayerResponse','ytInitialData'].forEach(function(p){var v=window[p];" +
                "try{Object.defineProperty(window,p,{configurable:true," +
                "get:function(){return v;},set:function(n){if(n&&typeof n==='object')strip(n,0);v=n;}});" +
                "if(v)window[p]=v;}catch(e){}});" +
                // Intercept fetch responses for YouTube API calls (browse/search/next/player)
                "var oFetch=window.fetch;window.fetch=function(){var args=arguments;" +
                "var url=typeof args[0]==='string'?args[0]:(args[0]&&args[0].url?args[0].url:'');" +
                "if(!/youtubei\\/v1\\/(browse|search|next|player|reel)/.test(url))return oFetch.apply(this,args);" +
                "return oFetch.apply(this,args).then(function(resp){" +
                "if(!resp||!resp.ok)return resp;" +
                "return resp.clone().text().then(function(txt){" +
                "try{var data=op.call(JSON,txt);strip(data,0);" +
                "return new Response(JSON.stringify(data),{status:resp.status,statusText:resp.statusText,headers:resp.headers});" +
                "}catch(e){return resp;}});});};" +
                "})()";
        }

        // Fallback injector — wraps the main world code in a <script> tag for AddScriptToExecuteOnDocumentCreatedAsync
        private static string BuildYouTubeInjector()
        {
            string escaped = YouTubeMainWorldCode.Replace("\\", "\\\\").Replace("'", "\\'");
            return "(function(){if(location.hostname.indexOf('youtube')===-1)return;" +
                   "var sc=document.createElement('script');" +
                   "sc.textContent='" + escaped + "';" +
                   "(document.head||document.documentElement).appendChild(sc);sc.remove();})()";
        }

        private async Task LoadOrUpdateBlocklistAsync()
        {
            // Load bundled blocklist from app directory
            var bundledList = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "blocklist.txt");
            if (File.Exists(bundledList))
            {
                int count = 0;
                foreach (var line in File.ReadAllLines(bundledList))
                {
                    var domain = line.Trim();
                    if (!string.IsNullOrEmpty(domain) && !domain.StartsWith("#") && domain.Contains('.'))
                    {
                        BlockedAdDomains.Add(domain);
                        count++;
                    }
                }
                statusLabel.Text = $"Ad blocker: {BlockedAdDomains.Count} domains loaded.";
            }

            // Also try to load/update from appdata (user can drop a custom blocklist.txt there)
            var userList = Path.Combine(appDataFolder, "blocklist.txt");
            if (File.Exists(userList))
            {
                foreach (var line in File.ReadAllLines(userList))
                {
                    var domain = line.Trim();
                    if (!string.IsNullOrEmpty(domain) && !domain.StartsWith("#") && domain.Contains('.'))
                        BlockedAdDomains.Add(domain);
                }
            }
            await Task.CompletedTask;
        }

        private async void InjectMainWorldBlocker(CoreWebView2 core)
        {
            if (BlockedAdDomains.Count == 0) return;
            // Skip YouTube — it gets its own dedicated DevTools main-world injection
            try
            {
                var pageHost = new Uri(core.Source ?? "").Host.ToLower();
                if (pageHost == "www.youtube.com" || pageHost == "youtube.com" ||
                    pageHost == "m.youtube.com" || pageHost == "music.youtube.com" ||
                    pageHost.EndsWith(".youtube.com"))
                    return;
            }
            catch { }
            try
            {
                // Build the blocker JS
                var topDomains = BlockedAdDomains
                    .Where(d => !d.Contains('*') && d.Length > 3 && d.Length < 60)
                    .Take(15000)
                    .ToList();

                var sb = new System.Text.StringBuilder();
                sb.Append("(function(){if(window.__cFB)return;window.__cFB=1;var b=new Set([");
                bool first = true;
                foreach (var d in topDomains)
                {
                    if (!first) sb.Append(',');
                    sb.Append('"');
                    sb.Append(d.Replace("\"", "").Replace("\\", ""));
                    sb.Append('"');
                    first = false;
                }
                sb.Append("]);");
                sb.Append("var wl=new Set(['google.com','youtube.com','accounts.google.com','apis.google.com','ssl.gstatic.com','gstatic.com','discord.com','discordapp.com','github.com','paypal.com','ebay.com','apple.com','icloud.com','mediafire.com','login.microsoftonline.com','login.live.com','pay.google.com','gog.com','steampowered.com','steamcommunity.com','epicgames.com','ea.com','origin.com','ubisoft.com','blizzard.com','battle.net','riotgames.com','xbox.com','playstation.com','nintendo.com','twitch.tv','chase.com','bankofamerica.com','wellsfargo.com','citibank.com','capitalone.com','revolut.com','wise.com','stripe.com','n26.com']);");
                sb.Append("function isWl(h){while(h){if(wl.has(h))return 1;var i=h.indexOf('.');if(i<0)break;h=h.substr(i+1);}return 0};");
                sb.Append("function chk(u){try{if(isWl(location.hostname))return 0;var l=u.toLowerCase();var h=new URL(l).hostname;if(isWl(h))return 0;while(h){if(b.has(h))return 1;var i=h.indexOf('.');if(i<0)break;h=h.substr(i+1);}");
                sb.Append("if(/(\\/ads?\\/|\\/ad[sx]?\\b|\\/pagead\\/|\\/ptracking|\\/advert|\\/sponsored|\\/promotion|\\/tracking\\/|\\/analytics\\/|\\/collect\\?|\\/beacon|\\/pixel|\\/imp\\?|\\/impression|\\/click\\?|ad_banner|ad_frame|sponsored_content|promo_banner|[?&](ad|ads|adunit|adformat|adtag)=)/i.test(l))return 1;");
                sb.Append("if(/(?:\\/(?:adcontent|img\\/adv|web-ad|iframead|contentad|ad\\/image|video-ad|stats\\/event|xtclicks|adscript|bannerad|googlead|adhandler|adimages|adconfig|tracking\\/track|tracker\\/track|adrequest|nativead|adman|advertisement|adframe|adcontrol|adoverlay|adserver|adsense|google-ads|ad-banner|banner-ad|adplacement|adblockdetect|advertising|admanagement|adprovider|adrotation|adunit|adcall|adlog|adcount|adserve|adsrv|adsys|adtrack|adview|adwidget|adzone|sidebar-ads|footer-ads|top-ads|bottom-ads|ads\\.php|ad\\.js|ad\\.css))/i.test(l))return 1;");
                sb.Append("if(/\\/api\\/stats\\/(ads|atr)/i.test(l))return 1;");
                sb.Append("var hh=new URL(l).hostname;");
                sb.Append("if(/^(?:.*[-_.])?(ads?|adv(ert(s|ising)?)?|banners?|track(er|ing|s)?|beacons?|doubleclick|adservice|adnxs|adtech|googleads|gads|adwords|partner|sponsor(ed)?|click(s|bank|tale|through)?|pop(up|under)s?|promo(tion)?|market(ing|er)?|affiliates?|metrics?|stat(s|counter|istics)?|analytics?|pixels?|campaign|traff(ic|iq)|monetize|syndicat(e|ion)|revenue|yield|impress(ion)?s?|conver(sion|t)?|audience|target(ing)?|behavior|profil(e|ing)|telemetry|survey|outbrain|taboola|quantcast|scorecard|omniture|comscore|krux|bluekai|exelate|adform|adroll|rubicon|vungle|inmobi|flurry|mixpanel|heap|amplitude|optimizely|bizible|pardot|hubspot|marketo|eloqua|media(math|net)|criteo|appnexus|turn|adbrite|admob|adsonar|adscale|zergnet|revcontent|mgid|nativeads|contentad|displayads|bannerflow|adblade|adcolony|chartbeat|newrelic|pingdom|kissmetrics|tradedesk|bidder|auction|rtb|programmatic|interstitial|overlay|trafficjunky|trafficstars|exoclick|juicyads|realsrv|magsrv)\\./i.test(hh))return 1;");
                sb.Append("if(/^(?:adcreative(s)?|imageserv|media(mgr)?|stats|switch|track(2|er)?|view|ads?\\d{0,3}|banners?\\d{0,3}|clicks?\\d{0,3}|count(er)?\\d{0,3}|servedby\\d{0,3}|toolbar\\d{0,3}|pageads\\d{0,3}|pops\\d{0,3}|promos?\\d{0,3})\\./i.test(hh))return 1;");
                sb.Append("if(/(?:\\/(1|blank|b|clear|pixel|transp|spacer)\\.gif|\\.swf)$/i.test(l))return 1;");
                sb.Append("return 0}catch(e){return 0}};");
                sb.Append("var F=fetch;window.fetch=function(a,o){var u=typeof a==='string'?a:a&&a.url?a.url:'';if(chk(u))return Promise.reject(new TypeError('blocked'));return F.apply(this,arguments)};");
                sb.Append("var X=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(){var u=arguments[1]||'';if(typeof u==='string'&&chk(u)){this.__blk=1;return}return X.apply(this,arguments)};");
                sb.Append("var S=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.send=function(){if(this.__blk)return;return S.apply(this,arguments)};");
                sb.Append("})()");

                // Use DevTools Protocol to inject into main world — bypasses CSP
                string escapedJs = sb.ToString().Replace("\\", "\\\\").Replace("\"", "\\\"");
                string cdpParams = "{\"expression\":\"" + escapedJs + "\",\"allowUnsafeEvalBlockedByCSP\":true}";
                await core.CallDevToolsProtocolMethodAsync("Runtime.evaluate", cdpParams);
            }
            catch { }
        }

        private async void InjectAdElementHider(BrowserTab tab)
        {
            try
            {
                var core = tab.WebView.CoreWebView2;
                if (core == null) return;
                var url = core.Source ?? "";
                string pageHost = "";
                try { pageHost = new Uri(url).Host.ToLower(); } catch { }

                // YouTube gets its own dedicated ad blocking — DevTools main-world injection
                // handles JSON stripping, and YouTubeAdBlockerJs handles DOM scrubbing
                bool isYouTube = pageHost == "www.youtube.com" || pageHost == "youtube.com" ||
                    pageHost == "m.youtube.com" || pageHost == "music.youtube.com" ||
                    pageHost.EndsWith(".youtube.com") || pageHost.EndsWith(".youtube-nocookie.com");

                if (isYouTube)
                {
                    await core.ExecuteScriptAsync(YouTubeAdBlockerJs);
                    return;
                }

                // Skip generic element hiding on whitelisted sites (non-YouTube)
                if (IsAdBlockWhitelisted(pageHost)) return;

                await core.ExecuteScriptAsync(AdElementHiderJs);
            }
            catch { }
        }

        // ── Password Manager ──
        private void LoadPasswords()
        {
            if (!File.Exists(passwordsFile)) return;
            try
            {
                var encrypted = File.ReadAllBytes(passwordsFile);
                var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
                var json = Encoding.UTF8.GetString(decrypted);
                savedPasswords.Clear();
                // Simple JSON array parse: [{"u":"url","n":"username","p":"password"},...]
                foreach (var entry in ParseCredentialJson(json))
                    savedPasswords.Add(entry);
            }
            catch { /* corrupted or wrong user — ignore */ }
        }

        private void SavePasswords()
        {
            try
            {
                var sb = new StringBuilder("[");
                for (int i = 0; i < savedPasswords.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    var c = savedPasswords[i];
                    sb.Append($"{{\"u\":\"{EscapeJson(c.Url)}\",\"n\":\"{EscapeJson(c.Username)}\",\"p\":\"{EscapeJson(c.Password)}\"}}");
                }
                sb.Append(']');
                var bytes = Encoding.UTF8.GetBytes(sb.ToString());
                var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(passwordsFile, encrypted);
            }
            catch { }
        }

        private void ImportPasswordsCsv()
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Import Passwords (Chrome/Edge CSV format)",
                Filter = "CSV Files (*.csv)|*.csv|All Files|*.*",
                RestoreDirectory = true,
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;

            try
            {
                var lines = File.ReadAllLines(dlg.FileName);
                int count = 0;
                // Chrome CSV format: name,url,username,password
                // Skip header row
                for (int i = 1; i < lines.Length; i++)
                {
                    var fields = ParseCsvLine(lines[i]);
                    if (fields.Count < 4) continue;
                    string url = fields[1].Trim();
                    string username = fields[2].Trim();
                    string password = fields[3].Trim();
                    if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(username)) continue;

                    // Avoid duplicates
                    if (!savedPasswords.Any(p => string.Equals(p.Url, url, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(p.Username, username, StringComparison.OrdinalIgnoreCase)))
                    {
                        savedPasswords.Add(new SavedCredential { Url = url, Username = username, Password = password });
                        count++;
                    }
                }
                SavePasswords();
                statusLabel.Text = $"Imported {count} passwords.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Import failed:\r\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ClearPasswords()
        {
            if (MessageBox.Show(this, "Clear all saved passwords?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            savedPasswords.Clear();
            SavePasswords();
            statusLabel.Text = "Passwords cleared.";
        }

        private async void TryAutoFillCredentials(BrowserTab tab)
        {
            // Debounce — don't re-trigger within 3 seconds of last attempt
            if ((DateTime.Now - tab.LastAutoFillAttempt).TotalSeconds < 3) return;
            tab.LastAutoFillAttempt = DateTime.Now;

            if (savedPasswords.Count == 0) return;
            var core = tab.WebView.CoreWebView2;
            if (core == null) return;

            string pageUrl = core.Source ?? "";
            if (string.IsNullOrEmpty(pageUrl)) return;

            string? pageDomain = null;
            try { pageDomain = new Uri(pageUrl).Host.ToLower(); } catch { return; }

            var matches = savedPasswords.Where(p =>
            {
                try { return new Uri(p.Url).Host.ToLower() == pageDomain; }
                catch { return false; }
            }).ToList();

            if (matches.Count == 0) return;

            // Only attempt autofill on login-like pages
            string pathLower = "";
            try { pathLower = new Uri(pageUrl).PathAndQuery.ToLower(); } catch { }
            bool isLoginPage = pathLower.Contains("login") || pathLower.Contains("signin") || pathLower.Contains("sign-in")
                || pathLower.Contains("auth") || pathLower.Contains("account") || pathLower.Contains("sso")
                || pathLower.Contains("register") || pathLower.Contains("signup") || pathLower.Contains("sign-up");

            // Retry up to 6 times with increasing delays for SPA pages
            for (int attempt = 0; attempt < 6; attempt++)
            {
                await Task.Delay(800 + (attempt * 600));

                if (tab.WebView.IsDisposed || tab.WebView.CoreWebView2 == null) return;
                core = tab.WebView.CoreWebView2;

                // Check for ANY input fields — password, email, text, tel
                string checkJs = @"(function() {
                    var pw = document.querySelector('input[type=""password""]');
                    var emailOrUser = document.querySelector(
                        'input[type=""email""], input[type=""tel""], input[name=""email""], input[name=""username""], ' +
                        'input[name=""login""], input[name=""user""], input[autocomplete=""username""], ' +
                        'input[autocomplete=""email""], input[aria-label*=""mail"" i], input[aria-label*=""user"" i], ' +
                        'input[aria-label*=""phone"" i], input[aria-label*=""login"" i], input[aria-label*=""Email""], ' +
                        'input[aria-label*=""Phone""]'
                    );
                    if (!emailOrUser) {
                        var all = document.querySelectorAll('input[type=""text""], input:not([type])');
                        for (var i = 0; i < all.length; i++) {
                            if (all[i].offsetParent !== null && all[i].offsetWidth > 0) { emailOrUser = all[i]; break; }
                        }
                    }
                    if (pw && emailOrUser) return 'both';
                    if (pw) return 'pwonly';
                    if (emailOrUser) return 'useronly';
                    return 'none';
                })()";

                try
                {
                    var result = await core.ExecuteScriptAsync(checkJs);
                    var fieldStatus = result.Trim('"');

                    if (fieldStatus == "none") continue;

                    // Only autofill if there's a password field, or it's a known login page with a username field
                    if (fieldStatus == "useronly" && !isLoginPage)
                        return; // Not a login page, just has text inputs — skip

                    if (fieldStatus == "both" || fieldStatus == "pwonly")
                    {
                        if (matches.Count == 1)
                        {
                            await FillCredentials(core, matches[0].Username, matches[0].Password);
                            Invoke(() => statusLabel.Text = $"Auto-filled credentials for {pageDomain}");
                        }
                        else
                            Invoke(() => ShowCredentialPicker(tab, matches));
                        return;
                    }

                    if (fieldStatus == "useronly")
                    {
                        if (matches.Count == 1)
                        {
                            await FillUsernameOnly(core, matches[0].Username);
                            Invoke(() => statusLabel.Text = $"Filled username for {pageDomain} (enter password manually or wait)");
                        }
                        else
                            Invoke(() => ShowCredentialPicker(tab, matches));
                        return;
                    }
                }
                catch { }
            }
            try { Invoke(() => statusLabel.Text = $"No login fields detected on {pageDomain}"); } catch { }
        }

        private async Task FillUsernameOnly(CoreWebView2 core, string username)
        {
            string safeUser = username.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "");
            string js = $@"(function() {{
                var user = document.querySelector(
                    'input[type=""email""], input[type=""tel""], input[name=""email""], input[name=""username""], ' +
                    'input[name=""login""], input[name=""user""], input[autocomplete=""username""], ' +
                    'input[autocomplete=""email""], input[aria-label*=""mail"" i], input[aria-label*=""user"" i], ' +
                    'input[aria-label*=""phone"" i], input[aria-label*=""login"" i], input[aria-label*=""Email""], ' +
                    'input[aria-label*=""Phone""]'
                );
                if (!user) {{
                    var all = document.querySelectorAll('input[type=""text""], input:not([type])');
                    for (var i = 0; i < all.length; i++) {{
                        if (all[i].offsetParent !== null && all[i].offsetWidth > 0) {{ user = all[i]; break; }}
                    }}
                }}
                if (user) {{
                    var nativeSet = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                    nativeSet.call(user, '{safeUser}');
                    user.dispatchEvent(new Event('input', {{bubbles:true}}));
                    user.dispatchEvent(new Event('change', {{bubbles:true}}));
                    user.dispatchEvent(new Event('blur', {{bubbles:true}}));
                }}
            }})()";
            await core.ExecuteScriptAsync(js);
        }

        private async Task FillCredentials(CoreWebView2 core, string username, string password)
        {
            string safeUser = username.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "");
            string safePwd = password.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "");

            string fillJs = $@"(function() {{
                var pw = document.querySelector('input[type=""password""]');
                if (!pw) return;
                var form = pw.closest('form') || document.body;
                var user = form.querySelector([
                    'input[type=""email""]',
                    'input[name=""email""]',
                    'input[name=""username""]',
                    'input[name=""login""]',
                    'input[name=""user""]',
                    'input[autocomplete=""username""]',
                    'input[autocomplete=""email""]',
                    'input[type=""text""][name*=""user""]',
                    'input[type=""text""][name*=""login""]',
                    'input[type=""text""][name*=""email""]',
                    'input[type=""text""][autocomplete*=""user""]',
                    'input[aria-label*=""mail""]',
                    'input[aria-label*=""user""]',
                    'input[aria-label*=""login""]',
                    'input[aria-label*=""phone""]'
                ].join(', '));
                if (!user) {{
                    var inputs = form.querySelectorAll('input[type=""text""], input[type=""email""], input:not([type])');
                    for (var i = 0; i < inputs.length; i++) {{
                        var inp = inputs[i];
                        if (inp !== pw && inp.offsetParent !== null) {{ user = inp; break; }}
                    }}
                }}
                if (user) {{
                    var nativeSet = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                    nativeSet.call(user, '{safeUser}');
                    user.dispatchEvent(new Event('input', {{bubbles:true}}));
                    user.dispatchEvent(new Event('change', {{bubbles:true}}));
                }}
                var nativeSet2 = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                nativeSet2.call(pw, '{safePwd}');
                pw.dispatchEvent(new Event('input', {{bubbles:true}}));
                pw.dispatchEvent(new Event('change', {{bubbles:true}}));
            }})()";

            await core.ExecuteScriptAsync(fillJs);
        }

        private void ShowCredentialPicker(BrowserTab tab, List<SavedCredential> matches)
        {
            var picker = new ContextMenuStrip { BackColor = Theme.ActiveTab, ForeColor = Color.White, ShowImageMargin = false };
            picker.Items.Add(new ToolStripMenuItem("Select account:") { Enabled = false, ForeColor = Theme.ForeDim });
            picker.Items.Add(new ToolStripSeparator());

            foreach (var cred in matches)
            {
                var c = cred; // capture
                var item = new ToolStripMenuItem(c.Username) { ForeColor = Color.White, BackColor = Theme.ActiveTab };
                item.Click += async (_, _) =>
                {
                    picker.Close();
                    var core = tab.WebView.CoreWebView2;
                    if (core != null)
                    {
                        await FillCredentials(core, c.Username, c.Password);
                        statusLabel.Text = $"Filled credentials for {c.Username}";
                    }
                };
                picker.Items.Add(item);
            }

            // Show near the top-left of the webview
            var pt = webViewPanel.PointToScreen(new Point(webViewPanel.Width / 2 - 80, 10));
            picker.Show(pt);
        }

        // ── CSV/JSON helpers ──
        private static List<string> ParseCsvLine(string line)
        {
            var fields = new List<string>();
            bool inQuotes = false;
            var current = new StringBuilder();
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"') { inQuotes = !inQuotes; continue; }
                if (c == ',' && !inQuotes) { fields.Add(current.ToString()); current.Clear(); continue; }
                current.Append(c);
            }
            fields.Add(current.ToString());
            return fields;
        }

        private static string EscapeJson(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
        }

        private static List<SavedCredential> ParseCredentialJson(string json)
        {
            var list = new List<SavedCredential>();
            // Minimal JSON array parser for our known format
            int pos = 0;
            while (pos < json.Length)
            {
                int objStart = json.IndexOf('{', pos);
                if (objStart < 0) break;
                int objEnd = json.IndexOf('}', objStart);
                if (objEnd < 0) break;
                string obj = json.Substring(objStart + 1, objEnd - objStart - 1);

                string url = ExtractJsonValue(obj, "u");
                string user = ExtractJsonValue(obj, "n");
                string pwd = ExtractJsonValue(obj, "p");
                if (!string.IsNullOrEmpty(url) && !string.IsNullOrEmpty(user))
                    list.Add(new SavedCredential { Url = url, Username = user, Password = pwd });

                pos = objEnd + 1;
            }
            return list;
        }

        private static string ExtractJsonValue(string obj, string key)
        {
            string search = $"\"{key}\":\"";
            int start = obj.IndexOf(search, StringComparison.Ordinal);
            if (start < 0) return "";
            start += search.Length;
            var sb = new StringBuilder();
            for (int i = start; i < obj.Length; i++)
            {
                if (obj[i] == '\\' && i + 1 < obj.Length) { sb.Append(obj[i + 1]); i++; continue; }
                if (obj[i] == '"') break;
                sb.Append(obj[i]);
            }
            return sb.ToString();
        }
    }

    internal sealed class SavedCredential
    {
        public string Url { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
    }
}
