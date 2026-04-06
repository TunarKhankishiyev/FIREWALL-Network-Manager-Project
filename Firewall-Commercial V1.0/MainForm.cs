using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FirewallApp
{
    // ─── Rounded card panel with GDI+ border ────────────────────────────────
    internal sealed class CardPanel : Panel
    {
        public int CornerRadius { get; set; } = 10;
        public Color BorderColor { get; set; } = Color.FromArgb(30, 45, 61);

        public CardPanel()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.UserPaint |
                     ControlStyles.AllPaintingInWmPaint, true);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = RoundedPath(ClientRectangle, CornerRadius);
            using var brush = new SolidBrush(BackColor);
            e.Graphics.FillPath(brush, path);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = RoundedPath(new Rectangle(0, 0, Width - 1, Height - 1), CornerRadius);
            using var pen = new Pen(BorderColor);
            e.Graphics.DrawPath(pen, path);
        }

        private static GraphicsPath RoundedPath(Rectangle r, int rad)
        {
            int d = rad * 2;
            var p = new GraphicsPath();
            p.AddArc(r.X,          r.Y,           d, d, 180, 90);
            p.AddArc(r.Right - d,  r.Y,           d, d, 270, 90);
            p.AddArc(r.Right - d,  r.Bottom - d,  d, d,   0, 90);
            p.AddArc(r.X,          r.Bottom - d,  d, d,  90, 90);
            p.CloseFigure();
            return p;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    public class MainForm : Form
    {
        // ─── Theme colors (updated by ApplyTheme) ───────────────────────────
        private Color _bg       = Color.FromArgb(10, 14, 23);
        private Color _card     = Color.FromArgb(17, 24, 39);
        private Color _sidebar  = Color.FromArgb(13, 19, 33);
        private Color _input    = Color.FromArgb(22, 30, 46);
        private Color _border   = Color.FromArgb(30, 45, 61);
        private Color _accent   = Color.FromArgb(0, 168, 255);
        private Color _danger   = Color.FromArgb(255, 59, 59);
        private Color _success  = Color.FromArgb(0, 214, 143);
        private Color _warning  = Color.FromArgb(255, 184, 48);
        private Color _text     = Color.FromArgb(226, 232, 240);
        private Color _textDim  = Color.FromArgb(100, 116, 139);

        // ─── Services ────────────────────────────────────────────────────────
        private readonly AppConfig        _config;
        private readonly FirewallManager  _firewallManager;
        private readonly PacketTester     _packetTester;
        private readonly AutoBlockEngine  _autoBlockEngine;
        private readonly TimedRuleService _timedRuleService;
        private readonly Dictionary<string, DateTime> _ruleExpirations = new();
        private System.Windows.Forms.Timer _rulesRefreshTimer;
        private WebServer _webServer;

        // ─── Layout panels ───────────────────────────────────────────────────
        private Panel _headerPanel;
        private Panel _sidebarPanel;
        private Panel _contentPanel;
        // Content pages (Panel — BackColor still works same as TabPage)
        private Panel _tabRules, _tabTests, _tabFirewall, _tabLogs;

        // ─── Tray ────────────────────────────────────────────────────────────
        private NotifyIcon _trayIcon;

        // ─── Rules tab ───────────────────────────────────────────────────────
        private TextBox       txtIp, txtPort;
        private ComboBox      cmbProtocol, cmbAction;
        private NumericUpDown numDuration;
        private CheckBox      chkPermanent;
        private Button        btnAddRule, btnRemoveRule, btnBlockAll;
        private DataGridView  dgvRules;
        private Button        btnExportRules, btnImportRules;
        private ComboBox      cmbProfile;
        private Button        btnSaveProfile, btnLoadProfile;

        // ─── Tests tab ───────────────────────────────────────────────────────
        private TextBox txtTestIp, txtTestPort;
        private Button  btnPing, btnTcp, btnUdp;
        private TextBox txtTestOutput;

        // ─── Firewall tab ────────────────────────────────────────────────────
        private CheckBox      chkAutoBlock;
        private NumericUpDown numIcmpThreshold;
        private Button        btnWinFirewallOn,  btnWinFirewallOff;
        private Button        btnAppFirewallOn,  btnAppFirewallOff;
        private Label         lblFirewallStatus, lblAppFirewallStatus;

        // ─── Theme & nav ─────────────────────────────────────────────────────
        private ComboBox cmbTheme;
        private Button   _btnNavRules, _btnNavTests, _btnNavFirewall, _btnNavLogs;
        private Button   _activeNavBtn;

        // ─── Logs tab ────────────────────────────────────────────────────────
        private DataGridView dgvLogs;
        private Button       btnRefreshLogs, btnOpenLogFolder;

        // ════════════════════════════════════════════════════════════════════
        public MainForm()
        {
            Text          = "Firewall";
            Width         = 1300;
            Height        = 860;
            MinimumSize   = new Size(1060, 720);
            StartPosition = FormStartPosition.CenterScreen;
            Font          = new Font("Segoe UI", 9F);
            BackColor     = _bg;
            ForeColor     = _text;

            _config           = AppConfig.Load("appsettings.json");
            Logger.Initialize(_config.LogFilePath);
            _firewallManager  = new FirewallManager();
            _packetTester     = new PacketTester();
            _autoBlockEngine  = new AutoBlockEngine(_firewallManager, _config.FirewallLogPath, _config.IcmpThreshold);
            _timedRuleService = new TimedRuleService(_firewallManager, "timed_rules.json");

            InitializeComponent();
            ApplyPrivileges();
            InitializeNotifyIcon();
            WireAutoBlockNotifications();
            ApplyTheme();

            _rulesRefreshTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            _rulesRefreshTimer.Tick += (_, __) => RefreshRulesGrid();
            _rulesRefreshTimer.Start();
            RefreshRulesGrid();
            LoadLogsIntoGrid();

            _webServer = new WebServer(_firewallManager, _timedRuleService, _config, port: 2309, getLocalIp: GetLocalIPv4);
            _webServer.Start();
        }

        // ─── Tray icon ───────────────────────────────────────────────────────
        private void InitializeNotifyIcon()
        {
            _trayIcon = new NotifyIcon { Visible = true, Text = "Firewall" };
            if (Icon != null) _trayIcon.Icon = Icon;
            FormClosed += (_, __) => { _trayIcon.Visible = false; _trayIcon.Dispose(); };
        }

        // ─── Privileges ──────────────────────────────────────────────────────
        private void ApplyPrivileges()
        {
            bool admin = AppSession.IsAdmin;
            foreach (var b in new[] { btnAddRule, btnRemoveRule, btnBlockAll,
                                      btnWinFirewallOn, btnWinFirewallOff,
                                      btnAppFirewallOn, btnAppFirewallOff })
                b.Enabled = admin;

            chkAutoBlock.Enabled      = admin;
            numIcmpThreshold.Enabled  = admin;
            cmbProtocol.Enabled       = admin;
            cmbAction.Enabled         = admin;
            numDuration.Enabled       = admin;
            chkPermanent.Enabled      = admin;
            txtIp.ReadOnly            = !admin;
            txtPort.ReadOnly          = !admin;
        }

        private void WireAutoBlockNotifications()
        {
            _autoBlockEngine.AutoBlocked += ip =>
            {
                try { BeginInvoke(new Action(() => ShowAutoBlockNotification(ip))); } catch { }
            };
        }

        private void ShowAutoBlockNotification(string ip)
        {
            _trayIcon.BalloonTipTitle = "Firewall — Auto Block";
            _trayIcon.BalloonTipText  = $"IP {ip} auto-blocked (ICMP threshold reached).";
            _trayIcon.ShowBalloonTip(3000);
        }

        private void TryLoadAppIcon()
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firewall.ico");
                if (File.Exists(path)) Icon = new Icon(path);
            }
            catch { }
        }

        private PictureBox CreateHeaderLogoPictureBox()
        {
            var pb = new PictureBox { Width = 36, Height = 36, SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent };
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firewall.png");
                if (File.Exists(path)) pb.Image = Image.FromFile(path);
            }
            catch { }
            return pb;
        }

        // ════════════════════════════════════════════════════════════════════
        //  INITIALIZE COMPONENT
        // ════════════════════════════════════════════════════════════════════
        private void InitializeComponent()
        {
            TryLoadAppIcon();
            SuspendLayout();

            // ── HEADER ───────────────────────────────────────────────────────
            _headerPanel = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = _sidebar };

            var logo = CreateHeaderLogoPictureBox();
            logo.Location = new Point(18, 14);
            _headerPanel.Controls.Add(logo);

            _headerPanel.Controls.Add(Lbl("FIREWALL", _text, 14F, FontStyle.Bold, new Point(64, 10)));
            _headerPanel.Controls.Add(Lbl("Network Security Manager", _textDim, 7.5F, FontStyle.Regular, new Point(66, 35), 
    fontName: "Segoe UI", 
    w: 200, 
    h: 23, 
    align: ContentAlignment.MiddleLeft));
            // _headerPanel.Controls.Add(Lbl("Network Security Manager", _textDim, 7.5F, FontStyle.Regular, new Point(66, 35)));
            _headerPanel.Controls.Add(new Panel { Width = 1, Height = 38, BackColor = _border, Location = new Point(310, 13) });
            _headerPanel.Controls.Add(Lbl("● PROTECTED", _success, 8.5F, FontStyle.Bold, new Point(324, 24)));
            _headerPanel.Controls.Add(Lbl($"{AppSession.Username}  [{AppSession.Role}]", _textDim, 8.5F, FontStyle.Regular, new Point(450, 24)));
            _headerPanel.Controls.Add(Lbl($"LAN: {GetLocalIPv4()}:2309", _accent, 8.5F, FontStyle.Regular, new Point(620, 24), "Consolas"));
            _headerPanel.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = _border });

            cmbTheme = new ComboBox
            {
                Left = 1160, Top = 20, Width = 110, DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = _card, ForeColor = _text, FlatStyle = FlatStyle.Flat,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            cmbTheme.Items.AddRange(new object[] { "Dark", "Light", "Hacker" });
            cmbTheme.SelectedItem = string.IsNullOrEmpty(_config.Theme) ? "Dark" : _config.Theme;
            cmbTheme.SelectedIndexChanged += (_, __) =>
            {
                _config.Theme = cmbTheme.SelectedItem?.ToString() ?? "Dark";
                _config.Save("appsettings.json");
                ApplyTheme();
            };
            _headerPanel.Controls.Add(cmbTheme);
            Controls.Add(_headerPanel);

            // ── SIDEBAR ──────────────────────────────────────────────────────
            _sidebarPanel = new Panel { Dock = DockStyle.Left, Width = 215, BackColor = _sidebar };
            _sidebarPanel.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 1, BackColor = _border });

            _sidebarPanel.Controls.Add(Lbl("NAVIGATION", _textDim, 7.5F, FontStyle.Bold, new Point(0, 18), null, 215, 30, ContentAlignment.MiddleCenter));

            int navY = 52;
            _btnNavRules    = NavBtn("▷  Rules",         navY); navY += 44;
            _btnNavTests    = NavBtn("⊡  Packet Tests",  navY); navY += 44;
            _btnNavFirewall = NavBtn("≡  Firewall",      navY); navY += 44;
            _btnNavLogs     = NavBtn("☰  Activity Logs", navY);

            _btnNavRules.Click    += (_, __) => ShowPage(_tabRules,    _btnNavRules);
            _btnNavTests.Click    += (_, __) => ShowPage(_tabTests,    _btnNavTests);
            _btnNavFirewall.Click += (_, __) => ShowPage(_tabFirewall, _btnNavFirewall);
            _btnNavLogs.Click     += (_, __) => ShowPage(_tabLogs,     _btnNavLogs);

            _sidebarPanel.Controls.Add(_btnNavRules);
            _sidebarPanel.Controls.Add(_btnNavTests);
            _sidebarPanel.Controls.Add(_btnNavFirewall);
            _sidebarPanel.Controls.Add(_btnNavLogs);

            _sidebarPanel.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = _border });
            _sidebarPanel.Controls.Add(new Label
            {
                Text      = AppSession.IsAdmin ? "● ADMIN" : "● VIEWER",
                ForeColor = AppSession.IsAdmin ? _success : _warning,
                Font      = new Font("Segoe UI", 8F, FontStyle.Bold),
                Dock      = DockStyle.Bottom, Height = 42, TextAlign = ContentAlignment.MiddleCenter
            });
            Controls.Add(_sidebarPanel);

            // ── CONTENT AREA ─────────────────────────────────────────────────
            _contentPanel = new Panel { Dock = DockStyle.Fill, BackColor = _bg };
            Controls.Add(_contentPanel);
            _contentPanel.BringToFront();

            _tabRules    = MakePage();
            _tabTests    = MakePage();
            _tabFirewall = MakePage();
            _tabLogs     = MakePage();
            _contentPanel.Controls.AddRange(new Control[] { _tabRules, _tabTests, _tabFirewall, _tabLogs });

            InitializeRulesTab(_tabRules);
            InitializeTestsTab(_tabTests);
            InitializeFirewallTab(_tabFirewall);
            InitializeLogsTab(_tabLogs);

            ShowPage(_tabRules, _btnNavRules);
            ResumeLayout();
        }

        private Panel MakePage() => new Panel { Dock = DockStyle.Fill, BackColor = _bg, Visible = false };

        private void ShowPage(Panel page, Button btn)
        {
            foreach (var p in new[] { _tabRules, _tabTests, _tabFirewall, _tabLogs })
                p.Visible = false;
            page.Visible = true;

            foreach (var b in new[] { _btnNavRules, _btnNavTests, _btnNavFirewall, _btnNavLogs })
            {
                b.BackColor = _sidebar;
                b.ForeColor = _textDim;
                b.Font = new Font("Segoe UI", 9.5F, FontStyle.Regular);
            }
            btn.BackColor = Color.FromArgb(18, 40, 65);
            btn.ForeColor = _accent;
            btn.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            _activeNavBtn = btn;
        }

        private Button NavBtn(string text, int top)
        {
            var b = new Button
            {
                Text = text, Location = new Point(0, top), Width = 215, Height = 42,
                FlatStyle = FlatStyle.Flat, BackColor = _sidebar, ForeColor = _textDim,
                Font = new Font("Segoe UI", 9.5F), TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(16, 0, 0, 0), Cursor = Cursors.Hand,
                FlatAppearance = { BorderSize = 0 }
            };
            b.MouseEnter += (_, __) => { if (b != _activeNavBtn) { b.BackColor = Color.FromArgb(18, 32, 52); b.ForeColor = _text; } };
            b.MouseLeave += (_, __) => { if (b != _activeNavBtn) { b.BackColor = _sidebar; b.ForeColor = _textDim; } };
            return b;
        }

        // ── Factory helpers ──────────────────────────────────────────────────
        private Button Btn(string text, Color? bgColor = null, Color? fgColor = null, int width = 0)
        {
            var bg = bgColor ?? _accent;
            var btn = new Button
            {
                Text      = text,
                Height    = 32,
                FlatStyle = FlatStyle.Flat,
                BackColor = bg,
                ForeColor = fgColor ?? _text,
                FlatAppearance = { BorderSize = 0 },
                Cursor    = Cursors.Hand,
                AutoSize  = false
            };
            if (width > 0) btn.Width = width;
            btn.MouseEnter += (_, __) => btn.BackColor = Brighten(bg, 18);
            btn.MouseLeave += (_, __) => btn.BackColor = bg;
            return btn;
        }

        private static Color Brighten(Color c, int amt) =>
            Color.FromArgb(Math.Min(255, c.R + amt), Math.Min(255, c.G + amt), Math.Min(255, c.B + amt));

        private TextBox Txt(string placeholder, int width = 150)
        {
            return new TextBox
            {
                Width = width, PlaceholderText = placeholder,
                BackColor = _input, ForeColor = _text, BorderStyle = BorderStyle.FixedSingle
            };
        }

        private ComboBox Cmb(string[] items, int width = 100)
        {
            var c = new ComboBox
            {
                Width = width, DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = _input, ForeColor = _text, FlatStyle = FlatStyle.Flat
            };
            c.Items.AddRange(items);
            if (c.Items.Count > 0) c.SelectedIndex = 0;
            return c;
        }

        private NumericUpDown Num(int min, int max, int val, int width = 80)
        {
            return new NumericUpDown
            {
                Width = width, Minimum = min, Maximum = max, Value = val,
                BackColor = _input, ForeColor = _text, BorderStyle = BorderStyle.FixedSingle
            };
        }

        private static Label Lbl(string text, Color fore, float size, FontStyle style, Point loc,
                                  string fontName = null, int w = 0, int h = 0,
                                  ContentAlignment align = ContentAlignment.TopLeft)
        {
            var lbl = new Label
            {
                Text      = text,
                ForeColor = fore,
                Font      = new Font(fontName ?? "Segoe UI", size, style),
                AutoSize  = (w == 0 && h == 0),
                Location  = loc,
                BackColor = Color.Transparent,
                TextAlign = align
            };
            if (w > 0) lbl.Width  = w;
            if (h > 0) lbl.Height = h;
            return lbl;
        }

        private Label FieldLabel(string text, int x, int y, Control parent)
        {
            var lbl = new Label
            {
                Text      = text,
                ForeColor = _textDim,
                Font      = new Font("Segoe UI", 7F, FontStyle.Regular),
                AutoSize  = true,
                Location  = new Point(x, y),
                BackColor = parent.BackColor
            };
            return lbl;
        }

        private DataGridView MakeGrid()
        {
            var g = new DataGridView
            {
                ReadOnly              = true,
                AllowUserToAddRows    = false,
                AutoGenerateColumns   = true,
                AutoSizeColumnsMode   = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode         = DataGridViewSelectionMode.FullRowSelect,
                BackgroundColor       = _card,
                GridColor             = _border,
                ForeColor             = _text,
                BorderStyle           = BorderStyle.None,
                RowHeadersVisible     = false,
                CellBorderStyle       = DataGridViewCellBorderStyle.SingleHorizontal,
                ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None
            };
            g.EnableHeadersVisualStyles = false;
            g.ColumnHeadersDefaultCellStyle.BackColor  = _sidebar;
            g.ColumnHeadersDefaultCellStyle.ForeColor  = _textDim;
            g.ColumnHeadersDefaultCellStyle.Font       = new Font("Segoe UI", 8.5F, FontStyle.Bold);
            g.ColumnHeadersDefaultCellStyle.Padding    = new Padding(10, 0, 0, 0);
            g.ColumnHeadersHeight = 36;
            g.DefaultCellStyle.BackColor              = _card;
            g.DefaultCellStyle.ForeColor              = _text;
            g.DefaultCellStyle.SelectionBackColor     = Color.FromArgb(0, 90, 140);
            g.DefaultCellStyle.SelectionForeColor     = Color.White;
            g.DefaultCellStyle.Padding                = new Padding(10, 0, 0, 0);
            g.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(20, 28, 44);
            g.RowTemplate.Height = 30;
            return g;
        }

        private Panel MakeTitleBar(string title, string subtitle,int w = 0, int h = 80)
        {
            var bar = new Panel { Dock = DockStyle.Top, Height = h, BackColor = _bg };  //height = 80
            bar.Controls.Add(Lbl(title,    _text,    13F, FontStyle.Bold,    new Point(22, 14)));  // 22,12
            bar.Controls.Add(Lbl(subtitle, _textDim, 7.5F, FontStyle.Regular, new Point(27, 46)));  // 22,36
            bar.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = _border });
            return bar;
        }

        private CardPanel MakeCard(int x, int y, int w, int h, string headerText = null)
        {
            var card = new CardPanel
            {
                BackColor = _card, BorderColor = _border, CornerRadius = 10,
                Location  = new Point(x, y), Width = w, Height = h
            };
            if (headerText != null)
            {
                card.Controls.Add(new Label
                {
                    Text      = headerText,
                    ForeColor = _accent,
                    Font      = new Font("Segoe UI", 8F, FontStyle.Bold),
                    AutoSize  = true,
                    Location  = new Point(14, 13),
                    BackColor = _card
                });
                card.Controls.Add(new Panel
                {
                    Location  = new Point(0, 33),
                    Width     = w,
                    Height    = 1,
                    BackColor = _border
                });
            }
            return card;
        }

        // ════════════════════════════════════════════════════════════════════
        //  RULES TAB
        // ════════════════════════════════════════════════════════════════════
        private void InitializeRulesTab(Panel tab)
        {
            // WinForms dock z-order: LAST added DockStyle.Top wins the topmost visual position.
            // Order: bottomBar → Fill grid → input card → titleBar (titleBar last = topmost)

            // ── Bottom toolbar ───────────────────────────────────────────────
            var bottomBar = new Panel { Dock = DockStyle.Bottom, Height = 52, BackColor = _sidebar };
            bottomBar.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, BackColor = _border });

            btnExportRules = Btn("↑ Export", _card, _text, 100); btnExportRules.Location = new Point(14, 11);
            btnImportRules = Btn("↓ Import", _card, _text, 100); btnImportRules.Location = new Point(124, 11);
            btnExportRules.Click += BtnExportRules_Click;
            btnImportRules.Click += BtnImportRules_Click;

            bottomBar.Controls.Add(new Panel { Width = 1, Height = 30, BackColor = _border, Location = new Point(238, 11) });

            cmbProfile = Cmb(new[] { "Default", "Lab", "Game" }, 130); cmbProfile.Location = new Point(252, 11);
            btnSaveProfile = Btn("Save Profile", _success, Color.Black, 110); btnSaveProfile.Location = new Point(392, 11);
            btnLoadProfile = Btn("Load Profile", null, null, 110);             btnLoadProfile.Location = new Point(512, 11);
            btnSaveProfile.Click += BtnSaveProfile_Click;
            btnLoadProfile.Click += BtnLoadProfile_Click;
            bottomBar.Controls.AddRange(new Control[] { btnExportRules, btnImportRules, cmbProfile, btnSaveProfile, btnLoadProfile });
            tab.Controls.Add(bottomBar);  // 1st — Bottom

            // ── Rules grid (fills space) ─────────────────────────────────────
            dgvRules      = MakeGrid();
            dgvRules.Dock = DockStyle.Fill;
            tab.Controls.Add(dgvRules);   // 2nd — Fill

            // ── Add Rule card ────────────────────────────────────────────────
            var addCard = new CardPanel
            {
                BackColor = _card, BorderColor = _border, CornerRadius = 10,
                Dock = DockStyle.Top, Height = 72
            };

            foreach (var (lbl, x) in new[] { ("Remote IP / CIDR", 14), ("Port", 184), ("Protocol", 260), ("Action", 354), ("Duration (min)", 448) })
                addCard.Controls.Add(FieldLabel(lbl, x, 6, addCard));

            txtIp       = Txt("e.g. 192.168.1.1", 160); txtIp.Location       = new Point(14,  26);
            txtPort     = Txt("0=all", 66);              txtPort.Location     = new Point(184, 26);
            cmbProtocol = Cmb(new[] { "Any", "TCP", "UDP" }, 88); cmbProtocol.Location = new Point(260, 26);
            cmbAction   = Cmb(new[] { "Block", "Allow" }, 88);    cmbAction.Location   = new Point(354, 26);
            numDuration = Num(1, 1440, _config.DefaultBlockMinutes, 74); numDuration.Location = new Point(448, 26);

            chkPermanent = new CheckBox
            {
                Text = "Permanent", Location = new Point(532, 28), Width = 96,
                ForeColor = _text, BackColor = _card, Checked = true
            };

            btnAddRule    = Btn("＋  Add Rule",      null,   null,   120); btnAddRule.Location    = new Point(640, 22);
            btnRemoveRule = Btn("✕  Remove",         _danger, null,  100); btnRemoveRule.Location = new Point(770, 22);
            btnBlockAll   = Btn("⚡ Block ALL",       _danger, null,  110); btnBlockAll.Location   = new Point(880, 22);

            btnAddRule.Click    += BtnAddRule_Click;
            btnRemoveRule.Click += BtnRemoveRule_Click;
            btnBlockAll.Click   += BtnBlockAll_Click;

            addCard.Controls.AddRange(new Control[]
            {
                txtIp, txtPort, cmbProtocol, cmbAction, numDuration, chkPermanent,
                btnAddRule, btnRemoveRule, btnBlockAll
            });
            tab.Controls.Add(addCard);  // 3rd — Top (below title)

            // ── Title bar — LAST so it appears at very top ───────────────────
            tab.Controls.Add(MakeTitleBar("Rules Management", "Active inbound firewall rules on this machine")); // 4th — TOP
        }

        // ════════════════════════════════════════════════════════════════════
        //  TESTS TAB
        // ════════════════════════════════════════════════════════════════════
        private void InitializeTestsTab(Panel tab)
        {
            // Fill first, then input card, then titleBar last = topmost
            // ── Terminal output ──────────────────────────────────────────────
            txtTestOutput = new TextBox
            {
                Dock        = DockStyle.Fill,
                Multiline   = true,
                ScrollBars  = ScrollBars.Vertical,
                BackColor   = Color.FromArgb(6, 10, 18),
                ForeColor   = _success,
                BorderStyle = BorderStyle.None,
                Font        = new Font("Consolas", 9.5F),
                ReadOnly    = true
            };
            tab.Controls.Add(txtTestOutput);   // 1st — Fill

            // ── Input card ───────────────────────────────────────────────────
            var inputCard = new CardPanel
            {
                BackColor = _card, BorderColor = _border, CornerRadius = 10,
                Dock = DockStyle.Top, Height = 62
            };
            txtTestIp   = Txt("Target IP / Hostname", 200); txtTestIp.Location   = new Point(14, 18);
            txtTestPort = Txt("Port", 72);                   txtTestPort.Location = new Point(224, 18);

            btnPing = Btn("⬡  Ping", null, null, 90); btnPing.Location = new Point(308, 16);
            btnTcp  = Btn("⬡  TCP",  null, null, 90); btnTcp.Location  = new Point(408, 16);
            btnUdp  = Btn("⬡  UDP",  null, null, 90); btnUdp.Location  = new Point(508, 16);

            btnPing.Click += async (_, __) => await OnPingClicked();
            btnTcp.Click  += async (_, __) => await OnTcpClicked();
            btnUdp.Click  += async (_, __) => await OnUdpClicked();

            inputCard.Controls.AddRange(new Control[] { txtTestIp, txtTestPort, btnPing, btnTcp, btnUdp });
            tab.Controls.Add(inputCard);  // 2nd — Top (below title)

            // ── Title bar — LAST ─────────────────────────────────────────────
            tab.Controls.Add(MakeTitleBar("Packet Testing", "Ping, TCP and UDP connectivity diagnostics",0,70)); // 3rd — topmost   50 idi
        }

        // ════════════════════════════════════════════════════════════════════
        //  FIREWALL TAB
        // ════════════════════════════════════════════════════════════════════
        private void InitializeFirewallTab(Panel tab)
        {
            // Fill body first, then titleBar last = topmost
            var body = new Panel { Dock = DockStyle.Fill, BackColor = _bg };
            body.Padding = new Padding(0);

            // ── Windows Firewall card ────────────────────────────────────────
            var winCard = MakeCard(22, 22, 300, 170, "WINDOWS FIREWALL");
            lblFirewallStatus = new Label
            {
                Text = "Status: (not checked)", ForeColor = _textDim,
                Font = new Font("Segoe UI", 8.5F), AutoSize = false,
                Width = 268, Height = 20, Location = new Point(16, 48), BackColor = _card
            };
            btnWinFirewallOn  = Btn("Enable Win FW",  _success, Color.Black, 128); btnWinFirewallOn.Location  = new Point(16, 80);
            btnWinFirewallOff = Btn("Disable Win FW", _danger,  null,        128); btnWinFirewallOff.Location = new Point(154, 80);
            btnWinFirewallOn.Click  += (_, __) => ToggleWindowsFirewall(true);
            btnWinFirewallOff.Click += (_, __) => ToggleWindowsFirewall(false);
            var lblWinNote = new Label
            {
                Text = "Controls Windows built-in firewall service\nfor all network profiles (Domain, Private, Public).",
                ForeColor = _textDim, Font = new Font("Segoe UI", 7.5F),
                AutoSize = false, Width = 268, Height = 42,
                Location = new Point(16, 122), BackColor = _card
            };
            winCard.Controls.AddRange(new Control[] { lblFirewallStatus, btnWinFirewallOn, btnWinFirewallOff, lblWinNote });

            // ── App Rules card ───────────────────────────────────────────────
            var appCard = MakeCard(342, 22, 300, 170, "APP RULES (FW-)");
            lblAppFirewallStatus = new Label
            {
                Text = "Status: (not checked)", ForeColor = _textDim,
                Font = new Font("Segoe UI", 8.5F), AutoSize = false,
                Width = 268, Height = 20, Location = new Point(16, 48), BackColor = _card
            };
            btnAppFirewallOn  = Btn("Enable All Rules",  _success, Color.Black, 128); btnAppFirewallOn.Location  = new Point(16,  80);
            btnAppFirewallOff = Btn("Disable All Rules", _warning, Color.Black, 128); btnAppFirewallOff.Location = new Point(154, 80);
            btnAppFirewallOn.Click  += (_, __) => ToggleAppFirewall(true);
            btnAppFirewallOff.Click += (_, __) => ToggleAppFirewall(false);
            var lblAppNote = new Label
            {
                Text = "Enables or disables only the FW- rules\ncreated by this application.",
                ForeColor = _textDim, Font = new Font("Segoe UI", 7.5F),
                AutoSize = false, Width = 268, Height = 42,
                Location = new Point(16, 122), BackColor = _card
            };
            appCard.Controls.AddRange(new Control[] { lblAppFirewallStatus, btnAppFirewallOn, btnAppFirewallOff, lblAppNote });

            // ── Auto-Block card ──────────────────────────────────────────────
            var autoCard = MakeCard(662, 22, 320, 170, "ICMP AUTO-BLOCK");
            chkAutoBlock = new CheckBox
            {
                Text      = "Enable auto-blocking engine",
                Location  = new Point(16, 50),
                Width     = 280,
                ForeColor = _text,
                BackColor = _card
            };
            chkAutoBlock.CheckedChanged += ChkAutoBlock_CheckedChanged;

            var lblThresh = new Label
            {
                Text = "Block threshold (ICMP packets):",
                ForeColor = _textDim, Font = new Font("Segoe UI", 8F),
                AutoSize = true, Location = new Point(16, 88), BackColor = _card
            };
            numIcmpThreshold = Num(1, 1000, _config.IcmpThreshold, 80);
            numIcmpThreshold.Location = new Point(224, 85);
            numIcmpThreshold.ValueChanged += NumIcmpThreshold_ValueChanged;

            var lblAutoNote = new Label
            {
                Text = "Auto-blocks any source IP that exceeds\nthe ICMP packet threshold.",
                ForeColor = _textDim, Font = new Font("Segoe UI", 7.5F),
                AutoSize = false, Width = 288, Height = 36,
                Location = new Point(16, 124), BackColor = _card
            };
            autoCard.Controls.AddRange(new Control[] { chkAutoBlock, lblThresh, numIcmpThreshold, lblAutoNote });

            // ── Built-in Rules card ──────────────────────────────────────────
            var builtinCard = MakeCard(22, 210, 960, 160, "WINDOWS BUILT-IN RULES");

            var lblBuiltinNote = new Label
            {
                Text      = "Disable all built-in Windows inbound rules so only your FW- rules control traffic.\n" +
                             "Also sets default inbound policy to BLOCK — nothing gets in unless you explicitly allow it.\n" +
                             "Use \"Restore Built-in Rules\" to undo and return Windows to its default state.",
                ForeColor = _textDim, Font = new Font("Segoe UI", 8F),
                AutoSize  = false, Width = 620, Height = 58,
                Location  = new Point(16, 44), BackColor = _card
            };

            var btnDisableBuiltin = Btn("⚡ Disable All Built-in Rules", _danger, null, 210);
            btnDisableBuiltin.Location = new Point(652, 44);
            btnDisableBuiltin.Click   += (_, __) =>
            {
                var confirm = MessageBox.Show(
                    "This will disable ALL Windows built-in inbound rules and set default inbound policy to BLOCK.\n\n" +
                    "Only your FW- rules will control traffic.\n\n" +
                    "Continue?",
                    "Confirm — Take Full Control",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

                if (confirm != DialogResult.Yes) return;

                try
                {
                    _firewallManager.DisableBuiltinRules();
                    MessageBox.Show("Done. Built-in rules disabled.\nDefault inbound policy set to BLOCK.\nYour FW- rules are now in full control.",
                        "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: " + ex.Message, "Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            var btnRestoreBuiltin = Btn("↩ Restore Built-in Rules", _warning, Color.Black, 200);
            btnRestoreBuiltin.Location = new Point(652, 96);
            btnRestoreBuiltin.Click   += (_, __) =>
            {
                try
                {
                    _firewallManager.EnableBuiltinRules();
                    MessageBox.Show("Done. Built-in rules re-enabled.\nDefault inbound policy restored to ALLOW.",
                        "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: " + ex.Message, "Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            var lblWarning = new Label
            {
                Text      = "⚠  WARNING: Disabling built-in rules may break RDP, file sharing, and other Windows services.",
                ForeColor = _warning, Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
                AutoSize  = false, Width = 920, Height = 18,
                Location  = new Point(16, 130), BackColor = _card
            };

            builtinCard.Controls.AddRange(new Control[] { lblBuiltinNote, btnDisableBuiltin, btnRestoreBuiltin, lblWarning });

            body.Controls.AddRange(new Control[] { winCard, appCard, autoCard, builtinCard });
            tab.Controls.Add(body);   // 1st — Fill

            // ── Title bar — LAST ─────────────────────────────────────────────
            tab.Controls.Add(MakeTitleBar("Firewall Control", "Manage Windows Firewall and application rule states")); // 2nd — topmost
        }

        // ════════════════════════════════════════════════════════════════════
        //  LOGS TAB
        // ════════════════════════════════════════════════════════════════════
        private void InitializeLogsTab(Panel tab)
        {
            // Fill first, toolbar, titleBar last = topmost
            dgvLogs      = MakeGrid();
            dgvLogs.Dock = DockStyle.Fill;
            tab.Controls.Add(dgvLogs);  // 1st — Fill

            var toolbar = new Panel { Dock = DockStyle.Top, Height = 52, BackColor = _bg };
            btnRefreshLogs   = Btn("⟳  Refresh",   null,  null, 110); btnRefreshLogs.Location   = new Point(22, 10);
            btnOpenLogFolder = Btn("Open Folder", _card, _text, 120); btnOpenLogFolder.Location = new Point(142, 10);
            btnRefreshLogs.Click += (_, __) => LoadLogsIntoGrid();
            btnOpenLogFolder.Click += (_, __) =>
            {
                try
                {
                    var folder = Path.GetDirectoryName(Logger.LogPath);
                    if (!string.IsNullOrEmpty(folder) && Directory.Exists(folder))
                        Process.Start(new ProcessStartInfo { FileName = "explorer.exe", Arguments = folder, UseShellExecute = true });
                }
                catch (Exception ex) { MessageBox.Show("Cannot open folder: " + ex.Message); }
            };
            toolbar.Controls.Add(btnRefreshLogs);
            toolbar.Controls.Add(btnOpenLogFolder);
            toolbar.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = _border });
            tab.Controls.Add(toolbar);  // 2nd — Top (below title)

            // ── Title bar — LAST ─────────────────────────────────────────────
            tab.Controls.Add(MakeTitleBar("Activity Logs", "Full audit trail of firewall events and changes")); // 3rd — topmost
        }

        // ════════════════════════════════════════════════════════════════════
        //  APPLY THEME
        // ════════════════════════════════════════════════════════════════════
        private void ApplyTheme()
        {
            string theme = _config.Theme ?? "Dark";

            switch (theme)
            {
                case "Light":
                    _bg      = Color.FromArgb(244, 246, 250);
                    _card    = Color.White;
                    _sidebar = Color.FromArgb(224, 230, 240);
                    _input   = Color.FromArgb(255, 255, 255);
                    _border  = Color.FromArgb(196, 208, 222);
                    _accent  = Color.FromArgb(0, 122, 204);
                    _danger  = Color.FromArgb(200, 30,  30);
                    _success = Color.FromArgb(0,   140, 80);
                    _warning = Color.FromArgb(180, 120, 0);
                    _text    = Color.FromArgb(28,  36,  52);
                    _textDim = Color.FromArgb(110, 120, 140);
                    break;

                case "Hacker":
                    _bg      = Color.Black;
                    _card    = Color.FromArgb(0,  14, 0);
                    _sidebar = Color.FromArgb(0,  10, 0);
                    _input   = Color.FromArgb(0,  20, 0);
                    _border  = Color.FromArgb(0,  55, 0);
                    _accent  = Color.FromArgb(0,  220, 0);
                    _danger  = Color.FromArgb(200, 0,  0);
                    _success = Color.Lime;
                    _warning = Color.Yellow;
                    _text    = Color.Lime;
                    _textDim = Color.FromArgb(0,  130, 0);
                    break;

                default: // Dark — Cyber Command Center
                    _bg      = Color.FromArgb(10, 14, 23);
                    _card    = Color.FromArgb(17, 24, 39);
                    _sidebar = Color.FromArgb(13, 19, 33);
                    _input   = Color.FromArgb(22, 30, 46);
                    _border  = Color.FromArgb(30, 45, 61);
                    _accent  = Color.FromArgb(0,  168, 255);
                    _danger  = Color.FromArgb(255, 59, 59);
                    _success = Color.FromArgb(0,  214, 143);
                    _warning = Color.FromArgb(255, 184, 48);
                    _text    = Color.FromArgb(226, 232, 240);
                    _textDim = Color.FromArgb(100, 116, 139);
                    break;
            }

            BackColor = _bg;
            ForeColor = _text;

            if (_headerPanel != null)  _headerPanel.BackColor  = _sidebar;
            if (_sidebarPanel != null) _sidebarPanel.BackColor = _sidebar;
            if (_contentPanel != null) _contentPanel.BackColor = _bg;

            foreach (var p in new[] { _tabRules, _tabTests, _tabFirewall, _tabLogs })
                if (p != null) p.BackColor = _bg;

            // Buttons
            if (btnAddRule    != null) { var c = _accent;  btnAddRule.BackColor    = c; btnAddRule.MouseEnter    += (_, __) => btnAddRule.BackColor    = Brighten(c, 18); btnAddRule.MouseLeave    += (_, __) => btnAddRule.BackColor    = c; }
            if (btnRemoveRule != null) { var c = _danger;  btnRemoveRule.BackColor = c; }
            if (btnBlockAll   != null) { var c = _danger;  btnBlockAll.BackColor   = c; }
            if (btnWinFirewallOn  != null) btnWinFirewallOn.BackColor  = _success;
            if (btnWinFirewallOff != null) btnWinFirewallOff.BackColor = _danger;
            if (btnAppFirewallOn  != null) { btnAppFirewallOn.BackColor = _success; btnAppFirewallOn.ForeColor = Color.Black; }
            if (btnAppFirewallOff != null) { btnAppFirewallOff.BackColor = _warning; btnAppFirewallOff.ForeColor = Color.Black; }
            if (btnPing != null) btnPing.BackColor = _accent;
            if (btnTcp  != null) btnTcp.BackColor  = _accent;
            if (btnUdp  != null) btnUdp.BackColor  = _accent;
            if (btnExportRules  != null) btnExportRules.BackColor  = _card;
            if (btnImportRules  != null) btnImportRules.BackColor  = _card;
            if (btnSaveProfile  != null) btnSaveProfile.BackColor  = _success;
            if (btnLoadProfile  != null) btnLoadProfile.BackColor  = _accent;
            if (btnRefreshLogs  != null) btnRefreshLogs.BackColor  = _accent;
            if (btnOpenLogFolder != null) btnOpenLogFolder.BackColor = _card;

            // Text inputs
            foreach (var tb in new[] { txtIp, txtPort, txtTestIp, txtTestPort })
                if (tb != null) { tb.BackColor = _input; tb.ForeColor = _text; }

            if (txtTestOutput != null) txtTestOutput.BackColor = Color.FromArgb(6, 10, 18);

            // Combos
            foreach (var cb in new ComboBox[] { cmbProtocol, cmbAction, cmbProfile })
                if (cb != null) { cb.BackColor = _input; cb.ForeColor = _text; }
            if (cmbTheme != null) { cmbTheme.BackColor = _card; cmbTheme.ForeColor = _text; }

            // Numerics
            foreach (var nu in new[] { numDuration, numIcmpThreshold })
                if (nu != null) { nu.BackColor = _input; nu.ForeColor = _text; }

            // Labels / checkboxes
            if (lblFirewallStatus    != null) { lblFirewallStatus.ForeColor    = _textDim; lblFirewallStatus.BackColor    = _card; }
            if (lblAppFirewallStatus != null) { lblAppFirewallStatus.ForeColor = _textDim; lblAppFirewallStatus.BackColor = _card; }
            if (chkAutoBlock         != null) { chkAutoBlock.ForeColor = _text; chkAutoBlock.BackColor = _card; }

            // Grids
            foreach (var g in new[] { dgvRules, dgvLogs })
            {
                if (g == null) continue;
                g.BackgroundColor = _card;
                g.GridColor       = _border;
                g.DefaultCellStyle.BackColor              = _card;
                g.DefaultCellStyle.ForeColor              = _text;
                g.DefaultCellStyle.SelectionBackColor     = Color.FromArgb(0, 90, 140);
                g.ColumnHeadersDefaultCellStyle.BackColor = _sidebar;
                g.ColumnHeadersDefaultCellStyle.ForeColor = _textDim;
                g.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(_sidebar.R, _sidebar.G, _sidebar.B);
            }

            // Nav buttons
            foreach (var b in new[] { _btnNavRules, _btnNavTests, _btnNavFirewall, _btnNavLogs })
            {
                if (b == null) continue;
                if (b == _activeNavBtn) { b.BackColor = Color.FromArgb(18, 40, 65); b.ForeColor = _accent; }
                else { b.BackColor = _sidebar; b.ForeColor = _textDim; }
            }

            Refresh();
        }

        // ════════════════════════════════════════════════════════════════════
        //  HELPERS
        // ════════════════════════════════════════════════════════════════════
        private string GetLocalIPv4()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                        return ip.ToString();
            }
            catch { }
            return "127.0.0.1";
        }

        private static Dictionary<string, DateTime> LoadExpirationsMap(string timedRulesPath)
        {
            var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(timedRulesPath)) return map;
                var json = File.ReadAllText(timedRulesPath);
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array) return map;
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    string? name = null;
                    DateTime? exp = null;
                    if (item.TryGetProperty("Name",      out var n1)) name = n1.GetString();
                    else if (item.TryGetProperty("RuleName", out var n2)) name = n2.GetString();
                    if (item.TryGetProperty("ExpiresAt", out var e1) && e1.ValueKind == System.Text.Json.JsonValueKind.String
                        && DateTime.TryParse(e1.GetString(), out var dt1)) exp = dt1;
                    else if (item.TryGetProperty("Expiry", out var e2) && e2.ValueKind == System.Text.Json.JsonValueKind.String
                        && DateTime.TryParse(e2.GetString(), out var dt2)) exp = dt2;
                    if (!string.IsNullOrWhiteSpace(name) && exp != null)
                        map[name] = exp.Value;
                }
            }
            catch { }
            return map;
        }

        // ════════════════════════════════════════════════════════════════════
        //  RULES GRID
        // ════════════════════════════════════════════════════════════════════
        private void RefreshRulesGrid()
        {
            // ── Save selection by rule Name (index shifts when rules expire) ──
            string? selectedName = null;
            if (dgvRules.CurrentRow?.DataBoundItem is FirewallRuleModel sel)
                selectedName = sel.Name;

            List<FirewallRuleModel> rules;
            try { rules = _firewallManager.GetAppRules(); }
            catch (Exception ex) { MessageBox.Show("Error reading rules: " + ex.Message); return; }

            string localIp = GetLocalIPv4();
            var expMap = LoadExpirationsMap("timed_rules.json");

            for (int i = 0; i < rules.Count; i++)
            {
                rules[i].Id            = i + 1;
                rules[i].SourceIp      = localIp;
                rules[i].DestinationIp = string.IsNullOrWhiteSpace(rules[i].RemoteIp) ? "Any" : rules[i].RemoteIp;
                rules[i].ExpiresAt     = !string.IsNullOrWhiteSpace(rules[i].Name) && expMap.TryGetValue(rules[i].Name, out var exp)
                                         ? exp : (DateTime?)null;
            }

            // Suspend layout to prevent flicker during DataSource swap
            dgvRules.SuspendLayout();
            dgvRules.AutoGenerateColumns = true;
            dgvRules.DataSource = null;
            dgvRules.DataSource = rules;

            void Hide(string col) { if (dgvRules.Columns[col] != null) dgvRules.Columns[col].Visible = false; }
            void Head(string col, string h) { if (dgvRules.Columns[col] != null) dgvRules.Columns[col].HeaderText = h; }

            Hide(nameof(FirewallRuleModel.Name));
            Hide(nameof(FirewallRuleModel.ExpiresAt));
            Head(nameof(FirewallRuleModel.Id),            "#");
            Head(nameof(FirewallRuleModel.RemoteIp),      "Remote IP");
            Head(nameof(FirewallRuleModel.SourceIp),      "Source IP");
            Head(nameof(FirewallRuleModel.DestinationIp), "Destination IP");
            Head(nameof(FirewallRuleModel.ExpiresText),   "Expires");

            if (dgvRules.Columns[nameof(FirewallRuleModel.CreatedAt)] != null)
                dgvRules.Columns[nameof(FirewallRuleModel.CreatedAt)].DefaultCellStyle.Format = "G";

            dgvRules.ResumeLayout();

            // ── Restore selection to the same rule by Name ───────────────────
            if (selectedName != null)
            {
                foreach (DataGridViewRow row in dgvRules.Rows)
                {
                    if (row.DataBoundItem is FirewallRuleModel m && m.Name == selectedName)
                    {
                        dgvRules.ClearSelection();
                        row.Selected = true;
                        dgvRules.CurrentCell = row.Cells[0];
                        break;
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════════════════════
        //  BUTTON HANDLERS — preserved exactly
        // ════════════════════════════════════════════════════════════════════
        private void BtnAddRule_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtIp.Text))
            { MessageBox.Show("Please enter remote IP."); return; }

            if (!int.TryParse(txtPort.Text, out int port)) port = 0;

            string protocol = cmbProtocol.SelectedItem?.ToString() ?? "Any";
            string action   = cmbAction.SelectedItem?.ToString()   ?? "Block";
            string ruleName = $"FW-{Guid.NewGuid()}";
            string localIp  = GetLocalIPv4();
            var now         = DateTime.Now;

            var model = new FirewallRuleModel
            {
                Name = ruleName, RemoteIp = txtIp.Text.Trim(), Port = port,
                Protocol = protocol, Action = action, CreatedAt = now,
                SourceIp = localIp, DestinationIp = txtIp.Text.Trim()
            };

            try
            {
                if (action == "Block")
                    _firewallManager.AddBlockRule(ruleName, model.RemoteIp, model.Port, model.Protocol);
                else
                    _firewallManager.AddAllowRule(ruleName, model.RemoteIp, model.Port, model.Protocol);

                if (chkPermanent.Checked || numDuration.Value <= 0)
                {
                    model.ExpiresAt = null;
                }
                else
                {
                    int minutes = (int)numDuration.Value;
                    model.ExpiresAt = now.AddMinutes(minutes);
                    _ruleExpirations[ruleName] = model.ExpiresAt.Value;
                    _timedRuleService.AddTimedRule(model, minutes);
                }

                Logger.LogRuleChange(model, "ADDED");
                RefreshRulesGrid();
            }
            catch (Exception ex) { MessageBox.Show("Error adding rule: " + ex.Message); }
        }

        private void BtnRemoveRule_Click(object sender, EventArgs e)
        {
            if (dgvRules.CurrentRow == null)
            { MessageBox.Show("Select a rule to remove."); return; }
            if (dgvRules.CurrentRow.DataBoundItem is not FirewallRuleModel model) return;
            try
            {
                _firewallManager.RemoveRule(model.Name);
                Logger.LogRuleChange(model, "REMOVED");
                RefreshRulesGrid();
            }
            catch (Exception ex) { MessageBox.Show("Error removing rule: " + ex.Message); }
        }

        private void BtnBlockAll_Click(object sender, EventArgs e)
        {
            string ruleName = $"FW-BlockAll-{Guid.NewGuid()}";
            var model = new FirewallRuleModel
            {
                Name = ruleName, RemoteIp = "Any", Port = 0, Protocol = "Any",
                Action = "Block", CreatedAt = DateTime.Now,
                SourceIp = GetLocalIPv4(), DestinationIp = "Any"
            };
            try
            {
                _firewallManager.AddBlockAllRule(ruleName);
                Logger.LogRuleChange(model, "ADDED_BLOCK_ALL");
                RefreshRulesGrid();
            }
            catch (Exception ex) { MessageBox.Show("Error adding Block ALL rule: " + ex.Message); }
        }

        private void BtnExportRules_Click(object sender, EventArgs e)
        {
            try
            {
                var rules = _firewallManager.GetAppRules();
                var sfd = new SaveFileDialog { Filter = "JSON files|*.json|All files|*.*", FileName = "firewall_rules.json" };
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    File.WriteAllText(sfd.FileName, JsonSerializer.Serialize(rules, new JsonSerializerOptions { WriteIndented = true }));
                    MessageBox.Show("Rules exported.");
                }
            }
            catch (Exception ex) { MessageBox.Show("Export failed: " + ex.Message); }
        }

        private void BtnImportRules_Click(object sender, EventArgs e)
        {
            try
            {
                var ofd = new OpenFileDialog { Filter = "JSON files|*.json|All files|*.*" };
                if (ofd.ShowDialog() != DialogResult.OK) return;
                var rules = JsonSerializer.Deserialize<List<FirewallRuleModel>>(File.ReadAllText(ofd.FileName));
                if (rules == null) { MessageBox.Show("No rules in file."); return; }
                foreach (var r in _firewallManager.GetAppRules()) _firewallManager.RemoveRule(r.Name);
                foreach (var r in rules)
                {
                    string name = $"FW-{Guid.NewGuid()}";
                    if (string.Equals(r.Action, "Allow", StringComparison.OrdinalIgnoreCase))
                        _firewallManager.AddAllowRule(name, r.RemoteIp, r.Port, r.Protocol);
                    else
                        _firewallManager.AddBlockRule(name, r.RemoteIp, r.Port, r.Protocol);
                }
                RefreshRulesGrid();
                MessageBox.Show("Rules imported.");
            }
            catch (Exception ex) { MessageBox.Show("Import failed: " + ex.Message); }
        }

        private void BtnSaveProfile_Click(object sender, EventArgs e)
        {
            try
            {
                var profile = cmbProfile.SelectedItem?.ToString();
                if (string.IsNullOrEmpty(profile)) { MessageBox.Show("Select a profile name."); return; }
                string dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "profiles");
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, $"{profile}.json"),
                    JsonSerializer.Serialize(_firewallManager.GetAppRules(), new JsonSerializerOptions { WriteIndented = true }));
                MessageBox.Show($"Profile '{profile}' saved.");
            }
            catch (Exception ex) { MessageBox.Show("Save profile failed: " + ex.Message); }
        }

        private void BtnLoadProfile_Click(object sender, EventArgs e)
        {
            try
            {
                var profile = cmbProfile.SelectedItem?.ToString();
                if (string.IsNullOrEmpty(profile)) { MessageBox.Show("Select a profile."); return; }
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "profiles", $"{profile}.json");
                if (!File.Exists(path)) { MessageBox.Show("Profile file not found."); return; }
                var rules = JsonSerializer.Deserialize<List<FirewallRuleModel>>(File.ReadAllText(path));
                if (rules == null) { MessageBox.Show("Profile file invalid."); return; }
                foreach (var r in _firewallManager.GetAppRules()) _firewallManager.RemoveRule(r.Name);
                foreach (var r in rules)
                {
                    string name = $"FW-{Guid.NewGuid()}";
                    if (string.Equals(r.Action, "Allow", StringComparison.OrdinalIgnoreCase))
                        _firewallManager.AddAllowRule(name, r.RemoteIp, r.Port, r.Protocol);
                    else
                        _firewallManager.AddBlockRule(name, r.RemoteIp, r.Port, r.Protocol);
                }
                RefreshRulesGrid();
                MessageBox.Show($"Profile '{profile}' loaded.");
            }
            catch (Exception ex) { MessageBox.Show("Load profile failed: " + ex.Message); }
        }

        // ════════════════════════════════════════════════════════════════════
        //  TESTS
        // ════════════════════════════════════════════════════════════════════
        private async Task OnPingClicked()
        {
            if (string.IsNullOrWhiteSpace(txtTestIp.Text)) { MessageBox.Show("Enter IP to test."); return; }
            string target = txtTestIp.Text.Trim(), source = GetLocalIPv4();
            var reply = await _packetTester.SendPingAsync(target);
            if (reply == null)
            {
                AppendTestOutput($"[PING] {source} → {target}  ✗  FAILED (exception)");
                Logger.LogPing(target, "EXCEPTION", -1);
            }
            else
            {
                string status = reply.Status == System.Net.NetworkInformation.IPStatus.Success ? "✓" : "✗";
                AppendTestOutput($"[PING] {source} → {target}  {status}  {reply.Status}  {reply.RoundtripTime}ms");
                Logger.LogPing(target, reply.Status.ToString(), reply.RoundtripTime);
            }
        }

        private async Task OnTcpClicked()
        {
            if (string.IsNullOrWhiteSpace(txtTestIp.Text) || !int.TryParse(txtTestPort.Text, out int port))
            { MessageBox.Show("Enter IP and port."); return; }
            string target = txtTestIp.Text.Trim(), source = GetLocalIPv4();
            bool ok = await _packetTester.SendTcpAsync(target, port);
            AppendTestOutput($"[TCP]  {source} → {target}:{port}  {(ok ? "✓  SUCCESS" : "✗  FAILED")}");
            Logger.LogTcpTest(target, port, ok);
        }

        private async Task OnUdpClicked()
        {
            if (string.IsNullOrWhiteSpace(txtTestIp.Text) || !int.TryParse(txtTestPort.Text, out int port))
            { MessageBox.Show("Enter IP and port."); return; }
            string target = txtTestIp.Text.Trim(), source = GetLocalIPv4();
            bool ok = await _packetTester.SendUdpAsync(target, port);
            AppendTestOutput($"[UDP]  {source} → {target}:{port}  {(ok ? "✓  SENT" : "✗  FAILED")}");
            Logger.LogUdpTest(target, port, ok);
        }

        private void AppendTestOutput(string text)
        {
            string ts = DateTime.Now.ToString("HH:mm:ss");
            txtTestOutput.AppendText($"{ts}  {text}{Environment.NewLine}");
        }

        // ════════════════════════════════════════════════════════════════════
        //  AUTO-BLOCK & FIREWALL CONTROLS
        // ════════════════════════════════════════════════════════════════════
        private void ChkAutoBlock_CheckedChanged(object sender, EventArgs e)
        {
            if (chkAutoBlock.Checked) { _autoBlockEngine.Start();  Logger.Log("ICMP auto-block enabled."); }
            else                      { _autoBlockEngine.Stop();   Logger.Log("ICMP auto-block disabled."); }
        }

        private void NumIcmpThreshold_ValueChanged(object sender, EventArgs e)
        {
            _config.IcmpThreshold = (int)numIcmpThreshold.Value;
            _config.Save("appsettings.json");
            _autoBlockEngine.SetThreshold(_config.IcmpThreshold);
        }

        private void ToggleWindowsFirewall(bool enabled)
        {
            try
            {
                _firewallManager.SetFirewallEnabled(enabled);
                Logger.LogFirewallToggle(enabled);
                lblFirewallStatus.Text = "Status: " + (enabled ? "● ENABLED" : "○ DISABLED");
                lblFirewallStatus.ForeColor = enabled ? _success : _danger;
            }
            catch (Exception ex) { MessageBox.Show("Failed to toggle Windows Firewall: " + ex.Message); }
        }

        private void ToggleAppFirewall(bool enabled)
        {
            try
            {
                _firewallManager.SetAppRulesEnabled(enabled);
                Logger.LogAppFirewall(enabled);
                lblAppFirewallStatus.Text = "Status: " + (enabled ? "● ENABLED" : "○ DISABLED");
                lblAppFirewallStatus.ForeColor = enabled ? _success : _danger;
            }
            catch (Exception ex) { MessageBox.Show("Failed to toggle app firewall rules: " + ex.Message); }
        }

        // ════════════════════════════════════════════════════════════════════
        //  LOG VIEWER
        // ════════════════════════════════════════════════════════════════════
        private void LoadLogsIntoGrid()
        {
            try
            {
                var list = new List<LogEntry>();
                if (File.Exists(Logger.LogPath))
                {
                    var lines = File.ReadAllLines(Logger.LogPath);
                    for (int i = 1; i < lines.Length; i++)
                    {
                        var parts = lines[i].Split(';');
                        if (parts.Length >= 3)
                            list.Add(new LogEntry { Timestamp = parts[0], Type = parts[1], Details = parts[2] });
                    }
                }
                dgvLogs.DataSource = list;
            }
            catch (Exception ex) { MessageBox.Show("Failed to read logs: " + ex.Message); }
        }

        private class LogEntry
        {
            public string Timestamp { get; set; } = "";
            public string Type      { get; set; } = "";
            public string Details   { get; set; } = "";
        }
    }
}
