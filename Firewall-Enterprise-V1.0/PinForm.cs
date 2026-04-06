using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace FirewallApp
{
    public class PinForm : Form
    {
        // ─── Public API (consumed by Program.cs) ────────────────────────────
        public string EnteredUsername => _txtUsername.Text;
        public string EnteredPassword => _txtPassword.Text;

        // ─── Controls ───────────────────────────────────────────────────────
        private TextBox _txtUsername;
        private TextBox _txtPassword;
        private Button  _btnLogin;
        private Button  _btnExit;
        private Label   _lblError;
        private Button  _btnShowPass;
        private bool    _passVisible = false;

        // ─── Drag support (borderless form) ─────────────────────────────────
        private Point _dragStart;

        // ─── Theme (matches MainForm Dark) ──────────────────────────────────
        private static readonly Color C_Bg      = Color.FromArgb(10,  14,  23);
        private static readonly Color C_Card    = Color.FromArgb(17,  24,  39);
        private static readonly Color C_Sidebar = Color.FromArgb(13,  19,  33);
        private static readonly Color C_Input   = Color.FromArgb(22,  30,  46);
        private static readonly Color C_Border  = Color.FromArgb(30,  45,  61);
        private static readonly Color C_Accent  = Color.FromArgb(0,  168, 255);
        private static readonly Color C_Danger  = Color.FromArgb(255, 59,  59);
        private static readonly Color C_Success = Color.FromArgb(0,  214, 143);
        private static readonly Color C_Text    = Color.FromArgb(226, 232, 240);
        private static readonly Color C_Dim     = Color.FromArgb(100, 116, 139);

        // ════════════════════════════════════════════════════════════════════
        public PinForm()
        {
            // ── Form setup ──────────────────────────────────────────────────
            Text            = "Firewall Login";
            Width           = 880;
            Height          = 520;
            FormBorderStyle = FormBorderStyle.None;
            StartPosition   = FormStartPosition.CenterScreen;
            BackColor       = C_Bg;
            Font            = new Font("Segoe UI", 9F);
            MaximizeBox     = false;
            MinimizeBox     = false;

            // Thin glowing border around the whole form
            Paint += OnFormPaint;

            // Drag to move (since we have no title bar)
            MouseDown += (_, e) => { if (e.Button == MouseButtons.Left) { _dragStart = e.Location; } };
            MouseMove += (_, e) => { if (e.Button == MouseButtons.Left) Location = new Point(Location.X + e.X - _dragStart.X, Location.Y + e.Y - _dragStart.Y); };

            BuildLayout();
        }

        // ─── Thin glowing border drawn on the form itself ────────────────────
        private void OnFormPaint(object sender, PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            // outer glow (soft blue halo)
            using var glowPen = new Pen(Color.FromArgb(40, 0, 168, 255), 6);
            g.DrawRectangle(glowPen, 2, 2, Width - 5, Height - 5);
            // sharp inner border
            using var borderPen = new Pen(C_Border, 1);
            g.DrawRectangle(borderPen, 0, 0, Width - 1, Height - 1);
        }

        // ════════════════════════════════════════════════════════════════════
        //  LAYOUT
        // ════════════════════════════════════════════════════════════════════
        private void BuildLayout()
        {
            // ── LEFT PANEL — branding ────────────────────────────────────────
            var leftPanel = new Panel
            {
                Location  = new Point(0, 0),
                Size      = new Size(360, 520),
                BackColor = C_Sidebar
            };
            leftPanel.Paint += OnLeftPanelPaint;
            // Make left panel also draggable
            leftPanel.MouseDown += (_, e) => { if (e.Button == MouseButtons.Left) _dragStart = new Point(e.X + leftPanel.Left, e.Y + leftPanel.Top); };
            leftPanel.MouseMove += (_, e) => { if (e.Button == MouseButtons.Left) Location = new Point(Location.X + (e.X + leftPanel.Left) - _dragStart.X, Location.Y + (e.Y + leftPanel.Top) - _dragStart.Y); _dragStart = new Point(e.X + leftPanel.Left, e.Y + leftPanel.Top); };

            // Vertical divider line (right edge of left panel)
            leftPanel.Controls.Add(new Panel
            {
                Location  = new Point(359, 0),
                Size      = new Size(1, 520),
                BackColor = C_Border
            });

            // Logo image
            var logo = new PictureBox
            {
                Size      = new Size(72, 72),
                Location  = new Point(144, 130),
                SizeMode  = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent
            };
            try
            {
                string p = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firewall.png");
                if (System.IO.File.Exists(p)) logo.Image = Image.FromFile(p);
            }
            catch { }
            leftPanel.Controls.Add(logo);

            // App name — height 50 gives plenty of room for 22pt bold
            leftPanel.Controls.Add(MakeLabel("FIREWALL", C_Text, 22F, FontStyle.Bold,
                new Point(0, 210), 360, 50, ContentAlignment.MiddleCenter, "Segoe UI"));

            // Tagline
            leftPanel.Controls.Add(MakeLabel("Network Security Manager", C_Dim, 9.5F, FontStyle.Regular,
                new Point(0, 264), 360, 22, ContentAlignment.MiddleCenter));

            // Accent divider
            var divider = new Panel
            {
                Location  = new Point(140, 294),
                Size      = new Size(80, 2),
                BackColor = C_Accent
            };
            leftPanel.Controls.Add(divider);

            // Feature bullets
            int bulletY = 310;
            foreach (var line in new[] { "⟫  Rule-based IP blocking", "⟫  ICMP auto-block engine", "⟫  Timed rules & profiles", "⟫  Real-time activity logs" })
            {
                leftPanel.Controls.Add(MakeLabel(line, C_Dim, 8.5F, FontStyle.Regular,
                    new Point(70, bulletY), 220, 22, ContentAlignment.MiddleLeft));
                bulletY += 26;
            }

            // Version tag at bottom
            leftPanel.Controls.Add(MakeLabel("Enterprise V1.0", C_Dim, 7.5F, FontStyle.Regular,
                new Point(0, 488), 360, 20, ContentAlignment.MiddleCenter));

            Controls.Add(leftPanel);

            // ── RIGHT PANEL — login ──────────────────────────────────────────
            var rightPanel = new Panel
            {
                Location  = new Point(360, 0),
                Size      = new Size(520, 520),
                BackColor = C_Bg
            };
            // Right panel also draggable
            rightPanel.MouseDown += (_, e) => { if (e.Button == MouseButtons.Left) _dragStart = new Point(e.X + 360, e.Y); };
            rightPanel.MouseMove += (_, e) => { if (e.Button == MouseButtons.Left) Location = new Point(Location.X + (e.X + 360) - _dragStart.X, Location.Y + e.Y - _dragStart.Y); _dragStart = new Point(e.X + 360, e.Y); };

            // Close [×] button top-right
            _btnExit = new Button
            {
                Text      = "×",
                Location  = new Point(476, 10),
                Size      = new Size(30, 28),
                FlatStyle = FlatStyle.Flat,
                BackColor = C_Bg,
                ForeColor = C_Dim,
                Font      = new Font("Segoe UI", 13F, FontStyle.Regular),
                Cursor    = Cursors.Hand,
                TabStop   = false,
                FlatAppearance = { BorderSize = 0 }
            };
            _btnExit.MouseEnter    += (_, __) => { _btnExit.ForeColor = C_Danger; };
            _btnExit.MouseLeave    += (_, __) => { _btnExit.ForeColor = C_Dim; };
            _btnExit.Click         += (_, __) => { DialogResult = DialogResult.Cancel; Close(); };
            // (added to rightPanel after the card — see below)

            // ── Login card (centered vertically) ─────────────────────────────
            var card = new CardPanelLogin
            {
                Location  = new Point(60, 80),
                Size      = new Size(400, 350),
                BackColor = C_Card,
                BorderCol = C_Border,
                Radius    = 14
            };

            // "Welcome back" heading
            card.Controls.Add(MakeLabel("Welcome back", C_Text, 16F, FontStyle.Bold,
                new Point(0, 28), 400, 32, ContentAlignment.MiddleCenter));
            card.Controls.Add(MakeLabel("Sign in to continue", C_Dim, 9F, FontStyle.Regular,
                new Point(0, 64), 400, 22, ContentAlignment.MiddleCenter));

            // ── Username field ────────────────────────────────────────────────
            card.Controls.Add(MakeLabel("USERNAME", C_Dim, 7F, FontStyle.Bold,
                new Point(40, 104), 0, 0, ContentAlignment.TopLeft));
            _txtUsername = new TextBox
            {
                Location    = new Point(40, 120),
                Size        = new Size(320, 26),
                BackColor   = C_Input,
                ForeColor   = C_Text,
                BorderStyle = BorderStyle.FixedSingle,
                Font        = new Font("Segoe UI", 10F),
                PlaceholderText = "Enter username"
            };
            card.Controls.Add(_txtUsername);

            // ── Password field ────────────────────────────────────────────────
            card.Controls.Add(MakeLabel("PASSWORD", C_Dim, 7F, FontStyle.Bold,
                new Point(40, 162), 0, 0, ContentAlignment.TopLeft));
            _txtPassword = new TextBox
            {
                Location     = new Point(40, 178),
                Size         = new Size(290, 26),
                BackColor    = C_Input,
                ForeColor    = C_Text,
                BorderStyle  = BorderStyle.FixedSingle,
                Font         = new Font("Segoe UI", 10F),
                PasswordChar = '●',
                PlaceholderText = "Enter password"
            };
            card.Controls.Add(_txtPassword);

            // Show/hide password toggle
            _btnShowPass = new Button
            {
                Text      = "👁",
                Location  = new Point(334, 178),
                Size      = new Size(26, 26),
                FlatStyle = FlatStyle.Flat,
                BackColor = C_Input,
                ForeColor = C_Dim,
                Font      = new Font("Segoe UI", 9F),
                Cursor    = Cursors.Hand,
                TabStop   = false,
                FlatAppearance = { BorderSize = 0 }
            };
            _btnShowPass.Click += (_, __) =>
            {
                _passVisible = !_passVisible;
                _txtPassword.PasswordChar = _passVisible ? '\0' : '●';
                _btnShowPass.ForeColor    = _passVisible ? C_Accent : C_Dim;
            };
            card.Controls.Add(_btnShowPass);

            // ── Error label ───────────────────────────────────────────────────
            _lblError = new Label
            {
                Text      = "",
                ForeColor = C_Danger,
                Font      = new Font("Segoe UI", 8F),
                Location  = new Point(40, 218),
                Size      = new Size(320, 18),
                BackColor = C_Card
            };
            card.Controls.Add(_lblError);

            // ── Login button ──────────────────────────────────────────────────
            _btnLogin = new Button
            {
                Text      = "SIGN IN  →",
                Location  = new Point(40, 248),
                Size      = new Size(320, 40),
                FlatStyle = FlatStyle.Flat,
                BackColor = C_Accent,
                ForeColor = Color.White,
                Font      = new Font("Segoe UI", 10F, FontStyle.Bold),
                Cursor    = Cursors.Hand,
                FlatAppearance = { BorderSize = 0 }
            };
            _btnLogin.MouseEnter += (_, __) => _btnLogin.BackColor = Color.FromArgb(0, 140, 215);
            _btnLogin.MouseLeave += (_, __) => _btnLogin.BackColor = C_Accent;
            _btnLogin.Click      += OnLoginClick;
            card.Controls.Add(_btnLogin);

            // Hint at bottom of card
            card.Controls.Add(MakeLabel("Press Enter to sign in  ·  × to exit", C_Dim, 7.5F, FontStyle.Regular,
                new Point(0, 310), 400, 22, ContentAlignment.MiddleCenter));

            rightPanel.Controls.Add(card);

            // Add exit button AFTER card so it renders on top (WinForms z-order)
            rightPanel.Controls.Add(_btnExit);
            _btnExit.BringToFront();

            // "Secured with" badge bottom-right
            rightPanel.Controls.Add(MakeLabel("🔒 Session protected  ·  3 attempts max", C_Dim, 7.5F, FontStyle.Regular,
                new Point(0, 490), 520, 18, ContentAlignment.MiddleCenter));

            Controls.Add(rightPanel);

            AcceptButton = _btnLogin;
            CancelButton = _btnExit;
            ActiveControl = _txtUsername;
        }

        // ─── Login click ─────────────────────────────────────────────────────
        private void OnLoginClick(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_txtUsername.Text))
            {
                ShowError("Username cannot be empty.");
                _txtUsername.Focus();
                return;
            }
            if (string.IsNullOrWhiteSpace(_txtPassword.Text))
            {
                ShowError("Password cannot be empty.");
                _txtPassword.Focus();
                return;
            }
            _lblError.Text = "";
            DialogResult = DialogResult.OK;
            Close();
        }

        // ─── Show inline error (called from outside or internally) ───────────
        public void ShowError(string message)
        {
            _lblError.Text = "⚠  " + message;
            // Brief shake of the password field to give tactile feedback
            var originalLeft = _txtPassword.Left;
            var t = new System.Windows.Forms.Timer { Interval = 30 };
            int step = 0;
            int[] offsets = { 6, -6, 5, -5, 3, -3, 0 };
            t.Tick += (_, __) =>
            {
                if (step < offsets.Length)
                {
                    _txtPassword.Left = originalLeft + offsets[step++];
                    _btnShowPass.Left = _txtPassword.Left + _txtPassword.Width + 4;
                }
                else { t.Stop(); t.Dispose(); }
            };
            t.Start();
        }

        // ─── Left panel GDI+ decorative painting ─────────────────────────────
        private void OnLeftPanelPaint(object sender, PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // Subtle grid lines (blueprint feel)
            using var gridPen = new Pen(Color.FromArgb(12, 255, 255, 255), 1);
            for (int x = 0; x < 360; x += 36)
                g.DrawLine(gridPen, x, 0, x, 520);
            for (int y = 0; y < 520; y += 36)
                g.DrawLine(gridPen, 0, y, 360, y);

            // Diagonal accent bar (bottom-left to mid-right)
            using var diagBrush = new LinearGradientBrush(
                new Point(0, 520), new Point(360, 0),
                Color.FromArgb(18, 0, 168, 255), Color.Transparent);
            g.FillRectangle(diagBrush, 0, 0, 360, 520);

            // Corner accent ring (top-left decorative arc)
            using var ringPen = new Pen(Color.FromArgb(25, 0, 168, 255), 1);
            for (int r = 60; r <= 160; r += 20)
                g.DrawEllipse(ringPen, -r, -r, r * 2, r * 2);

            // Bottom-right decorative arc
            using var arcPen = new Pen(Color.FromArgb(20, 0, 168, 255), 1);
            for (int r = 40; r <= 120; r += 20)
                g.DrawEllipse(arcPen, 360 - r, 520 - r, r * 2, r * 2);
        }

        // ─── Helpers ─────────────────────────────────────────────────────────
        private static Label MakeLabel(string text, Color fore, float size, FontStyle style,
            Point loc, int w = 0, int h = 0, ContentAlignment align = ContentAlignment.TopLeft,
            string font = "Segoe UI")
        {
            var lbl = new Label
            {
                Text      = text,
                ForeColor = fore,
                Font      = new Font(font, size, style),
                AutoSize  = (w == 0 && h == 0),
                Location  = loc,
                BackColor = Color.Transparent,
                TextAlign = align
            };
            if (w > 0) lbl.Width  = w;
            if (h > 0) lbl.Height = h;
            return lbl;
        }
    }

    // ── Rounded card panel (login card only, local to this file) ────────────
    internal sealed class CardPanelLogin : Panel
    {
        public int   Radius    { get; set; } = 12;
        public Color BorderCol { get; set; } = Color.FromArgb(30, 45, 61);

        public CardPanelLogin()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.UserPaint |
                     ControlStyles.AllPaintingInWmPaint, true);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = RoundedRect(ClientRectangle, Radius);
            using var brush = new SolidBrush(BackColor);
            e.Graphics.FillPath(brush, path);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = RoundedRect(new Rectangle(0, 0, Width - 1, Height - 1), Radius);
            using var pen  = new Pen(BorderCol);
            e.Graphics.DrawPath(pen, path);
        }

        private static GraphicsPath RoundedRect(Rectangle r, int rad)
        {
            int d = rad * 2;
            var p = new GraphicsPath();
            p.AddArc(r.X,         r.Y,          d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y,          d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d,   0, 90);
            p.AddArc(r.X,         r.Bottom - d, d, d,  90, 90);
            p.CloseFigure();
            return p;
        }
    }
}
