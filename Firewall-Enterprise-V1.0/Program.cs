using System;
using System.Windows.Forms;

namespace FirewallApp
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();

            AppConfig config;
            try { config = AppConfig.Load("appsettings.json"); }
            catch { config = new AppConfig(); }

            bool hasUsers = config.Users != null && config.Users.Count > 0;

            if (hasUsers)
            {
                const int maxAttempts = 3;
                int attempts = 0;

                using var loginForm = new PinForm();

                while (attempts < maxAttempts)
                {
                    var result = loginForm.ShowDialog();

                    if (result != DialogResult.OK)
                        return;

                    var enteredUser = loginForm.EnteredUsername ?? "";
                    var enteredPass = loginForm.EnteredPassword ?? "";

                    AppUser? matched = null;
                    foreach (var u in config.Users)
                    {
                        if (string.Equals(enteredUser, u.Username ?? "", StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(enteredPass, u.Password ?? "", StringComparison.Ordinal))
                        {
                            matched = u;
                            break;
                        }
                    }

                    if (matched != null)
                    {
                        AppSession.Set(matched.Username, matched.Role);
                        break;
                    }

                    attempts++;
                    int remaining = maxAttempts - attempts;

                    if (remaining > 0)
                        loginForm.ShowError($"Invalid credentials. {remaining} attempt{(remaining == 1 ? "" : "s")} remaining.");
                    else
                    {
                        loginForm.ShowError("Maximum attempts reached. Application will close.");
                        System.Threading.Thread.Sleep(1800);
                        return;
                    }
                }
            }
            else
            {
                AppSession.Set("local", "Admin");
            }

            Application.Run(new MainForm());
        }
    }
}
