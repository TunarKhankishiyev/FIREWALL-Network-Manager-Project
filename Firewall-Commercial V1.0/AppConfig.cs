using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace FirewallApp
{
    public class AppConfig
    {
        public string LogFilePath { get; set; } = "firewall_log.csv";
        public string FirewallLogPath { get; set; } = @"C:\Windows\System32\LogFiles\Firewall\pfirewall.log";
        public int IcmpThreshold { get; set; } = 10;
        public int DefaultBlockMinutes { get; set; } = 10;

        public string Theme { get; set; } = "Dark";

        // Köhnə sistemlə uyğunluq üçün saxlayırıq (istəsən sonra silə bilərsən)
        public string AppPin { get; set; } = "";

        // Multi-user
        public List<AppUser> Users { get; set; } = new();

        public static AppConfig Load(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    var cfg = JsonSerializer.Deserialize<AppConfig>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

                    if (cfg != null)
                    {
                        cfg.Users ??= new List<AppUser>();
                        return cfg;
                    }
                }
            }
            catch
            {
                // ignore
            }

            var def = new AppConfig();
            def.Save(path);
            return def;
        }

        public void Save(string path)
        {
            var opts = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(this, opts);
            File.WriteAllText(path, json);
        }
    }

    public class AppUser
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Role { get; set; } = "Viewer"; // Admin / Viewer
    }
}
