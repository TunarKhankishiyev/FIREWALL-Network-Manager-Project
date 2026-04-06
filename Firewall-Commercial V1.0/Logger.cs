using System;
using System.IO;

namespace FirewallApp
{
    public static class Logger
    {
        private static string _logPath = "firewall_log.csv";
        private static bool _initialized;
        private static readonly object _lock = new();

        public static void Initialize(string logPath)
        {
            try
            {
                _logPath = Path.GetFullPath(logPath);
            }
            catch
            {
                // Path problem olsa app ölməsin, köhnə dəyərdə qalsın
                _logPath = "firewall_log.csv";
            }

            lock (_lock)
            {
                try
                {
                    if (!File.Exists(_logPath))
                    {
                        File.WriteAllText(_logPath, "Timestamp;Type;Details" + Environment.NewLine);
                    }
                }
                catch
                {
                    // log yazıla bilməsə də app açılmalıdır
                }
            }

            _initialized = true;
        }

        private static void Write(string type, string details)
        {
            if (!_initialized) return;

            // newline-lar CSV-ni pozmasın
            details = (details ?? "").Replace("\r", " ").Replace("\n", " ");

            lock (_lock)
            {
                try
                {
                    if (!File.Exists(_logPath))
                    {
                        File.WriteAllText(_logPath, "Timestamp;Type;Details" + Environment.NewLine);
                    }

                    string newLine =
                        $"{DateTime.Now:yyyy-MM-dd HH:mm:ss};{type};{details}" + Environment.NewLine;

                    // ✅ Yeni log faylın ƏVVƏLİNƏ yazılsın (header-dən sonra)
                    string existing = File.ReadAllText(_logPath);

                    // 1) Header yoxdur/pozulubsa, header əlavə edib üstünə yaz
                    if (!existing.StartsWith("Timestamp;Type;Details"))
                    {
                        File.WriteAllText(_logPath,
                            "Timestamp;Type;Details" + Environment.NewLine + newLine + existing);
                        return;
                    }

                    // 2) Header var: birinci sətrin sonunu tapıb ondan sonra yeni logu yerləşdir
                    int firstNl = existing.IndexOf('\n'); // \r\n də burda işləyir
                    if (firstNl < 0)
                    {
                        // faylda tək header var
                        File.WriteAllText(_logPath,
                            existing + Environment.NewLine + newLine);
                        return;
                    }

                    int insertPos = firstNl + 1; // header sətrindən sonra
                    string updated = existing.Insert(insertPos, newLine);
                    File.WriteAllText(_logPath, updated);
                }
                catch
                {
                    // logger heç vaxt app-i öldürməsin
                }
            }
        }

        public static void Log(string message) => Write("INFO", message);

        // ✅ Random rule name-ləri log üçün oxunaqlı adla göstəririk (rule-un öz Name-i dəyişmir!)
        private static string FixRuleNameForLog(FirewallRuleModel rule)
        {
            if (rule == null) return "N/A";
            string n = rule.Name ?? "";

            bool looksGuid = Guid.TryParse(n, out _);

            // “random” kimi görünürsə (GUID və ya çox uzun, boşluqsuz, qarışıq)
            bool looksRandom =
                looksGuid ||
                (n.Length >= 16 && !n.Contains(" ") && !n.Contains("_"));

            if (!looksRandom && !string.IsNullOrWhiteSpace(n))
                return n;

            // Friendly ad: PROTO_IP_PORT_ACTION
            string proto = (rule.Protocol ?? "ANY").Trim();
            string ip = string.IsNullOrWhiteSpace(rule.RemoteIp) ? "ANY" : rule.RemoteIp.Trim();
            string act = (rule.Action ?? "ANY").Trim();
            string port = rule.Port.ToString();

            string friendly = $"{proto}_{ip}_{port}_{act}";
            return SanitizeName(friendly);
        }

        private static string SanitizeName(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return "RULE";

            char[] arr = s.ToCharArray();
            for (int i = 0; i < arr.Length; i++)
            {
                char c = arr[i];
                bool ok = char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.';
                if (!ok) arr[i] = '_';
            }

            string outName = new string(arr);
            if (outName.Length > 80) outName = outName.Substring(0, 80);
            return outName;
        }

        public static void LogRuleChange(FirewallRuleModel rule, string action)
        {
            string nameForLog = FixRuleNameForLog(rule);

            string details =
                $"{action} Name={nameForLog}, IP={rule.RemoteIp}, Port={rule.Port}, Proto={rule.Protocol}, Act={rule.Action}";
            Write("RULE", details);
        }

        public static void LogFirewallToggle(bool enabled)
        {
            Write("WINFW", enabled ? "Windows Firewall ENABLED" : "Windows Firewall DISABLED");
        }

        public static void LogAppFirewall(bool enabled)
        {
            Write("APPFW", enabled ? "App firewall ENABLED" : "App firewall DISABLED");
        }

        public static void LogPing(string targetIp, string status, long timeMs)
        {
            string details = $"PING {targetIp} => {status}, time={timeMs}ms";
            Write("PING", details);
        }

        public static void LogTcpTest(string targetIp, int port, bool success)
        {
            string details = $"TCP {targetIp}:{port} => {(success ? "SUCCESS" : "FAILED")}";
            Write("TCPTEST", details);
        }

        public static void LogUdpTest(string targetIp, int port, bool success)
        {
            string details = $"UDP {targetIp}:{port} => {(success ? "SENT" : "FAILED")}";
            Write("UDPTEST", details);
        }

        public static string LogPath => _logPath;
    }
}
