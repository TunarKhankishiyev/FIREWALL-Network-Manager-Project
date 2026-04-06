using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallApp
{
    public class AutoBlockEngine
    {
        private readonly FirewallManager _manager;
        private readonly string _firewallLogPath;
        private int _icmpThreshold;
        private CancellationTokenSource? _cts;

        // MainForm üçün event – auto-block olanda xəbər vermək
        public event Action<string>? AutoBlocked;

        public AutoBlockEngine(FirewallManager manager, string firewallLogPath, int icmpThreshold)
        {
            _manager = manager;
            _firewallLogPath = firewallLogPath;
            _icmpThreshold = icmpThreshold;
        }

        public void SetThreshold(int value)
        {
            _icmpThreshold = value;
        }

        public void Start()
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            Task.Run(() => RunAsync(_cts.Token));
        }

        public void Stop()
        {
            _cts?.Cancel();
            _cts = null;
        }

        private async Task RunAsync(CancellationToken token)
        {
            var ipCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            long lastLength = 0;

            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (File.Exists(_firewallLogPath))
                    {
                        using var fs = new FileStream(_firewallLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                        // Fayl böyüyübsə – yeni hissəni oxu
                        if (fs.Length > lastLength)
                        {
                            fs.Seek(lastLength, SeekOrigin.Begin);
                            using var reader = new StreamReader(fs);

                            string? line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                ProcessLine(line, ipCounts);
                            }

                            lastLength = fs.Length;
                        }
                        // Fayl sıfırlanıbsa (rotation) – başdan başla
                        else if (fs.Length < lastLength)
                        {
                            lastLength = 0;
                        }
                    }
                }
                catch
                {
                    // log path problemi və s. – sadəcə növbəti iterasiya
                }

                await Task.Delay(1000, token);
            }
        }

        private void ProcessLine(string line, Dictionary<string, int> counts)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            if (line[0] == '#') return; // header sətirləri (#Fields və s.)

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 7) return;

            string protocol = parts[3];  // date, time, action, protocol, src-ip, ...
            if (!protocol.Equals("ICMP", StringComparison.OrdinalIgnoreCase))
                return;

            string srcIp = parts[4];     // src-ip
            if (string.IsNullOrWhiteSpace(srcIp))
                return;

            counts.TryGetValue(srcIp, out var c);
            c++;
            counts[srcIp] = c;

            if (c >= _icmpThreshold && _icmpThreshold > 0)
            {
                string ruleName = $"FW-AutoBlock-{srcIp}";

                try
                {
                    _manager.AddBlockRule(ruleName, srcIp, 0, "Any");

                    var model = new FirewallRuleModel
                    {
                        Name = ruleName,
                        RemoteIp = srcIp,
                        Port = 0,
                        Protocol = "Any",
                        Action = "Block",
                        IsAutoBlock = true,
                        CreatedAt = DateTime.Now
                    };
                    Logger.LogRuleChange(model, "AUTOBLOCK");

                    AutoBlocked?.Invoke(srcIp);
                }
                catch
                {
                    // ignore – rule əlavə olunmasa da app çökməsin
                }

                // Eyni IP üçün sayacı sıfırla – yenidən threshold keçəndə yenə blok edə bilər
                counts[srcIp] = 0;
            }
        }
    }
}
