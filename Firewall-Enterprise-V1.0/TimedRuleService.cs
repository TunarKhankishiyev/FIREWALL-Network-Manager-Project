using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Timers;

namespace FirewallApp
{
    public class TimedRuleService
    {
        private readonly FirewallManager _firewall;
        private readonly List<TimedRule> _timedRules = new();
        private readonly Timer _timer;
        private readonly string _storagePath;

        public TimedRuleService(FirewallManager firewall, string storagePath)
        {
            _firewall = firewall;
            _storagePath = storagePath;
            Load();

            _timer = new Timer(60_000); // check every 60 seconds
            _timer.Elapsed += OnTimerTick;
            _timer.AutoReset = true;
            _timer.Start();
        }

        public void AddTimedRule(FirewallRuleModel rule, int durationMinutes)
        {
            var tr = new TimedRule
            {
                RuleName = rule.Name,
                ExpiresAt = DateTime.Now.AddMinutes(durationMinutes)
            };
            _timedRules.Add(tr);
            Save();
        }

        private void OnTimerTick(object sender, ElapsedEventArgs e)
        {
            var now = DateTime.Now;
            var expired = _timedRules.FindAll(r => r.ExpiresAt <= now);

            foreach (var tr in expired)
            {
                _firewall.RemoveRule(tr.RuleName);
                Logger.Log($"Timed rule expired and removed: {tr.RuleName}");
            }

            _timedRules.RemoveAll(r => r.ExpiresAt <= now);

            if (expired.Count > 0)
                Save();
        }

        private void Load()
        {
            try
            {
                if (File.Exists(_storagePath))
                {
                    var json = File.ReadAllText(_storagePath);
                    var list = JsonSerializer.Deserialize<List<TimedRule>>(json);
                    if (list != null)
                    {
                        _timedRules.Clear();
                        _timedRules.AddRange(list);
                    }
                }
            }
            catch
            {
                // ignore
            }
        }

        private void Save()
        {
            try
            {
                var json = JsonSerializer.Serialize(_timedRules, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_storagePath, json);
            }
            catch
            {
                // ignore
            }
        }
    }
}