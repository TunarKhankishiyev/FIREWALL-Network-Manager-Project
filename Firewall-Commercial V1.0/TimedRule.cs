using System;

namespace FirewallApp
{
    public class TimedRule
    {
        public string RuleName { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
    }
}
