using System;

namespace FirewallApp
{
    public class FirewallRuleModel
    {
        public int Id { get; set; }                 // 1,2,3... – grid üçün sıra nömrəsi

        public string Name { get; set; } = string.Empty;   // internal Windows rule name
        public string RemoteIp { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Protocol { get; set; } = "Any";
        public string Action { get; set; } = "Block"; // Block / Allow
        public bool IsAutoBlock { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime? ExpiresAt { get; set; }

        // Yeni: Source / Destination UI və log üçün
        public string SourceIp { get; set; } = string.Empty;
        public string DestinationIp { get; set; } = string.Empty;

        // ============================
        //  Yeni: Expires üçün display
        // ============================
        public string ExpiresText
        {
            get
            {
                // Auto-block üçün xüsusi məna vermək istəyirsənsə, lazım olsa dəyişə bilərsən
                if (IsAutoBlock && !ExpiresAt.HasValue)
                    return "-";

                // Permanent rule (ExpiresAt = null)
                if (!ExpiresAt.HasValue)
                    return "Permanent";

                var remaining = ExpiresAt.Value - DateTime.Now;

                // Vaxt keçibsə, TimedRuleService hələ tam silməyibsə
                if (remaining <= TimeSpan.Zero)
                    return "Expired";

                // 1 saatdan çoxdursa: hh:mm
                if (remaining.TotalHours >= 1)
                    return $"{(int)remaining.TotalHours:D2}h {remaining.Minutes:D2}m";

                // Əks halda: mm:ss
                return $"{remaining.Minutes:D2}m {remaining.Seconds:D2}s";
            }
        }
    }
}
