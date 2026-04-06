using System;

namespace FirewallApp
{
    public static class AppSession
    {
        public static string Username { get; private set; } = "";
        public static string Role { get; private set; } = "Viewer";

        public static bool IsAuthenticated => !string.IsNullOrWhiteSpace(Username);

        public static bool IsAdmin =>
            string.Equals(Role, "Admin", StringComparison.OrdinalIgnoreCase);

        public static void Set(string username, string role)
        {
            Username = username ?? "";
            Role = string.IsNullOrWhiteSpace(role) ? "Viewer" : role;
        }

        public static void Clear()
        {
            Username = "";
            Role = "Viewer";
        }
    }
}
