using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace FirewallApp
{
    public class FirewallManager
    {
        private const string RulePrefix = "FW-";

        // Full path avoids PATH resolution failures when UseShellExecute=false
        private static readonly string NetshPath =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");

        // ── Core netsh runner — logs every failure to Logger ─────────────────
        private static void RunNetsh(string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName               = NetshPath,
                Arguments              = args,
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true
            };

            using var p = Process.Start(psi)
                ?? throw new Exception("Failed to start netsh.exe");

            string output = p.StandardOutput.ReadToEnd();
            string error  = p.StandardError.ReadToEnd();
            p.WaitForExit();

            if (p.ExitCode != 0)
            {
                string msg = $"netsh failed (exit {p.ExitCode}): {(error + output).Trim()}";
                try { Logger.Log($"[FW ERROR] {msg}  args=[{args}]"); } catch { }
                throw new Exception(msg);
            }
        }

        // ── Public rule API ──────────────────────────────────────────────────
        public void AddBlockRule(string name, string remoteIp, int port, string protocol)
            => AddRuleInternal(name, remoteIp, port, protocol, "block");

        public void AddAllowRule(string name, string remoteIp, int port, string protocol)
            => AddRuleInternal(name, remoteIp, port, protocol, "allow");

        public void AddBlockAllRule(string name)
        {
            RunNetsh($"advfirewall firewall add rule name=\"{name}\" dir=in action=block protocol=any");
            try { Logger.Log($"[FW] Block-All rule added: {name}"); } catch { }
        }

        private void AddRuleInternal(string name, string remoteIp, int port, string protocol, string action)
        {
            string args = $"advfirewall firewall add rule name=\"{name}\" dir=in action={action} remoteip={remoteIp}";
            string proto = (protocol?.Trim() ?? "Any");

            if (proto.Equals("Any", StringComparison.OrdinalIgnoreCase))
                args += " protocol=any";
            else
            {
                args += $" protocol={proto.ToLower()}";
                if (port > 0) args += $" localport={port}";
            }

            RunNetsh(args);
            try { Logger.Log($"[FW] Rule added: name={name} ip={remoteIp} port={port} proto={proto} action={action}"); } catch { }
        }

        public void RemoveRule(string name)
        {
            try
            {
                RunNetsh($"advfirewall firewall delete rule name=\"{name}\"");
                try { Logger.Log($"[FW] Rule removed: {name}"); } catch { }
            }
            catch (Exception ex)
            {
                // Rule may already not exist — log but don't crash
                try { Logger.Log($"[FW WARN] RemoveRule '{name}': {ex.Message}"); } catch { }
            }
        }

        // ── Read all FW- rules ───────────────────────────────────────────────
        public List<FirewallRuleModel> GetAppRules()
        {
            var result = new List<FirewallRuleModel>();

            var psi = new ProcessStartInfo
            {
                FileName               = NetshPath,
                Arguments              = "advfirewall firewall show rule name=all",
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true
            };

            using var p = Process.Start(psi);
            if (p == null) return result;

            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            string[] blocks = output.Split(new[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var block in blocks)
            {
                if (!block.Contains("Rule Name:", StringComparison.OrdinalIgnoreCase)) continue;

                string name = ExtractField(block, "Rule Name:");
                if (string.IsNullOrWhiteSpace(name) ||
                    !name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase)) continue;

                string remoteIp    = ExtractField(block, "RemoteIP:");
                string protocol    = ExtractField(block, "Protocol:");
                string localPortStr = ExtractField(block, "LocalPort:");
                string action      = ExtractField(block, "Action:");

                int.TryParse(localPortStr, out int port);

                if (string.IsNullOrWhiteSpace(protocol) ||
                    protocol.Equals("Any", StringComparison.OrdinalIgnoreCase))
                    protocol = "Any";

                result.Add(new FirewallRuleModel
                {
                    Name        = name,
                    RemoteIp    = remoteIp,
                    Port        = port,
                    Protocol    = protocol,
                    Action      = action.Contains("Block", StringComparison.OrdinalIgnoreCase) ? "Block" : "Allow",
                    CreatedAt   = DateTime.Now,
                    IsAutoBlock = name.Contains("AutoBlock", StringComparison.OrdinalIgnoreCase)
                });
            }

            return result;
        }

        // ── Windows Firewall on/off — also enables logging so AutoBlockEngine works ──
        public void SetFirewallEnabled(bool enabled)
        {
            string state = enabled ? "on" : "off";
            RunNetsh($"advfirewall set allprofiles state {state}");
            try { Logger.Log($"[FW] Windows Firewall set to {state.ToUpper()}"); } catch { }

            // Enable drop/allow logging when turning ON so AutoBlockEngine can read the log
            if (enabled)
            {
                try
                {
                    RunNetsh("advfirewall set allprofiles logging droppedconnections enable");
                    RunNetsh("advfirewall set allprofiles logging allowedconnections enable");
                    try { Logger.Log("[FW] Firewall logging enabled (dropped + allowed)"); } catch { }
                }
                catch (Exception ex)
                {
                    try { Logger.Log($"[FW WARN] Could not enable logging: {ex.Message}"); } catch { }
                }
            }
        }

        // ── Enable/disable only FW- rules ────────────────────────────────────
        public void SetAppRulesEnabled(bool enabled)
        {
            string enableValue = enabled ? "yes" : "no";
            var rules = GetAppRules();
            int ok = 0, fail = 0;

            foreach (var rule in rules)
            {
                try
                {
                    RunNetsh($"advfirewall firewall set rule name=\"{rule.Name}\" new enable={enableValue}");
                    ok++;
                }
                catch (Exception ex)
                {
                    fail++;
                    try { Logger.Log($"[FW WARN] SetAppRulesEnabled '{rule.Name}': {ex.Message}"); } catch { }
                }
            }

            try { Logger.Log($"[FW] App rules set enable={enableValue}: {ok} ok, {fail} failed"); } catch { }
        }

        // ── Built-in Windows rule control ────────────────────────────────────

        /// <summary>
        /// Disables all Windows built-in inbound rules that were NOT created by this app.
        /// Your FW- rules remain untouched and fully active.
        /// Also sets default inbound policy to Block so only explicit rules pass traffic.
        /// </summary>
        public void DisableBuiltinRules()
        {
            // 1. Set default policy: block all inbound unless an explicit rule allows it
            try
            {
                RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
                Logger.Log("[FW] Default inbound policy set to BLOCK (allowoutbound kept)");
            }
            catch (Exception ex)
            {
                Logger.Log($"[FW ERROR] Could not set default policy: {ex.Message}");
            }

            // 2. Enumerate every rule and disable any that don't start with FW-
            var psi = new ProcessStartInfo
            {
                FileName               = NetshPath,
                Arguments              = "advfirewall firewall show rule name=all",
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true
            };

            using var p = Process.Start(psi);
            if (p == null)
            {
                Logger.Log("[FW ERROR] DisableBuiltinRules: could not start netsh");
                return;
            }

            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            int disabled = 0, skipped = 0, failed = 0;

            foreach (var block in output.Split(new[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                string name = ExtractField(block, "Rule Name:");
                if (string.IsNullOrWhiteSpace(name)) continue;

                // Skip our own rules — never touch them
                if (name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    skipped++;
                    continue;
                }

                // Skip already-disabled rules to avoid unnecessary netsh calls
                string enabled = ExtractField(block, "Enabled:");
                if (enabled.Equals("No", StringComparison.OrdinalIgnoreCase))
                {
                    skipped++;
                    continue;
                }

                try
                {
                    RunNetsh($"advfirewall firewall set rule name=\"{name}\" new enable=no");
                    disabled++;
                }
                catch (Exception ex)
                {
                    failed++;
                    Logger.Log($"[FW WARN] DisableBuiltin could not disable '{name}': {ex.Message}");
                }
            }

            Logger.Log($"[FW] DisableBuiltinRules done: {disabled} disabled, {skipped} skipped, {failed} failed");
        }

        /// <summary>
        /// Re-enables all Windows built-in inbound rules and restores default inbound policy to Allow.
        /// Use this to undo DisableBuiltinRules.
        /// </summary>
        public void EnableBuiltinRules()
        {
            // Restore default policy to allow inbound (Windows default)
            try
            {
                RunNetsh("advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound");
                Logger.Log("[FW] Default inbound policy restored to ALLOW");
            }
            catch (Exception ex)
            {
                Logger.Log($"[FW ERROR] Could not restore default policy: {ex.Message}");
            }

            var psi = new ProcessStartInfo
            {
                FileName               = NetshPath,
                Arguments              = "advfirewall firewall show rule name=all",
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true
            };

            using var p = Process.Start(psi);
            if (p == null)
            {
                Logger.Log("[FW ERROR] EnableBuiltinRules: could not start netsh");
                return;
            }

            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            int enabled = 0, skipped = 0, failed = 0;

            foreach (var block in output.Split(new[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                string name = ExtractField(block, "Rule Name:");
                if (string.IsNullOrWhiteSpace(name)) continue;

                // Skip our own rules
                if (name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    skipped++;
                    continue;
                }

                // Skip already-enabled rules
                string isEnabled = ExtractField(block, "Enabled:");
                if (isEnabled.Equals("Yes", StringComparison.OrdinalIgnoreCase))
                {
                    skipped++;
                    continue;
                }

                try
                {
                    RunNetsh($"advfirewall firewall set rule name=\"{name}\" new enable=yes");
                    enabled++;
                }
                catch (Exception ex)
                {
                    failed++;
                    Logger.Log($"[FW WARN] EnableBuiltin could not enable '{name}': {ex.Message}");
                }
            }

            Logger.Log($"[FW] EnableBuiltinRules done: {enabled} enabled, {skipped} skipped, {failed} failed");
        }

        // ── Helper ───────────────────────────────────────────────────────────
        private static string ExtractField(string block, string fieldName)
        {
            foreach (var line in block.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.TrimStart().StartsWith(fieldName, StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(new[] { ':' }, 2);
                    if (parts.Length == 2) return parts[1].Trim();
                }
            }
            return string.Empty;
        }
    }
}
