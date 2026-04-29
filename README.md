# 🔥 FIREWALL-Manager
<div align="center">

![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)
![Framework](https://img.shields.io/badge/.NET-8.0-purple?style=flat-square)
![Language](https://img.shields.io/badge/language-C%23-239120?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/version-Enterprise_V1.0-orange?style=flat-square)

**A professional Windows Firewall management application with a desktop GUI and a built-in web interface — manage your firewall rules from any device on your local network.**

</div>

---

## 📸 Overview

Firewall is a full-featured Windows Firewall manager built on .NET 8 (WinForms). It wraps the Windows `netsh advfirewall` API into a polished UI, adds role-based authentication, a real-time ICMP auto-block engine, timed rules, rule profiles, and exposes everything through a built-in local web server — so you can manage your firewall from a phone or another machine on the same LAN.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Rule Managements** | Add, remove and view inbound block/allow rules by IP, port and protocol |
| **Timed Rules** | Rules that automatically expire after a configurable duration |
| **Rule Profiles** | Save and load named rule sets (Default, Lab, Game, …) |
| **ICMP Auto-Block** | Background engine that auto-blocks IPs exceeding a ping flood threshold |
| **Windows FW Control** | Enable/disable Windows Firewall for all profiles from one click |
| **Built-in Rule Control** | Disable all Windows built-in rules and take full control of inbound traffic |
| **Packet Tester** | Ping, TCP and UDP connectivity tests with a terminal-style output |
| **Activity Logs** | Full CSV audit trail of every rule change and firewall event |
| **Web Interface** | Responsive browser UI served over LAN on port `2309` |
| **Multi-user Auth** | Username/password login with Admin and Viewer roles |
| **Themes** | Dark (Cyber Command Center), Light, and Hacker themes |
| **System Tray** | Minimises to tray with balloon-tip auto-block notifications |
| **Export / Import** | Rules serialised to JSON for backup or transfer |

---

## 🖥️ Desktop Application

The desktop app is built with **WinForms on .NET 8** and requires **Windows** with **Administrator privileges** (needed to call `netsh`).

### Screenshots

> Dark theme · Cyber Command Center palette

<img width="400" height="840" alt="App-Log_in" src="https://github.com/user-attachments/assets/60b35398-0358-4d56-a39f-1a668eec79b5" />
<img width="400" height="840" alt="Admin-Rules" src="https://github.com/user-attachments/assets/7c8c770b-288b-4cc0-892a-4c1640bdaaa8" />
<img width="400" height="840" alt="Admin-Packet_test" src="https://github.com/user-attachments/assets/2ea0fb48-5315-441d-b78e-41832aaeba85" />
<img width="400" height="840" alt="Admin-Firewall" src="https://github.com/user-attachments/assets/47faccd6-45b5-4487-850e-aa09196dd763" />


---

## 🌐 Web Interface

When the desktop app is running, it starts an embedded HTTP server on **port 2309**. Open a browser on any LAN device and navigate to:

```
http://<machine-ip>:2309
```

The address is displayed in the desktop app header. The web UI mirrors all desktop functionality and enforces the same role-based access control via Bearer token sessions.

---

## 🚀 Getting Started

### Prerequisites

- Windows 10 / 11 (or Windows Server 2019+)
- [.NET 8.0 Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Administrator** account (required for `netsh` firewall commands)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/TunarKhankishiyev/FIREWALL-Network-Manager-Project.git
   cd Firewall-Commercial V1.0
   ```

2. **Build**
   ```bash
   dotnet build Firewall.csproj
   ```

3. **Run as Administrator**
   ```bash
   Firewall-Enterprise-V1.0\bin\Debug\net8.0-windows\Firewall.exe
   # Right-click the executable → "Run as administrator"
   # or from an elevated prompt:
   dotnet run
   ```

> ⚠️ The application **must** be run as Administrator. Without elevated privileges, all `netsh` calls will fail.

---

## ⚙️ Configuration

Settings are stored in `appsettings.json` next to the executable:

```json
{
  "LogFilePath": "firewall_log.csv",
  "FirewallLogPath": "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log",
  "IcmpThreshold": 15,
  "DefaultBlockMinutes": 10,
  "Theme": "Dark",
  "Users": [
    { "Username": "admin",  "Password": "admin",  "Role": "Admin"  },
    { "Username": "viewer", "Password": "viewer", "Role": "Viewer" }
  ]
}
```

| Key | Description |
|---|---|
| `LogFilePath` | Path to the application's CSV activity log |
| `FirewallLogPath` | Path to the Windows Firewall packet log (used by auto-block engine) |
| `IcmpThreshold` | Number of ICMP packets from a single IP before auto-block fires |
| `DefaultBlockMinutes` | Default duration for timed rules |
| `Theme` | UI theme: `Dark`, `Light`, or `Hacker` |
| `Users` | User list. If empty, the app starts with a local Admin session (no login prompt) |

> 🔒 **Change the default passwords** before deploying in any shared environment.

---

## 👥 Roles

| Role | Capabilities |
|---|---|
| **Admin** | Full access — add/remove rules, toggle firewall, manage built-in rules, configure auto-block |
| **Viewer** | Read-only — view rules, run packet tests, view logs |

---

## 🌐 REST API

The embedded web server exposes a JSON REST API. All protected endpoints require a Bearer token obtained from `POST /api/login`.

### Authentication

```http
POST /api/login
Content-Type: application/json

{ "username": "admin", "password": "admin" }
```

```json
{ "ok": true, "token": "<bearer-token>", "username": "admin", "role": "Admin", "isAdmin": true }
```

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/login` | — | Authenticate and get a token |
| `POST` | `/api/logout` | — | Invalidate current token |
| `GET` | `/api/me` | ✅ | Get current session info |
| `GET` | `/api/rules` | ✅ | List all FW- rules |
| `POST` | `/api/rules` | 🔐 Admin | Add a new rule |
| `DELETE` | `/api/rules?name=...` | 🔐 Admin | Remove a rule by name |
| `POST` | `/api/rules/blockall` | 🔐 Admin | Add a block-all inbound rule |
| `POST` | `/api/firewall/windows/on` | 🔐 Admin | Enable Windows Firewall |
| `POST` | `/api/firewall/windows/off` | 🔐 Admin | Disable Windows Firewall |
| `POST` | `/api/firewall/app/on` | 🔐 Admin | Enable all FW- rules |
| `POST` | `/api/firewall/app/off` | 🔐 Admin | Disable all FW- rules |
| `POST` | `/api/firewall/builtin/disable` | 🔐 Admin | Disable all built-in inbound rules |
| `POST` | `/api/firewall/builtin/restore` | 🔐 Admin | Restore all built-in inbound rules |
| `POST` | `/api/ping` | ✅ | Run a ping test from the server |
| `GET` | `/api/logs` | ✅ | Retrieve activity log entries |

#### Add Rule — Request Body

```json
{
  "remoteIp":  "192.168.1.100",
  "port":       80,
  "protocol":  "TCP",
  "action":    "Block",
  "permanent":  false,
  "minutes":    30
}
```

---

## 📁 Project Structure

```
Firewall-Commercial V1.0/
│
├── 📄 firewall.sln                   — Solution file
├── 📄 Firewall.csproj                — Project file (.NET 8 WinForms)
├── 📄 app.manifest                   — Windows application manifest (UAC elevation)
│
├── ── Source Files ──────────────────────────────────────────
├── AppConfig.cs                      — Configuration model & JSON persistence
├── AppSession.cs                     — In-memory desktop session (username/role)
├── AutoBlockEngine.cs                — Background ICMP flood detection & auto-block
├── FirewallManager.cs                — All netsh.exe wrapper calls
├── FirewallRuleModel.cs              — Rule data model
├── Logger.cs                         — CSV audit log writer
├── MainForm.cs                       — WinForms main window (4 tabs)
├── MainForm.txt                      — MainForm backup / reference copy
├── PacketTester.cs                   — Ping / TCP / UDP test helpers
├── PinForm.cs                        — Login dialog (WinForms)
├── Program.cs                        — Entry point & authentication flow
├── TimedRule.cs                      — Timed rule data model
├── TimedRuleService.cs               — Background timer that removes expired rules
├── WebServer.cs                      — Embedded HttpListener REST API
│
├── web/                              — Web UI source (copied to build output)
│   ├── index.html                    — Single-page web application
│   ├── app.js                        — Vanilla JS frontend logic
│   └── style.css                     — Dark cyber theme CSS
│
|
│
├── bin/Debug/net8.0-windows/         — Build output (not committed)
│   ├── Firewall.exe                  — Application executable
│   ├── Firewall.dll
│   ├── Firewall.deps.json
│   ├── Firewall.runtimeconfig.json
│   ├── appsettings.json              — Runtime configuration (auto-copied)
│   ├── firewall.ico                  — App icon
│   ├── firewall.png                  — App logo
│   ├── firewall_log.csv              — Activity log (generated at runtime)
│   ├── timed_rules.json              — Persisted timed rule expiry data
│   ├── profiles/                     — Saved rule profile JSON files
│   │   ├── Default.json
│   │   └── Lab.json
│   └── web/                          — Web UI served by embedded HTTP server
│       ├── index.html
│       ├── app.js
│       └── style.css
│
└── obj/                              — MSBuild intermediates (not committed)
    └── Debug/net8.0-windows/
        ├── ref/
        ├── refint/
        └── *.cache / *.cs / *.dll
```

---

## 🔐 Security Notes

- The application calls `netsh advfirewall` via `Process.Start` — **Administrator rights are mandatory**.
- The web server binds to `http://+:2309/` (all interfaces). Ensure port `2309` is only accessible on your trusted LAN, or add a firewall rule to restrict it.
- Web sessions use 8-hour sliding-window Bearer tokens stored in memory only — they are lost on app restart.
- Passwords in `appsettings.json` are stored in **plain text**. Replace them before sharing or deploying the configuration.
- Disabling Windows built-in rules (`/api/firewall/builtin/disable`) will set default inbound policy to **BLOCK** and may break RDP, file sharing, and other OS services. Use with caution.

---

## 📋 Requirements Summary

| Requirement | Detail |
|---|---|
| OS | Windows 10 / 11 / Server 2019+ |
| Runtime | .NET 8.0 (Windows Desktop) |
| Privileges | Administrator |
| Network | LAN access to port `2309` for web UI |
| Windows Firewall Logging | Enable in Windows Security → Firewall → Advanced Settings for auto-block engine to function |


---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool modifies Windows Firewall rules and can affect network connectivity. Use responsibly. The authors are not liable for any network outages, security incidents, or data loss resulting from use of this software.

---

<div align="center">
Made with ❤️ · Built on .NET 8 · Windows Firewall API
</div>
