# 🌐 Ceprkac

> **A Chrome-inspired tabbed web browser for Windows, built with C# WinForms and WebView2.**

---

## 📋 Overview

Ceprkac is a feature-rich desktop web browser for Windows, powered by Microsoft's WebView2 (Chromium-based) rendering engine. It features a dark Chrome-like UI with tabbed browsing, a visual bookmarks bar with nested folder support, an encrypted password manager with auto-fill, and a built-in download manager — all in a single self-contained executable.

---

## ✨ Features

### 🗂️ Tabbed Browsing
- Chrome-style custom-drawn tab strip with rounded tabs
- Open new tabs with `Ctrl+T` or the `+` button
- Close tabs with `Ctrl+W`, the `×` button, or middle-click
- Tabs open next to the current tab, not in new windows
- Links that request new windows open as tabs instead
- Switch tabs with `Ctrl+Tab` / `Ctrl+Shift+Tab`

### 🔍 Smart Address Bar
- Type a URL and hit Enter to navigate
- Type plain text to search with your chosen search engine
- Auto-prepends `https://` for bare domains
- Focus with `Ctrl+L`

### 🔎 Search Engine Choice
- First-run prompt to pick your default search engine
- Choose from Google, Bing, DuckDuckGo, Yahoo, Brave Search, or Startpage
- Used as both home page and address bar search
- Change anytime from the `≡` menu → "Change Search Engine..."

### ⭐ Bookmarks
- **Bookmarks Bar** — always visible below the toolbar with clickable chips
- **Nested Folders** — folders appear as dropdown buttons with recursive submenus, just like Chrome
- **Add/Remove** — click `☆` to toggle bookmark for current page (`Ctrl+D`)
- **Import** — import from Chrome, Firefox, or Edge via standard HTML bookmark files (preserves full folder tree)
- **Export** — export to Netscape HTML format compatible with all major browsers
- **Clear** — remove all bookmarks with confirmation

### 🔑 Password Manager
- **Import from CSV** — reads Chrome/Edge password export format (`name,url,username,password`)
- **Encrypted Storage** — passwords encrypted with Windows DPAPI, tied to your user account
- **Auto-Fill** — automatically fills login forms when you visit a saved site
- **Multi-Account Picker** — if multiple accounts exist for a site, shows a dropdown to choose which one
- **SPA Support** — retries with increasing delays for single-page apps like Discord
- **Smart Detection** — only triggers on pages with login fields or login-related URLs

### 📥 Downloads
- Intercepts all downloads with a Save As dialog
- Real-time progress in the status bar (bytes received / total)
- Completion and interruption notifications

### 📜 History
- Automatically records the last 100 visited URLs
- Clear all history from the `≡` menu

### 🎨 Dark Theme
- Chrome-inspired dark color scheme across all UI elements
- Dark Windows title bar via `DwmSetWindowAttribute`
- Dark toolbar, tab strip, bookmarks bar, menus, and status bar

### ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+T` | New tab |
| `Ctrl+W` | Close current tab |
| `Ctrl+L` | Focus address bar |
| `Ctrl+D` | Add/remove bookmark |
| `Ctrl+I` | Open DevTools |
| `Ctrl+Tab` | Next tab |
| `Ctrl+Shift+Tab` | Previous tab |
| `Enter` (in address bar) | Navigate or search |

### 🛡️ Ad Blocker (powered by GSecurity Ad Shield)
- **Network-level blocking** — blocks requests to 100+ known ad/tracking domains (Google Ads, Taboola, Outbrain, Facebook Pixel, etc.)
- **Element hiding** — removes ad containers, sponsored content, and overlay ads from page DOM
- **Always on** — no configuration needed, works on all sites
- **Lightweight** — domain matching via HashSet, no external filter lists to download

### 🛡️ WebView2 Auto-Install
- On first run, if the WebView2 Evergreen Runtime is not installed, Ceprkac automatically downloads and silently installs it
- No manual setup required for end users

---

## 🚀 Usage

### Run from source

```bash
dotnet run
```

### Build & publish

```bash
dotnet publish Ceprkac.csproj -c Release -r win-x64 --self-contained true -o bin\publish
```

### Build the installer

The included `build.bat` handles publishing, icon copying, and Inno Setup compilation in one step:

```bash
build.bat
```

The installer is output to `releases\0.6.5.0\Ceprkac-0.6.5.0-Setup.exe`.

---

## 📦 Requirements

- **Windows 10/11** (x64)
- **.NET 8.0** — bundled in self-contained publish
- **WebView2 Evergreen Runtime** — auto-installed if missing
- **Inno Setup 6** — only needed to build the installer

---

## 🏗️ Project Structure

| File | Description |
|---|---|
| `MainForm.cs` | Browser UI — tabs, toolbar, bookmarks bar, password manager, all logic |
| `Program.cs` | Application entry point |
| `Ceprkac.csproj` | Project file targeting `net8.0-windows` with WebView2 NuGet |
| `Ceprkac.iss` | Inno Setup installer script |
| `Ceprkac.ico` | Application icon |
| `build.bat` | One-click build + installer pipeline |

---

## 💾 Data Storage

All user data is stored in `%AppData%\Ceprkac`:

| File | Contents |
|---|---|
| `bookmarks.txt` | Bookmark tree (folders and links) |
| `history.txt` | Browsing history (last 100 URLs) |
| `passwords.dat` | Saved passwords (DPAPI encrypted) |
| `settings.txt` | Search engine and home page preference |
| `WebView2UserData/` | Chromium profile data (cookies, cache, etc.) |

---

## 📜 License & Disclaimer

This project is intended for authorized defensive, administrative, research, or educational use only.

- Use only on systems, networks, and environments where you have explicit permission.
- Misuse may violate law, contracts, policy, or acceptable-use terms.
- Running security, hardening, monitoring, or response tooling can impact stability and may disrupt legitimate software.
- Validate all changes in a test environment before production use.
- This project is provided **"AS IS"**, without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement.
- Authors and contributors are **not liable** for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact.
- You are solely responsible for lawful operation, configuration choices, and compliance obligations in your jurisdiction.
- Saved passwords are encrypted using Windows DPAPI and are only accessible by the Windows user account that created them. The authors are not responsible for any credential exposure resulting from system compromise, misconfiguration, or misuse.
- This software is not affiliated with or endorsed by Google, Microsoft, Discord, or any other third party.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>
