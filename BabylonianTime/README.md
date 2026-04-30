# 🏛️ BabylonianTime

> **Displays the current date in the ancient Babylonian lunisolar calendar — right in your browser.**

---

## 📋 Overview

BabylonianTime is a single-page web app that converts today's Gregorian date into its Babylonian calendar equivalent. It calculates the current lunar month and day based on the average lunation cycle (29.5 days) and displays the date using authentic Akkadian month names like **Nisannu**, **Ayyāru**, **Simānu**, and more.

The page updates every second, so the Babylonian date stays current as long as the tab is open.

---

## 🎯 Features

- 🌙 **Lunisolar Conversion** — Maps the current date to one of 12 Babylonian months using lunar cycle math
- 📜 **Authentic Month Names** — Nisannu, Ayyāru, Simānu, Dûzu, Abu, Ulūlu, Tashrītu, Araḫsamna, Kislimu, Ṭebētu, Šabātu, Addaru
- ⏱️ **Live Update** — Refreshes every second via `setInterval`
- 📖 **Explanation Section** — Brief overview of how the Babylonian calendar worked
- 🪶 **Zero Dependencies** — Pure HTML, CSS, and vanilla JavaScript in a single file

---

## 🚀 Usage

Just open the file in any modern browser:

```bash
# Open directly
start index.html        # Windows
open index.html         # macOS
xdg-open index.html     # Linux
```

Or serve it locally:

```bash
python -m http.server 8000
# Then visit http://localhost:8000
```

The page displays output like:

```
Babylonian Date: Simānu 14, 2025
```

---

## 🔢 How It Works

1. A reference new moon date (`2025-01-29`) anchors the calendar to the month of Šabātu
2. The number of days elapsed since that anchor is calculated
3. Dividing by the average lunar month length (29.5 days) determines the current month index
4. The remainder gives the day within that month
5. Month names cycle through the 12-element Akkadian array

---

## 📜 License & Disclaimer

This project is intended for authorized defensive, administrative, research, or educational use only.

- Use only on systems, networks, and environments where you have explicit permission.
- Misuse may violate law, contracts, policy, or acceptable-use terms.
- Running security, hardening, monitoring, or response tooling can impact stability and may disrupt legitimate software.
- Validate all changes in a test environment before production use.
- This project is provided "AS IS", without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement.
- Authors and contributors are not liable for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact.
- You are solely responsible for lawful operation, configuration choices, and compliance obligations in your jurisdiction.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>
