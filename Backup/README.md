# 💾 Backup

> **Flatten an entire folder tree into a single directory with automatic dedup naming.**

---

## 📋 Overview

Backup is a Python CLI tool that recursively walks a source directory and moves every file into a flat target directory. When filenames collide, it appends `_1`, `_2`, etc. to avoid overwrites. Files are moved, not copied — the source tree is emptied in the process.

---

## 🎯 Features

- 📂 **Recursive Flatten** — Walks all subdirectories and collects every file
- 🔢 **Dedup Naming** — Appends `_1`, `_2`, `_3`… to duplicate filenames, preserving extensions
- 🚚 **Move, Not Copy** — Files are relocated via `shutil.move` for speed and to avoid duplication
- 📁 **Auto-Create Target** — Creates the target directory if it doesn't exist
- 🛡️ **Skip Self** — Skips files already in the target directory to avoid conflicts

---

## 🚀 Usage

```bash
python Backup.py <source_directory> <target_directory>
```

### Example

```bash
python Backup.py "C:\Users\admin\pictures" "F:\media"
```

Output:

```
Moved: photo.jpg -> photo.jpg
Moved: photo.jpg -> photo_1.jpg
Moved: report.pdf -> report.pdf
Moved: report.pdf -> report_1.pdf
```

---

## 📦 Requirements

- **Python 3.x**
- Standard library only (`os`, `shutil`, `argparse`)

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
