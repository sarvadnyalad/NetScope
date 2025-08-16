# NetScope — Automated Nmap Recon & Reporting (Beginner-Friendly)

A Windows-friendly, portfolio-ready automation that:
1) Discovers live hosts on your home network,
2) Maps open ports and services,
3) Optionally runs basic vulnerability scripts,
4) Generates a professional Word report automatically.

> **Ethical Use Only:** Scan only networks you own or have explicit permission to scan.

---

## 1) Install Prerequisites (Windows)

- **Nmap:** https://nmap.org/download.html (Windows installer)
- **Python 3.10+ (64‑bit):** https://www.python.org/downloads/
- **Git (optional):** https://git-scm.com/download/win
- **VS Code (optional):** https://code.visualstudio.com/

Verify in a new **Command Prompt**:
```bat
nmap --version
python --version
pip --version
```

---

## 2) Create Project & Virtual Environment

Open **Command Prompt** in this project folder and run:
```bat
python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
```

> Each time you work on the project, activate the venv:
```bat
call .venv\Scripts\activate
```

---

## 3) Configure Your Network Range

Open `config\settings.json` and set:
- `"network": "AUTO"` (recommended) to auto-detect from `ipconfig`
  - or put a CIDR like `"192.168.0.0/24"`

You can also toggle profiles and options there.

---

## 4) Run Quick Scan

```bat
call .venv\Scripts\activate
python src\netscope.py --profile quick
```

This will:
- Discover live hosts
- Scan services on top ports
- Save raw results to `scans\...json` and `...csv`
- Build a Word report in `reports\NetScope_Report_YYYYMMDD_HHMMSS.docx`

Open the report in Word and review.

---

## 5) Run Full Scan (All TCP Ports)

```bat
call .venv\Scripts\activate
python src\netscope.py --profile full
```

> **Note:** Full scans take longer. Use on your own/lab network only.

---

## 6) Run Vulnerability Scripts (NSE)

```bat
call .venv\Scripts\activate
python src\netscope.py --profile vuln
```

This executes Nmap's `--script vuln` suite on discovered hosts and includes findings in the report.

---

## 7) Change Output Folder

```bat
python src\netscope.py --profile quick --out myresults
```

Outputs will appear under `myresults\scans` and `myresults\reports` (folders auto-created).

---

## 8) Troubleshooting

- **No hosts found?**
  - Ensure you're on Wi‑Fi/Ethernet (not offline).
  - Try setting `"network"` explicitly (e.g. `"192.168.1.0/24"`).
- **Permission issues?** Run **Command Prompt as Administrator**.
- **Nmap not found?** Re‑install Nmap and restart the terminal so PATH updates.
- **Slow scans?** Use `--profile quick` and ensure `"T4"` timing in config.

---

## 9) Portfolio Tips

- Add screenshots of your command, console output, and the Word report.
- Include the generated `.csv` in your repo for transparency.
- Write a short "Methodology" section describing discovery → service mapping → optional vuln scripts.
- Keep an **Ethical Use** disclaimer.

---

## 10) Command Reference

- Host discovery only:
  ```bat
  python src\netscope.py --discovery-only
  ```
- Custom target (overrides config):
  ```bat
  python src\netscope.py --target 192.168.0.0/24 --profile quick
  ```
- Save with a custom project title (appears in the report):
  ```bat
  python src\netscope.py --title "My Home Lab Scan"
  ```

---

**Enjoy, and scan responsibly!**
