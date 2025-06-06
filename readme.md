# 🛡️ NakulaScan v2.8

NakulaScan is a lightweight, modular, and stealth-optimized reconnaissance tool built for red team operators, bug bounty hunters, and cybersecurity learners.

Perform active stealth scans, gather passive OSINT, and receive CVE suggestions — all in one clean command-line tool.

---

## ⚙️ Features

- ✅ Stealth TCP Scan Modes (FIN, NULL, XMAS)
- ✅ Passive Recon: WHOIS, DNS, ASN, GeoIP
- ✅ CVE Matching from Service Banners (Offline)
- ✅ Protocol-aware Banner Grabbing (HTTP/HTTPS, FTP, SSH, etc.)
- ✅ Save & Resume Mid-Scan
- ✅ Codename Generator for Operator Identity
- ✅ Clean HTML + Markdown Report Generation
- ✅ Subdomain Resolution Support (Passive Mode)
- ✅ CIDR Range Scanning
- ✅ CSV Report Generation
- ✅ UDP Scanning with DNS/SNMP/NTP payloads and full port range
- ✅ Plugin Architecture for Custom Checks
- ✅ Asynchronous Thread Pool Scanning
- ✅ Interactive mode when launched with no arguments
- ✅ Quick-scan profiles for common scenarios
- ✅ Automatic crash resume via `--auto-resume`
- ✅ Debug logging to `debug.log`

---

## 🚀 Usage Examples

### Active Stealth Scan (XMAS):
```bash
sudo python3 nakula.py -t 192.168.1.5 -S xmas
```

### Passive Recon Only:
```bash
python3 nakula.py -t example.com --passive
```

### Scan From List:
```bash
sudo python3 nakula.py -T targets.txt -S fin
```

### Scan a CIDR Range:
```bash
sudo python3 nakula.py -c 192.168.1.0/24 -S fin
```

### Per-Host Reports from CIDR Range:
```bash
sudo python3 nakula.py -c 192.168.1.0/24 -S fin --per-host
```

### Save + Resume a Scan:
```bash
sudo python3 nakula.py -t scanme.nmap.org -S null --save session.json
sudo python3 nakula.py --resume session.json
```
### UDP Scan Example:
```bash
sudo python3 nakula.py -t 192.168.1.5 -U
```

### Quick Profile (Webscan):
```bash
sudo python3 nakula.py -c 192.168.1.0/24 -F webscan
```

### Interactive Mode:
```bash
python3 nakula.py
```


---

## 📁 Output Files

- `reports/active_results.json`
- `reports/passive_results.json`
- `reports/NakulaScan_<target>_<timestamp>.html`
- `reports/NakulaScan_<target>_<timestamp>.csv`
- `reports/NakulaScan_<target>_<timestamp>.md`
- `reports/NakulaScan_summary_<timestamp>.*` for multi-target scans
- `reports/NakulaScan_<ip>_<timestamp>.*` when using `--per-host`


## 🔍 CVE Matching Logic
Matches banners to known CVE patterns locally, with no internet required. Add new entries in `cve_suggester.py` to expand the database.

---

## ⚖️ License
MIT License. For educational and ethical red team use only.

> “He who moves without being seen is the truest warrior.” — Nakula  
> ॐ
