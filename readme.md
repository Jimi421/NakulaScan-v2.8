# 🛡️ NakulaScan v2.8

NakulaScan is a lightweight, modular, and stealth-optimized reconnaissance tool built for red team operators, bug bounty hunters, and cybersecurity learners.

Perform active stealth scans, gather passive OSINT, and receive CVE suggestions — all in one clean command-line tool.

---

## ⚙️ Features

- ✅ Stealth TCP Scan Modes (FIN, NULL, XMAS)
- ✅ Passive Recon: WHOIS, DNS, ASN, GeoIP
- ✅ CVE Matching from Service Banners (Offline)
- ✅ Save & Resume Mid-Scan
- ✅ Codename Generator for Operator Identity
- ✅ Clean HTML + Markdown Report Generation
- ✅ Subdomain Resolution Support (Passive Mode)
- ✅ CIDR Range Scanning
- ✅ CSV Report Generation
- ✅ UDP Scanning and Full Port Range
- ✅ Plugin Architecture for Custom Checks
- ✅ Asynchronous Thread Pool Scanning

---

## 🚀 Usage Examples

### Active Stealth Scan (XMAS):
```bash
sudo python3 nakulascan.py -t 192.168.1.5 --scan xmas
```

### Passive Recon Only:
```bash
python3 nakulascan.py -t example.com --passive
```

### Scan From List:
```bash
sudo python3 nakulascan.py -T examples/targets.txt --scan fin
```

### Scan a CIDR Range:
```bash
sudo python3 nakulascan.py -c 192.168.1.0/24 --scan fin
```

### Save + Resume a Scan:
```bash
sudo python3 nakulascan.py -t scanme.nmap.org --scan null --save session.json
sudo python3 nakulascan.py --resume session.json
```
### UDP Scan Example:
```bash
sudo python3 nakulascan.py -t 192.168.1.5 --udp
```


---

## 📁 Output Files

- `reports/active_results.json`
- `reports/passive_results.json`
- `reports/NakulaScan_<target>_<timestamp>.html`
- `reports/NakulaScan_<target>_<timestamp>.csv`
- `reports/NakulaScan_<target>_<timestamp>.md`


## 🔍 CVE Matching Logic
Matches banners to known CVE patterns locally, with no internet required. Add new entries in `cve_suggester.py` to expand the database.

---

## ⚖️ License
MIT License. For educational and ethical red team use only.

> “He who moves without being seen is the truest warrior.” — Nakula  
> ॐ
