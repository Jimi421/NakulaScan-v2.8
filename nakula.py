import argparse
import socket
import random
import threading
import time
import os
import json
from scapy.all import *
from resumemanager import ResumeManager
from passive_recon import PassiveRecon
from report_writer import generate_html_report, generate_md_report
from cve_suggester import suggest_cves

conf.verb = 0

# CLI colors
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "SMB", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

def banner():
    return f"""{CYAN}
███╗   ██╗ █████╗ ██╗  ██╗██╗   ██╗██╗      █████╗ 
████╗  ██║██╔══██╗██║ ██╔╝██║   ██║██║     ██╔══██╗
██╔██╗ ██║███████║█████╔╝ ██║   ██║██║     ███████║
██║╚██╗██║██╔══██║██╔═██╗ ██║   ██║██║     ██╔══██║
██║ ╚████║██║  ██║██║  ██╗╚██████╔╝███████╗██║  ██║
╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

        ॐ  (Om - Sacred Operator Mind)
{RESET}"""

def generate_codename():
    names = ["SilentFalcon", "GhostTiger", "ShadowWolf", "PhantomEagle", "SwiftViper", "DarkCobra"]
    return random.choice(names) + str(random.randint(10, 99))

def grab_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1) as s:
            s.settimeout(1)
            return s.recv(1024).decode(errors='ignore').strip()
    except:
        return ""

def guess_os(ttl):
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux"
    return "Unknown"

def stealth_tcp_scan(ip, port, scan_type):
    flags_map = {"fin": "F", "null": "", "xmas": "FPU"}
    try:
        pkt = IP(dst=ip, ttl=random.randint(32, 128)) / TCP(dport=port, flags=flags_map[scan_type.lower()])
        response = sr1(pkt, timeout=1, verbose=0)
        if response is None:
            return True
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            return False
    except:
        pass
    return None

parser = argparse.ArgumentParser(description="NakulaScan - Elite Red Team Recon Platform")
parser.add_argument("-t", "--target", help="Target IP or hostname")
parser.add_argument("-T", "--targetlist", help="File containing list of targets")
parser.add_argument("-p", "--ports", choices=["common", "full"], default="common", help="Port set to scan")
parser.add_argument("--scan", choices=["fin", "null", "xmas"], help="Stealth TCP scan mode")
parser.add_argument("--passive", action="store_true", help="Perform passive OSINT recon only (no active scan)")
parser.add_argument("--save", help="File path to save scan/resume state as JSON")
parser.add_argument("--resume", help="File path to resume scan state from JSON")
parser.add_argument("--auto-resume", action="store_true", help="Automatically resume on crash using last save file")
parser.add_argument("--nobanner", action="store_true", help="Suppress ASCII banner")
args = parser.parse_args()

if not args.nobanner:
    print(banner())
codename = generate_codename()
print(f"{CYAN}[+] Operator Codename: {codename}{RESET}")

if args.targetlist:
    with open(args.targetlist) as f:
        targets = [l.strip() for l in f if l.strip()]
elif args.target:
    targets = [args.target]
else:
    print(f"{RED}[-] No targets specified.{RESET}")
    exit(1)

if args.passive:
    os.makedirs("reports", exist_ok=True)
    passive_results = []
    for t in targets:
        print(f"{CYAN}[+] Passive recon: {t}{RESET}")
        recon = PassiveRecon(t)
        data = recon.run()
        passive_results.append(data)
    with open("reports/passive_results.json", "w") as pf:
        json.dump(passive_results, pf, indent=4)
    print(f"{CYAN}[+] Passive recon saved to reports/passive_results.json{RESET}")
    if not args.scan:
        exit(0)

resume_mgr = None
if args.resume or args.auto_resume:
    resume_file = args.resume or "scanstate.json"
    resume_mgr = ResumeManager(resume_file)
    resume_mgr.load()

ports = list(PORT_SERVICES.keys()) if args.ports == "common" else list(range(1, 1025))
if resume_mgr:
    targets, ports = resume_mgr.get_state(targets, ports)

results = []

def scan_target(ip):
    print(f"\n{CYAN}[+] Scanning {ip}...{RESET}")
    try:
        ans = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        os_guess = guess_os(ans.ttl if ans else 0)
    except:
        os_guess = "Unknown"

    for port in ports:
        try:
            status = None
            if args.scan:
                status = stealth_tcp_scan(ip, port, args.scan)
                if status is None:
                    continue
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                status = (s.connect_ex((ip, port)) == 0)
                s.close()

            if status:
                service = PORT_SERVICES.get(port, "Unknown")
                banner = grab_banner(ip, port) if not args.scan else ""
                cves = suggest_cves(banner)
                with threading.Lock():
                    print(f"{GREEN}[+] {ip}:{port} OPEN ({service}) [{os_guess}] ({args.scan.upper() if args.scan else 'CONNECT'}){RESET}")
                if resume_mgr:
                    resume_mgr.mark_scanned(ip, port)
                results.append({
                    'ip': ip,
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': banner,
                    'os_guess': os_guess,
                    'scan_type': args.scan.upper() if args.scan else 'CONNECT',
                    'cve_suggestions': cves
                })
            if resume_mgr and args.save:
                resume_mgr.save()
        except:
            continue

threads = []
for t in targets:
    th = threading.Thread(target=scan_target, args=(t,))
    th.start()
    threads.append(th)
    time.sleep(0.1)
for th in threads:
    th.join()

if resume_mgr and args.save:
    resume_mgr.save()
    print(f"{CYAN}[+] Scan state saved to {resume_mgr.file}{RESET}")

os.makedirs("reports", exist_ok=True)
with open("reports/active_results.json", "w") as af:
    json.dump(results, af, indent=4)
print(f"\n{CYAN}[+] Active scan complete. Results saved to reports/active_results.json{RESET}")

if results and args.target:
    html_path = generate_html_report(results, args.target, codename)
    md_path = generate_md_report(results, args.target, codename)
    print(f"{CYAN}[+] HTML report written to {html_path}{RESET}")
    print(f"{CYAN}[+] Markdown report written to {md_path}{RESET}")
