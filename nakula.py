#!/usr/bin/env python3
import argparse
import socket
import ssl
import threading
import re
import time
import os
import concurrent.futures
import json
import ipaddress
import logging
import sys
import random

from scapy.all import (
    IP, TCP, UDP, ICMP, sr1, sr, conf,
    RandShort, DNS, DNSQR, SNMP, SNMPvarbind, NTPHeader
)

from plugin_loader import load_plugins
from resume_manager import ResumeManager
from passive_recon import PassiveRecon
from report_writer import generate_html_report, generate_md_report, generate_csv_report
from cve_suggester import suggest_cves

# ──▶ Import fingerprint manager (if available)
try:
    from fingerprint_manager import fingerprint_services
except ImportError:
    fingerprint_services = None

# ──▶ Silence Scapy verbosity
conf.verb = 0

# ──▶ Color constants
CYAN = "\033[96m"
GREEN = "\033[92m"
RESET = "\033[0m"

# ──▶ Common ports → service names
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
}

# Shared result lists
results = []
plugin_data = []
resume_mgr = None


def prompt_for_target_mode():
    """
    When no CLI args are provided, interactively prompt the user to choose a target mode.
    """
    print("\nNakulaScan Interactive Mode")
    print("----------------------------")
    print("1) Scan Single Host")
    print("2) Scan CIDR Range")
    print("3) Scan from File")
    print("4) Quit")
    choice = None
    while choice not in ("1", "2", "3", "4"):
        choice = input("Enter choice [1-4]: ").strip()
    if choice == "4":
        sys.exit(0)
    if choice == "1":
        host = input("Enter IP or hostname: ").strip()
        return {"target": host}
    elif choice == "2":
        cidr = input("Enter CIDR (e.g. 192.168.1.0/24): ").strip()
        return {"cidr": cidr}
    else:
        filepath = input("Enter path to target list file: ").strip()
        return {"targetlist": filepath}


def parse_args():
    """
    Parse command-line arguments, including short aliases, defaults, profiles, and examples.
    """
    parser = argparse.ArgumentParser(
        description="NakulaScan v2.8 Final — Red Team Scanner",
        epilog="""
Quick Examples:
  nakula -t 10.0.0.5
      # TCP connect scan on common ports
  nakula -t 10.0.0.5 -S fin -U
      # FIN stealth scan + UDP on common ports
  nakula -c 192.168.1.0/24 -F webscan
      # Preset webscan (stealth FIN, common ports, plugins)
  nakula -t 8.8.8.8 -F udpscan
      # Preset udpscan (DNS/SNMP/NTP UDP + plugins)
  nakula -c 10.0.0.0/24 -F fullscan
      # Preset fullscan (TCP full 1–65535 + UDP + plugins)
"""
    )
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-t", "--target", metavar="HOST",
        help="Single target IP or hostname"
    )
    target_group.add_argument(
        "-c", "--cidr", metavar="CIDR",
        help="CIDR block (e.g. 192.168.1.0/24)"
    )
    target_group.add_argument(
        "-T", "--targetlist", metavar="FILE",
        help="File containing list of targets"
    )

    parser.add_argument(
        "-p", "--ports", choices=["common", "full"], default="common",
        help="Port set to scan; default='common' (~20 well-known ports). Use 'full' to scan 1–65535."
    )
    parser.add_argument(
        "-S", "--scan", choices=["fin", "null", "xmas"],
        help="Stealth TCP scan mode: fin, null, or xmas"
    )
    parser.add_argument(
        "-U", "--udp", action="store_true",
        help="Enable UDP scanning (DNS/SNMP/NTP payloads)"
    )
    parser.add_argument(
        "-P", "--enable-plugins", action="store_true",
        help="Run plugins from the 'plugins' directory"
    )
    parser.add_argument(
        "-N", "--nobanner", action="store_true",
        help="Suppress ASCII banner at startup"
    )
    parser.add_argument(
        "-D", "--debug", action="store_true",
        help="Enable debug logging (write errors to debug.log)"
    )
    parser.add_argument(
        "-F", "--profile", choices=["webscan", "udpscan", "fullscan"],
        help="Quick-scan profiles: webscan, udpscan, fullscan"
    )

    # ──▶ Restore passive, save, resume, and auto-resume flags
    parser.add_argument(
        "--passive", action="store_true",
        help="Perform passive OSINT recon only (no active scan)"
    )
    parser.add_argument(
        "--save", metavar="FILE",
        help="File path to save scan/resume state as JSON"
    )
    parser.add_argument(
        "--resume", metavar="FILE",
        help="File path to resume scan state from JSON"
    )
    parser.add_argument(
        "--auto-resume", action="store_true",
        help="Automatically resume on crash using last save file"
    )

    return parser.parse_args()


def grab_banner(ip: str, port: int) -> str:
    """
    Try to grab a service banner from ip:port using protocol-specific logic:
      - HTTP  (port 80)       → send HEAD request, extract Server header
      - HTTPS (port 443)      → wrap in SSL (SNI), send HEAD request
      - FTP   (port 21)       → read initial 220 greeting
      - SSH   (port 22)       → read initial SSH-2.0 banner
      - Telnet (port 23)      → read initial data if any
      - SMTP  (port 25 or 587)→ read initial 220 greeting
      - POP3  (port 110 or 995)→ read initial +OK greeting
      - Fallback: generic TCP recv()

    Returns:
      - banner string (first line or Server header), or "" on timeout/failure
    """
    # HTTP (80)
    if port == 80:
        try:
            http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            http_sock.settimeout(3.0)
            http_sock.connect((ip, 80))
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            http_sock.sendall(req.encode())
            data = http_sock.recv(1024)
            http_sock.close()
            text = data.decode(errors="ignore")
            match = re.search(r"Server:\s*(.+)", text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            first_line = text.split("\r\n")[0]
            return first_line.strip()
        except Exception as e:
            logging.error(f"[!] HTTP banner failed from {ip}:{port} – {e}")
            return ""

    # HTTPS (443)
    if port == 443:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=ip
            ) as ssock:
                ssock.settimeout(3.0)
                ssock.connect((ip, 443))
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode())
                data = ssock.recv(1024)
                text = data.decode(errors="ignore")
                match = re.search(r"Server:\s*(.+)", text, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
                first_line = text.split("\r\n")[0]
                return first_line.strip()
        except Exception as e:
            logging.error(f"[!] HTTPS banner failed from {ip}:{port} – {e}")
            return ""

    # Banner-first protocols (FTP, SSH, Telnet, SMTP, POP3)
    if port in (21, 22, 23, 25, 110, 587, 995):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((ip, port))
            data = s.recv(1024)
            s.close()
            return data.decode(errors="ignore").strip()
        except Exception as e:
            logging.error(f"[!] Banner-protocol failed from {ip}:{port} – {e}")
            return ""

    # Fallback: generic TCP banner grab
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        data = s.recv(512)
        s.close()
        return data.decode(errors="ignore").strip()
    except Exception as e:
        logging.error(f"[!] Generic banner failed from {ip}:{port} – {e}")
        return ""


def guess_os(ttl: int) -> str:
    """
    Simple TTL-based OS guess:
      - TTL >= 128 → Windows
      - TTL >= 64  → Linux/Unix
      - Else       → Unknown
    """
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    else:
        return "Unknown"


def stealth_tcp_scan(ip, port, scan_type, retries=1):
    """
    Stealth TCP scan ("fin", "null", "xmas") with:
      - Retries (default: 1 retry) on no response
      - Adaptive TTL: random in [64..128]
      - Random source port per probe (RandShort)
    Returns:
      True  → open or filtered (no RST seen within timeout)
      False → closed (RST+ACK seen)
      None  → error
    """
    flags_map = {"fin": "F", "null": "", "xmas": "FPU"}

    if scan_type.lower() not in flags_map:
        logging.error(f"[!] Unknown stealth scan type: {scan_type}")
        return None

    base_ttl = random.randint(64, 128)

    for attempt in range(retries + 1):
        try:
            packet = IP(dst=ip, ttl=base_ttl) / TCP(
                sport=RandShort(),
                dport=port,
                flags=flags_map[scan_type.lower()]
            )
            response = sr1(packet, timeout=1.5, verbose=0)

            if response is None:
                if attempt < retries:
                    time.sleep(0.5 + random.random() * 0.5)
                    continue
                return True

            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                return False

            if response.haslayer(TCP):
                # Some other TCP response → treat as filtered/open
                return True

            if response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code in (1, 2, 3, 9, 10, 13):
                    return False
                return True

        except Exception as e:
            logging.error(f"[!] Stealth scan exception on {ip}:{port} - {e}")
            return None

    return None


def udp_scan(ip, port, retries=1, service_payload=True):
    """
    Enhanced UDP scan:
      - If service_payload=True, send protocol‐specific payloads for DNS(53), SNMP(161), NTP(123)
      - Retries once on no response
      - Distinguish closed (ICMP unreachable) vs open|filtered (no response)
      - Fallback on an empty UDP packet
    Returns:
      True  → open or filtered (no ICMP unreachable after retries)
      False → closed (ICMP type 3 unreachable)
      None  → error
    """
    def send_and_recv(pkt, timeout=2.0):
        return sr1(pkt, timeout=timeout, verbose=0)

    for attempt in range(retries + 1):
        try:
            if service_payload and port == 53:
                dns_pkt = IP(dst=ip) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
                resp = send_and_recv(dns_pkt, timeout=2.0)

            elif service_payload and port == 161:
                snmp_req = (
                    IP(dst=ip) /
                    UDP(sport=RandShort(), dport=161) /
                    SNMP(community="public", PDU=SNMPvarbind(oid="1.3.6.1.2.1.1.1.0"))
                )
                resp = send_and_recv(snmp_req, timeout=2.5)

            elif service_payload and port == 123:
                ntp_req = (
                    IP(dst=ip) /
                    UDP(sport=RandShort(), dport=123) /
                    NTPHeader()
                )
                resp = send_and_recv(ntp_req, timeout=2.5)

            else:
                pkt = IP(dst=ip) / UDP(sport=RandShort(), dport=port)
                resp = send_and_recv(pkt, timeout=2.0)

            if resp is None:
                if attempt < retries:
                    time.sleep(0.5 + random.random() * 0.5)
                    continue
                return True

            if resp.haslayer(ICMP):
                icmp_layer = resp.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code in (1, 2, 3, 9, 10, 13):
                    return False
                return True

            if resp.haslayer(UDP) or resp.haslayer(DNS) or resp.haslayer(SNMP) or resp.haslayer(NTPHeader):
                return True

            if resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x14 == 0x14:
                return False

            return True

        except Exception as e:
            logging.error(f"[!] UDP scan error on {ip}:{port} – {e}")
            return None

    return None


def scan_target(ip: str):
    """
    For one IP:
      1. ICMP ping + TTL → guess OS
      2. For each port in PORT_SERVICES:
         - Choose scan method (stealth TCP, UDP, or TCP connect)
         - If open → banner grab, CVE suggest, fingerprint, plugins
      3. Append results to global lists
    """
    print(f"{CYAN}[+] Scanning {ip}...{RESET}")
    try:
        resp = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
        ttl = resp.ttl if resp else 0
        os_guess = guess_os(ttl)
    except:
        os_guess = "Unknown"

    # Determine port list based on args.ports
    if args.ports == "common":
        ports_to_scan = list(PORT_SERVICES.keys())
    else:
        ports_to_scan = list(range(1, 65536))

    if resume_mgr:
        _, ports_to_scan = resume_mgr.get_state([ip], ports_to_scan)

    for port in ports_to_scan:
        try:
            if args.passive:
                continue

            elif args.scan:
                is_open = stealth_tcp_scan(ip, port, args.scan, retries=1)
                if is_open is None or not is_open:
                    continue

            elif args.udp:
                is_open = udp_scan(ip, port, retries=1, service_payload=True)
                if is_open is None or not is_open:
                    continue

            else:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.75)
                    is_open = (s.connect_ex((ip, port)) == 0)
                    s.close()
                except:
                    continue
                if not is_open:
                    continue

            # Port is open (or open|filtered). Now do banner, CVE, fingerprint, plugins:
            service = PORT_SERVICES.get(port, "Unknown")
            banner = grab_banner(ip, port)
            cves = suggest_cves(banner)

            # ──▶ FIXED: Always embed fingerprint details under port key
            fingerprint = {}
            if fingerprint_services:
                try:
                    raw_fp = fingerprint_services(ip, [port]).get(port, {})
                    # Only wrap it if raw_fp is a non-empty dict
                    if isinstance(raw_fp, dict) and raw_fp:
                        fingerprint = {port: raw_fp}
                    else:
                        fingerprint = {}
                except Exception as e:
                    logging.error(f"[!] Fingerprint error on {ip}:{port} - {e}")
                    fingerprint = {}

            print(f"{GREEN}[+] {ip}:{port} OPEN ({service}){RESET}")
            results.append({
                "ip": ip,
                "port": port,
                "service": service,
                "banner": banner,
                "os_guess": os_guess,
                "cve_suggestions": cves,
                "fingerprint": fingerprint
            })

            for plugin in plugins:
                try:
                    pdata = plugin.run(ip, port, banner)
                    if pdata:
                        plugin_data.extend(pdata)
                except Exception as e:
                    logging.error(f"[!] Plugin error on {ip}:{port} - {e}")

            if resume_mgr and args.save:
                resume_mgr.mark_scanned(ip, port)

        except Exception as e:
            logging.error(f"[!] Scan exception on {ip}:{port} - {e}")
            continue


def expand_targets(args) -> list:
    """
    Build the list of targets based on -t, -c, or -T.
    """
    targets = []
    if args.cidr:
        try:
            net = ipaddress.ip_network(args.cidr, strict=False)
            targets.extend([str(ip) for ip in net.hosts()])
        except ValueError:
            print(f"{CYAN}[-] Invalid CIDR: {args.cidr}{RESET}")
            exit(1)

    if args.targetlist:
        if not os.path.exists(args.targetlist):
            print(f"{CYAN}[-] Target list file not found: {args.targetlist}{RESET}")
            exit(1)
        with open(args.targetlist) as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if args.target:
        targets.append(args.target)

    if not targets:
        print(f"{CYAN}[-] No targets specified.{RESET}")
        exit(1)

    return targets


def main():
    global args, plugins, resume_mgr

    # 1) If no args given, run interactive prompt to choose target mode
    if len(sys.argv) == 1:
        forced = prompt_for_target_mode()
        if "target" in forced:
            sys.argv.extend(["-t", forced["target"]])
        elif "cidr" in forced:
            sys.argv.extend(["-c", forced["cidr"]])
        else:
            sys.argv.extend(["-T", forced["targetlist"]])

    # 2) Parse arguments (with short aliases, defaults, profiles)
    args = parse_args()

    # 3) Apply profile presets (overridable by explicit flags)
    if args.profile:
        if args.profile == "webscan":
            args.scan = args.scan or "fin"
            args.udp = args.udp or False
            args.ports = args.ports or "common"
            args.enable_plugins = True
        elif args.profile == "udpscan":
            args.scan = None
            args.udp = True
            args.ports = "common"
            args.enable_plugins = True
        elif args.profile == "fullscan":
            args.scan = args.scan or "null"
            args.udp = True
            args.ports = "full"
            args.enable_plugins = True

    # 4) Configure logging (debug to file if requested)
    if args.debug:
        logging.basicConfig(
            filename="debug.log",
            filemode="a",
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.ERROR)

    # 5) Print ASCII banner (unless suppressed)
    if not args.nobanner:
        print(rf"""{CYAN}
███╗   ██╗ █████╗ ██╗  ██╗██╗   ██╗██╗      █████╗ 
████╗  ██║██╔══██╗██║ ██╔╝██║   ██║██║     ██╔══██╗
██╔██╗ ██║███████║█████╔╝ ██║   ██║██║     ███████║
██║╚██╗██║██╔══██║██╔═██╗ ██║   ██║██║     ██╔══██║
██║ ╚████║██║  ██║██║  ██╗╚██████╔╝███████╗██║  ██║
╚═╝  ╚═══╝╝═╝  ╝═╝╝═╝  ╝═╝ ╝═════╝ ╝══════╝╝═╝  ╝═╝

    ॐ   (Om – Sacred Operator Mind)
{RESET}
""")

    # 6) Expand targets
    targets = expand_targets(args)

    # 7) Initialize resume manager if requested
    resume_mgr = None
    if args.resume or args.auto_resume:
        resume_file = args.resume if args.resume else "autosave.json"
        resume_mgr = ResumeManager(resume_file)
        resume_mgr.load()

    # 8) Load plugins if enabled
    plugins = load_plugins() if args.enable_plugins else []

    # 9) Passive recon only?
    if args.passive:
        pr = PassiveRecon(targets)
        pr.run()
        sys.exit(0)

    # 10) Stage 1: ThreadPoolExecutor for parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as scan_pool:
        scan_pool.map(scan_target, targets)

    # 11) Write JSON results
    os.makedirs("reports", exist_ok=True)
    try:
        with open("reports/active_results.json", "w") as af:
            json.dump(results, af, indent=4)
    except PermissionError:
        print(f"{CYAN}[!] ERROR: Cannot write to reports/active_results.json — permission denied.{RESET}")
        print(f"{CYAN}    Try: sudo rm reports/active_results.json or run as sudo.{RESET}")
        sys.exit(1)

    # 12) Write plugin data if any
    if plugin_data:
        with open("reports/plugin_results.json", "w") as pf:
            json.dump(plugin_data, pf, indent=4)

    print(f"\n{CYAN}[+] Active scan complete. Results saved to reports/active_results.json{RESET}")

    # 13) If a single target was specified, also produce HTML/MD/CSV reports
    if results and args.target:
        html_path = generate_html_report(results, args.target, codename=None)
        print(f"{CYAN}[+] HTML report written to {html_path}{RESET}")
        md_path = generate_md_report(results, args.target, codename=None)
        print(f"{CYAN}[+] Markdown report written to {md_path}{RESET}")
        csv_path = generate_csv_report(results, args.target, codename=None)
        print(f"{CYAN}[+] CSV report written to {csv_path}{RESET}")


if __name__ == "__main__":
    main()
