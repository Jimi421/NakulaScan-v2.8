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
from scapy.all import IP, TCP, ICMP, sr1, conf
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

# ──▶ Globals
CYAN = "\033[96m"
GREEN = "\033[92m"
RESET = "\033[0m"

# Common ports → service names (unchanged)
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
}

# Shared result lists
results = []
plugin_data = []
resume_mgr = None


def group_results_by_host(data):
    from collections import defaultdict
    host_map = defaultdict(list)
    for entry in data:
        host_map[entry.get("ip")].append(entry)
    return host_map


def parse_args():
    """
    Parse command-line arguments, including the new --debug flag.
    """
    parser = argparse.ArgumentParser(description="NakulaScan v2.8 Final — Red Team Scanner")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Single target IP or hostname")
    target_group.add_argument("-c", "--cidr", help="CIDR block (e.g. 10.0.0.0/24)")
    target_group.add_argument("-T", "--targetlist", help="File containing list of targets")
    parser.add_argument(
        "--ports", choices=["common", "full"], default="common",
        help="Port set to scan ('common' = typical services, 'full' = 1-65535)"
    )
    parser.add_argument(
        "--scan", choices=["fin", "null", "xmas"],
        help="Stealth TCP scan mode (fin, null, xmas)"
    )
    parser.add_argument(
        "--passive", action="store_true",
        help="Perform passive OSINT recon only (no active scan)"
    )
    parser.add_argument(
        "--save", help="File path to save scan/resume state as JSON"
    )
    parser.add_argument(
        "--resume", help="File path to resume scan state from JSON"
    )
    parser.add_argument(
        "--udp", action="store_true",
        help="Enable UDP scanning in addition to TCP"
    )
    parser.add_argument(
        "--enable-plugins", action="store_true",
        help="Run plugins from the 'plugins' directory"
    )
    parser.add_argument(
        "--auto-resume", action="store_true",
        help="Automatically resume on crash using last save file"
    )
    parser.add_argument(
        "--nobanner", action="store_true",
        help="Suppress ASCII banner at startup"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging (write banner‐grab errors to debug.log)"
    )
    parser.add_argument(
        "--per-host", action="store_true",
        help="Generate individual reports per host when scanning multiple targets"
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
    # 1) HTTP (port 80)
    if port == 80:
        try:
            http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            http_sock.settimeout(3.0)
            http_sock.connect((ip, 80))
            # Minimal HEAD request
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            http_sock.sendall(req.encode())
            data = http_sock.recv(1024)
            http_sock.close()
            text = data.decode(errors="ignore")
            # Try to extract "Server:" header
            match = re.search(r"Server:\s*(.+)", text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            # Otherwise return first status line
            first_line = text.split("\r\n")[0]
            return first_line.strip()
        except Exception as e:
            logging.error(f"[!] HTTP banner failed from {ip}:{port} – {e}")
            return ""

    # 2) HTTPS (port 443) → SSL with SNI
    if port == 443:
        try:
            ctx = ssl.create_default_context()
            # Use server_hostname=ip so SNI is sent
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

    # 3) Banner‐first protocols (FTP, SSH, Telnet, SMTP, POP3)
    if port in (21, 22, 23, 25, 110, 587, 995):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((ip, port))
            data = s.recv(1024)
            s.close()
            return data.decode(errors="ignore").strip()
        except Exception as e:
            logging.error(f"[!] Banner‐protocol failed from {ip}:{port} – {e}")
            return ""

    # 4) Fallback: Generic TCP banner grab
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


def scan_target(ip: str):
    """
    For one IP:
      1. ICMP ping + TTL → guess OS
      2. For each port in PORT_SERVICES:
         - Connect (TCP/UDP/stealth based on args)
         - If open → banner grab, CVE suggest, fingerprint, plugins
      3. Append results to global `results` and `plugin_data`
    """
    print(f"{CYAN}[+] Scanning {ip}...{RESET}")
    try:
        pkt = IP(dst=ip) / ICMP()
        resp = sr1(pkt, timeout=2, verbose=0)
        ttl = resp.ttl if resp else 0
        os_guess = guess_os(ttl)
    except:
        os_guess = "Unknown"

    # If doing a resume, adjust ports accordingly (resume_mgr logic)
    # … assume resume_mgr was initialized in main() …
    # ports_to_scan = PORT_SERVICES.keys() or trimmed by resume_mgr
    for port in PORT_SERVICES:
        try:
            # 1) Determine if port is open
            if args.passive:
                is_open = False
            elif args.scan:
                # Example stealth scan (fin/null/xmas) – placeholder
                is_open = stealth_tcp_scan(ip, port, args.scan)  # assume this function exists
            elif args.udp:
                is_open = udp_scan(ip, port)  # assume this function exists
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                is_open = (s.connect_ex((ip, port)) == 0)
                s.close()

            if not is_open:
                continue

            service = PORT_SERVICES.get(port, "Unknown")
            # 2) Grab banner using new protocol-aware function
            banner = grab_banner(ip, port)
            # 3) Suggest CVEs based on banner
            cves = suggest_cves(banner)

            # 4) Fingerprint (if available)
            fingerprint = {}
            if fingerprint_services:
                try:
                    fingerprint = fingerprint_services(ip, [port]).get(port, {})
                except Exception as e:
                    logging.error(f"[!] Fingerprint error on {ip}:{port} - {e}")
                    fingerprint = {}

            # 5) Print and save result
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

            # 6) Run all plugins (pass ip, port, banner)
            for plugin in plugins:
                try:
                    pdata = plugin.run(ip, port, banner)
                    if pdata:
                        plugin_data.extend(pdata)
                except Exception as e:
                    logging.error(f"[!] Plugin error on {ip}:{port} - {e}")

            # 7) If using resume, mark this port as scanned
            if resume_mgr and args.save:
                resume_mgr.mark_scanned(ip, port)

        except Exception as e:
            logging.error(f"[!] Socket error on {ip}:{port} - {e}")
            continue

    # End of scan_target()


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

    args = parse_args()

    # 1) Configure logging (debug to file if requested)
    if args.debug:
        logging.basicConfig(
            filename="debug.log",
            filemode="a",
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.ERROR)

    # 2) Print ASCII banner (unless suppressed)
    if not args.nobanner:
        print(rf"""{CYAN}
███╗   ██╗ █████╗ ██╗  ██╗██╗   ██╗██╗      █████╗ 
████╗  ██║██╔══██╗██║ ██╔╝██║   ██║██║     ██╔══██╗
██╔██╗ ██║███████║█████╔╝ ██║   ██║██║     ███████║
██║╚██╗██║██╔══██║██╔═██╗ ██║   ██║██║     ██╔══██║
██║ ╚████║██║  ██║██║  ██╗╚██████╔╝███████╗██║  ██║
╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

    ॐ   (Om – Sacred Operator Mind)
{RESET}
""")

    # 3) Expand targets
    targets = expand_targets(args)

    # 4) Initialize resume manager if requested
    resume_mgr = None
    if args.resume or args.auto_resume:
        # Use specified file or default autosave.json
        resume_file = args.resume if args.resume else "autosave.json"
        resume_mgr = ResumeManager(resume_file)
        resume_mgr.load()

    # 5) Load plugins if enabled
    plugins = load_plugins() if args.enable_plugins else []

    # 6) Determine ports to scan (common vs full)
    port_list = list(PORT_SERVICES.keys()) if args.ports == "common" else list(range(1, 65536))
    if resume_mgr:
        # Filter out already-scanned ports/IPs if resuming
        targets, port_list = resume_mgr.get_state(targets, port_list)

    # 7) Passive recon only?
    if args.passive:
        pr = PassiveRecon(targets)
        pr.run()
        sys.exit(0)

    # 8) Stage 1: ThreadPoolExecutor for parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as scan_pool:
        # Each thread runs scan_target() which scans all ports in PORT_SERVICES
        scan_pool.map(scan_target, targets)

    # 9) Write JSON results
    os.makedirs("reports", exist_ok=True)
    with open("reports/active_results.json", "w") as af:
        json.dump(results, af, indent=4)

    # 10) Write plugin data if any
    if plugin_data:
        with open("reports/plugin_results.json", "w") as pf:
            json.dump(plugin_data, pf, indent=4)

    print(f"\n{CYAN}[+] Active scan complete. Results saved to reports/active_results.json{RESET}")

    if not results:
        return

    host_map = group_results_by_host(results)

    if len(targets) == 1 and args.target:
        # Single target behaviour remains the same
        html_path = generate_html_report(results, args.target, codename=None)
        print(f"{CYAN}[+] HTML report written to {html_path}{RESET}")
        md_path = generate_md_report(results, args.target, codename=None)
        print(f"{CYAN}[+] Markdown report written to {md_path}{RESET}")
        csv_path = generate_csv_report(results, args.target, codename=None)
        print(f"{CYAN}[+] CSV report written to {csv_path}{RESET}")
    else:
        if args.per_host:
            for host, entries in host_map.items():
                html_path = generate_html_report(entries, host, codename=None)
                print(f"{CYAN}[+] HTML report for {host} written to {html_path}{RESET}")
                md_path = generate_md_report(entries, host, codename=None)
                print(f"{CYAN}[+] Markdown report for {host} written to {md_path}{RESET}")
                csv_path = generate_csv_report(entries, host, codename=None)
                print(f"{CYAN}[+] CSV report for {host} written to {csv_path}{RESET}")
        else:
            html_path = generate_html_report(results, "summary", codename=None)
            print(f"{CYAN}[+] HTML summary written to {html_path}{RESET}")
            md_path = generate_md_report(results, "summary", codename=None)
            print(f"{CYAN}[+] Markdown summary written to {md_path}{RESET}")
            csv_path = generate_csv_report(results, "summary", codename=None)
            print(f"{CYAN}[+] CSV summary written to {csv_path}{RESET}")


if __name__ == "__main__":
    main()
