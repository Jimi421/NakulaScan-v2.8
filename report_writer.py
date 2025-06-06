# report_writer.py

import os
import json
from datetime import datetime

def generate_html_report(results, target, codename):
    """
    Create a simple HTML table from `results`:
    Each result item is a dict:
      {
        "ip": "...",
        "port": 80,
        "service": "HTTP",
        "banner": "...",
        "os_guess": "...",
        "cve_suggestions": [...],
        "fingerprint": {...}
      }
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"reports/NakulaScan_{safe_target}_{timestamp}.html"
    os.makedirs("reports", exist_ok=True)

    with open(filename, "w") as f:
        f.write(f"<html><head><title>NakulaScan Report: {target}</title></head><body>\n")
        f.write(f"<h1>NakulaScan Report for {target}</h1>\n")
        f.write("<table border='1' cellpadding='5' cellspacing='0'>\n")
        f.write("<tr>"
                "<th>IP</th>"
                "<th>Port</th>"
                "<th>Service</th>"
                "<th>OS Guess</th>"
                "<th>Banner</th>"
                "<th>CVE Suggestions</th>"
                "<th>Fingerprint</th>"
                "</tr>\n")

        for entry in results:
            ip        = entry.get("ip", "")
            port      = entry.get("port", "")
            service   = entry.get("service", "")
            os_guess  = entry.get("os_guess", "")
            banner    = entry.get("banner", "").replace("<", "&lt;").replace(">", "&gt;")
            cves_list = entry.get("cve_suggestions", [])
            cves_html = "<br/>".join(cves_list) if cves_list else "None"
            fp_data   = entry.get("fingerprint", {})

            # Convert fingerprint dict to an HTML string
            if isinstance(fp_data, dict) and fp_data:
                # Example: {22:{service:'ssh',version:'OpenSSH_8.4p1',...}, 80:{...}}
                fp_html_parts = []
                for p, details in fp_data.items():
                    svc  = details.get("service", "")
                    ver  = details.get("version", "")
                    oth  = ", ".join(f"{k}:{v}" for k, v in details.items() if k not in ("service","version"))
                    fp_html_parts.append(f"Port {p}: {svc}/{ver}<br/>{oth}")
                fp_html = "<br/><br/>".join(fp_html_parts)
            else:
                fp_html = "None"

            f.write("<tr>")
            f.write(f"<td>{ip}</td>")
            f.write(f"<td>{port}</td>")
            f.write(f"<td>{service}</td>")
            f.write(f"<td>{os_guess}</td>")
            f.write(f"<td><pre style='font-family:monospace'>{banner}</pre></td>")
            f.write(f"<td>{cves_html}</td>")
            f.write(f"<td>{fp_html}</td>")
            f.write("</tr>\n")

        f.write("</table>\n")
        f.write("</body></html>\n")

    return filename


def generate_md_report(results, target, codename):
    """
    Create a Markdown report of the scan results.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"reports/NakulaScan_{safe_target}_{timestamp}.md"
    os.makedirs("reports", exist_ok=True)

    with open(filename, "w") as f:
        f.write(f"# NakulaScan Report for {target}\n\n")
        f.write("| IP | Port | Service | OS Guess | Banner | CVE Suggestions | Fingerprint |\n")
        f.write("|----|------|---------|----------|--------|-----------------|-------------|\n")
        for entry in results:
            ip        = entry.get("ip", "")
            port      = entry.get("port", "")
            service   = entry.get("service", "")
            os_guess  = entry.get("os_guess", "")
            banner    = entry.get("banner", "").replace("\n", " ").replace("|", "\\|")
            cves_list = entry.get("cve_suggestions", [])
            cves_md   = "; ".join(cves_list) if cves_list else "None"
            fp_data   = entry.get("fingerprint", {})

            if isinstance(fp_data, dict) and fp_data:
                fp_md_parts = []
                for p, details in fp_data.items():
                    svc  = details.get("service", "")
                    ver  = details.get("version", "")
                    om   = ", ".join(f"{k}:{v}" for k, v in details.items() if k not in ("service","version"))
                    fp_md_parts.append(f"Port {p}: {svc}/{ver} ({om})")
                fp_md = "; ".join(fp_md_parts)
            else:
                fp_md = "None"

            f.write(f"| {ip} | {port} | {service} | {os_guess} | `{banner}` | {cves_md} | {fp_md} |\n")

    return filename


def generate_csv_report(results, target, codename):
    """
    Create a CSV report of the scan results.
    """
    import csv
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"reports/NakulaScan_{safe_target}_{timestamp}.csv"
    os.makedirs("reports", exist_ok=True)

    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        # Header
        writer.writerow([
            "IP", "Port", "Service", "OS Guess", "Banner", "CVE Suggestions", "Fingerprint"
        ])
        for entry in results:
            ip        = entry.get("ip", "")
            port      = entry.get("port", "")
            service   = entry.get("service", "")
            os_guess  = entry.get("os_guess", "")
            banner    = entry.get("banner", "")
            cves_list = entry.get("cve_suggestions", [])
            cves_csv  = ";".join(cves_list) if cves_list else ""
            fp_data   = entry.get("fingerprint", {})

            if isinstance(fp_data, dict) and fp_data:
                fp_csv_parts = []
                for p, details in fp_data.items():
                    svc  = details.get("service", "")
                    ver  = details.get("version", "")
                    om   = "|".join(f"{k}:{v}" for k, v in details.items() if k not in ("service","version"))
                    fp_csv_parts.append(f"{p}:{svc}/{ver}({om})")
                fp_csv = ";".join(fp_csv_parts)
            else:
                fp_csv = ""

            writer.writerow([ip, port, service, os_guess, banner, cves_csv, fp_csv])

    return filename
