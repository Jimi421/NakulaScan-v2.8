# NakulaScan - Report Writer

import datetime
from pathlib import Path


def generate_html_report(data, target, codename):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"reports/NakulaScan_{target}_{timestamp}.html"
    Path("reports").mkdir(exist_ok=True)

    html = f"""
    <html>
    <head>
        <title>NakulaScan Report - {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #222; color: white; }}
            h1 {{ color: #2c3e50; }}
            .cve {{ color: darkorange; font-size: 0.9em; }}
        </style>
    </head>
    <body>
        <h1>NakulaScan Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Codename:</strong> {codename}</p>
        <p><strong>Date:</strong> {timestamp}</p>

        <table>
            <tr>
                <th>IP</th>
                <th>Port</th>
                <th>Service</th>
                <th>Status</th>
                <th>Banner</th>
                <th>OS Guess</th>
                <th>Scan Type</th>
                <th>CVE Suggestions</th>
            </tr>
    """

    for entry in data:
        cves = ", ".join(entry.get('cve_suggestions', [])) if entry.get('cve_suggestions') else "None"
        html += f"""
            <tr>
                <td>{entry['ip']}</td>
                <td>{entry['port']}</td>
                <td>{entry['service']}</td>
                <td>{entry['status']}</td>
                <td>{entry['banner']}</td>
                <td>{entry['os_guess']}</td>
                <td>{entry['scan_type']}</td>
                <td class='cve'>{cves}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    with open(filename, 'w') as f:
        f.write(html)

    return filename


def generate_md_report(data, target, codename):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"reports/NakulaScan_{target}_{timestamp}.md"
    Path("reports").mkdir(exist_ok=True)

    lines = [
        "# NakulaScan Report\n",
        f"**Target:** {target}\n",
        f"**Codename:** {codename}\n",
        f"**Date:** {timestamp}\n\n",
        "| IP | Port | Service | Status | Banner | OS Guess | Scan Type | CVE Suggestions |",
        "|----|------|---------|--------|--------|----------|-----------|-----------------|"
    ]

    for entry in data:
        cves = ", ".join(entry.get('cve_suggestions', [])) if entry.get('cve_suggestions') else "None"
        lines.append(
            f"| {entry['ip']} | {entry['port']} | {entry['service']} | {entry['status']} | "
            f"{entry['banner']} | {entry['os_guess']} | {entry['scan_type']} | {cves} |"
        )

    with open(filename, 'w') as f:
        f.write("\n".join(lines))

    return filename

import csv


def generate_csv_report(data, target, codename):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"reports/NakulaScan_{target}_{timestamp}.csv"
    Path("reports").mkdir(exist_ok=True)

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Service", "Status", "Banner", "OS Guess", "Scan Type", "CVE Suggestions"])
        for entry in data:
            cves = ", ".join(entry.get('cve_suggestions', [])) if entry.get('cve_suggestions') else "None"
            writer.writerow([
                entry['ip'], entry['port'], entry['service'], entry['status'],
                entry['banner'], entry['os_guess'], entry['scan_type'], cves
            ])
    return filename
