import socket
import re

SSH_CVE_MAPPING = {
    "OpenSSH_8.4p1": ["CVE-2021-41617", "CVE-2021-28041"],
    "OpenSSH_8.2p1": ["CVE-2020-14145", "CVE-2020-15778"],
    "Dropbear_2020.80": ["CVE-2021-36222"],
}

def run(ip: str, port: int) -> dict:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        version_match = re.search(r"^SSH-[0-9]\.[0-9]-(?P<version>[^\s]+)", banner)
        version = version_match.group("version") if version_match else "unknown"
        cves = SSH_CVE_MAPPING.get(version, [])

        os_guess = None
        if "Ubuntu" in banner:
            os_guess = "Ubuntu"
        elif "Debian" in banner:
            os_guess = "Debian"
        elif "FreeBSD" in banner:
            os_guess = "FreeBSD"

        return {
            "service": "ssh",
            "banner": banner,
            "version": version,
            "os": os_guess,
            "cves": cves,
        }
    except socket.timeout:
        return {"error": "SSH banner timeout"}
    except Exception as e:
        return {"error": f"SSH fingerprint error: {e}"}
