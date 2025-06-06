import socket
import re

HTTP_CVE_MAPPING = {
    "Apache/2.4.41": ["CVE-2019-0211", "CVE-2020-9490"],
    "nginx/1.18.0": ["CVE-2019-20372"],
    "Microsoft-IIS/10.0": ["CVE-2020-0688", "CVE-2021-31166"],
}

def run(ip: str, port: int) -> dict:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4.0)
        sock.connect((ip, port))
        request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        text = response.decode("iso-8859-1", errors="ignore")
        server_line = next((line for line in text.split("\r\n") if line.lower().startswith("server:")), None)
        banner = server_line.split(":", 1)[1].strip() if server_line else "unknown"

        version_match = re.match(r"^(?P<ver>[^/\s]+/[^/\s]+)", banner)
        version = version_match.group("ver") if version_match else banner

        cves = []
        for key, vuln_list in HTTP_CVE_MAPPING.items():
            if key.lower() in banner.lower():
                cves = vuln_list
                break

        titles = []
        title_match = re.search(r"<title>([^<]+)</title>", text, re.IGNORECASE)
        if title_match:
            titles.append(title_match.group(1))

        return {
            "service": "http",
            "banner": banner,
            "version": version,
            "cves": cves,
            "titles": titles,
        }
    except socket.timeout:
        return {"error": "HTTP timeout or no response"}
    except Exception as e:
        return {"error": f"HTTP fingerprint error: {e}"}
