# NakulaScan - CVE Suggester

cve_db = {
    "OpenSSH 7.2": ["CVE-2016-0777", "CVE-2016-0778"],
    "Apache 2.4.49": ["CVE-2021-41773"],
    "nginx/1.18.0": ["CVE-2021-23017"],
    "vsFTPd 2.3.4": ["CVE-2011-2523"],
    "ProFTPD 1.3.5": ["CVE-2015-3306"],
    "Exim 4.92": ["CVE-2019-10149"]
}

def suggest_cves(banner):
    matches = []
    for keyword in cve_db:
        if keyword.lower() in banner.lower():
            matches.extend(cve_db[keyword])
    return list(set(matches))
