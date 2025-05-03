# NakulaScan - PassiveRecon Module

import socket
import whois
import requests
import json
from ipwhois import IPWhois

class PassiveRecon:
    def __init__(self, domain):
        self.domain = domain
        self.data = {"domain": domain}

    def resolve_ip(self):
        try:
            return socket.gethostbyname(self.domain)
        except:
            return None

    def run(self):
        self.data["ip"] = self.resolve_ip()

        # WHOIS lookup
        try:
            w = whois.whois(self.domain)
            self.data["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "emails": w.emails
            }
        except:
            self.data["whois"] = "unavailable"

        # ASN / GeoIP
        if self.data["ip"]:
            try:
                obj = IPWhois(self.data["ip"])
                details = obj.lookup_rdap(depth=1)
                self.data["asn"] = details.get("asn")
                self.data["isp"] = details.get("network", {}).get("name")
                self.data["country"] = details.get("network", {}).get("country")
            except:
                self.data["asn"] = self.data["isp"] = self.data["country"] = "unknown"

        return self.data