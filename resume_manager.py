# NakulaScan - ResumeManager
# Handles saving/resuming stealth scans between sessions

import json
import os

class ResumeManager:
    def __init__(self, file):
        self.file = file
        self.state = {"scanned": {}}  # structure: { ip: [port1, port2] }

    def load(self):
        if os.path.exists(self.file):
            try:
                with open(self.file, 'r') as f:
                    self.state = json.load(f)
                print(f"[+] Loaded scan state from {self.file}")
            except:
                print("[-] Failed to load previous scan state. Starting fresh.")

    def save(self):
        with open(self.file, 'w') as f:
            json.dump(self.state, f, indent=4)

    def mark_scanned(self, ip, port):
        self.state["scanned"].setdefault(ip, []).append(port)

    def get_state(self, targets, ports):
        filtered_targets = []
        filtered_ports = list(ports)

        for ip in targets:
            already_scanned = self.state["scanned"].get(ip, [])
            remaining_ports = [p for p in ports if p not in already_scanned]
            if remaining_ports:
                filtered_targets.append(ip)
                filtered_ports = remaining_ports
        return filtered_targets, filtered_ports
