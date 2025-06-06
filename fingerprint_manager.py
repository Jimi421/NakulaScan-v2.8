import importlib
import logging

LOGGER = logging.getLogger("fingerprint")

PORT_PLUGIN_MAP = {
    22: "plugins.fingerprinting.ssh_fingerprint",
    80: "plugins.fingerprinting.http_fingerprint",
    443: "plugins.fingerprinting.http_fingerprint",
}

def fingerprint_services(ip, open_ports):
    results = {}
    for port in open_ports:
        plugin_module_name = PORT_PLUGIN_MAP.get(port)
        if not plugin_module_name:
            continue
        try:
            module = importlib.import_module(plugin_module_name)
            fp_data = module.run(ip, port)
            if fp_data:
                results[port] = fp_data
        except Exception as e:
            LOGGER.error(f"[!] Fingerprint plugin error on {ip}:{port} → {e}")
    return results
