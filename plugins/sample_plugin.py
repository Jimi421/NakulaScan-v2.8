"""Sample plugin to run an additional check."""

def run(ip, port, banner):
    # Placeholder plugin that flags default Apache page
    results = []
    if port == 80 and 'Apache' in banner:
        results.append({'ip': ip, 'port': port, 'issue': 'Default Apache page detected'})
    return results
