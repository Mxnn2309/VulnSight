import nmap
import requests
from bs4 import BeautifulSoup


class VulnScanner:
    def __init__(self, target_url, target_ip):
        self.target_url = target_url
        self.target_ip = target_ip
        self.results = {"ports": [], "headers": {}, "forms": []}

    def scan_ports(self):
        """Scans the target IP for open ports using Nmap."""
        nm = nmap.PortScanner()
        # Scanning common ports 21-443
        nm.scan(self.target_ip, '21-443')
        for proto in nm[self.target_ip].all_protocols():
            lport = nm[self.target_ip][proto].keys()
            for port in lport:
                state = nm[self.target_ip][proto][port]['state']
                self.results["ports"].append({"port": port, "state": state})
        return self.results["ports"]

    def check_headers(self):
        """Analyzes HTTP headers for security weaknesses."""
        try:
            response = requests.get(self.target_url, timeout=5)
            headers = response.headers
            security_headers = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']

            for header in security_headers:
                self.results["headers"][header] = headers.get(header, "MISSING")

        except requests.exceptions.RequestException as e:
            print(f"\n      [!] Warning: Could not connect to {self.target_url} for headers.")
            self.results["headers"] = {"Status": "Host Unreachable or Timed Out"}

        return self.results["headers"]

    def get_forms(self):
        """Extracts forms from the page to identify injection points."""
        try:
            res = requests.get(self.target_url, timeout=5)
            soup = BeautifulSoup(res.content, "html.parser")
            forms = soup.find_all("form")
            self.results["forms"] = [str(f.get('action')) for f in forms]
        except requests.exceptions.RequestException:
            self.results["forms"] = []

        return self.results["forms"]