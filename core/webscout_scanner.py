import socket
import requests
import whois
import dns.resolver
import ssl
import OpenSSL
from datetime import datetime
import urllib.parse
import warnings

# Suppress insecure request warnings for self-signed certificates
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class WebScoutScanner:
    def __init__(self, target_url):
        self.target_url = target_url

        # Parse the domain properly for WHOIS/DNS/SSL
        parsed = urllib.parse.urlparse(self.target_url)
        self.domain = parsed.netloc or parsed.path

        try:
            self.target_ip = socket.gethostbyname(self.domain)
        except socket.gaierror:
            self.target_ip = None

        # Data structure to feed the AI Risk Engine
        self.results = {
            "ip": self.target_ip,
            "whois": {},
            "dns": {},
            "ssl": {"status": "Unknown", "days_valid": 0},
            "technologies": [],
            "subdomains": [],
            "ports": [],
            "headers": {}
        }

    def get_whois_info(self):
        """Feature 1: WHOIS Information"""
        try:
            w = whois.whois(self.domain)
            self.results["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
                "updated_date": str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date),
                "name_servers": w.name_servers[:3] if isinstance(w.name_servers, list) else w.name_servers,
                "status": str(w.status[0] if isinstance(w.status, list) else w.status)
            }
        except:
            self.results["whois"] = {"status": "Lookup Failed"}
        return self.results["whois"]

    def get_dns_records(self):
        """Feature 2: DNS Records"""
        for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            try:
                answers = dns.resolver.resolve(self.domain, r_type)
                self.results["dns"][r_type] = [str(rdata) for rdata in answers[:4]]
            except:
                pass
        return self.results["dns"]

    def get_ssl_info(self):
        """Feature 3: SSL Certificate Analysis"""
        try:
            cert = ssl.get_server_certificate((self.domain, 443), timeout=3)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

            not_after = x509.get_notAfter().decode()
            expiry_str = f"{not_after[0:4]}-{not_after[4:6]}-{not_after[6:8]}"
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
            days_left = (expiry_date - datetime.now()).days

            self.results["ssl"] = {
                "expiry_date": expiry_str,
                "days_valid": days_left,
                "status": "Valid" if days_left > 0 else "Expired"
            }
        except:
            self.results["ssl"] = {"status": "Expired",
                                   "days_valid": -1}  # Default to Expired for safety if check fails
        return self.results["ssl"]

    def detect_technologies(self):
        """Feature 4: Technology Detection"""
        try:
            response = requests.get(self.target_url, timeout=5, verify=False)
            text = response.text.lower()
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            tech_map = {
                'WordPress': ['wp-content'], 'PHP': ['php'], 'nginx': ['nginx'],
                'Apache': ['apache'], 'jQuery': ['jquery'], 'Laravel': ['laravel']
            }

            for tech, patterns in tech_map.items():
                if any(p in text or p in str(headers) for p in patterns):
                    self.results["technologies"].append(tech)
        except:
            pass
        return self.results["technologies"]

    def discover_subdomains(self):
        """Feature 5: Subdomain Discovery"""
        subs = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'cpanel', 'whm', 'autodiscover', 'm', 'imap', 'test', 'blog', 'dev', 'admin', 'forum', 'news', 'vpn', 'mail2', 'new', 'mysql', 'old', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'api', 'cdn', 'stats']
        for sub in subs:
            try:
                host = f"{sub}.{self.domain}"
                socket.gethostbyname(host)
                self.results["subdomains"].append(host)
            except:
                pass
        return self.results["subdomains"]

    def scan_ports(self):
        """Feature 6: Port Scanning"""
        if not self.target_ip: return []
        for port in [21, 22, 23, 25, 53, 80 , 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.3)
                    if s.connect_ex((self.target_ip, port)) == 0:
                        self.results["ports"].append(port)
            except:
                pass
        return self.results["ports"]

    def check_headers(self):
        """Feature 7: HTTP Headers"""
        try:
            response = requests.get(self.target_url, timeout=5, verify=False)
            for h in ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']:
                self.results["headers"][h] = response.headers.get(h, "MISSING")
        except:
            pass
        return self.results["headers"]

    def run_full_recon(self):
        """Master Orchestrator"""
        self.get_whois_info()
        self.get_dns_records()
        self.get_ssl_info()
        self.detect_technologies()
        self.discover_subdomains()
        self.scan_ports()
        self.check_headers()
        return self.results