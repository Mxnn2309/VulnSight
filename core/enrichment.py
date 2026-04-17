import requests
import time

class DataEnricher:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_api_url = "https://api.first.org/data/v1/epss"

    def get_cve_details(self, cve_id):
        """Fetches CVSS base score and description from NVD."""
        params = {'cveId': cve_id}
        try:
            response = requests.get(self.nvd_api_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                if vulnerabilities:
                    metrics = vulnerabilities[0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']
                    return {
                        "base_score": metrics['baseScore'],
                        "severity": metrics['baseSeverity'],
                        "vector": metrics['vectorString']
                    }
        except Exception as e:
            print(f"Error fetching NVD data: {e}")
        return None

    def get_epss_score(self, cve_id):
        """Fetches the EPSS probability score (0.0 to 1.0)."""
        params = {'cve': cve_id}
        try:
            response = requests.get(self.epss_api_url, params=params)
            if response.status_code == 200:
                data = response.json()
                if data['data']:
                    return float(data['data'][0]['epss'])
        except Exception as e:
            print(f"Error fetching EPSS data: {e}")
        return 0.0