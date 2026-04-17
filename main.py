import os
import socket
from datetime import datetime
import time
import urllib.parse
from dotenv import load_dotenv

# VulnSight AI Custom Modules
from core.webscout_scanner import WebScoutScanner
from core.enrichment import DataEnricher
from ai_engine.risk_model import RiskScorer
from ai_engine.recommender import AIRecommender
from core.report_gen import ReportGenerator

# Load Environment Variables (API Keys)
load_dotenv()


def run_vulnsight_system(target_url, asset_criticality, is_exposed):
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc or parsed.path

    # ==========================================
    # PHASE 1: WEBSCOUT RECONNAISSANCE
    # ==========================================
    print("=" * 80)
    print("VULNSIGHT AI: INTEGRATED RECONNAISSANCE & RISK REPORT")
    print("=" * 80)
    print(f"Target: {target_url}")
    print(f"Domain: {domain}")
    print(f"Started: {start_time}")
    print("=" * 80)

    print("\n[1/5] INITIALIZING WEBSCOUT MODULES...")
    scanner = WebScoutScanner(target_url)
    recon_data = scanner.run_full_recon()

    if not recon_data['ip']:
        print("❌ Critical Error: Could not resolve target. Check your connection.")
        return

    # --- Print Recon Data ---
    print("\n[ IP ADDRESS ]")
    print(f"  ✓ IPv4: {recon_data['ip']}")

    print("\n[ WHOIS INFORMATION ]")
    whois_data = recon_data.get('whois', {})
    if whois_data and "registrar" in whois_data:
        print(f"  • Domain Name: {domain.upper()}")
        print(f"  • Registrar: {whois_data.get('registrar', 'N/A')}")
        print(f"  • Creation Date: {whois_data.get('creation_date', 'N/A')}")
        print(f"  • Expiration Date: {whois_data.get('expiration_date', 'N/A')}")
        print(f"  • Updated Date: {whois_data.get('updated_date', 'N/A')}")

        ns = whois_data.get('name_servers', [])
        print(f"  • Name Servers: {', '.join(ns) if isinstance(ns, list) else ns}")
        print(f"  • Status: {whois_data.get('status', 'N/A')}")
    else:
        print("  • WHOIS lookup failed or unavailable")

    print("\n[ DNS RECORDS ]")
    dns_data = recon_data.get('dns', {})
    if dns_data:
        for rec_type, records in dns_data.items():
            print(f"  • {rec_type} Records:")
            for rec in records:
                print(f"    - {rec}")
    else:
        print("  • No DNS records retrieved")

    print("\n[ HTTP HEADERS ]")
    headers_data = recon_data.get('headers', {})
    if headers_data:
        for k, v in headers_data.items():
            print(f"  • {k}: {v}")

    print("\n[ SSL CERTIFICATE ]")
    ssl_data = recon_data.get('ssl', {})
    if ssl_data.get('status') != "Unknown":
        status_icon = "✓" if ssl_data.get('status') == "Valid" else "✗"
        print(f"  {status_icon} Status: {ssl_data.get('status')} ({ssl_data.get('days_valid')} days remaining)")
        print(f"  • Expiry Date: {ssl_data.get('expiry_date')}")
    else:
        print("  • No SSL/HTTPS Certificate found")

    print("\n[ TECHNOLOGY DETECTION ]")
    tech_data = recon_data.get('technologies', [])
    if tech_data:
        for tech in tech_data:
            print(f"  ✓ {tech}")
    else:
        print("  No specific technologies detected")

    print("\n[ SUBDOMAIN DISCOVERY ]")
    sub_data = recon_data.get('subdomains', [])
    if sub_data:
        for sub in sub_data:
            print(f"  ✓ {sub} -> {recon_data['ip']}")
        print(f"  Found {len(sub_data)} subdomains")
    else:
        print("  No subdomains discovered")

    print("\n[ PORT SCANNING ]")
    port_data = recon_data.get('ports', [])
    port_map = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    if port_data:
        for p in port_data:
            service = port_map.get(p, 'UNKNOWN')
            print(f"  ✓ Port {p}: {service} - OPEN")
    else:
        print("  No open ports detected")

    # ==========================================
    # PHASE 2: MULTI-CVE AI RISK SCORING
    # ==========================================
    print("\n" + "=" * 80)
    print("VULNSIGHT AI ENGINE: RISK SCORING & REMEDIATION")
    print("=" * 80)

    # Initialize Engines
    enricher = DataEnricher()
    scorer = RiskScorer()
    recommender = AIRecommender()

    # Simulate discovering multiple CVEs based on WebScout's Tech Stack
    detected_cves = ["CVE-2024-23234"]  # A baseline generic vulnerability
    if "PHP" in tech_data:
        detected_cves.append("CVE-2024-4577")
    if "Apache" in tech_data:
        detected_cves.append("CVE-2021-41773")
    if "jQuery" in tech_data:
        detected_cves.append("CVE-2020-11022")

    # Ensure list is unique
    detected_cves = list(set(detected_cves))
    all_findings = []

    print(f"\n[2/5] PROCESSING {len(detected_cves)} VULNERABILITIES...")

    ssl_flag = 1 if recon_data['ssl'].get('status') == 'Expired' else 0
    exposure_flag = 1 if is_exposed else 0

    # Loop through all detected vulnerabilities
    for cve in detected_cves:
        print(f"\n  ► Analyzing {cve}...")

        # Enrich
        cve_info = enricher.get_cve_details(cve) or {"base_score": 7.5}
        epss_val = enricher.get_epss_score(cve)

        # AI Score
        try:
            real_risk = scorer.predict_risk(cve_info['base_score'], epss_val, asset_criticality, exposure_flag,
                                            ssl_flag)
        except Exception:
            scorer.train_initial_model()
            real_risk = scorer.predict_risk(cve_info['base_score'], epss_val, asset_criticality, exposure_flag,
                                            ssl_flag)

        print(f"    - Static CVSS: {cve_info['base_score']} | VulnSight AI Score: {real_risk}/100")

        # Gemini Remediation with Rate Limit Handling
        print(f"    - Generating Gemini AI Remediation...")
        desc = f"Vulnerability {cve} affecting {', '.join(tech_data) if tech_data else 'web services'}."

        fix = "Error generating recommendation."
        max_retries = 3

        for attempt in range(max_retries):
            fix = recommender.generate_fix(cve, desc, "Enterprise Server")

            # If the fix contains the word "RateLimitError", we wait and retry
            if "RateLimitError" in fix or "429" in fix:
                wait_time = 15  # Wait 15 seconds to clear the free-tier limit
                print(
                    f"      [!] Gemini Rate Limit Hit. Waiting {wait_time}s before retrying (Attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait_time)
            else:
                # Success! Break out of the retry loop
                break

        # Save to findings list
        all_findings.append({
            "cve_id": cve,
            "cvss_score": cve_info['base_score'],
            "ai_score": real_risk,
            "fix": fix,
            "tech": ", ".join(tech_data)
        })

    # ==========================================
    # PHASE 3: PRIORITIZATION & REPORTING
    # ==========================================
    print(f"\n[3/5] AI PRIORITIZING VULNERABILITIES BY BUSINESS RISK...")

    # THIS is the core of your research: Sorting by the AI's Real Risk Score instead of CVSS
    prioritized_findings = sorted(all_findings, key=lambda x: x['ai_score'], reverse=True)

    print("\n  🏆 Top Priority Triage List:")
    for idx, vuln in enumerate(prioritized_findings):
        print(f"  {idx + 1}. {vuln['cve_id']} -> AI Risk Score: {vuln['ai_score']}")

    print(f"\n[4/5] ARCHIVING RESULTS & GENERATING PDF...")
    report = ReportGenerator(recon_data, prioritized_findings, domain)
    report.export_pdf("VulnSight_Full_Analysis.pdf")

    end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("\n" + "=" * 80)
    print(f"SCAN COMPLETED at {end_time}")
    print("Check 'VulnSight_Full_Analysis.pdf' for details.")
    print("=" * 80)


if __name__ == "__main__":
    # ---------------------------------------------------------
    # CONFIGURATION FOR RESEARCH TEST
    # ---------------------------------------------------------
    URL = "http://portswigger-labs.net"
    CRITICALITY = 9
    IS_EXPOSED = True

    run_vulnsight_system(URL, CRITICALITY, IS_EXPOSED)