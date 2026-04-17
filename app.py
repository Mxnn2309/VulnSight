import os
import time
import urllib.parse
from flask import Flask, render_template, request, jsonify, send_file
from dotenv import load_dotenv

# VulnSight Modules
from core.webscout_scanner import WebScoutScanner
from core.enrichment import DataEnricher
from ai_engine.risk_model import RiskScorer
from ai_engine.recommender import AIRecommender
from core.report_gen import ReportGenerator

load_dotenv()
app = Flask(__name__)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def run_scan():
    data = request.json
    target_url = data.get('url')
    asset_criticality = int(data.get('criticality', 5))
    is_exposed = data.get('is_exposed', True)

    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc or parsed.path

    # 1. Reconnaissance
    scanner = WebScoutScanner(target_url)
    recon_data = scanner.run_full_recon()

    if not recon_data['ip']:
        return jsonify({"error": "Could not resolve target URL. Check connection."}), 400

    # 2. Setup AI Engines
    enricher = DataEnricher()
    scorer = RiskScorer()
    recommender = AIRecommender()

    # 3. Determine CVEs based on Tech Stack
    tech_data = recon_data.get('technologies', [])
    detected_cves = ["CVE-2024-23234"]  # Default
    if "PHP" in tech_data: detected_cves.append("CVE-2024-4577")
    if "Apache" in tech_data: detected_cves.append("CVE-2021-41773")
    if "jQuery" in tech_data: detected_cves.append("CVE-2020-11022")

    detected_cves = list(set(detected_cves))
    all_findings = []

    ssl_flag = 1 if recon_data['ssl'].get('status') == 'Expired' else 0
    exposure_flag = 1 if is_exposed else 0

    # 4. Processing Loop
    for cve in detected_cves:
        cve_info = enricher.get_cve_details(cve) or {"base_score": 7.5}
        epss_val = enricher.get_epss_score(cve)

        try:
            real_risk = scorer.predict_risk(cve_info['base_score'], epss_val, asset_criticality, exposure_flag,
                                            ssl_flag)
        except Exception:
            scorer.train_initial_model()
            real_risk = scorer.predict_risk(cve_info['base_score'], epss_val, asset_criticality, exposure_flag,
                                            ssl_flag)

        desc = f"Vulnerability {cve} affecting {', '.join(tech_data) if tech_data else 'web services'}."

        # Add a small 2-second "breather" to respect Gemini 2.5 Flash rate limits
        time.sleep(2)

        # The recommender now handles its own fallback if the API fails
        fix = recommender.generate_fix(cve, desc, "Enterprise Server")

        all_findings.append({
            "cve_id": cve,
            "cvss_score": cve_info['base_score'],
            "ai_score": real_risk,
            "fix": fix,
            "tech": ", ".join(tech_data)
        })

    # 5. Prioritize & Generate Report
    prioritized_findings = sorted(all_findings, key=lambda x: x['ai_score'], reverse=True)
    report_filename = f"VulnSight_Report_{domain.replace('.', '_')}.pdf"

    report = ReportGenerator(recon_data, prioritized_findings, domain)
    report.export_pdf(report_filename)

    # Return data to frontend
    return jsonify({
        "status": "success",
        "domain": domain,
        "ip": recon_data['ip'],
        "top_risk": prioritized_findings[0]['ai_score'] if prioritized_findings else 0,
        "cves_found": len(prioritized_findings),
        "report_url": f"/download/{report_filename}"
    })


@app.route('/download/<filename>')
def download_report(filename):
    return send_file(filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True, port=5000)