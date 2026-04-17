import os
from dotenv import load_dotenv
from core.enrichment import DataEnricher
from ai_engine.risk_model import RiskScorer
from ai_engine.recommender import AIRecommender

load_dotenv()


def test_system_health():
    print("📋 Starting System Health Check...\n")

    # 1. Test Gemini API Connection
    print("[1/3] Testing Gemini API...")
    try:
        recommender = AIRecommender()
        response = recommender.generate_fix("CVE-TEST", "Buffer Overflow", "Web Server")
        if response and "Error" not in response:
            print("✅ Gemini API: Connected & Responding.")
        else:
            print(f"❌ Gemini API: Failed. Response: {response}")
    except Exception as e:
        print(f"❌ Gemini API: Error - {str(e)}")

    # 2. Test NVD/EPSS Enrichment
    print("\n[2/3] Testing Data Enrichment (NVD/EPSS)...")
    enricher = DataEnricher()
    # Testing with a known CVE: Heartbleed
    cve_data = enricher.get_cve_details("CVE-2014-0160")
    if cve_data:
        print(f"✅ NVD API: Success. (CVSS: {cve_data['base_score']})")
    else:
        print("❌ NVD API: Failed to fetch data.")

    # 3. Test AI Risk Scoring Logic
    print("\n[3/3] Testing AI Risk Model...")
    scorer = RiskScorer()
    try:
        # Features: CVSS=9.8, EPSS=0.9, Asset_Crit=10, Exposure=1
        score = scorer.predict_risk(9.8, 0.9, 10, 1)
        print(f"✅ AI Scorer: Success. Predicted Risk: {score}/100")
    except Exception as e:
        print(f"❌ AI Scorer: Failed. Error - {str(e)}")

    print("\n--- Health Check Complete ---")


if __name__ == "__main__":
    test_system_health()