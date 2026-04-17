import os
import time
from litellm import completion
from dotenv import load_dotenv

load_dotenv()

class AIRecommender:
    def __init__(self):
        # Using LiteLLM to route to Google Gemini
        # self.model = "gemini/gemini-2.5-flash"
        # self.model = "gemini/gemini-2.5-pro"
        self.model = "gemini/gemini-2.5-flash-lite"
        # self.model = "gemini/gemini-3-flash-preview"
        # self.model = "gemini/gemini-3.1-flash"
        self.api_key = os.getenv("GEMINI_API_KEY")

    # FIX: These methods must be at the same indentation level as __init__
    def generate_fix(self, cve_id, description, asset_type):
        prompt = f"""
                Act as a Senior Cybersecurity Engineer.
                Vulnerability: {cve_id}
                Context: {description}
                Asset Type: {asset_type}

                Provide a 3-step remediation plan using simple, non-technical language where possible. 
        
                STRICT RULES:
                1. Start immediately with '1. ' 
                2. DO NOT include introductions like 'As a Senior Engineer...' or 'Here is the plan...'
                3. The format for EVERY step must be:
                   [Step Number]. [Action to take]
                   *Why: [One short sentence explaining why]*
                4. Do not use markdown bolding (**). Use italics (*) only for the word 'Why'.
                """

        try:
            if not self.api_key:
                print("      [!] Error: GEMINI_API_KEY is missing!")
                return self._fallback_recommendation(cve_id, description)

            response = completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                api_key=self.api_key
            )
            return response.choices[0].message.content.strip()

        except Exception as e:
            # Universal fallback for any API or Quota error
            print(f"      [!] AI Engine Issue: {str(e)}. Using local fallback.")
            return self._fallback_recommendation(cve_id, description)

    def _fallback_recommendation(self, cve_id, description):
        """Standard professional remediation used when the AI is unavailable."""
        return f"""[STANDARD TRIAGE ADVISORY]

1. VULNERABILITY VERIFICATION:
Isolate the affected infrastructure components associated with {cve_id} and map the exploitability path using internal scanning tools.

2. VENDOR PATCHING & MITIGATION:
Consult the official NVD database for {cve_id} to identify the latest stable vendor patch. Apply this patch immediately during the next available maintenance window.

3. COMPENSATING CONTROLS:
If a patch cannot be deployed immediately, configure Web Application Firewall (WAF) rules or IPS signatures to block known exploit vectors targeting {description}."""