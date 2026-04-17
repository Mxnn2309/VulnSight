# 👁️ VulnSight: Context-Aware Recon & Remediation 

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![Google Gemini](https://img.shields.io/badge/google%20gemini-8E75B2?style=for-the-badge&logo=google%20gemini&logoColor=white)

**VulnSight** is a cybersecurity tool designed to find and fix security weaknesses (vulnerabilities) in websites before hackers can exploit them. Think of it as a digital health check-up for a website that not only finds the *"illness"* but also writes the exact *"prescription"* to cure it.

## Core Features of VulnSight

### 1. Reconnaissance (Phase 1)
* **Live Asset Discovery:** Performs real-time DNS resolution and identifies the target's IP address.
* **Infrastructure Mapping:** Conducts WHOIS lookups to identify domain ownership and registration details.
* **Security Header Audit:** Analyzes HTTP security headers (like HSTS and CSP) to find missing defensive configurations.
* **Technology Fingerprinting:** Automatically detects the server's tech stack, such as Apache, PHP, or jQuery.
* **Attack Surface Expansion:** Discovers subdomains and scans for active ports and their associated services (e.g., HTTP, HTTPS, SSH).

### 2. Context-Aware Risk Scoring (Phase 2)
* **ML-Driven Prioritization:** Uses a Random Forest classifier to calculate a "Real Risk" score (0-100).
* **Environmental Intelligence:** Unlike static CVSS scores, VulnSight adjusts risk based on real-world factors like SSL expiration status, whether the asset is public-facing, and the business criticality of the server.
* **Dynamic Visualizations:** Generates bar charts comparing standard "Static CVSS" against the "VulnSight AI Risk" to show which threats actually matter most in your specific environment.

### 3. Agentic AI Remediation (Phase 3)
* **Tailored Fix Strategies:** Utilizes Google Gemini 2.5 Flash to write specific, 3-step remediation plans.
* **Layman-Friendly Advice:** Translates complex technical jargon into easy-to-understand steps, including a "Why it matters" section for every recommendation.
* **Fault-Tolerant Engine:** Includes a "Universal Fallback" mechanism that provides verified security advice even if the AI API is unavailable or rate-limited.

### 4. Executive Reporting
* **Professional PDF Export:** Generates high-fidelity, branded reports featuring custom typography and a clean red-and-black aesthetic.
* **Automated Triage Table:** Provides a concise summary table of all detected vulnerabilities, their CVSS scores, and the AI-adjusted risk levels.

## How it works

### 🔍 1. Digital Reconnaissance (Phase 1)

Instead of just looking at the surface, VulnSight performs a "deep dive" into a website's infrastructure. It automatically identifies:
* WHOIS & DNS: Who owns the site and where it lives.
* Tech Stack: What software the site is running (like Apache or jQuery).
* Subdomains & Ports: Hidden "doors" or entry points into the server.

### ⚖️ 2. Smart Risk Scoring (Phase 2)

Not every security flaw is equally dangerous. VulnSight uses Machine Learning to calculate a "Real Risk" score from 0 to 100. It doesn't just look at how bad a bug is in theory; it looks at your specific server context—like whether your SSL security certificate is expired or if the server is easily reachable by the public.

### 🛠️ 3. AI-Powered Fixes (Phase 3)

Once a problem is found, the system uses Google Gemini AI to write a simple, 3-step repair plan.
* Easy to Understand: It explains "Why" a fix matters in plain English.
* Step-by-Step: It tells you exactly what to update or change to stay safe.
* Bulletproof: Even if the AI service is busy, the tool has a built-in "safety net" to provide professional advice so you are never left without a solution.

### 📄 4. Professional Reports

Finally, it bundles all this complex data into a branded PDF report. This report includes easy-to-read charts that compare standard security scores against VulnSight's "Context-Aware" AI scores, helping you focus on fixing the most dangerous problems first.

## Installation

#### 1. Clone the Repository

Open your terminal or command prompt and run the following command to download the project files:

```bash
git clone https://github.com/Mxnn2309/VulnSight.git
cd VulnSight
```

#### 2. Install Dependencies

Install all required libraries, including flask, scikit-learn, litellm, and fpdf2, using the provided requirements file:

```bash
pip install -r requirements.txt
```

#### 3. Configure Your API Key

The system requires a [Google Gemini API Key](https://aistudio.google.com/api-keys) to generate the AI remediation strategies.
1. Create a file named `.env` in the root directory.
2. Add your key to the file:

```txt
GEMINI_API_KEY=your_actual_key_here
```

#### 4. Launch the Application

Start the Flask development server:

```bash
python app.py
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
