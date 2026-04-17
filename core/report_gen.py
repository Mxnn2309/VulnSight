from fpdf import FPDF
from datetime import datetime
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os


class ReportGenerator(FPDF):
    def __init__(self, recon_data, prioritized_findings, domain):
        super().__init__()
        self.recon_data = recon_data
        self.findings = prioritized_findings
        self.domain = domain
        self.date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Register Brand Fonts
        try:
            self.add_font("BungeeTint", "", os.path.join(current_dir, "BungeeTint-Regular.ttf"))
            self.add_font("Geo", "", os.path.join(current_dir, "Geo-Regular.ttf"))
        except Exception as e:
            print(f"[!] Font Error: {e}. Ensure .ttf files are in the 'core/' folder.")

    def header(self):
        if os.path.exists('static/logo-dark.png'):
            self.image('static/logo-dark.png', 10, 8, 12)

        try:
            self.set_font('BungeeTint', '', 14)
        except:
            self.set_font('Helvetica', 'B', 14)

        self.set_text_color(200, 0, 0)  # Red Branding [cite: 2, 38, 49]
        self.set_x(25)
        self.cell(40, 10, 'VULNSIGHT', new_x="RIGHT", new_y="TOP")

        try:
            self.set_font('Geo', '', 12)
        except:
            self.set_font('Helvetica', '', 12)

        self.set_text_color(100, 100, 100)
        self.cell(0, 10, '| Context-Aware Recon & Remediation', new_x="LMARGIN", new_y="NEXT", align='L')

        self.set_draw_color(200, 0, 0)
        self.line(10, 22, 200, 22)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()} | Confidential AI Risk Report | {self.domain}', align='C')

    def _generate_chart(self):
        labels = [f['cve_id'] for f in self.findings]
        cvss_scores = [float(f['cvss_score']) * 10 for f in self.findings]
        ai_scores = [float(f['ai_score']) for f in self.findings]

        x = np.arange(len(labels))
        width = 0.35

        fig, ax = plt.subplots(figsize=(8, 4))
        # Using dashboard-themed colors
        rects1 = ax.bar(x - width / 2, cvss_scores, width, label='Static CVSS (Scaled x10)', color='#414446')
        rects2 = ax.bar(x + width / 2, ai_scores, width, label='VulnSight AI Risk', color='#C80000')

        ax.set_ylabel('Risk Score (0-100)')
        ax.set_title('Static Severity vs. Context-Aware AI Risk', pad=15)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.legend()

        ax.bar_label(rects1, padding=3, fontsize=8)
        ax.bar_label(rects2, padding=3, fontsize=8)

        fig.tight_layout()
        chart_path = 'temp_ai_chart.png'
        plt.savefig(chart_path, dpi=300)
        plt.close()
        return chart_path

    def export_pdf(self, filename):
        self.add_page()

        # 1. HEADER SUMMARY
        self.set_font("Helvetica", 'B', 16)
        self.set_text_color(200, 0, 0)
        self.cell(0, 10, f"Analysis Report: {self.domain}", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", '', 10)
        self.set_text_color(50)
        self.cell(0, 6, f"Scan Executed: {self.date} | Target IP: {self.recon_data.get('ip')}", new_x="LMARGIN",
                  new_y="NEXT")
        self.ln(5)

        # 2. RECONNAISSANCE
        self.set_fill_color(245, 245, 245)
        self.set_font("Helvetica", 'B', 11)
        self.set_text_color(0, 0, 0)  # Black Section Title
        self.cell(0, 8, " PHASE 1: RECONNAISSANCE", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

        # Mapping common ports to services for professional display
        port_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }

        # Define sub-sections for the PDF
        sections = [
            ("WHOIS Information", self.recon_data.get('whois', 'N/A')),
            ("DNS Records", self.recon_data.get('dns', 'N/A')),
            ("HTTP Security Headers", self.recon_data.get('headers', 'N/A')),
            ("Technology Stack", self.recon_data.get('technologies', [])),
            ("Subdomains Discovered", self.recon_data.get('subdomains', [])),
            ("Active Ports & Services", self.recon_data.get('ports', []))
        ]

        for title, content in sections:
            self.set_font("Helvetica", 'B', 10)
            self.set_text_color(200, 0, 0)
            self.cell(0, 6, f"> {title}", new_x="LMARGIN", new_y="NEXT")
            self.set_font("Courier", '', 8)
            self.set_text_color(0, 0, 0)

            formatted_text = ""

            # 1. Format Subdomains as a vertical list
            if title == "Subdomains Discovered" and isinstance(content, list):
                formatted_text = "\n".join(content)

            # 2. Format Ports with Service Names
            elif title == "Active Ports & Services" and isinstance(content, list):
                port_lines = []
                for p in content:
                    service = port_map.get(p, "Unknown Service")
                    port_lines.append(f"Port {p}: {service}")
                formatted_text = "\n".join(port_lines)

            # 3. Clean up Dictionaries (WHOIS, Headers)
            elif isinstance(content, dict):
                formatted_text = "\n".join([f"{k}: {v}" for k, v in content.items()])

            # 4. Clean up generic Lists (DNS, Tech Stack)
            elif isinstance(content, list):
                formatted_text = ", ".join(map(str, content))

            else:
                formatted_text = str(content)

            # Final check to remove any remaining brackets or quotes from strings
            formatted_text = formatted_text.replace("[", "").replace("]", "").replace("'", "")

            # Safe PDF encoding and output
            clean_content = formatted_text.encode('latin-1', 'replace').decode('latin-1')
            self.multi_cell(0, 4, clean_content, new_x="LMARGIN", new_y="NEXT")
            self.ln(4)

        # 3. AI CHART
        self.set_font("Helvetica", 'B', 11)
        self.cell(0, 8, " PHASE 2: AI RISK PRIORITIZATION VISUALIZATION", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        chart_path = self._generate_chart()
        self.image(chart_path, x=15, w=170)
        os.remove(chart_path)
        self.set_y(self.get_y() + 85)
        self.ln(5)

        # 4. TRIAGE TABLE
        self.set_fill_color(30, 31, 32)
        self.set_text_color(255)
        self.set_font("Helvetica", 'B', 10)
        self.cell(60, 10, " Vulnerability ID", fill=True, border=1, new_x="RIGHT", new_y="TOP")
        self.cell(60, 10, " Static CVSS (NVD)", fill=True, border=1, align="C", new_x="RIGHT", new_y="TOP")
        self.cell(60, 10, " VulnSight AI Score", fill=True, border=1, align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_text_color(0)
        self.set_font("Helvetica", '', 10)
        for vuln in self.findings:
            self.cell(60, 10, f" {vuln['cve_id']}", border=1, new_x="RIGHT", new_y="TOP")
            self.cell(60, 10, str(vuln['cvss_score']), border=1, align="C", new_x="RIGHT", new_y="TOP")

            # Highlight high risk in red
            if vuln['ai_score'] > 70:
                self.set_text_color(200, 0, 0)
                self.set_font("Helvetica", 'B', 10)

            self.cell(60, 10, f"{vuln['ai_score']}/100", border=1, align="C", new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(0)
            self.set_font("Helvetica", '', 10)

        # 5. DETAILED REMEDIATION (With Markdown Parser)
        self.add_page()
        self.set_font("Helvetica", 'B', 14)
        self.set_text_color(200, 0, 0)
        self.cell(0, 10, "PHASE 3: AI-GENERATED REMEDIATION STRATEGIES", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

        for vuln in self.findings:
            self.set_fill_color(245, 245, 245)
            self.set_font("Helvetica", 'B', 11)
            self.set_text_color(0, 0, 0)
            self.cell(0, 8, f" Fix Advisory for {vuln['cve_id']}", fill=True, new_x="LMARGIN", new_y="NEXT")
            self.ln(4)

            # Logic to split lines and color "Why" parts grey
            lines = vuln['fix'].split('\n')
            for line in lines:
                line = line.strip()
                if not line: continue

                if "Why" in line:
                    self.set_text_color(128, 128, 128)  # Grey for 'Why' [cite: 43, 48, 58]
                    self.set_font("Helvetica", 'I', 9)
                else:
                    self.set_text_color(0, 0, 0)  # Black for steps
                    self.set_font("Helvetica", '', 10)

                self.multi_cell(0, 6, line.encode('latin-1', 'replace').decode('latin-1'), new_x="LMARGIN",
                                new_y="NEXT")
            self.ln(10)

        self.output(filename)