import matplotlib.pyplot as plt
import pandas as pd

class Evaluator:
    def __init__(self, data):
        """
        data: List of dicts with ['cve', 'cvss', 'ai_score', 'is_exploited']
        'is_exploited' is a ground-truth flag (1 if actually seen in wild, 0 if not).
        """
        self.df = pd.DataFrame(data)

    def plot_comparison(self):
        """Generates a bar chart comparing top-ranked items."""
        # Sort by CVSS
        cvss_top = self.df.sort_values(by='cvss', ascending=False).head(5)
        # Sort by AI Score
        ai_top = self.df.sort_values(by='ai_score', ascending=False).head(5)

        fig, ax = plt.subplots(1, 2, figsize=(12, 5))

        ax[0].bar(cvss_top['cve'], cvss_top['cvss'], color='skyblue')
        ax[0].set_title('Top 5 by CVSS (Traditional)')
        ax[0].set_ylabel('Score')

        ax[1].bar(ai_top['cve'], ai_top['ai_score'], color='salmon')
        ax[1].set_title('Top 5 by VulnSight AI (Proposed)')
        ax[1].set_ylabel('Real Risk Score')

        plt.tight_layout()
        plt.savefig('evaluation_results.png')
        print("Comparison graph saved as evaluation_results.png")

    def calculate_precision(self):
        """
        Research Metric: How many 'Critical' alerts were actually exploited?
        High precision = fewer false alarms for the security team.
        """
        ai_critical = self.df[self.df['ai_score'] > 80]
        precision = (ai_critical['is_exploited'].sum() / len(ai_critical)) * 100
        return f"AI Prioritization Precision: {precision}%"