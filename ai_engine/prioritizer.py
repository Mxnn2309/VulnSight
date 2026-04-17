class Prioritizer:
    @staticmethod
    def rank_vulnerabilities(vuln_list):
        """
        Expects a list of dictionaries containing:
        {'id': 'CVE-X', 'ai_score': 85.5, 'impact': 'High'}
        """
        # Sort by AI Risk Score descending
        ranked = sorted(vuln_list, key=lambda x: x['ai_score'], reverse=True)

        for idx, vuln in enumerate(ranked):
            vuln['priority_rank'] = idx + 1

        return ranked