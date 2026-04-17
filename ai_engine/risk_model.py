import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor
import joblib
import os

class RiskScorer:
    def __init__(self):
        self.model = RandomForestRegressor(n_estimators=100, random_state=42)
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.base_dir, "risk_model.pkl")
        self.model = RandomForestRegressor(n_estimators=100, random_state=42)

    def train_initial_model(self):
        """
        Generates synthetic training data for research evaluation.
        In a real scenario, this would be historical breach data.
        """
        # Features: [CVSS, EPSS, Asset_Crit, Exposure]
        # Label: Real_Risk (0-100)
        data = {
            'cvss': [9.8, 5.0, 7.5, 3.0, 9.0, 4.0],
            'epss': [0.95, 0.10, 0.80, 0.05, 0.20, 0.90],
            'asset_crit': [10, 2, 8, 1, 9, 5],
            'exposure': [1, 0, 1, 0, 1, 1],
            'ssl_expired': [1, 0, 1, 0, 0, 1],
            'real_risk': [98, 15, 85, 5, 60, 70]  # Target score
        }
        df = pd.DataFrame(data)
        X = df.drop('real_risk', axis=1)
        y = df['real_risk']

        self.model.fit(X, y)
        joblib.dump(self.model, self.model_path)

        print(f"✅ Model saved at {self.model_path}")

    def predict_risk(self, cvss, epss, asset_crit, exposure, ssl_expired):
        """Predicts a 0-100 risk score for a new vulnerability."""
        loaded_model = joblib.load(self.model_path)
        features = pd.DataFrame(
            [[cvss, epss, asset_crit, exposure, ssl_expired]],
            columns=['cvss', 'epss', 'asset_crit', 'exposure', 'ssl_expired']  # <-- ADDED HERE
        )
        prediction = loaded_model.predict(features)
        return round(prediction[0], 2)


# Quick Test
if __name__ == "__main__":
    scorer = RiskScorer()
    scorer.train_initial_model()
    # Test: High CVSS (9.0) but Low EPSS (0.1) and Low Asset Crit (2)
    score = scorer.predict_risk(9.0, 0.1, 2, 0, 1)
    print(f"Predicted Real Risk Score: {score}")