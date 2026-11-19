"""
Anomaly_Detection/anomaly_detector.py
Statistical anomaly detection layered on top of the Baseline class.
Flags an IP as anomalous if any feature's z-score exceeds the configured
threshold, and reports which features drove the flag (for explainability).
"""

from Anomaly_Detection.baseline import Baseline
from config import Config


class AnomalyDetector:
    def __init__(self, threshold: float = None):
        self.threshold = threshold or Config.ANOMALY_ZSCORE_THRESHOLD
        self.baseline = Baseline()

    def fit(self, feature_dicts: list):
        self.baseline.fit(feature_dicts)

    def evaluate(self, feature_dict: dict) -> dict:
        """
        Returns:
            {
                "is_anomaly": bool,
                "max_zscore": float,
                "contributing_features": [ (feature_name, zscore), ... ]
            }
        """
        zscores = self.baseline.zscore(feature_dict)
        contributing = [
            (name, round(z, 2)) for name, z in zscores.items() if abs(z) >= self.threshold
        ]
        contributing.sort(key=lambda pair: abs(pair[1]), reverse=True)

        max_z = max((abs(z) for z in zscores.values()), default=0.0)

        return {
            "is_anomaly": len(contributing) > 0,
            "max_zscore": round(max_z, 2),
            "contributing_features": contributing,
        }
