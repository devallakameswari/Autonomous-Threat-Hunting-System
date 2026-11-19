"""
Anomaly_Detection/baseline.py
Maintains simple running statistics (mean/std) per feature across all
observed IPs in the current batch, used as a lightweight statistical
baseline for z-score anomaly detection. In production this would be
persisted and updated incrementally over days/weeks rather than
recomputed per upload batch.
"""

import statistics
from Log_Processing.feature_extractor import FEATURE_NAMES


class Baseline:
    def __init__(self):
        self.means = {}
        self.stdevs = {}
        self.fitted = False

    def fit(self, feature_dicts: list):
        """feature_dicts: list of per-IP feature dicts (values of extract_features_per_ip)."""
        if not feature_dicts:
            self.fitted = False
            return

        for name in FEATURE_NAMES:
            values = [fd.get(name, 0) for fd in feature_dicts]
            self.means[name] = statistics.fmean(values) if values else 0.0
            self.stdevs[name] = statistics.pstdev(values) if len(values) > 1 else 0.0

        self.fitted = True

    def zscore(self, feature_dict: dict) -> dict:
        """Returns per-feature z-scores given the fitted baseline."""
        if not self.fitted:
            return {name: 0.0 for name in FEATURE_NAMES}

        scores = {}
        for name in FEATURE_NAMES:
            value = feature_dict.get(name, 0)
            mean = self.means.get(name, 0.0)
            std = self.stdevs.get(name, 0.0)
            if std == 0:
                scores[name] = 0.0
            else:
                scores[name] = (value - mean) / std
        return scores
