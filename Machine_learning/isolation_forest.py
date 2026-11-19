"""
Machine_learning/isolation_forest.py
Wraps a scikit-learn IsolationForest used for unsupervised outlier
detection over per-IP feature vectors (catches novel attack patterns
that the supervised RandomForest was never trained on).
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestDetector:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None

    def train(self, X, contamination=0.1):
        X = np.asarray(X)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        return self.model

    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def load(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            return True
        return False

    def predict(self, feature_vector):
        """
        Returns (is_anomaly: bool, anomaly_score: float).
        anomaly_score is normalized so higher = more anomalous.
        """
        if self.model is None:
            if not self.load():
                raise RuntimeError(
                    "IsolationForest model not trained/loaded. Run train_model.py first."
                )
        X = np.asarray([feature_vector])
        raw_prediction = self.model.predict(X)[0]  # -1 = anomaly, 1 = normal
        raw_score = self.model.decision_function(X)[0]  # higher = more normal
        anomaly_score = float(-raw_score)  # flip sign so higher = more anomalous
        is_anomaly = raw_prediction == -1
        return is_anomaly, anomaly_score
