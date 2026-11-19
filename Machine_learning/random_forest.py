"""
Machine_learning/random_forest.py
Wraps a scikit-learn RandomForestClassifier used to classify per-IP
feature vectors as "benign" (0) or "malicious" (1), plus a probability score.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier


class RandomForestDetector:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None

    def train(self, X, y):
        X = np.asarray(X)
        y = np.asarray(y)
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X, y)
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
        """Returns (label, probability_malicious) for a single feature vector."""
        if self.model is None:
            if not self.load():
                raise RuntimeError(
                    "RandomForest model not trained/loaded. Run train_model.py first."
                )
        X = np.asarray([feature_vector])
        label = int(self.model.predict(X)[0])
        proba = float(self.model.predict_proba(X)[0][1])  # probability of class "1" (malicious)
        return label, proba
