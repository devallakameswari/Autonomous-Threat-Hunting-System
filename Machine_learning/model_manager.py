"""
Machine_learning/model_manager.py
Loads all three ML models once and exposes a single convenient
interface for the detection engine to score a feature vector.
"""

from config import Config
from Machine_learning.random_forest import RandomForestDetector
from Machine_learning.isolation_forest import IsolationForestDetector
from Machine_learning.autoencoder import AutoencoderDetector


class ModelManager:
    _instance = None

    def __init__(self):
        self.rf = RandomForestDetector(Config.RANDOM_FOREST_PATH)
        self.iso = IsolationForestDetector(Config.ISOLATION_FOREST_PATH)
        self.ae = AutoencoderDetector(Config.AUTOENCODER_PATH, Config.AUTOENCODER_FALLBACK_PATH)
        self._loaded = {"rf": False, "iso": False, "ae": False}
        self._try_load_all()

    def _try_load_all(self):
        self._loaded["rf"] = self.rf.load()
        self._loaded["iso"] = self.iso.load()
        self._loaded["ae"] = self.ae.load()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def is_ready(self) -> bool:
        return all(self._loaded.values())

    def score(self, feature_vector: list) -> dict:
        """
        Runs the feature vector through all available models.
        Returns a dict combining each model's verdict; models that
        failed to load are safely skipped (result fields are None).
        """
        result = {
            "rf_label": None, "rf_probability": None,
            "iso_is_anomaly": None, "iso_score": None,
            "ae_is_anomaly": None, "ae_error": None,
        }

        if self._loaded["rf"]:
            try:
                label, proba = self.rf.predict(feature_vector)
                result["rf_label"] = label
                result["rf_probability"] = proba
            except Exception:
                pass

        if self._loaded["iso"]:
            try:
                is_anom, score = self.iso.predict(feature_vector)
                result["iso_is_anomaly"] = is_anom
                result["iso_score"] = score
            except Exception:
                pass

        if self._loaded["ae"]:
            try:
                is_anom, error = self.ae.predict(feature_vector)
                result["ae_is_anomaly"] = is_anom
                result["ae_error"] = error
            except Exception:
                pass

        return result
