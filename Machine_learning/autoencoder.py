"""
Machine_learning/autoencoder.py
Reconstruction-error based anomaly detector.

If TensorFlow/Keras is installed, trains a small dense autoencoder.
If not installed, transparently falls back to a PCA-based reconstruction
error model (sklearn), so the rest of the system never has to know which
backend is active. This keeps the project runnable without a heavy
TensorFlow dependency while still supporting the "real" deep model
when available.
"""

import os
import joblib
import numpy as np

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler


class AutoencoderDetector:
    """
    Unified interface regardless of backend:
        detector.train(X)
        detector.save()
        detector.load()
        detector.predict(feature_vector) -> (is_anomaly, reconstruction_error)
    """

    def __init__(self, keras_path: str, fallback_path: str, error_threshold_percentile=95):
        self.keras_path = keras_path
        self.fallback_path = fallback_path
        self.backend = "keras" if TF_AVAILABLE else "pca"
        self.model = None
        self.scaler = None
        self.threshold = None
        self.error_threshold_percentile = error_threshold_percentile

    # ---------------------------------------------------------- training --
    def train(self, X):
        X = np.asarray(X, dtype="float32")
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        if self.backend == "keras":
            n_features = X_scaled.shape[1]
            encoding_dim = max(2, n_features // 2)

            inputs = keras.Input(shape=(n_features,))
            encoded = layers.Dense(encoding_dim, activation="relu")(inputs)
            decoded = layers.Dense(n_features, activation="linear")(encoded)
            self.model = keras.Model(inputs, decoded)
            self.model.compile(optimizer="adam", loss="mse")
            self.model.fit(
                X_scaled, X_scaled,
                epochs=50, batch_size=16, shuffle=True, verbose=0,
            )
            reconstructions = self.model.predict(X_scaled, verbose=0)
        else:
            n_features = X_scaled.shape[1]
            n_components = max(1, min(n_features - 1, n_features // 2) or 1)
            self.model = PCA(n_components=n_components, random_state=42)
            self.model.fit(X_scaled)
            transformed = self.model.transform(X_scaled)
            reconstructions = self.model.inverse_transform(transformed)

        errors = np.mean(np.square(X_scaled - reconstructions), axis=1)
        self.threshold = float(np.percentile(errors, self.error_threshold_percentile))
        return self.model

    # -------------------------------------------------------------- I/O --
    def save(self):
        if self.backend == "keras":
            os.makedirs(os.path.dirname(self.keras_path), exist_ok=True)
            self.model.save(self.keras_path)
            joblib.dump(
                {"scaler": self.scaler, "threshold": self.threshold, "backend": "keras"},
                self.keras_path + ".meta.pkl",
            )
        else:
            os.makedirs(os.path.dirname(self.fallback_path), exist_ok=True)
            joblib.dump(
                {"model": self.model, "scaler": self.scaler, "threshold": self.threshold, "backend": "pca"},
                self.fallback_path,
            )

    def load(self):
        if self.backend == "keras" and os.path.exists(self.keras_path):
            self.model = keras.models.load_model(self.keras_path)
            meta = joblib.load(self.keras_path + ".meta.pkl")
            self.scaler = meta["scaler"]
            self.threshold = meta["threshold"]
            return True
        elif os.path.exists(self.fallback_path):
            data = joblib.load(self.fallback_path)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.threshold = data["threshold"]
            self.backend = "pca"
            return True
        return False

    # ------------------------------------------------------------ infer --
    def predict(self, feature_vector):
        if self.model is None:
            if not self.load():
                raise RuntimeError(
                    "Autoencoder model not trained/loaded. Run train_model.py first."
                )

        X = np.asarray([feature_vector], dtype="float32")
        X_scaled = self.scaler.transform(X)

        if self.backend == "keras":
            reconstruction = self.model.predict(X_scaled, verbose=0)
        else:
            transformed = self.model.transform(X_scaled)
            reconstruction = self.model.inverse_transform(transformed)

        error = float(np.mean(np.square(X_scaled - reconstruction)))
        is_anomaly = error > self.threshold
        return is_anomaly, error
