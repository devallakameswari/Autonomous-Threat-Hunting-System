"""
Machine_learning/train_model.py
Generates a synthetic but realistic labeled dataset that mirrors the
feature schema in Log_Processing/feature_extractor.py, then trains and
saves the RandomForest, IsolationForest, and Autoencoder models.

Run directly:
    python -m Machine_learning.train_model

Replace the synthetic data generation with real historical/labeled
log features for production use.
"""

import os
import sys
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import Config
from Machine_learning.random_forest import RandomForestDetector
from Machine_learning.isolation_forest import IsolationForestDetector
from Machine_learning.autoencoder import AutoencoderDetector

# Must match Log_Processing/feature_extractor.py FEATURE_NAMES order:
# [failed_login_count, successful_login_count, unique_users, unique_dest_ports,
#  http_error_count, http_request_count, distinct_paths, total_events, night_time_ratio]

RNG = np.random.default_rng(42)


def generate_benign_samples(n=800):
    samples = []
    for _ in range(n):
        failed = RNG.poisson(0.3)
        success = RNG.poisson(1.2)
        users = RNG.integers(1, 3)
        ports = RNG.integers(1, 3)
        http_err = RNG.poisson(0.5)
        http_req = RNG.poisson(5)
        paths = RNG.integers(1, 5)
        total = max(failed + success + http_req, 1)
        night_ratio = round(float(RNG.uniform(0, 0.15)), 3)
        samples.append([failed, success, users, ports, http_err, http_req, paths, total, night_ratio])
    return samples


def generate_malicious_samples(n=400):
    samples = []
    for _ in range(n):
        attack_type = RNG.choice(["brute_force", "port_scan", "web_attack", "exfil"])
        if attack_type == "brute_force":
            failed = RNG.integers(6, 60)
            success = RNG.integers(0, 2)
            users = RNG.integers(3, 15)
            ports = 1
            http_err, http_req, paths = 0, 0, 0
            night_ratio = round(float(RNG.uniform(0.2, 0.9)), 3)
        elif attack_type == "port_scan":
            failed, success = 0, 0
            users = 0
            ports = RNG.integers(10, 60)
            http_err, http_req, paths = 0, 0, 0
            night_ratio = round(float(RNG.uniform(0.1, 0.8)), 3)
        elif attack_type == "web_attack":
            failed, success, users, ports = 0, 0, 0, 1
            http_err = RNG.integers(5, 40)
            http_req = RNG.integers(10, 60)
            paths = RNG.integers(8, 40)
            night_ratio = round(float(RNG.uniform(0.1, 0.7)), 3)
        else:  # exfil - large volume of requests, odd hours
            failed, success, users, ports = 0, 1, 1, 1
            http_err = RNG.integers(0, 3)
            http_req = RNG.integers(50, 300)
            paths = RNG.integers(1, 5)
            night_ratio = round(float(RNG.uniform(0.5, 1.0)), 3)

        total = max(failed + success + http_req + ports, 1)
        samples.append([failed, success, users, ports, http_err, http_req, paths, total, night_ratio])
    return samples


def build_dataset():
    benign = generate_benign_samples(800)
    malicious = generate_malicious_samples(400)
    X = np.array(benign + malicious, dtype="float32")
    y = np.array([0] * len(benign) + [1] * len(malicious), dtype="int32")
    return X, y


def main():
    print("[train_model] Generating synthetic training data...")
    X, y = build_dataset()
    print(f"[train_model] Dataset shape: {X.shape}, malicious ratio: {y.mean():.2%}")

    os.makedirs(Config.MODEL_DIR, exist_ok=True)

    print("[train_model] Training RandomForestClassifier...")
    rf = RandomForestDetector(Config.RANDOM_FOREST_PATH)
    rf.train(X, y)
    rf.save()
    print(f"[train_model] Saved -> {Config.RANDOM_FOREST_PATH}")

    print("[train_model] Training IsolationForest (benign-only baseline)...")
    benign_only = X[y == 0]
    iso = IsolationForestDetector(Config.ISOLATION_FOREST_PATH)
    iso.train(benign_only, contamination=0.05)
    iso.save()
    print(f"[train_model] Saved -> {Config.ISOLATION_FOREST_PATH}")

    print(f"[train_model] Training Autoencoder (backend: "
          f"{'keras' if _tf_available() else 'pca-fallback'})...")
    ae = AutoencoderDetector(Config.AUTOENCODER_PATH, Config.AUTOENCODER_FALLBACK_PATH)
    ae.train(benign_only)
    ae.save()
    print("[train_model] Saved autoencoder model.")

    print("[train_model] All models trained and saved successfully.")


def _tf_available():
    try:
        import tensorflow  # noqa: F401
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    main()
