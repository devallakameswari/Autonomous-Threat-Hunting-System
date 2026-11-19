"""
Backend_support/file_handler.py
Handles safe saving/reading of uploaded log files.
"""

import os
import uuid
from werkzeug.utils import secure_filename


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions


def save_uploaded_file(file_storage, upload_folder: str, allowed_extensions: set):
    """
    Saves a Werkzeug FileStorage object safely to disk.
    Returns (saved_path, safe_filename) or raises ValueError on invalid input.
    """
    if file_storage is None or file_storage.filename == "":
        raise ValueError("No file selected.")

    if not allowed_file(file_storage.filename, allowed_extensions):
        raise ValueError(
            f"File type not allowed. Allowed types: {', '.join(sorted(allowed_extensions))}"
        )

    original_name = secure_filename(file_storage.filename)
    unique_name = f"{uuid.uuid4().hex[:10]}_{original_name}"

    os.makedirs(upload_folder, exist_ok=True)
    saved_path = os.path.join(upload_folder, unique_name)
    file_storage.save(saved_path)

    return saved_path, unique_name


def read_text_file(path: str, max_lines: int = 200000):
    """Reads a text-based log file line by line, guarding against huge files."""
    lines = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            line = line.rstrip("\n")
            if line.strip():
                lines.append(line)
    return lines
