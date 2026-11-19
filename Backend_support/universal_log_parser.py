import csv
import json
import os


def parse_log_file(filepath):

    extension = os.path.splitext(filepath)[1].lower()

    if extension == ".csv":
        return parse_csv(filepath)

    elif extension == ".json":
        return parse_json(filepath)

    elif extension in [".log", ".txt"]:
        return parse_text_log(filepath)

    else:
        raise ValueError(
            "Unsupported file format. "
            "Use CSV, JSON, LOG or TXT."
        )


def parse_csv(filepath):

    records = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file:

        reader = csv.DictReader(file)

        for row in reader:
            records.append(dict(row))

    return records


def parse_json(filepath):

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file:

        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        if "logs" in data:
            return data["logs"]

        return [data]

    return []


def parse_text_log(filepath):

    records = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file:

        for line in file:

            line = line.strip()

            if line:
                records.append({
                    "raw_log": line
                })

    return records