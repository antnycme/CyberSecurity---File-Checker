
import os
import csv
import json
import hashlib
import logging
import argparse
import mimetypes
import requests

from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# CONFIGURATION

VT_API_KEY = os.getenv("VT_API_KEY")

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

LOG_FILE = "file_checker.log"

CSV_REPORT = "scan_report.csv"
JSON_REPORT = "scan_report.json"


# LOGGING CONFIGURATION

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# FILE SIGNATURE DATABASE

SIGNATURES = {
    "PDF": {
        "signature": [b"%PDF-"],
        "extensions": [".pdf"]
    },

    "JPEG": {
        "signature": [b"\xff\xd8\xff"],
        "extensions": [".jpg", ".jpeg"]
    },

    "PNG": {
        "signature": [b"\x89PNG\r\n\x1a\n"],
        "extensions": [".png"]
    },

    "GIF": {
        "signature": [b"GIF87a", b"GIF89a"],
        "extensions": [".gif"]
    },

    "ZIP": {
        "signature": [
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08"
        ],
        "extensions": [".zip"]
    },

    "EXE": {
        "signature": [b"MZ"],
        "extensions": [".exe", ".dll", ".scr"]
    },

    "RAR": {
        "signature": [
            b"Rar!\x1a\x07\x00",
            b"Rar!\x1a\x07\x01\x00"
        ],
        "extensions": [".rar"]
    },

    "7Z": {
        "signature": [b"7z\xbc\xaf\x27\x1c"],
        "extensions": [".7z"]
    },

    "GZIP": {
        "signature": [b"\x1f\x8b"],
        "extensions": [".gz"]
    },

    "ELF": {
        "signature": [b"\x7fELF"],
        "extensions": [".elf"]
    },

    "OLE": {
        "signature": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
        "extensions": [".doc", ".xls", ".ppt"]
    },

    "SQLITE": {
        "signature": [b"SQLite format 3\x00"],
        "extensions": [".db", ".sqlite"]
    }
}


# FILE TYPE IDENTIFICATION

def identify_file_type(file_path):

    try:
        with open(file_path, "rb") as file:
            header = file.read(16)

        for file_type, details in SIGNATURES.items():

            for signature in details["signature"]:

                if header.startswith(signature):
                    return file_type

        return "UNKNOWN"

    except OSError as error:
        logging.error("Signature check failed: %s", error)
        return "ERROR"


# SHA256 HASHING

def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()

# EXTENSION VALIDATION

def check_extension(file_path, detected_type):

    extension = Path(file_path).suffix.lower()

    if detected_type in ("UNKNOWN", "ERROR"):
        return "UNKNOWN"

    expected_extensions = SIGNATURES[detected_type]["extensions"]

    if extension in expected_extensions:
        return "MATCH"

    return "MISMATCH"


# VIRUSTOTAL INTEGRATION

def check_virustotal(file_hash):

    if not VT_API_KEY:
        return "NOT CONFIGURED"

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return "NOT FOUND"

        response.raise_for_status()

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "detection_ratio": f"{malicious}/{total}",
            "report_url": f"https://www.virustotal.com/gui/file/{file_hash}"
        }

    except requests.RequestException as error:

        logging.error("VirusTotal lookup failed: %s", error)

        return "API ERROR"


# RISK ASSESSMENT

def calculate_risk(extension_status, detected_type, vt_result):

    score = 0
    findings = []

    if extension_status == "MISMATCH":

        score += 40
        findings.append("File extension does not match signature")

    if detected_type == "UNKNOWN":

        score += 15
        findings.append("Unknown file signature")

    if detected_type == "EXE":

        score += 15
        findings.append("Executable file identified")

    if isinstance(vt_result, dict):

        malicious = vt_result["malicious"]

        if malicious > 0:

            score += 60
            findings.append(
                f"VirusTotal malicious detections: {malicious}"
            )

        if vt_result["suspicious"] > 0:

            score += 20
            findings.append(
                f"VirusTotal suspicious detections: {vt_result['suspicious']}"
            )

    if score >= 60:
        severity = "CRITICAL"

    elif score >= 40:
        severity = "HIGH"

    elif score >= 20:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "score": min(score, 100),
        "severity": severity,
        "findings": findings
    }


# FILE ANALYSIS

def analyze_file(file_path):

    path = Path(file_path)

    result = {
        "filename": path.name,
        "path": str(path),
        "scan_time": datetime.now(timezone.utc).isoformat()
    }

    try:

        if not path.is_file():
            raise ValueError("Not a regular file")

        file_size = path.stat().st_size

        result["file_size"] = file_size

        if file_size > MAX_FILE_SIZE:

            result["status"] = "SKIPPED - FILE TOO LARGE"
            logging.warning("Skipped large file: %s", path)

            return result

        detected_type = identify_file_type(path)

        extension_status = check_extension(
            path,
            detected_type
        )

        file_hash = calculate_sha256(path)

        vt_result = check_virustotal(file_hash)

        risk = calculate_risk(
            extension_status,
            detected_type,
            vt_result
        )

        result.update({

            "detected_type": detected_type,

            "extension": path.suffix.lower(),

            "extension_status": extension_status,

            "sha256": file_hash,

            "virustotal": vt_result,

            "risk_score": risk["score"],

            "severity": risk["severity"],

            "findings": risk["findings"],

            "status": "COMPLETED"
        })

        logging.info(
            "Analyzed %s | Type: %s | Severity: %s",
            path.name,
            detected_type,
            risk["severity"]
        )

    except (OSError, ValueError) as error:

        result["status"] = f"ERROR: {error}"

        logging.error(
            "Analysis failed for %s: %s",
            path,
            error
        )

    return result


# BATCH SCANNING

def scan_directory(directory):

    results = []

    for root, dirs, files in os.walk(directory):

        for filename in files:

            file_path = Path(root) / filename

            if file_path.is_symlink():
                continue

            result = analyze_file(file_path)

            results.append(result)

            print_result(result)

    return results



# DISPLAY RESULTS


def print_result(result):

    print("\n" + "=" * 55)

    print(f"File: {result['filename']}")

    print(f"Status: {result['status']}")

    if result["status"] != "COMPLETED":
        return

    print(f"Detected Type: {result['detected_type']}")

    print(f"Extension: {result['extension']}")

    print(f"Extension Check: {result['extension_status']}")

    print(f"SHA256: {result['sha256']}")

    print(f"Risk Score: {result['risk_score']}/100")

    print(f"Severity: {result['severity']}")

    print("Findings:")

    if result["findings"]:

        for finding in result["findings"]:
            print(f"  [!] {finding}")

    else:
        print("  No configured indicators identified")

    vt = result["virustotal"]

    if isinstance(vt, dict):

        print(
            "VirusTotal: "
            f"{vt['detection_ratio']} malicious detections"
        )

    else:

        print(f"VirusTotal: {vt}")


# REPORT GENERATION

def generate_reports(results):

    with open(
        JSON_REPORT,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    fields = [
        "filename",
        "path",
        "file_size",
        "detected_type",
        "extension",
        "extension_status",
        "sha256",
        "risk_score",
        "severity",
        "findings",
        "virustotal",
        "status",
        "scan_time"
    ]

    with open(
        CSV_REPORT,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for result in results:

            row = result.copy()

            row["findings"] = "; ".join(
                row.get("findings", [])
            )

            row["virustotal"] = json.dumps(
                row.get("virustotal")
            )

            writer.writerow(row)

    print("\nReports generated:")
    print(f" - {JSON_REPORT}")
    print(f" - {CSV_REPORT}")


# MAIN

def main():

    parser = argparse.ArgumentParser(
        description="File Signature Checker"
    )

    parser.add_argument(
        "target",
        help="File or directory to scan"
    )

    args = parser.parse_args()

    target = Path(args.target)

    if not target.exists():

        print("Target does not exist.")
        return

    print("\nFILE SIGNATURE CHECKER v2.0")

    print("=" * 55)

    if target.is_file():

        results = [analyze_file(target)]

        print_result(results[0])

    elif target.is_dir():

        results = scan_directory(target)

    else:

        print("Target must be a file or directory.")
        return

    generate_reports(results)

    print("\nScan completed.")


if __name__ == "__main__":
    main()

