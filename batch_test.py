import sys
import csv
import time
from pathlib import Path
from datetime import datetime
import requests

API_URL = "http://127.0.0.1:8000/api/scan/"
# API_URL = "https://websense-1ic6.onrender.com/api/scan/"

INPUT_CSV = sys.argv[1] if len(sys.argv) > 1 else "classification_dataset.csv"
OUTPUT_CSV = f"classification_results_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.csv"
TIMEOUT_SECONDS = 8
REQUEST_DELAY_SECONDS = 0.2


def normalise_expected(value: str) -> str:
    value = (value or "").strip().upper()
    if value in {"SAFE", "PHISHING"}:
        return value
    return "UNKNOWN"


def classify_evaluation(expected: str, predicted: str) -> str:
    predicted = (predicted or "").strip().upper()

    if expected == "SAFE":
        if predicted == "SAFE":
            return "TRUE_NEGATIVE"
        if predicted in {"BE_CAREFUL", "UNSAFE"}:
            return "FALSE_POSITIVE"
        return "UNKNOWN"

    if expected == "PHISHING":
        if predicted in {"BE_CAREFUL", "UNSAFE"}:
            return "TRUE_POSITIVE"
        if predicted == "SAFE":
            return "FALSE_NEGATIVE"
        return "UNKNOWN"

    return "UNKNOWN"


def is_prediction_correct(expected: str, predicted: str) -> str:
    evaluation = classify_evaluation(expected, predicted)
    return "YES" if evaluation in {"TRUE_POSITIVE", "TRUE_NEGATIVE"} else "NO"


def flatten_reasons(reasons) -> str:
    if not reasons:
        return ""

    if isinstance(reasons, dict):
        parts = []
        for key, value in reasons.items():
            if isinstance(value, list):
                joined = "; ".join(str(v) for v in value)
                parts.append(f"{key}: {joined}")
            else:
                parts.append(f"{key}: {value}")
        return " | ".join(parts)

    return str(reasons)


def scan_url(url: str) -> tuple[dict, float, int]:
    start = time.perf_counter()

    response = requests.post(
        API_URL,
        json={"url": url},
        timeout=TIMEOUT_SECONDS,
        headers={"Content-Type": "application/json"},
    )

    elapsed_ms = (time.perf_counter() - start) * 1000
    status_code = response.status_code

    response.raise_for_status()
    return response.json(), elapsed_ms, status_code


def calculate_metrics(output_rows: list[dict]) -> dict:
    total = len(output_rows)
    correct = sum(1 for row in output_rows if row["Correct?"] == "YES")

    true_positive = sum(1 for row in output_rows if row["Evaluation"] == "TRUE_POSITIVE")
    true_negative = sum(1 for row in output_rows if row["Evaluation"] == "TRUE_NEGATIVE")
    false_positive = sum(1 for row in output_rows if row["Evaluation"] == "FALSE_POSITIVE")
    false_negative = sum(1 for row in output_rows if row["Evaluation"] == "FALSE_NEGATIVE")

    total_safe = sum(1 for row in output_rows if row["Expected Result"] == "SAFE")
    total_phishing = sum(1 for row in output_rows if row["Expected Result"] == "PHISHING")

    accuracy = (correct / total * 100) if total else 0
    safe_accuracy = (true_negative / total_safe * 100) if total_safe else 0
    phishing_detection_rate = (true_positive / total_phishing * 100) if total_phishing else 0

    precision = (true_positive / (true_positive + false_positive)) if (true_positive + false_positive) else 0
    recall = (true_positive / (true_positive + false_negative)) if (true_positive + false_negative) else 0
    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    response_times = []
    for row in output_rows:
        value = (row.get("Response Time (ms)") or "").strip()
        if value:
            try:
                response_times.append(float(value))
            except ValueError:
                pass

    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    min_response_time = min(response_times) if response_times else 0
    max_response_time = max(response_times) if response_times else 0

    return {
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "safe_accuracy": safe_accuracy,
        "phishing_detection_rate": phishing_detection_rate,
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "avg_response_time": avg_response_time,
        "min_response_time": min_response_time,
        "max_response_time": max_response_time,
    }


def main() -> None:
    input_path = Path(INPUT_CSV)
    output_path = Path(OUTPUT_CSV)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_CSV}")

    with input_path.open("r", newline="", encoding="utf-8-sig") as infile:
        reader = csv.DictReader(infile)
        rows = list(reader)

    output_rows = []
    total_rows = len(rows)

    print(f"Loaded {total_rows} rows from {INPUT_CSV}")

    for idx, row in enumerate(rows, start=1):
        url = (row.get("url") or row.get("URL Tested") or row.get("URL") or "").strip()
        expected = normalise_expected(
            row.get("expected") or row.get("Expected Result") or row.get("Expected") or ""
        )
        label_source = (row.get("label_source") or "").strip()
        notes = (row.get("notes") or "").strip()

        print(f"[{idx}/{total_rows}] Testing: {url or '(missing URL)'}")

        if not url:
            output_rows.append({
                "ID": idx,
                "URL Tested": "",
                "Expected Result": expected,
                "WebSense Result": "ERROR",
                "Score": "",
                "Response Time (ms)": "",
                "HTTP Status": "",
                "Reason Flags": "",
                "Correct?": "NO",
                "Evaluation": "UNKNOWN",
                "Label Source": label_source,
                "Notes": "Missing URL",
            })
            continue

        try:
            result, elapsed_ms, status_code = scan_url(url)
            state = str(result.get("state", "")).upper()
            score = result.get("score", "")
            reasons = flatten_reasons(result.get("reasons"))
            evaluation = classify_evaluation(expected, state)
            correct = is_prediction_correct(expected, state)

            combined_notes = notes

            output_rows.append({
                "ID": idx,
                "URL Tested": url,
                "Expected Result": expected,
                "WebSense Result": state,
                "Score": score,
                "Response Time (ms)": f"{elapsed_ms:.2f}",
                "HTTP Status": status_code,
                "Reason Flags": reasons,
                "Correct?": correct,
                "Evaluation": evaluation,
                "Label Source": label_source,
                "Notes": combined_notes,
            })

        except requests.Timeout:
            output_rows.append({
                "ID": idx,
                "URL Tested": url,
                "Expected Result": expected,
                "WebSense Result": "TIMEOUT",
                "Score": "",
                "Response Time (ms)": "",
                "HTTP Status": "",
                "Reason Flags": "",
                "Correct?": "NO",
                "Evaluation": "UNKNOWN",
                "Label Source": label_source,
                "Notes": "Request timed out",
            })

        except requests.RequestException as e:
            output_rows.append({
                "ID": idx,
                "URL Tested": url,
                "Expected Result": expected,
                "WebSense Result": "ERROR",
                "Score": "",
                "Response Time (ms)": "",
                "HTTP Status": "",
                "Reason Flags": "",
                "Correct?": "NO",
                "Evaluation": "UNKNOWN",
                "Label Source": label_source,
                "Notes": str(e),
            })

        time.sleep(REQUEST_DELAY_SECONDS)

    with output_path.open("w", newline="", encoding="utf-8") as outfile:
        fieldnames = [
            "ID",
            "URL Tested",
            "Expected Result",
            "WebSense Result",
            "Score",
            "Response Time (ms)",
            "HTTP Status",
            "Reason Flags",
            "Correct?",
            "Evaluation",
            "Label Source",
            "Notes",
        ]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    metrics = calculate_metrics(output_rows)

    print("\nDone.")
    print(f"Results saved to {OUTPUT_CSV}")
    print(f"Correct: {metrics['correct']}/{metrics['total']}")
    print(f"Overall accuracy: {metrics['accuracy']:.2f}%")
    print(f"Safe-site accuracy: {metrics['safe_accuracy']:.2f}%")
    print(f"Phishing detection rate: {metrics['phishing_detection_rate']:.2f}%")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1-score: {metrics['f1_score']:.4f}")
    print(f"True Positives: {metrics['true_positive']}")
    print(f"True Negatives: {metrics['true_negative']}")
    print(f"False Positives: {metrics['false_positive']}")
    print(f"False Negatives: {metrics['false_negative']}")
    print(f"Average response time: {metrics['avg_response_time']:.2f} ms")
    print(f"Min response time: {metrics['min_response_time']:.2f} ms")
    print(f"Max response time: {metrics['max_response_time']:.2f} ms")


if __name__ == "__main__":
    main()