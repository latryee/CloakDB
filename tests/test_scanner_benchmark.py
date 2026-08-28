"""PII auto-scanner benchmark suite measuring precision, recall, and F1 score against real-world schemas and edge cases."""

from __future__ import annotations

from typing import Any
from cloakdb.scanner.detector import PIIDetector


def test_scanner_precision_recall_benchmark():
    """Runs a rigorous classification benchmark measuring precision & recall on sensitive vs benign data."""
    detector = PIIDetector()

    # Benchmark dataset: (column_name, sample_values, expected_pii_type_or_none)
    benchmark_dataset: list[tuple[str, list[Any], str | None]] = [
        # === SENSITIVE COLUMNS (Ground Truth Positive) ===
        # 1. Emails
        ("email", ["alice@example.com", "bob.smith@corp.co.uk", "user+tag@domain.org"], "email"),
        ("contact_email", ["support@company.com", "billing@service.io"], "email"),
        ("unlabeled_col_1", ["carol.danvers@avengers.org", "peter.parker@dailybugle.com"], "email"),

        # 2. International Phone Numbers
        ("phone", ["+44 20 7946 0958", "+49 30 123456", "+90 532 123 45 67", "(555) 123-4567"], "phone"),
        ("mobile_number", ["0532 999 88 77", "+1-800-555-0199"], "phone"),
        ("unlabeled_col_2", ["+44 7911 123456", "+33 1 42 68 59 00"], "phone"),

        # 3. Credit Cards (Luhn Mod-10 Valid)
        ("credit_card", ["4532015018092784", "5424000000000001", "378282246310005"], "credit_card"),
        ("card_no", ["4000001234567891", "4111111111111111"], "credit_card"),
        ("unlabeled_cc", ["4111-1111-1111-1111", "5424-0000-0000-0001"], "credit_card"),

        # 4. Turkish Citizenship IDs (TCKN Valid Checksum)
        ("tckn", ["10000000146", "36454799638", "51649372138"], "tckn"),
        ("tc_kimlik_no", ["10000000146", "36454799638"], "tckn"),
        ("unlabeled_tckn", ["51649372138", "10000000146"], "tckn"),

        # 5. International Bank Account Numbers (IBAN Valid Mod-97)
        ("iban", ["TR330006100519786457841326", "DE89370400440532013000", "GB29NWBK60161331926819"], "iban"),
        ("bank_account", ["FR1420041010050500013M02606", "TR120006200000012345678901"], "iban"),

        # 6. Full Names & Names
        ("full_name", ["Alice Johnson", "Mehmet Yılmaz", "François Dubois"], "full_name"),
        ("first_name", ["John", "Ahmet", "Elena"], "first_name"),
        ("last_name", ["Smith", "Kaya", "Müller"], "last_name"),

        # 7. Physical Addresses
        ("shipping_address", ["123 Main St, New York, NY", "Atatürk Cad. No:45, Kadıköy, İstanbul"], "address"),
        ("city", ["London", "Berlin", "Ankara"], "city"),

        # 8. High-Entropy Password Hashes & Secrets
        ("password_hash", ["$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgTVBcFLmwHQ", "pbkdf2_sha256$260000$secret$salthashvalue12345678901234567890"], "password"),

        # === BENIGN / NON-PII COLUMNS (Ground Truth Negative) ===
        ("order_id", [10001, 10002, 10003, 10004], None),
        ("quantity", [1, 5, 12, 100, 3], None),
        ("unit_price", [19.99, 149.50, 9.95, 1200.00], None),
        ("product_sku", ["SKU-100293", "PROD-A882-XYZ", "ITEM-991"], None),
        ("status_code", [200, 404, 500, 301], None),
        ("is_active", [True, False, True, True], None),
        ("created_at", ["2026-01-01 10:00:00", "2026-02-15 18:30:25"], None),
        ("category_name", ["Electronics", "Books", "Home & Garden"], None),
        ("rating", [4.5, 3.8, 5.0, 1.2], None),

        # === TRICKY NEGATIVE EDGE CASES (Should NOT falsely match PII) ===
        # Bad Credit Cards (Invalid Luhn algorithm)
        ("random_16_digits", ["1234567812345670", "9876543210987650"], None),
        # Bad TCKN (Invalid 10th or 11th digit checks)
        ("invalid_tckn_samples", ["10000000140", "01234567890", "12345678901"], None),
        # Bad IBAN (Invalid MOD-97 checksum)
        ("invalid_iban_samples", ["TR000000000000000000000000", "DE00000000000000000000"], None),
    ]

    tp = 0  # True Positives
    fp = 0  # False Positives
    fn = 0  # False Negatives
    tn = 0  # True Negatives

    results_summary = []

    for col_name, samples, expected_type in benchmark_dataset:
        detection = detector.detect_column(col_name, samples)
        detected_type = detection.pii_type if detection else None

        if expected_type is not None:
            # Column IS sensitive
            if detected_type is not None:
                tp += 1
                results_summary.append((col_name, expected_type, detected_type, "TP"))
            else:
                fn += 1
                results_summary.append((col_name, expected_type, "NONE", "FN"))
        else:
            # Column is NOT sensitive (benign)
            if detected_type is not None:
                fp += 1
                results_summary.append((col_name, "NONE", detected_type, "FP"))
            else:
                tn += 1
                results_summary.append((col_name, "NONE", "NONE", "TN"))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 60)
    print("CLOAKDB PII AUTO-SCANNER BENCHMARK REPORT")
    print("=" * 60)
    print(f"Total Evaluated Test Cases: {len(benchmark_dataset)}")
    print(f"True Positives  (TP): {tp}")
    print(f"True Negatives  (TN): {tn}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")
    print("-" * 60)
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall:    {recall * 100:.2f}%")
    print(f"F1-Score:  {f1_score * 100:.2f}%")
    print("=" * 60 + "\n")

    # Assert rigorous production quality metrics
    assert precision >= 0.95, f"Expected scanner precision >= 95%, got {precision:.2%}"
    assert recall >= 0.95, f"Expected scanner recall >= 95%, got {recall:.2%}"
    assert f1_score >= 0.95, f"Expected scanner F1 >= 95%, got {f1_score:.2%}"
