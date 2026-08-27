"""PII (Personally Identifiable Information) detector using regex, checksum algorithms, entropy, and semantics."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PIIDetectionResult:
    """Result of PII analysis on a single column."""

    column_name: str
    pii_type: str
    confidence: float
    recommended_strategy: str
    recommended_params: Dict[str, Any]
    sample_matches: List[str]


def _shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log2(p) for p in prob)


def _validate_luhn(card_number: str) -> bool:
    """Validates credit card / numeric identifier with Luhn mod-10 algorithm."""
    digits = [int(c) for c in re.sub(r"\D", "", card_number)]
    if len(digits) < 8 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _validate_tckn(tckn: str) -> bool:
    """Validates Turkish Citizenship Number (TCKN)."""
    digits_str = re.sub(r"\D", "", tckn)
    if len(digits_str) != 11 or digits_str[0] == "0":
        return False
    d = [int(c) for c in digits_str]
    odd_sum = d[0] + d[2] + d[4] + d[6] + d[8]
    even_sum = d[1] + d[3] + d[5] + d[7]
    d10 = ((odd_sum * 7) - even_sum) % 10
    if d[9] != d10:
        return False
    d11 = sum(d[:10]) % 10
    return d[10] == d11


def _validate_iban(iban: str) -> bool:
    """Validates International Bank Account Number (IBAN) using MOD-97 algorithm."""
    clean = re.sub(r"[\s-]", "", iban).upper()
    if len(clean) < 15 or len(clean) > 34 or not clean[:2].isalpha():
        return False
    reordered = clean[4:] + clean[:4]
    numeric = ""
    for char in reordered:
        if char.isdigit():
            numeric += char
        else:
            numeric += str(ord(char) - ord("A") + 10)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


class PIIDetector:
    """Analyzes schema and sample data values to automatically detect sensitive PII fields."""

    # Regex patterns
    PATTERNS = {
        "email": re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"),
        "phone": re.compile(r"^\+?[0-9]{1,4}?[-.\s]?\(?[0-9]{1,3}?\)?[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}$"),
        "credit_card": re.compile(r"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$"),
        "ssn": re.compile(r"^(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}$"),
        "ipv4": re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"),
        "uuid": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    }

    # Semantic column name heuristics (ordered with specific before generic)
    NAME_KEYWORDS = {
        "ip_address": ["ip_address", "ip", "ipv4", "client_ip", "remote_addr", "ip_adresi"],
        "credit_card": ["credit_card", "card_number", "card_no", "cc_num", "kart_no", "kredi_karti", "kredi_kart_no"],
        "date_of_birth": ["dob", "birth_date", "birthdate", "birthday", "dogum_tarihi", "dogum_gunu", "d_tarihi"],
        "tckn": ["tckn", "tc_kimlik", "tc_no", "kimlik_no", "tc_kimlik_no", "citizenship_id", "tcno", "vergi_no"],
        "iban": ["iban", "bank_account", "account_number", "hesap_no", "iban_no", "banka_hesap_no"],
        "email": ["email", "e_mail", "mail", "eposta", "e_posta", "e-posta", "email_adresi"],
        "first_name": ["first_name", "firstname", "fname", "ad", "isim", "musteri_adi"],
        "last_name": ["last_name", "lastname", "lname", "surname", "soyad", "soyisim"],
        "full_name": ["full_name", "fullname", "ad_soyad", "isim_soyad", "adsoyad", "kullanici_adi"],
        "phone": ["phone_number", "phone", "mobile", "cell", "tel", "telefon", "gsm", "cep_tel", "cep_telefonu", "iletisim_no"],
        "ssn": ["ssn", "social_security"],
        "address": ["shipping_address", "billing_address", "full_address", "street_address", "address", "street", "adres", "sokak", "cadde", "mahalle", "teslimat_adresi", "fatura_adresi"],
        "city": ["city", "sehir", "il", "ilce"],
        "country": ["country", "ulke"],
        "postcode": ["postcode", "zip", "zip_code", "posta_kodu"],
        "salary": ["salary", "wage", "compensation", "maas", "gelir", "balance", "bakiye", "tutar", "ucret"],
        "password": ["password", "passwd", "pwd", "hash", "secret", "token", "sifre", "parola", "api_key", "gizli_anahtar"],
    }

    def detect_column(
        self,
        column_name: str,
        sample_values: List[Any],
    ) -> Optional[PIIDetectionResult]:
        """Runs multi-layered heuristics against a column name and its sample values."""
        non_null_samples = [str(v).strip() for v in sample_values if v is not None and str(v).strip() != ""]
        norm_col = column_name.lower().strip().strip('"').strip('`').strip('[]')

        # 1. Match semantic column keywords
        for pii_type, keywords in self.NAME_KEYWORDS.items():
            for kw in keywords:
                if kw == norm_col or norm_col.endswith(f"_{kw}") or norm_col.startswith(f"{kw}_"):
                    strategy, params = self._get_recommendation(pii_type)
                    return PIIDetectionResult(
                        column_name=column_name,
                        pii_type=pii_type,
                        confidence=0.90,
                        recommended_strategy=strategy,
                        recommended_params=params,
                        sample_matches=non_null_samples[:3],
                    )

        if not non_null_samples:
            return None

        # 2. Check sample values with regex and checksum algorithms
        email_matches = sum(1 for v in non_null_samples if self.PATTERNS["email"].match(v))
        if email_matches / len(non_null_samples) >= 0.5:
            strategy, params = self._get_recommendation("email")
            return PIIDetectionResult(
                column_name=column_name,
                pii_type="email",
                confidence=0.95,
                recommended_strategy=strategy,
                recommended_params=params,
                sample_matches=non_null_samples[:3],
            )

        phone_matches = sum(1 for v in non_null_samples if self.PATTERNS["phone"].match(v))
        if phone_matches / len(non_null_samples) >= 0.5:
            strategy, params = self._get_recommendation("phone")
            return PIIDetectionResult(
                column_name=column_name,
                pii_type="phone",
                confidence=0.85,
                recommended_strategy=strategy,
                recommended_params=params,
                sample_matches=non_null_samples[:3],
            )

        # Check for Credit Card with Luhn algorithm
        cc_matches = sum(1 for v in non_null_samples if _validate_luhn(v))
        if cc_matches / len(non_null_samples) >= 0.3:
            strategy, params = self._get_recommendation("credit_card")
            return PIIDetectionResult(
                column_name=column_name,
                pii_type="credit_card",
                confidence=0.98,
                recommended_strategy=strategy,
                recommended_params=params,
                sample_matches=non_null_samples[:3],
            )

        # Check for TCKN (Turkish Citizen ID)
        tckn_matches = sum(1 for v in non_null_samples if _validate_tckn(v))
        if tckn_matches / len(non_null_samples) >= 0.3:
            strategy, params = self._get_recommendation("tckn")
            return PIIDetectionResult(
                column_name=column_name,
                pii_type="tckn",
                confidence=0.98,
                recommended_strategy=strategy,
                recommended_params=params,
                sample_matches=non_null_samples[:3],
            )

        # Check for IBAN
        iban_matches = sum(1 for v in non_null_samples if _validate_iban(v))
        if iban_matches / len(non_null_samples) >= 0.3:
            strategy, params = self._get_recommendation("iban")
            return PIIDetectionResult(
                column_name=column_name,
                pii_type="iban",
                confidence=0.98,
                recommended_strategy=strategy,
                recommended_params=params,
                sample_matches=non_null_samples[:3],
            )

        # Check for high-entropy secrets / hashes
        avg_entropy = sum(_shannon_entropy(v) for v in non_null_samples) / len(non_null_samples)
        if avg_entropy > 4.5 and len(non_null_samples[0]) >= 20:
            strategy, params = self._get_recommendation("password")
            return PIIDetectionResult(
                column_name=column_name,
                pii_type="secret_hash",
                confidence=0.80,
                recommended_strategy=strategy,
                recommended_params=params,
                sample_matches=["[HIGH_ENTROPY_HASH]"],
            )

        return None

    def _get_recommendation(self, pii_type: str) -> Tuple[str, Dict[str, Any]]:
        """Maps detected PII type to recommended masking strategy and params."""
        mapping = {
            "email": ("faker", {"provider": "email", "preserve_domain": True}),
            "first_name": ("faker", {"provider": "first_name"}),
            "last_name": ("faker", {"provider": "last_name"}),
            "full_name": ("faker", {"provider": "name"}),
            "phone": ("faker", {"provider": "phone_number"}),
            "credit_card": ("credit_card_mask", {"mask_char": "*"}),
            "ssn": ("pattern_mask", {"keep_first": 0, "keep_last": 4, "mask_char": "*"}),
            "tckn": ("tckn", {}),
            "iban": ("faker", {"provider": "iban"}),
            "address": ("faker", {"provider": "address"}),
            "city": ("faker", {"provider": "city"}),
            "country": ("faker", {"provider": "country"}),
            "postcode": ("faker", {"provider": "postcode"}),
            "salary": ("jitter", {"percentage": 15.0, "distribution": "gaussian"}),
            "password": ("constant", {"value_to_set": "argon2$placeholder$masked"}),
            "date_of_birth": ("date_shift", {"max_days_forward": 60, "max_days_backward": 60}),
            "ip_address": ("faker", {"provider": "ipv4"}),
            "secret_hash": ("deterministic_hash", {"length": 32}),
        }
        return mapping.get(pii_type, ("deterministic_hash", {}))
