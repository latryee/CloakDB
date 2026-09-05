"""Algorithmic checksum validators: Luhn mod-10, Turkish TCKN, and IBAN MOD-97."""

from __future__ import annotations

import re


def validate_luhn(card_number: str) -> bool:
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


def validate_tckn(tckn: str) -> bool:
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


def validate_iban(iban: str) -> bool:
    """Validates International Bank Account Number (IBAN) using MOD-97 algorithm."""
    clean = re.sub(r"[\s-]", "", iban).upper()
    if len(clean) < 15 or len(clean) > 34 or not clean[:2].isalpha():
        return False
    reordered = clean[4:] + clean[:4]
    numeric = ""
    for char in reordered:
        if char.isdigit():
            numeric += char
        elif char.isupper():
            numeric += str(ord(char) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False
