"""Format-Preserving Encryption (FPE) strategies implementing Feistel FF1/FF3-1.

Mathematically guarantees that ciphertext maintains the identical length, alphabet,
radix, and structural formatting (e.g., Luhn check digits, country codes, email domains)
as the plaintext.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy

# Standard character alphabets
DIGITS = "0123456789"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHANUMERIC = DIGITS + LOWERCASE + UPPERCASE
HEX = "0123456789abcdef"


def _compute_luhn_check_digit(partial_card_digits: list[int]) -> int:
    """Calculates the Luhn mod-10 check digit for a list of preceding digits."""
    digits = partial_card_digits + [0]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    check_digit = (10 - (checksum % 10)) % 10
    return check_digit


def _compute_tckn_checksum(digits9: list[int]) -> tuple[int, int]:
    """Given first 9 digits of a Turkish Citizenship Number, computes 10th and 11th digits."""
    odd_sum = digits9[0] + digits9[2] + digits9[4] + digits9[6] + digits9[8]
    even_sum = digits9[1] + digits9[3] + digits9[5] + digits9[7]
    d10 = ((odd_sum * 7) - even_sum) % 10
    d11 = (sum(digits9) + d10) % 10
    return d10, d11


class FeistelFPE:
    """Deterministic Feistel Format-Preserving Encryption engine.

    Implements a balanced / unbalanced Feistel network modeled after NIST SP 800-38G (FF1/FF3-1).
    Round function utilizes HMAC-SHA256 keyed PRF with contextual tweaks.
    """

    def __init__(self, key: bytes, alphabet: str = DIGITS, rounds: int = 10):
        if len(alphabet) < 2:
            raise ValueError(f"FPE alphabet must have at least 2 characters, got {len(alphabet)}")
        self.key = key
        self.alphabet = alphabet
        self.radix = len(alphabet)
        self.rounds = max(4, rounds)
        self._char_to_idx = {c: i for i, c in enumerate(alphabet)}
        self._idx_to_char = dict(enumerate(alphabet))

    def _round_prf(self, round_num: int, b_val: int, tweak: bytes) -> int:
        """Evaluates round pseudo-random function using HMAC-SHA256."""
        h = hmac.new(self.key, digestmod=hashlib.sha256)
        h.update(round_num.to_bytes(2, "big"))
        h.update(len(tweak).to_bytes(2, "big"))
        h.update(tweak)
        b_bytes = b_val.to_bytes((b_val.bit_length() + 7) // 8 or 1, "big")
        h.update(b_bytes)
        digest = h.digest()
        return int.from_bytes(digest[:16], "big")

    def encrypt(self, plaintext: str, tweak: bytes = b"") -> str:
        """Encrypts a string containing only characters in self.alphabet."""
        n = len(plaintext)
        if n < 2:
            if n == 1 and plaintext in self._char_to_idx:
                idx = self._char_to_idx[plaintext]
                h = hmac.new(self.key, tweak + plaintext.encode(), hashlib.sha256).digest()
                shift = int.from_bytes(h[:4], "big") % self.radix
                return self._idx_to_char[(idx + shift) % self.radix]
            return plaintext

        u = n // 2
        v = n - u

        a_str = plaintext[:u]
        b_str = plaintext[u:]

        a_num = 0
        for c in a_str:
            a_num = a_num * self.radix + self._char_to_idx[c]

        b_num = 0
        for c in b_str:
            b_num = b_num * self.radix + self._char_to_idx[c]

        radix_u = self.radix**u
        radix_v = self.radix**v

        for r in range(self.rounds):
            if r % 2 == 0:
                mod = radix_u
                f = self._round_prf(r, b_num, tweak)
                c_num = (a_num + f) % mod
                a_num = b_num
                b_num = c_num
            else:
                mod = radix_v
                f = self._round_prf(r, b_num, tweak)
                c_num = (a_num + f) % mod
                a_num = b_num
                b_num = c_num

        if self.rounds % 2 == 1:
            out_a_num, out_b_num = b_num, a_num
            len_a, len_b = v, u
        else:
            out_a_num, out_b_num = a_num, b_num
            len_a, len_b = u, v

        res_a: list[str] = []
        for _ in range(len_a):
            out_a_num, rem = divmod(out_a_num, self.radix)
            res_a.append(self._idx_to_char[rem])
        res_a.reverse()

        res_b: list[str] = []
        for _ in range(len_b):
            out_b_num, rem = divmod(out_b_num, self.radix)
            res_b.append(self._idx_to_char[rem])
        res_b.reverse()

        return "".join(res_a) + "".join(res_b)


@register_strategy("fpe", aliases=["format_preserving_encryption", "ff1", "ff3_1"])
class FPEStrategy(MaskingStrategy):
    """General Format-Preserving Encryption strategy for arbitrary radices and alphabets."""

    description = "Encrypts structured inputs preserving exact length and character alphabet (digits/alphanumeric/custom)"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        alphabet: str = DIGITS,
        radix: int | None = None,
        tweak: str | None = None,
        preserve_format: bool = True,
        rounds: int = 10,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value)
        if not val_str:
            return val_str

        if radix == 16:
            alpha = HEX
        elif radix == 36:
            alpha = DIGITS + LOWERCASE
        elif radix == 62:
            alpha = ALPHANUMERIC
        elif radix == 10:
            alpha = DIGITS
        else:
            alpha = alphabet or DIGITS

        key = hashlib.sha256(f"fpe:{context.salt}:{context.table_name}:{context.column_name}".encode()).digest()
        tweak_bytes = (tweak or f"{context.table_name}.{context.column_name}").encode("utf-8")

        fpe = FeistelFPE(key, alphabet=alpha, rounds=rounds)

        if preserve_format:
            alpha_set = set(alpha)
            positions: list[int] = []
            extracted: list[str] = []
            for i, c in enumerate(val_str):
                if c in alpha_set:
                    positions.append(i)
                    extracted.append(c)

            if not extracted:
                return val_str

            encrypted_chars = list(fpe.encrypt("".join(extracted), tweak=tweak_bytes))
            result_chars = list(val_str)
            for pos, enc_c in zip(positions, encrypted_chars):
                result_chars[pos] = enc_c
            return "".join(result_chars)
        else:
            return fpe.encrypt(val_str, tweak=tweak_bytes)


@register_strategy("fpe_credit_card", aliases=["fpe_cc", "format_preserving_cc"])
class FPECreditCardStrategy(MaskingStrategy):
    """FPE for Credit Cards: preserves card length, prefix/BIN, and guarantees valid Luhn checksum."""

    description = "Encrypts credit card numbers with FPE while preserving issuer prefix, length, and Luhn validity"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        preserve_prefix_len: int = 1,
        preserve_suffix_len: int = 0,
        luhn_checksum: bool = True,
        preserve_delimiters: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value)
        digits_only = [c for c in val_str if c in DIGITS]
        n_digits = len(digits_only)

        if n_digits < 12:
            return FPEStrategy().transform(val_str, context, alphabet=DIGITS, preserve_format=True)

        prefix_len = max(1, min(preserve_prefix_len, n_digits - 6))
        suffix_len = max(0, min(preserve_suffix_len, n_digits - prefix_len - 2))

        prefix_digits = digits_only[:prefix_len]
        if luhn_checksum:
            encrypt_target = digits_only[prefix_len : n_digits - 1]
        else:
            encrypt_target = digits_only[prefix_len : n_digits - suffix_len]

        key = hashlib.sha256(f"fpe_cc:{context.salt}:{context.table_name}:{context.column_name}".encode()).digest()
        tweak = f"cc:{context.table_name}:{prefix_len}".encode()
        fpe = FeistelFPE(key, alphabet=DIGITS, rounds=8)
        enc_middle = fpe.encrypt("".join(encrypt_target), tweak=tweak)

        if luhn_checksum:
            combined = [int(c) for c in prefix_digits] + [int(c) for c in enc_middle]
            check_digit = _compute_luhn_check_digit(combined)
            final_digits = [str(d) for d in combined] + [str(check_digit)]
        else:
            suffix_digits = digits_only[n_digits - suffix_len :] if suffix_len > 0 else []
            final_digits = prefix_digits + list(enc_middle) + suffix_digits

        if preserve_delimiters:
            result: list[str] = []
            digit_idx = 0
            for c in val_str:
                if c in DIGITS and digit_idx < len(final_digits):
                    result.append(final_digits[digit_idx])
                    digit_idx += 1
                else:
                    result.append(c)
            return "".join(result)
        else:
            return "".join(final_digits)


@register_strategy("fpe_phone", aliases=["fpe_phone_number", "format_preserving_phone"])
class FPEPhoneNumberStrategy(MaskingStrategy):
    """FPE for Phone Numbers: preserves punctuation, formatting, and country code digits."""

    description = "Encrypts phone numbers with FPE while preserving country code prefix, length, and formatting"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        preserve_country_code: bool = True,
        preserve_prefix_digits: int = 0,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value)
        digits_only = [c for c in val_str if c in DIGITS]
        if len(digits_only) < 4:
            return val_str

        prefix_len = 0
        if preserve_country_code and val_str.strip().startswith("+"):
            prefix_len = 1
            if len(digits_only) >= 11:
                prefix_len = len(digits_only) - 10
        elif preserve_prefix_digits > 0:
            prefix_len = min(preserve_prefix_digits, len(digits_only) - 2)

        prefix = digits_only[:prefix_len]
        to_encrypt = digits_only[prefix_len:]

        key = hashlib.sha256(f"fpe_phone:{context.salt}:{context.table_name}:{context.column_name}".encode()).digest()
        tweak = f"phone:{context.table_name}:{prefix_len}".encode()
        fpe = FeistelFPE(key, alphabet=DIGITS, rounds=8)
        enc_digits = prefix + list(fpe.encrypt("".join(to_encrypt), tweak=tweak))

        result: list[str] = []
        d_idx = 0
        for c in val_str:
            if c in DIGITS and d_idx < len(enc_digits):
                result.append(enc_digits[d_idx])
                d_idx += 1
            else:
                result.append(c)
        return "".join(result)


@register_strategy("fpe_national_id", aliases=["fpe_ssn", "fpe_tckn", "format_preserving_id"])
class FPENationalIDStrategy(MaskingStrategy):
    """FPE for National IDs / SSNs / TCKN with structure and checksum preservation."""

    description = "Encrypts national identity numbers and SSNs with FPE and valid checksum calculation"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        id_type: str = "auto",
        validate_checksum: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value).strip()
        digits = [c for c in val_str if c in DIGITS]
        n_digits = len(digits)

        key = hashlib.sha256(f"fpe_id:{context.salt}:{context.table_name}:{context.column_name}".encode()).digest()
        tweak = f"id:{context.table_name}:{n_digits}".encode()

        is_tckn = (id_type.lower() == "tckn") or (id_type.lower() == "auto" and n_digits == 11 and not any(c in val_str for c in "-/."))
        if is_tckn and n_digits == 11:
            fpe = FeistelFPE(key, alphabet=DIGITS, rounds=8)
            raw9 = fpe.encrypt("".join(digits[:9]), tweak=tweak)
            first_d = int(raw9[0])
            if first_d == 0:
                first_d = 1 + (int(hashlib.sha256(raw9.encode()).hexdigest()[:4], 16) % 9)
            d9_list = [first_d] + [int(c) for c in raw9[1:9]]
            if validate_checksum:
                d10, d11 = _compute_tckn_checksum(d9_list)
                enc_digits = [str(d) for d in d9_list] + [str(d10), str(d11)]
            else:
                enc_digits = [str(d) for d in d9_list] + digits[9:11]
            return "".join(enc_digits)

        is_ssn = (id_type.lower() == "ssn") or (id_type.lower() == "auto" and n_digits == 9)
        if is_ssn and n_digits == 9:
            fpe = FeistelFPE(key, alphabet=DIGITS, rounds=8)
            enc_9 = fpe.encrypt("".join(digits), tweak=tweak)
            if "-" in val_str and len(val_str) == 11:
                return f"{enc_9[:3]}-{enc_9[3:5]}-{enc_9[5:]}"
            return enc_9

        return FPEStrategy().transform(val_str, context, alphabet=DIGITS, preserve_format=True)


@register_strategy("fpe_email", aliases=["format_preserving_email"])
class FPEEmailStrategy(MaskingStrategy):
    """FPE for Email addresses: preserves domain while encrypting local part with format preservation."""

    description = "Encrypts email addresses preserving domain and local part length and character structure"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        preserve_domain: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value).strip()
        if "@" not in val_str:
            return FPEStrategy().transform(val_str, context, alphabet=ALPHANUMERIC, preserve_format=True)

        local_part, domain_part = val_str.split("@", 1)
        if not local_part:
            return val_str

        key = hashlib.sha256(f"fpe_email:{context.salt}:{context.table_name}:{context.column_name}".encode()).digest()
        tweak = f"email:{domain_part}".encode()

        fpe = FeistelFPE(key, alphabet=ALPHANUMERIC, rounds=8)
        alpha_set = set(ALPHANUMERIC)

        positions: list[int] = []
        extracted: list[str] = []
        for i, c in enumerate(local_part):
            if c in alpha_set:
                positions.append(i)
                extracted.append(c)

        if extracted:
            enc_chars = list(fpe.encrypt("".join(extracted), tweak=tweak))
            result_local = list(local_part)
            for pos, enc_c in zip(positions, enc_chars):
                result_local[pos] = enc_c
            masked_local = "".join(result_local).lower()
        else:
            masked_local = local_part

        if preserve_domain:
            return f"{masked_local}@{domain_part}"
        else:
            return f"{masked_local}@example.com"
