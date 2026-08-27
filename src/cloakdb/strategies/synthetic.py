"""Realistic synthetic data generation using Faker with deterministic seeding."""

from __future__ import annotations

import random
from typing import Any

from faker import Faker

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


class _FakerPool:
    """Thread-safe pool of cached Faker instances indexed by locale."""

    _instances: dict[str, Faker] = {}

    @classmethod
    def get(cls, locale: str = "en_US") -> Faker:
        if locale not in cls._instances:
            cls._instances[locale] = Faker(locale)
        return cls._instances[locale]


@register_strategy("faker", aliases=["fake", "synthetic"])
class SyntheticFakerStrategy(MaskingStrategy):
    """Generates realistic synthetic data using Faker (names, addresses, emails, phones, IBANs, etc.)."""

    description = "Generates realistic synthetic data via Faker (preserves format and semantics)"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        provider: str = "name",
        locale: str | None = None,
        deterministic: bool = True,
        preserve_domain: bool = False,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        effective_locale = locale or context.locale or "en_US"
        fake = _FakerPool.get(effective_locale)

        # If deterministic mode is active, seed the generator with a hash of value + salt + column
        if deterministic:
            seed = context.derive_seed(value)
            fake.seed_instance(seed)
            random.seed(seed)

        provider_clean = provider.lower().strip()

        # Special handling for email with preserved domain
        if provider_clean in ("email", "safe_email", "company_email"):
            if preserve_domain and isinstance(value, str) and "@" in value:
                _, domain = value.rsplit("@", 1)
                user_part = fake.user_name()
                return f"{user_part}@{domain}"
            return fake.email()

        if provider_clean in ("name", "full_name"):
            return fake.name()
        elif provider_clean in ("first_name", "firstname"):
            return fake.first_name()
        elif provider_clean in ("last_name", "lastname", "surname"):
            return fake.last_name()
        elif provider_clean in ("phone", "phone_number", "mobile"):
            return fake.phone_number()
        elif provider_clean in ("address", "full_address"):
            return fake.address().replace("\n", ", ")
        elif provider_clean in ("street", "street_address"):
            return fake.street_address()
        elif provider_clean in ("city",):
            return fake.city()
        elif provider_clean in ("country",):
            return fake.country()
        elif provider_clean in ("postcode", "zipcode", "zip"):
            return fake.postcode()
        elif provider_clean in ("company", "company_name"):
            return fake.company()
        elif provider_clean in ("job", "occupation"):
            return fake.job()
        elif provider_clean in ("credit_card", "credit_card_number", "cc"):
            return fake.credit_card_number()
        elif provider_clean in ("ssn",):
            return fake.ssn()
        elif provider_clean in ("iban",):
            return fake.iban()
        elif provider_clean in ("ipv4", "ip"):
            return fake.ipv4()
        elif provider_clean in ("ipv6",):
            return fake.ipv6()
        elif provider_clean in ("user_name", "username"):
            return fake.user_name()
        elif provider_clean in ("url", "website"):
            return fake.url()
        elif provider_clean in ("text", "sentence"):
            return fake.sentence()
        elif provider_clean in ("paragraph",):
            return fake.paragraph()
        elif provider_clean in ("date_of_birth", "dob"):
            return fake.date_of_birth().isoformat()
        elif provider_clean in ("date_this_century", "date"):
            return fake.date_this_century().isoformat()

        # Fallback to direct attribute on Faker instance if available
        if hasattr(fake, provider_clean):
            attr = getattr(fake, provider_clean)
            if callable(attr):
                return attr()

        # Fallback to general text
        return fake.word()
