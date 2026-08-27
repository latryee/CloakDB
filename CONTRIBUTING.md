# Contributing to CloakDB

Thank you for your interest in contributing to CloakDB.

## Development Setup

1. **Clone the repository and set up a virtual environment:**
   ```bash
   git clone https://github.com/latryee/CloakDB.git
   cd CloakDB
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install development dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

## Quality Checks & Testing

All pull requests must pass the automated test suite, linting, formatting, and type checks.

### Running Tests & Coverage
```bash
pytest --cov=cloakdb --cov-report=term-missing
```

### Linting & Formatting
We use [Ruff](https://github.com/astral-sh/ruff) for linting and code formatting:
```bash
# Check linting
ruff check .

# Auto-fix lint issues
ruff check --fix .

# Check formatting
ruff format --check .

# Auto-format code
ruff format .
```

### Type Checking
We use [Mypy](https://mypy-lang.org/) for static type checking:
```bash
mypy src
```

### Verification Suite
Run all checks in one command:
```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Adding a Masking Strategy

1. Create or open the relevant module in `src/cloakdb/strategies/` (e.g., `general.py`, `numeric.py`, `redaction.py`).
2. Subclass `MaskingStrategy` from `cloakdb.strategies.base`.
3. Implement the `transform(self, value, context, **params)` method.
4. Register the strategy using `@register_strategy("<name>", aliases=["<alias1>"])`.
5. Add comprehensive unit tests in `tests/test_strategies.py`.

Example:
```python
from typing import Any
from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


@register_strategy("custom_prefix", aliases=["prefix"])
class CustomPrefixStrategy(MaskingStrategy):
    description = "Prepends a fixed prefix to string values"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        prefix: str = "MASKED_",
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None
        return f"{prefix}{value}"
```

## Pull Request Guidelines

- Keep changes focused and minimal. Avoid large refactors or unnecessary dependencies.
- Ensure new features and bug fixes include automated tests.
- Keep documentation up to date.
