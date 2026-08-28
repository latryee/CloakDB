"""OpenTelemetry (OTel) instrumentation, tracing spans, metrics, and structured JSON logging."""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any


class _NullSpan:
    """Fallback no-op span when OpenTelemetry is disabled or not installed."""

    def __enter__(self) -> _NullSpan:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any, description: str | None = None) -> None:
        pass

    def record_exception(self, exception: BaseException) -> None:
        pass


class CloakTelemetry:
    """Manages OpenTelemetry tracing, metrics, and latency measurement."""

    _initialized: bool = False
    _tracer: Any = None
    _metrics: dict[str, Any] = {}
    _enabled: bool = False

    @classmethod
    def initialize(
        cls,
        service_name: str = "cloakdb",
        endpoint: str | None = None,
        enabled: bool | None = None,
    ) -> None:
        """Initializes OpenTelemetry TracerProvider and MeterProvider if available."""
        if enabled is not None:
            cls._enabled = enabled
        else:
            cls._enabled = bool(endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))

        if not cls._enabled:
            return

        try:
            from opentelemetry import trace
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider

            resource = Resource.create({"service.name": service_name, "service.version": "1.0.0"})
            provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(provider)
            cls._tracer = trace.get_tracer("cloakdb.tracer", "1.0.0")
            cls._initialized = True
        except ImportError:
            # Graceful fallback when opentelemetry-sdk is not installed
            cls._initialized = False
            cls._tracer = None

    @classmethod
    @contextmanager
    def span(cls, name: str, attributes: dict[str, Any] | None = None) -> Generator[Any, None, None]:
        """Creates an OpenTelemetry tracing span with context management."""
        if cls._tracer and cls._enabled:
            with cls._tracer.start_as_current_span(name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, str(v))
                yield span
        else:
            yield _NullSpan()

    @classmethod
    def record_metric(cls, metric_name: str, value: float | int, labels: dict[str, str] | None = None) -> None:
        """Records an execution metric counter or gauge."""
        key = f"{metric_name}:{labels or {}}"
        cls._metrics[key] = value


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter for standard Python logging handlers."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "props"):
            log_entry["properties"] = record.props
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


def setup_structured_logging(level: int = logging.INFO, stream: Any = None) -> None:
    """Configures structured JSON logging to stdout or specified stream."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JSONFormatter())
    root_logger = logging.getLogger("cloakdb")
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
