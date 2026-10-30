"""OpenTelemetry instrumentation and distributed tracing for FirmwareX."""

from firmwarex.telemetry.tracer import (
    JobTrace,
    PipelineTracer,
    SpanRecord,
    generate_span_id,
    generate_trace_id,
    get_trace,
    register_trace,
)

__all__ = [
    "JobTrace",
    "PipelineTracer",
    "SpanRecord",
    "generate_span_id",
    "generate_trace_id",
    "get_trace",
    "register_trace",
]

