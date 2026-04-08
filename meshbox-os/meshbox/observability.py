"""
MeshBox Observability Module.
Prometheus metrics and OpenTelemetry tracing for production monitoring.
"""

import time
import logging
from typing import Optional

try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import Status, StatusCode
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False


logger = logging.getLogger("meshbox.observability")


class MetricsCollector:
    """Prometheus metrics collector for MeshBox."""

    _instance: Optional['MetricsCollector'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._tracer: Optional[object] = None

        if not PROMETHEUS_AVAILABLE:
            logger.warning("prometheus_client not installed - metrics disabled")
            return

        self.messages_sent_total = Counter(
            'meshbox_messages_sent_total',
            'Total messages sent',
            ['priority']
        )
        self.messages_received_total = Counter(
            'meshbox_messages_received_total',
            'Total messages received',
            ['priority']
        )
        self.bytes_transferred_total = Counter(
            'meshbox_bytes_transferred_total',
            'Total bytes transferred',
            ['direction']
        )
        self.peers_connected_total = Counter(
            'meshbox_peers_connected_total',
            'Total peer connections',
            ['connection_type']
        )

        self.message_latency_seconds = Histogram(
            'meshbox_message_latency_seconds',
            'Message latency in seconds',
            ['stage'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )
        self.connection_setup_seconds = Histogram(
            'meshbox_connection_setup_seconds',
            'Connection setup time in seconds',
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )

        self.active_connections = Gauge(
            'meshbox_active_connections',
            'Number of active connections'
        )
        self.queue_depth = Gauge(
            'meshbox_queue_depth',
            'Current queue depth',
            ['queue_type']
        )
        self.peers_online = Gauge(
            'meshbox_peers_online',
            'Number of peers online',
            ['connection_type']
        )

    def init_tracing(self, service_name: str = "meshbox", otlp_endpoint: Optional[str] = None):
        """Initialize OpenTelemetry tracing."""
        if not OPENTELEMETRY_AVAILABLE:
            logger.warning("opentelemetry not installed - tracing disabled")
            return

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)

        if otlp_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
                processor = BatchSpanProcessor(exporter)
                provider.add_span_processor(processor)
                logger.info("OTLP tracing enabled to %s", otlp_endpoint)
            except ImportError:
                logger.warning("opentelemetry-exporter-otlp not installed")
                provider.add_span_processor(BatchSpanProcessor(console_exporter()))
        else:
            try:
                from opentelemetry.sdk.trace.export import ConsoleSpanExporter
                provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
            except ImportError:
                pass

        self._tracer = trace.get_tracer(__name__)

    def get_tracer(self):
        """Get the OpenTelemetry tracer."""
        return self._tracer

    def start_span(self, name: str, **attributes):
        """Start a tracing span."""
        if self._tracer is None:
            return SpanStub()

        span = self._tracer.start_span(name)
        for key, value in attributes.items():
            span.set_attribute(key, value)
        return span

    def increment_messages_sent(self, priority: str = "direct"):
        """Increment messages sent counter."""
        if PROMETHEUS_AVAILABLE:
            self.messages_sent_total.labels(priority=priority).inc()

    def increment_messages_received(self, priority: str = "direct"):
        """Increment messages received counter."""
        if PROMETHEUS_AVAILABLE:
            self.messages_received_total.labels(priority=priority).inc()

    def add_bytes_transferred(self, bytes_count: int, direction: str):
        """Add to bytes transferred counter."""
        if PROMETHEUS_AVAILABLE:
            self.bytes_transferred_total.labels(direction=direction).inc(bytes_count)

    def increment_peers_connected(self, connection_type: str = "wifi"):
        """Increment peers connected counter."""
        if PROMETHEUS_AVAILABLE:
            self.peers_connected_total.labels(connection_type=connection_type).inc()

    def observe_message_latency(self, latency: float, stage: str = "send"):
        """Observe message latency."""
        if PROMETHEUS_AVAILABLE:
            self.message_latency_seconds.labels(stage=stage).observe(latency)

    def observe_connection_setup(self, duration: float):
        """Observe connection setup time."""
        if PROMETHEUS_AVAILABLE:
            self.connection_setup_seconds.observe(duration)

    def set_active_connections(self, count: int):
        """Set active connections gauge."""
        if PROMETHEUS_AVAILABLE:
            self.active_connections.set(count)

    def set_queue_depth(self, depth: int, queue_type: str = "send"):
        """Set queue depth gauge."""
        if PROMETHEUS_AVAILABLE:
            self.queue_depth.labels(queue_type=queue_type).set(depth)

    def set_peers_online(self, count: int, connection_type: str = "wifi"):
        """Set peers online gauge."""
        if PROMETHEUS_AVAILABLE:
            self.peers_online.labels(connection_type=connection_type).set(count)

    def generate_metrics(self) -> bytes:
        """Generate Prometheus metrics output."""
        if not PROMETHEUS_AVAILABLE:
            return b"# Metrics unavailable - prometheus_client not installed"
        return generate_latest(REGISTRY)


class SpanStub:
    """Stub for tracing spans when OpenTelemetry is not available."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key, value):
        pass

    def set_status(self, status):
        pass

    def end(self):
        pass


def console_exporter():
    """Create a simple console span exporter for debugging."""
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter
    return ConsoleSpanExporter()


_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def init_observability(service_name: str = "meshbox", otlp_endpoint: Optional[str] = None):
    """Initialize observability (metrics + tracing)."""
    collector = get_metrics_collector()
    collector.init_tracing(service_name, otlp_endpoint)
    return collector
