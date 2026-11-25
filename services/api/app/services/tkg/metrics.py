"""Low-cardinality metrics for the standalone TKG integration processes."""

import logging

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, write_to_textfile

logger = logging.getLogger(__name__)
registry = CollectorRegistry()
deliveries = Counter("aisoc_tkg_deliveries_total", "Outbox processing outcomes", ("state",), registry=registry)
delivery_seconds = Histogram("aisoc_tkg_delivery_seconds", "Preview through acknowledgement", registry=registry)
receipt_polls = Counter("aisoc_tkg_receipt_polls_total", "Receipt poll outcomes", ("state",), registry=registry)
receipt_seconds = Histogram("aisoc_tkg_receipt_poll_seconds", "Receipt poll duration", registry=registry)
queue = Gauge("aisoc_tkg_queue_entries", "Outbox and receipt backlog", ("queue",), registry=registry)
oldest = Gauge("aisoc_tkg_queue_oldest_seconds", "Age of the oldest backlog entry", ("queue",), registry=registry)


def export(role):
    try:
        write_to_textfile(f"/tmp/aisoc-tkg-{role}.prom", registry)
    except OSError as exc:
        logger.warning("tkg_metrics_export_failed error_type=%s", type(exc).__name__)
