from prometheus_client import Counter, Gauge, Histogram

healthy_gateways = Gauge(
    "syndichan_gateway_healthy_total", "Verified healthy gateways"
)
managed_dns_records = Gauge(
    "syndichan_gateway_dns_records_total", "Controller-owned DNS records"
)
dns_desired_records = Gauge(
    "syndichan_gateway_dns_desired_records",
    "DNS records required by the current healthy gateway state",
)
dns_existing_records = Gauge(
    "syndichan_gateway_dns_existing_records",
    "Existing provider records in the controller-managed answer set",
)
dns_divergence = Gauge(
    "syndichan_gateway_dns_divergence_records",
    "Symmetric difference between desired and existing managed DNS records",
)
dns_reconcile_failures = Counter(
    "syndichan_gateway_dns_reconcile_failures_total",
    "Failed DNS reconciliation passes",
)
provider_rate_limits = Counter(
    "syndichan_gateway_dns_provider_rate_limits_total",
    "DNS provider rate-limit responses",
)
trusted_gateway_addresses = Gauge(
    "syndichan_gateway_trusted_addresses",
    "Healthy verified gateway addresses admitted to the origin listener",
)
network_policy_divergence = Gauge(
    "syndichan_gateway_network_policy_divergence_addresses",
    "Difference between desired and admitted origin gateway addresses",
)
network_policy_reconcile_failures = Counter(
    "syndichan_gateway_network_policy_reconcile_failures_total",
    "Failed gateway origin NetworkPolicy reconciliation passes",
)
failed_registrations = Counter(
    "syndichan_gateway_registration_failures_total", "Failed registrations"
)
verification_failures = Counter(
    "syndichan_gateway_verification_failures_total", "Verification failures"
)
gateway_latency = Histogram(
    "syndichan_gateway_verification_latency_ms",
    "External gateway verification latency in milliseconds",
    buckets=(10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000),
)
dns_changes = Counter(
    "syndichan_gateway_dns_changes_total",
    "Name.com DNS mutations",
    labelnames=("action",),
)
