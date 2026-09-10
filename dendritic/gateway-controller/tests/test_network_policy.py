from backend.network_policy import (
    admitted_addresses,
    gateway_ingress_rule,
    reconcile_ingress_rules,
)


def test_gateway_rule_uses_exact_ipv4_and_ipv6_cidrs():
    rule = gateway_ingress_rule(
        {"8.8.8.8", "2606:4700:4700::1111"}, 9443
    )
    assert rule == {
        "from": [
            {"ipBlock": {"cidr": "2606:4700:4700::1111/128"}},
            {"ipBlock": {"cidr": "8.8.8.8/32"}},
        ],
        "ports": [{"port": 9443, "protocol": "TCP"}],
    }
    assert admitted_addresses([rule], 9443) == {
        "8.8.8.8",
        "2606:4700:4700::1111",
    }


def test_reconcile_preserves_unrelated_ingress_and_replaces_gateway_rule():
    public = {"ports": [{"port": 443, "protocol": "TCP"}]}
    old_gateway = {
        "from": [{"ipBlock": {"cidr": "1.1.1.1/32"}}],
        "ports": [{"port": 9443, "protocol": "TCP"}],
    }
    result = reconcile_ingress_rules(
        [public, old_gateway], {"8.8.8.8"}, 9443
    )
    assert result[0] == public
    assert admitted_addresses(result, 9443) == {"8.8.8.8"}


def test_empty_registry_removes_gateway_rule_without_opening_port():
    public = {"ports": [{"port": 80}, {"port": 443}]}
    old_gateway = {
        "from": [{"ipBlock": {"cidr": "1.1.1.1/32"}}],
        "ports": [{"port": 9443}],
    }
    assert reconcile_ingress_rules([public, old_gateway], set(), 9443) == [
        public
    ]


def test_empty_registry_removes_unsafe_allow_all_gateway_rule():
    public = {"ports": [{"port": 443}]}
    unsafe_gateway = {"ports": [{"port": 9443}]}
    assert reconcile_ingress_rules(
        [public, unsafe_gateway], set(), 9443
    ) == [public]
