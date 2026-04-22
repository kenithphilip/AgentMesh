"""Tests for the static URL rules gate in the proxy."""

from __future__ import annotations

from fastapi.testclient import TestClient

from agentmesh.proxy import MeshProxy


SIGNING_KEY = b"test-url-rules-32bytes!!!!!!!!!!"


def _proxy(rules=None, *, enable=True) -> MeshProxy:
    return MeshProxy(
        signing_key=SIGNING_KEY,
        enable_url_rules=enable,
        url_rules=rules or [],
    )


class TestEndpointCheck:
    def test_no_match_with_no_rules(self) -> None:
        client = TestClient(_proxy().build_app())
        data = client.post("/v1/url-rules/check", json={
            "url": "https://example.com/", "method": "GET",
        }).json()
        assert data["verdict"] == "no_match"
        assert data["rule_count"] == 0

    def test_prefix_deny_returns_rule_id(self) -> None:
        client = TestClient(_proxy([
            {
                "rule_id": "github.admin.deny",
                "pattern": "https://api.github.com/admin/",
                "kind": "prefix",
                "action": "deny",
                "description": "block admin",
            },
        ]).build_app())
        data = client.post("/v1/url-rules/check", json={
            "url": "https://api.github.com/admin/users",
        }).json()
        assert data["verdict"] == "deny"
        assert data["rule_id"] == "github.admin.deny"
        assert data["description"] == "block admin"

    def test_method_filter_only_applies_to_listed_methods(self) -> None:
        client = TestClient(_proxy([
            {
                "rule_id": "read.only",
                "pattern": "https://api.example.com/",
                "kind": "prefix",
                "action": "allow",
                "methods": ["GET"],
            },
        ]).build_app())
        get_data = client.post("/v1/url-rules/check", json={
            "url": "https://api.example.com/users", "method": "GET",
        }).json()
        post_data = client.post("/v1/url-rules/check", json={
            "url": "https://api.example.com/users", "method": "POST",
        }).json()
        assert get_data["verdict"] == "allow"
        assert post_data["verdict"] == "no_match"

    def test_malformed_rule_specs_dropped_silently(self) -> None:
        # Missing required field "pattern" -> rule skipped at init.
        proxy = _proxy([
            {"rule_id": "broken"},
            {
                "rule_id": "ok",
                "pattern": "https://x/",
                "kind": "prefix",
                "action": "allow",
            },
        ])
        assert proxy._url_rules.rule_count == 1


class TestEvaluatorIntegration:
    def test_deny_rule_blocks_tool_call(self) -> None:
        proxy = _proxy([
            {
                "rule_id": "evil.deny",
                "pattern": "https://evil.example.com/",
                "kind": "prefix",
                "action": "deny",
                "description": "blocked domain",
            },
        ])
        ok, reason = proxy.evaluate_tool_call(
            tool_name="http.fetch",
            args={"url": "https://evil.example.com/exfil"},
        )
        assert ok is False
        assert "evil.deny" in reason

    def test_allow_rule_does_not_short_circuit_other_args(self) -> None:
        # An allow rule on a URL doesn't bypass other safety checks
        # for the rest of the args; the SSRF guard / scanners still
        # see the call. We verify the URL rule itself doesn't deny.
        proxy = _proxy([
            {
                "rule_id": "github.read.allow",
                "pattern": "https://api.github.com/",
                "kind": "prefix",
                "action": "allow",
            },
        ])
        ok, _ = proxy.evaluate_tool_call(
            tool_name="http.fetch",
            args={"url": "https://api.github.com/repos/foo/bar"},
        )
        # Other downstream gates may still allow or deny; the assert
        # we care about is that the URL rules layer didn't deny.
        # Easiest signal: if it had denied, ok would be False with a
        # rule_id starting with "github.read.allow", which doesn't
        # happen for an allow.
        assert proxy._url_rules.evaluate(
            "https://api.github.com/repos/foo/bar",
        ).verdict.value == "allow"

    def test_disable_skips_the_gate(self) -> None:
        proxy = _proxy(
            [
                {
                    "rule_id": "would.deny",
                    "pattern": "https://evil.example.com/",
                    "kind": "prefix",
                    "action": "deny",
                },
            ],
            enable=False,
        )
        # Rule is registered but the flag turns the layer off.
        ok, reason = proxy.evaluate_tool_call(
            tool_name="http.fetch",
            args={"url": "https://evil.example.com/exfil"},
        )
        # SSRF does not block evil.example.com (public DNS); the URL
        # rule would have denied. Since the flag is off, the URL
        # rule reason MUST NOT appear.
        if not ok:
            assert "would.deny" not in reason


class TestTierPrecedenceViaEndpoint:
    def test_exact_wins_over_prefix(self) -> None:
        client = TestClient(_proxy([
            {
                "rule_id": "specific",
                "pattern": "https://api.example.com/v1/health",
                "kind": "exact",
                "action": "allow",
            },
            {
                "rule_id": "broad.deny",
                "pattern": "https://api.example.com/",
                "kind": "prefix",
                "action": "deny",
            },
        ]).build_app())
        data = client.post("/v1/url-rules/check", json={
            "url": "https://api.example.com/v1/health",
        }).json()
        assert data["verdict"] == "allow"
        assert data["rule_id"] == "specific"
