"""Tests for destructive operation guard in the proxy."""

from __future__ import annotations

from fastapi.testclient import TestClient

from agentmesh.proxy import MeshProxy


class TestDestructiveGuardIntegration:
    def test_enabled_by_default(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        assert proxy.enable_destructive_guard is True

    def test_rm_rf_root_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("clean up")
        allowed, reason = proxy.evaluate_tool_call(
            "shell",
            args={"command": "rm -rf /"},
        )
        assert not allowed
        assert "destructive" in reason.lower()
        assert "rm-rf-root" in reason

    def test_drop_database_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("migrate")
        allowed, reason = proxy.evaluate_tool_call(
            "db_query",
            args={"query": "DROP DATABASE production;"},
        )
        assert not allowed
        assert "drop-database" in reason

    def test_terraform_destroy_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("tear down staging")
        allowed, reason = proxy.evaluate_tool_call(
            "shell",
            args={"command": "terraform destroy -auto-approve"},
        )
        assert not allowed
        assert "terraform-destroy" in reason

    def test_force_push_main_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("push changes")
        allowed, reason = proxy.evaluate_tool_call(
            "shell",
            args={"command": "git push --force origin main"},
        )
        assert not allowed
        assert "force-push" in reason or "main" in reason

    def test_warn_level_allowed_by_default(self) -> None:
        """WARN-level patterns (rm -rf subdir, git reset --hard) allowed
        by default; callers can opt in to blocking them."""
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("clean build")
        allowed, reason = proxy.evaluate_tool_call(
            "shell",
            args={"command": "rm -rf ./dist"},
        )
        # Default: warn-level not blocked. Check destructive was not the blocker.
        assert "destructive" not in reason.lower()

    def test_warn_level_blocked_when_opted_in(self) -> None:
        proxy = MeshProxy(
            signing_key=b"test-destructive-32bytes!!",
            destructive_guard_block_severity="warn",
        )
        proxy.add_user_prompt("reset branch")
        allowed, reason = proxy.evaluate_tool_call(
            "shell",
            args={"command": "git reset --hard HEAD~3"},
        )
        assert not allowed
        assert "destructive" in reason.lower()

    def test_guard_disabled_allows_destruction(self) -> None:
        proxy = MeshProxy(
            signing_key=b"test-destructive-32bytes!!",
            enable_destructive_guard=False,
        )
        proxy.add_user_prompt("test")
        allowed, reason = proxy.evaluate_tool_call(
            "shell",
            args={"command": "rm -rf /"},
        )
        # Guard disabled: destructive not the reason for any block
        assert "destructive" not in reason.lower()

    def test_clean_command_allowed(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("list files")
        allowed, reason = proxy.evaluate_tool_call(
            "shell",
            args={"command": "ls -la"},
        )
        assert allowed

    def test_no_args_skips_check(self) -> None:
        """Destructive check only runs when args are present."""
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("status")
        allowed, reason = proxy.evaluate_tool_call("get_status")
        assert "destructive" not in reason.lower()


class TestDestructiveEndpoint:
    def test_check_endpoint_clean(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        client = TestClient(proxy.build_app())
        r = client.post("/v1/destructive/check", json={
            "text": "ls -la",
            "tool_name": "shell",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["destructive"] is False
        assert data["matches"] == []

    def test_check_endpoint_rm_rf(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        client = TestClient(proxy.build_app())
        r = client.post("/v1/destructive/check", json={
            "text": "rm -rf /",
            "tool_name": "shell",
        })
        data = r.json()
        assert data["destructive"] is True
        assert data["should_block"] is True
        assert data["max_severity"] == "block"
        assert any(m["rule_id"] == "rm-rf-root" for m in data["matches"])

    def test_check_endpoint_warn_level(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        client = TestClient(proxy.build_app())
        r = client.post("/v1/destructive/check", json={
            "text": "git reset --hard HEAD~1",
            "tool_name": "shell",
        })
        data = r.json()
        assert data["destructive"] is True
        assert data["should_block"] is False  # WARN, not BLOCK
        assert data["max_severity"] == "warn"
