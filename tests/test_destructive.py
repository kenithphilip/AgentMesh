"""Tests for destructive operation guard integration in the proxy."""

from __future__ import annotations

from fastapi.testclient import TestClient

from agentmesh.proxy import MeshProxy


class TestDestructiveGuardIntegration:
    def test_enabled_by_default(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        assert proxy.enable_destructive_guard is True
        assert proxy._destructive_guard is not None

    def test_rm_rf_root_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("clean up")
        allowed, reason = proxy.evaluate_tool_call(
            "bash.run",
            args={"command": "rm -rf /"},
        )
        assert not allowed
        assert "rm_rf_root" in reason

    def test_rm_rf_subdirectory_allowed(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("clean build")
        allowed, reason = proxy.evaluate_tool_call(
            "bash.run",
            args={"command": "rm -rf ./dist"},
        )
        # dist/ is a workspace path, not root. Should not be blocked by destructive guard.
        assert "rm_rf" not in reason

    def test_drop_database_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("migrate")
        allowed, reason = proxy.evaluate_tool_call(
            "db.query.write",
            args={"sql": "DROP DATABASE production;"},
        )
        assert not allowed
        assert "drop_database" in reason

    def test_terraform_destroy_auto_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("tear down staging")
        allowed, reason = proxy.evaluate_tool_call(
            "bash.run",
            args={"command": "terraform destroy -auto-approve"},
        )
        assert not allowed
        assert "terraform_destroy_auto" in reason

    def test_force_push_main_blocked(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("push changes")
        allowed, reason = proxy.evaluate_tool_call(
            "bash.run",
            args={"command": "git push --force origin main"},
        )
        assert not allowed
        assert "push_force_protected" in reason

    def test_force_with_lease_allowed(self) -> None:
        """--force-with-lease is the safer variant."""
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("push")
        allowed, reason = proxy.evaluate_tool_call(
            "bash.run",
            args={"command": "git push --force-with-lease origin feature/x"},
        )
        assert "push_force" not in reason

    def test_guard_disabled_allows_destruction(self) -> None:
        proxy = MeshProxy(
            signing_key=b"test-destructive-32bytes!!",
            enable_destructive_guard=False,
        )
        proxy.add_user_prompt("test")
        allowed, reason = proxy.evaluate_tool_call(
            "bash.run",
            args={"command": "rm -rf /"},
        )
        # Guard disabled: destructive pattern_id should not appear in reason
        assert "rm_rf" not in reason

    def test_clean_command_allowed(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("list files")
        allowed, reason = proxy.evaluate_tool_call(
            "bash.run",
            args={"command": "ls -la"},
        )
        assert allowed

    def test_nested_arg_path_reported(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        proxy.add_user_prompt("webhook")
        allowed, reason = proxy.evaluate_tool_call(
            "http.post",
            args={"headers": {"x-run": "rm -rf /"}, "body": "{}"},
        )
        assert not allowed


class TestDestructiveEndpoint:
    def test_check_endpoint_clean(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        client = TestClient(proxy.build_app())
        r = client.post("/v1/destructive/check", json={
            "text": "ls -la",
            "tool_name": "bash.run",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is True
        assert data["matches"] == []

    def test_check_endpoint_rm_rf(self) -> None:
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        client = TestClient(proxy.build_app())
        r = client.post("/v1/destructive/check", json={
            "text": "rm -rf /",
            "tool_name": "bash.run",
        })
        data = r.json()
        assert data["allowed"] is False
        assert "rm_rf_root" in data["primary_reason"]
        assert data["matches"][0]["pattern_id"] == "fs.rm_rf_root"
        assert data["matches"][0]["category"] == "filesystem"

    def test_check_endpoint_reports_arg_path(self) -> None:
        """The HTTP endpoint takes a raw string; the arg_path will be $."""
        proxy = MeshProxy(signing_key=b"test-destructive-32bytes!!")
        client = TestClient(proxy.build_app())
        r = client.post("/v1/destructive/check", json={
            "text": "rm -rf /",
            "tool_name": "bash.run",
        })
        data = r.json()
        assert data["matches"][0]["arg_path"] == "$"
