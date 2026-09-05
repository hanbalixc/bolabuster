"""Tests fuer das Autorisierungs-Gate `ScopeEnforcer`."""

from bolabuster.config.scope import EnumerationConfig, LimitsConfig, ScopeConfig, TargetConfig
from bolabuster.engine.scope import ScopeEnforcer
from bolabuster.models import CanonicalRequest


def _scope(allow_paths=None, deny_paths=None, base_url="https://api.example.com") -> ScopeConfig:
    return ScopeConfig(
        engagement_ref="BB-2026-xyz",
        target=TargetConfig(
            base_url=base_url,
            allow_paths=allow_paths or ["/api/v1/*"],
            deny_paths=deny_paths or [],
        ),
        limits=LimitsConfig(),
        enumeration=EnumerationConfig(),
    )


def _req(method="GET", path="/api/v1/users/1") -> CanonicalRequest:
    return CanonicalRequest(
        method=method,
        url=f"https://api.example.com{path}",
        headers={},
        body=None,
        body_media_type=None,
        source_ref="test",
    )


def test_on_scope_get_allowed():
    enforcer = ScopeEnforcer(_scope())
    decision = enforcer.check(_req())
    assert decision.allowed is True


def test_off_scope_host_rejected_with_host_in_reason():
    enforcer = ScopeEnforcer(_scope())
    req = _req()
    req.url = "https://evil.example.com/api/v1/users/1"
    decision = enforcer.check(req)
    assert decision.allowed is False
    assert "evil.example.com" in decision.reason


def test_path_outside_allow_paths_rejected():
    enforcer = ScopeEnforcer(_scope(allow_paths=["/api/v1/*"]))
    decision = enforcer.check(_req(path="/other/path"))
    assert decision.allowed is False


def test_deny_paths_take_precedence_over_allow_match():
    enforcer = ScopeEnforcer(_scope(allow_paths=["/api/v1/*"], deny_paths=["/api/v1/admin/*"]))
    decision = enforcer.check(_req(path="/api/v1/admin/users"))
    assert decision.allowed is False


def test_write_method_without_allow_writes_rejected():
    enforcer = ScopeEnforcer(_scope(), allow_writes=False)
    decision = enforcer.check(_req(method="PUT"))
    assert decision.allowed is False

    delete_decision = enforcer.check(_req(method="DELETE"))
    assert delete_decision.allowed is False


def test_write_method_with_allow_writes_and_on_scope_allowed():
    enforcer = ScopeEnforcer(_scope(), allow_writes=True)
    decision = enforcer.check(_req(method="PUT"))
    assert decision.allowed is True


def test_path_traversal_does_not_bypass_deny():
    enforcer = ScopeEnforcer(_scope(allow_paths=["/api/v1/*"], deny_paths=["/api/v1/admin/*"]))
    decision = enforcer.check(_req(path="/api/v1/../admin/secret"))
    assert decision.allowed is False


def test_url_encoded_dot_dot_traversal_does_not_bypass_deny():
    enforcer = ScopeEnforcer(_scope(allow_paths=["/api/v1/*"], deny_paths=["/admin*"]))
    decision = enforcer.check(_req(path="/api/v1/%2e%2e/%2e%2e/admin"))
    assert decision.allowed is False


def test_url_encoded_slash_traversal_does_not_bypass_deny():
    enforcer = ScopeEnforcer(_scope(allow_paths=["/api/v1/*"], deny_paths=["/admin*"]))
    decision = enforcer.check(_req(path="/api/v1/..%2f..%2fadmin"))
    assert decision.allowed is False


def test_scheme_mismatch_rejected():
    enforcer = ScopeEnforcer(_scope(base_url="https://api.example.com"))
    req = _req()
    req.url = "http://api.example.com/api/v1/users/1"
    decision = enforcer.check(req)
    assert decision.allowed is False


def test_port_mismatch_rejected():
    enforcer = ScopeEnforcer(_scope(base_url="https://api.example.com"))
    req = _req()
    req.url = "https://api.example.com:8443/api/v1/users/1"
    decision = enforcer.check(req)
    assert decision.allowed is False
