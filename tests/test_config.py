"""Tests fuer die Config-Schicht (Identitaeten, Scope, Auth-Handler)."""

import pytest

from bolabuster.config import load_identities, load_scope
from bolabuster.errors import ConfigError
from bolabuster.models import Identity, PreparedRequest

VALID_IDENTITIES = {
    "identities": [
        {
            "name": "alice",
            "auth": {"type": "bearer", "token": "eyJ.alice.token"},
            "known_object_ids": ["1001"],
        },
        {
            "name": "bob",
            "auth": {"type": "cookie", "cookies": {"session": "abc"}},
            "known_object_ids": ["1002"],
        },
    ]
}

VALID_SCOPE = {
    "authorization": {"confirmed": True, "engagement_ref": "BB-2026-xyz"},
    "target": {
        "base_url": "https://api.example.com",
        "allow_paths": ["/api/v1/*"],
        "deny_paths": ["/api/v1/admin/*"],
    },
}


def test_load_identities_valid():
    identities = load_identities(VALID_IDENTITIES)
    assert len(identities) == 2
    assert all(isinstance(i, Identity) for i in identities)
    names = {i.name for i in identities}
    assert names == {"alice", "bob"}
    alice = next(i for i in identities if i.name == "alice")
    assert alice.auth.type == "bearer"
    assert alice.known_object_ids == ["1001"]
    bob = next(i for i in identities if i.name == "bob")
    assert bob.auth.type == "cookie"


def test_load_scope_valid_with_defaults():
    scope = load_scope(VALID_SCOPE)
    assert scope.engagement_ref == "BB-2026-xyz"
    assert scope.target.base_url == "https://api.example.com"
    assert scope.target.allow_paths == ["/api/v1/*"]
    assert scope.target.deny_paths == ["/api/v1/admin/*"]
    # Defaults, da limits/enumeration im YAML weggelassen wurden
    assert scope.limits.rate_per_sec == 3.0
    assert scope.limits.max_requests == 5000
    assert scope.limits.timeout_sec == 15.0
    assert scope.enumeration.enabled is False
    assert scope.enumeration.neighbor_range == 5


def test_scope_confirmed_missing_raises():
    cfg = {
        "authorization": {"engagement_ref": "x"},
        "target": {"base_url": "https://api.example.com", "allow_paths": ["/api/v1/*"]},
    }
    with pytest.raises(ConfigError):
        load_scope(cfg)


def test_scope_confirmed_false_raises():
    cfg = {
        "authorization": {"confirmed": False},
        "target": {"base_url": "https://api.example.com", "allow_paths": ["/api/v1/*"]},
    }
    with pytest.raises(ConfigError):
        load_scope(cfg)


def test_identities_less_than_two_raises():
    cfg = {
        "identities": [
            {"name": "alice", "auth": {"type": "bearer", "token": "t"}},
        ]
    }
    with pytest.raises(ConfigError):
        load_identities(cfg)


def test_identities_duplicate_names_raises():
    cfg = {
        "identities": [
            {"name": "alice", "auth": {"type": "bearer", "token": "t1"}},
            {"name": "alice", "auth": {"type": "bearer", "token": "t2"}},
        ]
    }
    with pytest.raises(ConfigError):
        load_identities(cfg)


def test_identities_unknown_auth_type_raises():
    cfg = {
        "identities": [
            {"name": "alice", "auth": {"type": "bearer", "token": "t"}},
            {"name": "bob", "auth": {"type": "oauth2"}},
        ]
    }
    with pytest.raises(ConfigError):
        load_identities(cfg)


def test_scope_missing_allow_paths_raises():
    cfg = {
        "authorization": {"confirmed": True},
        "target": {"base_url": "https://api.example.com", "allow_paths": []},
    }
    with pytest.raises(ConfigError):
        load_scope(cfg)


def test_identities_bearer_without_token_raises():
    cfg = {
        "identities": [
            {"name": "alice", "auth": {"type": "bearer"}},
            {"name": "bob", "auth": {"type": "cookie", "cookies": {"session": "abc"}}},
        ]
    }
    with pytest.raises(ConfigError):
        load_identities(cfg)


def test_bearer_auth_apply_sets_header():
    identities = load_identities(VALID_IDENTITIES)
    alice = next(i for i in identities if i.name == "alice")
    prepared = PreparedRequest(
        method="GET",
        url="https://example.test/api/1",
        headers={},
        body=None,
        identity_name="alice",
        strategy="self",
    )
    result = alice.auth.apply(prepared)
    assert result.headers["Authorization"] == "Bearer eyJ.alice.token"
