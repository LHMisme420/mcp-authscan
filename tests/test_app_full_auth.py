"""app_full tenant auth: no token without a verified credential.

Two defects, both reachable over HTTP with nothing but a tenant name:

  * `/auth/login` mints a JWT for any existing org name - no secret, no
    password, no key. Knowing (or guessing) a tenant name is enough.
  * `/auth/register` does the same *and* returns a token for an org that
    already exists, so it doubles as an unauthenticated impersonation endpoint.

The stored credential was also derivable: `api_key = f'key_{org_name}'`.

Each test imports app_full fresh with its own database and secret, because the
module reads DB_FILE/JWT_SECRET at import time and is shared across the suite.
"""
import os
import subprocess
import sys

import pytest


@pytest.fixture()
def full_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_FILE", str(tmp_path / "auth.db"))
    monkeypatch.setenv("JWT_SECRET", "app-full-auth-tests-only-secret")
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    sys.modules.pop("app_full", None)
    import app_full

    yield app_full
    sys.modules.pop("app_full", None)


def _register(client, org_name="acme"):
    return client.post("/auth/register", json={"org_name": org_name})


def test_login_without_a_credential_is_refused(full_app):
    client = full_app.app.test_client()
    assert _register(client).status_code == 200

    response = client.post("/auth/login", json={"org_name": "acme"})

    assert response.status_code in (400, 401), (
        f"login with only an org name returned {response.status_code}: "
        f"{response.get_json()}"
    )
    assert "access_token" not in (response.get_json() or {})


def test_register_cannot_impersonate_an_existing_org(full_app):
    client = full_app.app.test_client()
    first = _register(client)
    assert first.status_code == 200

    second = _register(client)

    assert second.status_code == 409, (
        f"re-registering an existing org returned {second.status_code} with "
        f"{list((second.get_json() or {}))}"
    )
    assert "access_token" not in (second.get_json() or {})


def test_api_key_is_not_derived_from_the_org_name(full_app):
    client = full_app.app.test_client()
    response = _register(client, "derived-name-check")

    key = (response.get_json() or {}).get("api_key")
    assert key, "register did not return the credential the org must store"
    assert key != "key_derived-name-check", "api_key is still derived from the name"
    assert "derived-name-check" not in key


def test_login_with_the_issued_key_works_and_wrong_key_does_not(full_app):
    client = full_app.app.test_client()
    key = _register(client, "good-key-org").get_json()["api_key"]

    ok = client.post("/auth/login", json={"org_name": "good-key-org", "api_key": key})
    assert ok.status_code == 200 and "access_token" in ok.get_json()

    bad = client.post("/auth/login", json={"org_name": "good-key-org", "api_key": "nope"})
    assert bad.status_code == 401
    assert "access_token" not in (bad.get_json() or {})


def test_legacy_org_without_a_stored_secret_is_refused_not_500(full_app):
    """Rows created before this change have no hash; they must fail closed."""
    conn = full_app.sqlite3.connect(full_app.DB_FILE)
    conn.execute(
        "INSERT INTO organizations (name, api_key) VALUES (?, ?)",
        ("legacy-org", "key_legacy-org"),
    )
    conn.commit()
    conn.close()

    client = full_app.app.test_client()
    response = client.post("/auth/login", json={"org_name": "legacy-org", "api_key": "key_legacy-org"})

    assert response.status_code == 401, f"expected 401, got {response.status_code}"
    assert "access_token" not in (response.get_json() or {})


def test_missing_jwt_secret_fails_closed(tmp_path):
    """Importing the app without a configured secret must raise, like app.py."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("JWT_SECRET", "SESSION_SECRET")}
    env["DB_FILE"] = str(tmp_path / "unused.db")
    result = subprocess.run(
        [sys.executable, "-c", "import app_full"],
        capture_output=True, text=True, env=env, cwd=os.getcwd(),
    )
    assert result.returncode != 0, "app_full started without a JWT secret"
    assert "JWT_SECRET" in (result.stderr + result.stdout)


def test_cors_does_not_allow_arbitrary_origins(full_app):
    client = full_app.app.test_client()
    response = client.get("/api/findings", headers={"Origin": "https://evil.example"})

    assert response.headers.get("Access-Control-Allow-Origin") is None, (
        "wildcard CORS lets any origin read this API with a stolen token"
    )


def test_error_body_does_not_echo_internal_detail(full_app, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("SECRET-INTERNAL-DETAIL")

    monkeypatch.setattr(full_app.sqlite3, "connect", boom)
    client = full_app.app.test_client()
    response = client.post("/auth/login", json={"org_name": "x", "api_key": "y"})

    body = response.get_data(as_text=True)
    assert response.status_code >= 500
    assert "SECRET-INTERNAL-DETAIL" not in body, f"internal detail leaked: {body}"
    assert "correlation" in body or "error" in body
