import pytest
from pydantic import ValidationError

from backend.config import Settings


def write_env(tmp_path, body):
    path = tmp_path / ".env"
    path.write_text(body, encoding="utf-8")
    return path


def test_namecom_ttl_floor():
    with pytest.raises(ValidationError):
        Settings(ttl=299)


def test_credentials_are_not_required_to_import_public_config():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        namecom_username=None,
        namecom_api_token=None,
    )
    with pytest.raises(RuntimeError):
        settings.require_namecom_credentials()


def test_credential_bearing_api_url_is_not_in_example():
    example = open("config.example.yaml", encoding="utf-8").read()
    assert "token:" not in example
    assert "username:" not in example


def test_credentials_are_read_from_the_env_file(tmp_path, monkeypatch):
    env = write_env(
        tmp_path, "NAMECOM_USERNAME=file-user\nNAMECOM_API_TOKEN=file-token\n"
    )
    monkeypatch.setenv("GATEWAY_ENV_FILE", str(env))
    monkeypatch.delenv("NAMECOM_USERNAME", raising=False)
    monkeypatch.delenv("NAMECOM_API_TOKEN", raising=False)
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")
    assert settings.require_namecom_credentials() == ("file-user", "file-token")


def test_environment_overrides_the_env_file(tmp_path, monkeypatch):
    env = write_env(
        tmp_path, "NAMECOM_USERNAME=file-user\nNAMECOM_API_TOKEN=file-token\n"
    )
    monkeypatch.setenv("GATEWAY_ENV_FILE", str(env))
    monkeypatch.setenv("NAMECOM_USERNAME", "injected-user")
    monkeypatch.setenv("NAMECOM_API_TOKEN", "injected-token")
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")
    assert settings.require_namecom_credentials() == (
        "injected-user",
        "injected-token",
    )


def test_env_file_cannot_override_security_critical_public_settings(
    tmp_path, monkeypatch
):
    # The shared .env belongs to the app tier and defines both of these for it.
    env = write_env(
        tmp_path,
        "NAMECOM_USERNAME=file-user\nNAMECOM_API_TOKEN=file-token\n"
        "DOMAIN=attacker.example\nTRUSTED_PROXY_CIDRS=[\"0.0.0.0/0\"]\n",
    )
    monkeypatch.setenv("GATEWAY_ENV_FILE", str(env))
    monkeypatch.delenv("DOMAIN", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_CIDRS", raising=False)
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        domain="syndichan.org",
        trusted_proxy_cidrs=["10.42.0.0/16"],
    )
    assert settings.domain == "syndichan.org"
    assert settings.trusted_proxy_cidrs == ["10.42.0.0/16"]


def test_missing_env_file_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.delenv("NAMECOM_USERNAME", raising=False)
    monkeypatch.delenv("NAMECOM_API_TOKEN", raising=False)
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        namecom_username=None,
        namecom_api_token=None,
    )
    with pytest.raises(RuntimeError):
        settings.require_namecom_credentials()

