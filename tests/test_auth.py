# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import pytest
from pydantic import SecretStr

from personal_agent_protocol import (
    AuthorizationCodeGrant,
    AuthorizationError,
    build_direct_sign_in_request,
    validate_direct_sign_in_callback,
)


def fixed_random(length: int) -> bytes:
    return bytes(range(length))


def request():  # type: ignore[no-untyped-def]
    return build_direct_sign_in_request(
        authorization_endpoint="https://auth.example.com/oauth/authorize",
        issuer="https://auth.example.com",
        client_id="https://agent.example/agent.json",
        redirect_uri="https://agent.example/oauth/callback",
        scopes=("poppy:read", "poppy:write"),
        random_bytes=fixed_random,
    )


def callback_url(**overrides: str) -> str:
    sign_in = request()
    values = {
        "code": "one-time-code",
        "state": sign_in.state.get_secret_value(),
        "iss": sign_in.issuer,
        **overrides,
    }
    return urlunsplit(("https", "agent.example", "/oauth/callback", urlencode(values), ""))


def test_builds_direct_sign_in_url_with_s256_pkce() -> None:
    sign_in = request()
    values = parse_qs(urlsplit(sign_in.authorization_url.get_secret_value()).query)

    assert values["response_type"] == ["code"]
    assert values["scope"] == ["poppy:read poppy:write"]
    assert values["code_challenge_method"] == ["S256"]
    assert len(sign_in.code_verifier.get_secret_value()) == 43
    assert sign_in.state.get_secret_value() not in repr(sign_in)


def test_validates_callback_and_redacts_code_exchange() -> None:
    sign_in = request()
    callback = validate_direct_sign_in_callback(sign_in, callback_url())
    grant = AuthorizationCodeGrant(
        code=callback.code,
        redirect_uri=sign_in.redirect_uri,
        code_verifier=sign_in.code_verifier,
        session_id="ses_2Lm0",
        client_id=sign_in.client_id,
        client_assertion=SecretStr("signed-client-assertion"),
    )

    assert grant.as_form()["code"] == "one-time-code"
    assert "one-time-code" not in repr(grant)
    assert "signed-client-assertion" not in grant.model_dump_json()


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"state": "attacker-state"}, "state_mismatch"),
        ({"iss": "https://attacker.example"}, "issuer_mismatch"),
        ({"code": ""}, "invalid_callback"),
        ({"error": "access_denied", "code": ""}, "authorization_denied"),
    ],
)
def test_rejects_invalid_callbacks(override: dict[str, str], code: str) -> None:
    with pytest.raises(AuthorizationError) as caught:
        validate_direct_sign_in_callback(request(), callback_url(**override))

    assert caught.value.code == code


def test_rejects_weak_entropy() -> None:
    with pytest.raises(AuthorizationError, match="weak_entropy"):
        build_direct_sign_in_request(
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            issuer="https://auth.example.com",
            client_id="https://agent.example/agent.json",
            redirect_uri="https://agent.example/oauth/callback",
            scopes=("poppy:read",),
            random_bytes=lambda _: b"short",
        )


def test_rejects_duplicate_callback_security_parameters() -> None:
    sign_in = request()
    callback = callback_url() + "&state=second-state"

    with pytest.raises(AuthorizationError) as caught:
        validate_direct_sign_in_callback(sign_in, callback)

    assert caught.value.code == "invalid_callback"


def test_rejects_callback_at_another_redirect_location() -> None:
    with pytest.raises(AuthorizationError) as caught:
        validate_direct_sign_in_callback(
            request(), callback_url().replace("/oauth/callback", "/other/callback")
        )

    assert caught.value.code == "redirect_mismatch"
