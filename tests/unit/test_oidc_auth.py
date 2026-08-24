import pytest

from apps.security.oidc import OIDCIdentityAdapter


def test_oidc_claims_map_to_identity():
    identity = OIDCIdentityAdapter("https://issuer", "aiops").validate_claims({
        "iss": "https://issuer",
        "aud": "aiops",
        "sub": "user-1",
        "roles": ["operator"],
        "email": "user@example.com",
    })
    assert identity.subject == "user-1"
    assert identity.roles == ("operator",)


def test_oidc_rejects_wrong_issuer():
    with pytest.raises(ValueError, match="invalid_issuer"):
        OIDCIdentityAdapter("https://issuer", "aiops").validate_claims({
            "iss": "https://wrong",
            "aud": "aiops",
            "sub": "user-1",
        })
