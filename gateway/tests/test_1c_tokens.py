"""JWT verification matrix (RS256/ES256 only), JWKS refresh behaviour and claim → Principal mapping."""

from __future__ import annotations

import httpx
import jwt
import pytest
import respx

from acl.contracts.common import AuthMethod, PrincipalKind
from acl.identity.testing import (
    AUDIENCE,
    ISSUER,
    FakeClock,
    TestKey,
    claims,
    jwks_document,
    unsigned_token,
)
from acl.identity.tokens import (
    AuthError,
    IdentityProviderUnavailable,
    JwksCache,
    TokenVerifier,
    delegation_chain,
    normalise_groups,
    principal_from_claims,
)

JWKS_URL = "http://kc.test/realms/acl/protocol/openid-connect/certs"


@pytest.fixture(scope="module")
def key() -> TestKey:
    return TestKey("k1")


@pytest.fixture(scope="module")
def other_key() -> TestKey:
    return TestKey("k1")  # same kid, different key material: a forgery


def make_verifier(*keys: TestKey, clock: FakeClock | None = None) -> tuple[TokenVerifier, JwksCache, respx.MockRouter]:
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL, name="jwks").respond(json=jwks_document(*keys))
    clock = clock or FakeClock()
    cache = JwksCache(JWKS_URL, client=httpx.AsyncClient(), clock=clock.monotonic)
    return TokenVerifier(ISSUER, AUDIENCE, cache), cache, router


async def reason_of(verifier: TokenVerifier, token: str) -> str:
    with pytest.raises(AuthError) as exc:
        await verifier.verify(token)
    return exc.value.reason


async def test_valid_rs256_token(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        got = await verifier.verify(key.sign(claims()))
    assert got["preferred_username"] == "anna"


async def test_valid_es256_token() -> None:
    ec_key = TestKey("ec1", alg="ES256")
    verifier, _, router = make_verifier(ec_key)
    with router:
        got = await verifier.verify(ec_key.sign(claims()))
    assert got["sub"] == "user-1"


async def test_expired_beyond_leeway_rejected_but_within_leeway_accepted(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        assert await reason_of(verifier, key.sign(claims(exp_in=-120))) == "expired"
        assert (await verifier.verify(key.sign(claims(exp_in=-10))))["sub"] == "user-1"  # 30 s leeway


async def test_not_yet_valid(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        assert await reason_of(verifier, key.sign(claims(nbf_in=300))) == "not_yet_valid"
        assert (await verifier.verify(key.sign(claims(nbf_in=10))))["sub"] == "user-1"  # within leeway


async def test_wrong_issuer(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        assert await reason_of(verifier, key.sign(claims(issuer="http://evil.test/realms/acl"))) == "wrong_issuer"


async def test_wrong_and_missing_audience(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        assert await reason_of(verifier, key.sign(claims(audience="account"))) == "wrong_audience"
        assert await reason_of(verifier, key.sign(claims(audience=["account", "other"]))) == "wrong_audience"
        assert (await verifier.verify(key.sign(claims(audience=["account", AUDIENCE]))))["sub"] == "user-1"
        no_aud = claims()
        del no_aud["aud"]
        assert await reason_of(verifier, key.sign(no_aud)) in {"wrong_audience", "missing_claim"}


async def test_forged_signature_same_kid(key: TestKey, other_key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        assert await reason_of(verifier, other_key.sign(claims())) == "bad_signature"


async def test_tampered_payload_rejected(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    head, _, sig = key.sign(claims(roles=["acl-user"])).split(".")
    forged_payload = key.sign(claims(roles=["acl-admin"])).split(".")[1]
    with router:
        assert await reason_of(verifier, f"{head}.{forged_payload}.{sig}") == "bad_signature"


async def test_alg_none_rejected(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        assert await reason_of(verifier, unsigned_token(claims())) == "alg_not_allowed"


async def test_hs256_confusion_rejected(key: TestKey) -> None:
    """Classic attack: sign with HS256 using the (public) RSA key bytes as the shared secret."""
    verifier, _, router = make_verifier(key)
    token = jwt.encode(claims(), "x" * 40, algorithm="HS256", headers={"kid": key.kid})
    with router:
        assert await reason_of(verifier, token) == "alg_not_allowed"


async def test_garbage_token(key: TestKey) -> None:
    verifier, _, router = make_verifier(key)
    with router:
        assert await reason_of(verifier, "not-a-jwt") == "malformed_token"


async def test_unknown_kid_triggers_one_refresh_then_is_rate_limited(key: TestKey) -> None:
    clock = FakeClock()
    rotated = TestKey("k2")
    verifier, cache, router = make_verifier(key, clock=clock)
    route = router["jwks"]
    with router:
        await verifier.verify(key.sign(claims()))
        assert cache.fetch_count == 1

        # Key rotation: the IdP now publishes k2. First token with the new kid → exactly one refresh, accepted.
        clock.advance(11)
        route.respond(json=jwks_document(key, rotated))
        assert (await verifier.verify(rotated.sign(claims())))["sub"] == "user-1"
        assert cache.fetch_count == 2

        # A token with a kid nobody publishes: one refresh attempt, then rejected...
        ghost = TestKey("ghost")
        clock.advance(11)
        assert await reason_of(verifier, ghost.sign(claims())) == "unknown_kid"
        assert cache.fetch_count == 3
        # ...and a flood of them within the interval does not hammer the IdP.
        for _ in range(5):
            assert await reason_of(verifier, ghost.sign(claims())) == "unknown_kid"
        assert cache.fetch_count == 3
        # Known keys keep verifying from cache.
        assert (await verifier.verify(rotated.sign(claims())))["sub"] == "user-1"
        assert cache.fetch_count == 3


async def test_encryption_keys_in_jwks_are_ignored(key: TestKey) -> None:
    enc = dict(key.jwk(), kid="enc1", use="enc", alg="RSA-OAEP")
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).respond(json={"keys": [enc, key.jwk()]})
    cache = JwksCache(JWKS_URL, client=httpx.AsyncClient())
    verifier = TokenVerifier(ISSUER, AUDIENCE, cache)
    with router:
        assert (await verifier.verify(key.sign(claims())))["sub"] == "user-1"
        assert await reason_of(verifier, key.sign(claims(), kid="enc1")) == "unknown_kid"


async def test_jwks_unreachable_without_cache_is_503_class_error(key: TestKey) -> None:
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).mock(side_effect=httpx.ConnectError("down"))
    cache = JwksCache(JWKS_URL, client=httpx.AsyncClient())
    verifier = TokenVerifier(ISSUER, AUDIENCE, cache)
    with router, pytest.raises(IdentityProviderUnavailable):
        await verifier.verify(key.sign(claims()))


async def test_jwks_outage_keeps_serving_cached_keys(key: TestKey) -> None:
    clock = FakeClock()
    verifier, _, router = make_verifier(key, clock=clock)
    route = router["jwks"]
    with router:
        await verifier.verify(key.sign(claims()))
        route.mock(side_effect=httpx.ConnectError("down"))
        clock.advance(601)  # TTL elapsed: refresh attempted, fails, cached key still used
        assert (await verifier.verify(key.sign(claims())))["sub"] == "user-1"


# ---------------------------------------------------------------- claims → principal


def test_user_principal_mapping() -> None:
    p = principal_from_claims(
        claims("sub-1", username="jan", groups=["/credit-analysts", "/agents/x", "credit-analysts"], roles=["acl-user"])
    )
    assert p.kind == PrincipalKind.user and p.auth_method == AuthMethod.jwt
    assert p.groups == ["credit-analysts", "agents/x"]  # leading slash stripped, deduplicated
    assert p.roles == ["acl-user"] and p.client_id == "opencode" and p.agent_id is None


def test_agent_principal_from_agent_id_claim() -> None:
    p = principal_from_claims(
        claims(
            "sa-1",
            username="service-account-agent-research-bot",
            groups=["/agents/research-bot"],
            azp="agent-research-bot",
            agent_id="research-bot",
        )
    )
    assert p.kind == PrincipalKind.agent and p.auth_method == AuthMethod.client_credentials
    assert p.agent_id == "research-bot" and p.groups == ["agents/research-bot"]


def test_agent_principal_from_service_account_username() -> None:
    p = principal_from_claims(claims("sa-2", username="service-account-agent-ledger", azp="agent-ledger"))
    assert p.kind == PrincipalKind.agent and p.agent_id == "ledger"


def test_delegation_chain_from_act_claim() -> None:
    c = claims("user-sub", act={"sub": "agent-b", "act": {"sub": "agent-a"}})
    assert delegation_chain(c) == ["user-sub", "agent-a", "agent-b"]  # originating user → ... → current actor
    assert principal_from_claims(c).delegation_chain == ["user-sub", "agent-a", "agent-b"]
    assert delegation_chain(claims()) == []


def test_group_normalisation() -> None:
    assert normalise_groups(["/a/b", "a/b", "", "/", "c"]) == ["a/b", "c"]
    assert normalise_groups("/solo") == ["solo"]
    assert normalise_groups(None) == []
