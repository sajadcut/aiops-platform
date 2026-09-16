from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from agents.identity.safety import redact_identity_value


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _lookup(item: Mapping[str, Any], *keys: str) -> Any:
    raw = _raw(item)
    labels = raw.get("labels") if isinstance(raw.get("labels"), Mapping) else {}
    for source in (raw, labels, item):
        for key in keys:
            value = source.get(key)
            if value not in (None, ""):
                return value
    return None


def _eid(item: Mapping[str, Any], index: int) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _text(item: Mapping[str, Any]) -> str:
    safe = redact_identity_value({
        "name": item.get("name"),
        "message": item.get("message"),
        "value": item.get("value"),
        "raw_data": _raw(item),
    })
    return str(safe).lower()


def _number(value: Any) -> Optional[float]:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            value = value.strip().rstrip("%").replace(",", "")
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "ok", "healthy", "up", "reachable", "valid", "success", "available", "allowed"}:
        return True
    if normalized in {"0", "false", "no", "failed", "down", "unreachable", "invalid", "error", "unavailable", "denied"}:
        return False
    return None


def _parse_time(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _timestamp(item: Mapping[str, Any]) -> Optional[datetime]:
    for value in (
        item.get("observed_at"), item.get("timestamp"), item.get("created_at"),
        _lookup(item, "@timestamp", "timestamp", "time"),
    ):
        parsed = _parse_time(value)
        if parsed:
            return parsed
    return None


def _time_window(items: Sequence[Mapping[str, Any]], context: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    supplied = context.get("time_range")
    if isinstance(supplied, Mapping):
        start = supplied.get("start") or supplied.get("from")
        end = supplied.get("end") or supplied.get("to")
        if start or end:
            return {"start": str(start) if start else None, "end": str(end) if end else None}
    start = context.get("incident_start") or context.get("started_at")
    end = context.get("incident_end") or context.get("ended_at")
    if start or end:
        return {"start": str(start) if start else None, "end": str(end) if end else None}
    stamps = sorted(stamp for stamp in (_timestamp(item) for item in items) if stamp)
    return {"start": stamps[0].isoformat() if stamps else None, "end": stamps[-1].isoformat() if stamps else None}


def _metric_name(item: Mapping[str, Any]) -> str:
    return str(item.get("name") or item.get("metric") or _lookup(item, "metric", "item_key") or "").lower()


def _metric_value(item: Mapping[str, Any]) -> Optional[float]:
    value = item.get("value") if item.get("value") is not None else _lookup(item, "value", "current", "current_value")
    return _number(value)


def _status_code(item: Mapping[str, Any]) -> Optional[int]:
    value = _lookup(item, "status_code", "http_status", "response_status", "status")
    try:
        code = int(value)
        return code if 100 <= code <= 599 else None
    except (TypeError, ValueError):
        text = _text(item)
        if " 401" in f" {text}" or "unauthorized" in text:
            return 401
        if " 403" in f" {text}" or "forbidden" in text:
            return 403
        return None


def _matches(name: str, *tokens: str) -> bool:
    normalized = name.replace("-", "_").replace(" ", "_")
    return any(token.replace("-", "_").replace(" ", "_") in normalized for token in tokens)


def _collect_metrics(items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    aliases = {
        "authentication_failure_rate": ("auth_failure_rate", "authentication_failure", "login_failure_rate", "authn_failure"),
        "authorization_denial_rate": ("authz_denial_rate", "authorization_denial", "forbidden_rate", "rbac_denial"),
        "idp_latency_ms": ("idp_latency", "oidc_latency", "identity_provider_latency"),
        "jwks_latency_ms": ("jwks_latency",),
        "dns_latency_ms": ("dns_latency",),
        "clock_skew_seconds": ("clock_skew", "time_skew", "ntp_offset"),
    }
    rows = {key: [] for key in aliases}
    for index, item in enumerate(items):
        name = _metric_name(item)
        if not name:
            continue
        for feature, names in aliases.items():
            if not _matches(name, *names):
                continue
            rows[feature].append({
                "evidence_id": _eid(item, index),
                "value": _metric_value(item),
                "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
            })
    return rows


def _last(rows: Mapping[str, List[Dict[str, Any]]], key: str) -> Optional[float]:
    values = rows.get(key) or []
    return _number(values[-1].get("value")) if values else None


def _stage(name: str, status: str, evidence_ids: Iterable[str], detail: str) -> Dict[str, Any]:
    return {
        "stage": name,
        "status": status,
        "evidence_ids": list(dict.fromkeys(str(x) for x in evidence_ids if x))[:20],
        "detail": detail,
    }


def _build_observations(items: Sequence[Mapping[str, Any]], metrics: Mapping[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    obs: Dict[str, Any] = {
        "http_401": [], "http_403": [], "discovery": [], "issuer": [], "audience": [], "algorithm": [],
        "jwks": [], "signature": [], "token_time": [], "role_mapping": [], "idp": [], "callback": [],
        "certificate": [], "tls": [], "dns": [], "jwks_rotation": [],
    }
    now = datetime.now(timezone.utc)
    for index, item in enumerate(items):
        eid = _eid(item, index)
        text = _text(item)
        raw = _raw(item)
        code = _status_code(item)
        if code == 401:
            obs["http_401"].append(eid)
        elif code == 403:
            obs["http_403"].append(eid)

        diagnostic = str(_lookup(item, "diagnostic", "kind", "subtype", "event_type") or "").lower()
        reachable = _bool(_lookup(item, "reachable", "healthy", "success", "available"))

        if diagnostic in {"oidc_discovery", "openid_configuration", "discovery"} or ".well-known/openid-configuration" in text:
            if any(token in text for token in ("timeout", "unreachable", "connection refused", "failed")):
                reachable = False
            obs["discovery"].append({"evidence_id": eid, "reachable": reachable})

        expected_issuer = _lookup(item, "expected_issuer", "configured_issuer")
        actual_issuer = _lookup(item, "issuer", "actual_issuer", "token_issuer")
        if expected_issuer is not None or actual_issuer is not None or "issuer mismatch" in text:
            mismatch = "issuer mismatch" in text or (
                expected_issuer not in (None, "") and actual_issuer not in (None, "") and str(expected_issuer) != str(actual_issuer)
            )
            obs["issuer"].append({"evidence_id": eid, "mismatch": mismatch})

        expected_aud = _lookup(item, "expected_audience", "configured_audience")
        actual_aud = _lookup(item, "audience", "actual_audience", "aud")
        if expected_aud is not None or actual_aud is not None or "audience mismatch" in text or "wrong audience" in text:
            mismatch = any(token in text for token in ("audience mismatch", "wrong audience")) or (
                expected_aud not in (None, "") and actual_aud not in (None, "") and str(expected_aud) != str(actual_aud)
            )
            obs["audience"].append({"evidence_id": eid, "mismatch": mismatch})

        expected_alg = _lookup(item, "expected_algorithm", "expected_alg", "configured_alg")
        actual_alg = _lookup(item, "algorithm", "alg", "signature_algorithm")
        if expected_alg is not None or actual_alg is not None or "algorithm mismatch" in text:
            mismatch = "algorithm mismatch" in text or (
                expected_alg not in (None, "") and actual_alg not in (None, "") and str(expected_alg).lower() != str(actual_alg).lower()
            )
            obs["algorithm"].append({"evidence_id": eid, "mismatch": mismatch})

        kid = _lookup(item, "kid", "key_id", "signing_key_id")
        key_present = _bool(_lookup(item, "key_present", "signing_key_present", "kid_found"))
        jwks_reachable = _bool(_lookup(item, "jwks_reachable", "reachable", "available")) if diagnostic in {"jwks", "jwks_fetch", "jwks_validation"} or "jwks" in text else None
        if "jwks" in text or diagnostic in {"jwks", "jwks_fetch", "jwks_validation"} or kid is not None or key_present is not None:
            if any(token in text for token in ("jwks timeout", "jwks unavailable", "failed to fetch jwks", "jwks unreachable")):
                jwks_reachable = False
            missing_key = key_present is False or any(token in text for token in ("kid not found", "missing signing key", "unknown kid", "no matching key"))
            obs["jwks"].append({"evidence_id": eid, "reachable": jwks_reachable, "missing_key": missing_key, "kid_present": bool(kid)})

        signature_valid = _bool(_lookup(item, "signature_valid", "cryptographic_validation", "jwt_signature_valid"))
        if signature_valid is not None or "invalid signature" in text or "signature validation" in text:
            if "invalid signature" in text or "signature verification failed" in text:
                signature_valid = False
            obs["signature"].append({"evidence_id": eid, "valid": signature_valid})

        exp = _parse_time(_lookup(item, "exp", "expires_at", "token_expiry", "expiration"))
        nbf = _parse_time(_lookup(item, "nbf", "not_before", "valid_from"))
        validation_time = _parse_time(_lookup(item, "validation_time", "current_time")) or _timestamp(item) or now
        if exp or nbf or any(token in text for token in ("token expired", "expired token", "token not yet valid", "nbf")):
            expired = bool(exp and validation_time > exp) or "token expired" in text or "expired token" in text
            not_yet_valid = bool(nbf and validation_time < nbf) or "token not yet valid" in text
            obs["token_time"].append({"evidence_id": eid, "expired": expired, "not_yet_valid": not_yet_valid})

        expected_role = _lookup(item, "expected_role", "required_role", "required_scope", "required_group")
        mapping_ok = _bool(_lookup(item, "role_mapping_valid", "authorization_mapping_valid", "scope_satisfied"))
        if expected_role is not None or mapping_ok is not None or any(token in text for token in ("insufficient role", "missing role", "missing scope", "rbac denied", "authorization denied")):
            denied = mapping_ok is False or any(token in text for token in ("insufficient role", "missing role", "missing scope", "rbac denied", "authorization denied"))
            obs["role_mapping"].append({"evidence_id": eid, "denied": denied})

        if diagnostic in {"idp", "identity_provider", "token_endpoint"} or any(token in text for token in ("identity provider", "idp", "token endpoint")):
            healthy = _bool(_lookup(item, "healthy", "reachable", "available", "success"))
            if any(token in text for token in ("outage", "unavailable", "timeout", "connection refused")):
                healthy = False
            obs["idp"].append({"evidence_id": eid, "healthy": healthy})

        if diagnostic in {"callback", "redirect", "oidc_callback"} or any(token in text for token in ("redirect_uri", "callback error", "redirect mismatch")):
            failed = any(token in text for token in ("error", "mismatch", "invalid", "failed"))
            obs["callback"].append({"evidence_id": eid, "failed": failed})

        expires = _parse_time(_lookup(item, "certificate_expiry", "cert_expiry", "not_after"))
        renewed = _parse_time(_lookup(item, "certificate_renewal_timestamp", "renewed_at", "last_renewal"))
        cert_valid = _bool(_lookup(item, "certificate_valid", "cert_valid"))
        if expires or renewed or cert_valid is not None or any(token in text for token in ("certificate expired", "certificate expiry", "x509", "unknown ca", "trust chain")):
            expired = bool(expires and (_timestamp(item) or now) > expires) or "certificate expired" in text
            trust_error = any(token in text for token in ("unknown ca", "untrusted", "trust chain", "unable to get local issuer", "certificate verify failed"))
            obs["certificate"].append({
                "evidence_id": eid, "expired": expired, "trust_error": trust_error,
                "expiry": expires.isoformat() if expires else None,
                "renewed_at": renewed.isoformat() if renewed else None,
            })

        if diagnostic in {"tls", "tls_handshake"} or any(token in text for token in ("tls handshake", "ssl handshake", "handshake failure")):
            failed = any(token in text for token in ("failed", "failure", "error", "timeout"))
            obs["tls"].append({"evidence_id": eid, "failed": failed})

        if diagnostic in {"dns", "dns_lookup"} or any(token in text for token in ("dns", "nxdomain", "servfail")):
            ok = _bool(_lookup(item, "success", "reachable", "resolved"))
            if any(token in text for token in ("nxdomain", "servfail", "timeout", "failed")):
                ok = False
            obs["dns"].append({"evidence_id": eid, "success": ok})

        rotation = _parse_time(_lookup(item, "jwks_rotation_timestamp", "key_rotation_timestamp", "rotated_at"))
        if rotation:
            obs["jwks_rotation"].append({"evidence_id": eid, "rotated_at": rotation.isoformat()})

    obs["authentication_failure_rate"] = _last(metrics, "authentication_failure_rate")
    obs["authorization_denial_rate"] = _last(metrics, "authorization_denial_rate")
    obs["idp_latency_ms"] = _last(metrics, "idp_latency_ms")
    obs["jwks_latency_ms"] = _last(metrics, "jwks_latency_ms")
    obs["dns_latency_ms"] = _last(metrics, "dns_latency_ms")
    obs["clock_skew_seconds"] = _last(metrics, "clock_skew_seconds")
    return obs


_FALSIFICATION = {
    "expired_token": "A freshly issued token within exp validates successfully while the same request still fails.",
    "token_not_yet_valid": "The token validates after nbf or with clocks synchronized while the request still fails identically.",
    "clock_skew": "NTP/clock offset is within tolerance while exp/nbf validation failures persist.",
    "invalid_signature": "The same token metadata validates against the authoritative current JWKS/signing key while access still fails.",
    "missing_signing_key": "The referenced key ID is present in authoritative JWKS and signature validation still fails.",
    "jwks_unavailable": "JWKS is reachable with acceptable latency from the validator while signature/key-resolution failures persist.",
    "wrong_audience": "A token issued for the configured audience is rejected in the same path.",
    "issuer_mismatch": "Issuer metadata and configured issuer match while validation still fails.",
    "signature_algorithm_mismatch": "Expected and observed algorithms match policy while signature validation still fails.",
    "insufficient_role": "The principal has the required role/scope/group mapping while the same authorization decision remains denied.",
    "oidc_discovery_unavailable": "OIDC discovery is reachable and internally consistent while token acquisition/validation remains broken.",
    "identity_provider_outage": "The IdP/token endpoint is healthy with normal latency while authentication failures persist.",
    "tls_certificate_failure": "TLS succeeds with a valid, trusted, non-expired certificate while the identity path still fails.",
    "dns_dependency": "IdP/JWKS DNS resolves consistently from the affected client/validator while identity failures persist.",
    "callback_redirect_issue": "Configured callback/redirect URI is accepted by the IdP while the login flow still fails.",
    "healthy_auth": "Cryptographic validation or IdP reachability becomes unhealthy while the same successful authentication pattern continues.",
}


def _cause_candidates(obs: Mapping[str, Any]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    def add(code: str, ids: Iterable[str], basis: str, confidence: float, handoff: Optional[str] = None, role: str = "identity_origin_candidate") -> None:
        candidates.append({
            "code": code,
            "evidence_ids": list(dict.fromkeys(str(x) for x in ids if x))[:20],
            "basis": basis,
            "confidence": max(0.0, min(1.0, confidence)),
            "handoff": handoff,
            "causal_role": role,
            "root_cause_status": "candidate_requires_falsification",
            "expected_falsification_result": _FALSIFICATION[code],
        })

    for row in obs["token_time"]:
        if row.get("expired"):
            add("expired_token", [row["evidence_id"]], "token expiry evidence is explicit", 0.93, "application")
        if row.get("not_yet_valid"):
            add("token_not_yet_valid", [row["evidence_id"]], "token nbf/not-before validation is failing", 0.9, "application")
    skew = obs.get("clock_skew_seconds")
    if skew is not None and abs(float(skew)) >= 30:
        ids = [row["evidence_id"] for row in obs.get("token_time", [])]
        add("clock_skew", ids, "clock offset is large enough to affect exp/nbf validation", 0.82, "infrastructure")

    for row in obs["signature"]:
        if row.get("valid") is False:
            add("invalid_signature", [row["evidence_id"]], "signature validation failed", 0.93, "security")
    for row in obs["jwks"]:
        if row.get("reachable") is False:
            add("jwks_unavailable", [row["evidence_id"]], "JWKS endpoint is unavailable from the validation path", 0.9, "network")
        if row.get("missing_key"):
            add("missing_signing_key", [row["evidence_id"]], "referenced signing key is absent from current JWKS", 0.91, "security")
    for row in obs["audience"]:
        if row.get("mismatch"):
            add("wrong_audience", [row["evidence_id"]], "token audience does not match configured audience", 0.94, "application")
    for row in obs["issuer"]:
        if row.get("mismatch"):
            add("issuer_mismatch", [row["evidence_id"]], "token/discovery issuer does not match configured issuer", 0.93, "application")
    for row in obs["algorithm"]:
        if row.get("mismatch"):
            add("signature_algorithm_mismatch", [row["evidence_id"]], "observed signing algorithm conflicts with validator policy", 0.9, "security")
    for row in obs["role_mapping"]:
        if row.get("denied"):
            add("insufficient_role", [row["evidence_id"]], "cryptographic identity may be valid but role/scope/group mapping denies access", 0.88, "security", "authorization_policy_candidate")
    for row in obs["discovery"]:
        if row.get("reachable") is False:
            add("oidc_discovery_unavailable", [row["evidence_id"]], "OIDC discovery endpoint is unreachable or failing", 0.88, "network")
    for row in obs["idp"]:
        if row.get("healthy") is False:
            add("identity_provider_outage", [row["evidence_id"]], "IdP/token endpoint evidence shows outage or unavailability", 0.9, "dependency")
    if obs.get("idp_latency_ms") is not None and float(obs["idp_latency_ms"]) >= 1000:
        add("identity_provider_outage", [row["evidence_id"] for row in obs.get("idp", [])], "IdP latency is severely elevated in the incident window", 0.7, "dependency")
    cert_bad = [row for row in obs["certificate"] if row.get("expired") or row.get("trust_error")]
    tls_bad = [row for row in obs["tls"] if row.get("failed")]
    if cert_bad or tls_bad:
        add("tls_certificate_failure", [row["evidence_id"] for row in cert_bad + tls_bad], "certificate expiry/trust-chain or TLS handshake evidence is failing", 0.9, "network")
    dns_bad = [row for row in obs["dns"] if row.get("success") is False]
    if dns_bad:
        add("dns_dependency", [row["evidence_id"] for row in dns_bad], "DNS resolution for an identity dependency is failing", 0.87, "network")
    callback_bad = [row for row in obs["callback"] if row.get("failed")]
    if callback_bad:
        add("callback_redirect_issue", [row["evidence_id"] for row in callback_bad], "callback/redirect evidence shows a configuration or flow failure", 0.83, "application")

    crypto_failure_codes = {
        "expired_token", "token_not_yet_valid", "clock_skew", "invalid_signature", "missing_signing_key",
        "jwks_unavailable", "wrong_audience", "issuer_mismatch", "signature_algorithm_mismatch",
        "oidc_discovery_unavailable", "identity_provider_outage", "tls_certificate_failure", "dns_dependency",
    }
    crypto_failure = any(row["code"] in crypto_failure_codes for row in candidates)
    has_success_signal = bool(
        any(row.get("valid") is True for row in obs["signature"])
        or any(row.get("reachable") is True and not row.get("missing_key") for row in obs["jwks"])
        or any(row.get("mismatch") is False for row in obs["issuer"] + obs["audience"] + obs["algorithm"])
    )
    authz_denied = bool(obs["http_403"] or any(row.get("denied") for row in obs["role_mapping"]))
    if has_success_signal and not crypto_failure and authz_denied:
        add("healthy_auth", obs["http_403"] + [row["evidence_id"] for row in obs["signature"] if row.get("valid") is True], "authentication/cryptographic validation is healthy while authorization is denied", 0.86, "application", "identity_not_primary_candidate")

    return candidates[:20]


def _authentication_chain(obs: Mapping[str, Any]) -> List[Dict[str, Any]]:
    dns_bad = [r for r in obs["dns"] if r.get("success") is False]
    tls_bad = [r for r in obs["tls"] if r.get("failed")] + [r for r in obs["certificate"] if r.get("expired") or r.get("trust_error")]
    discovery_bad = [r for r in obs["discovery"] if r.get("reachable") is False]
    idp_bad = [r for r in obs["idp"] if r.get("healthy") is False]
    jwks_bad = [r for r in obs["jwks"] if r.get("reachable") is False or r.get("missing_key")]
    sig_bad = [r for r in obs["signature"] if r.get("valid") is False]
    claims_bad = [r for r in obs["issuer"] + obs["audience"] + obs["algorithm"] if r.get("mismatch")] + [r for r in obs["token_time"] if r.get("expired") or r.get("not_yet_valid")]
    authz_bad = [r for r in obs["role_mapping"] if r.get("denied")]

    client_ids = obs["http_401"] + obs["http_403"]
    chain = [
        _stage("client", "fail" if obs["http_401"] else "pass" if obs["http_403"] else "unknown", client_ids, "401 indicates authentication failure; 403 indicates authenticated/recognized request denied by authorization policy"),
        _stage("dns_tls", "fail" if dns_bad or tls_bad else "pass" if obs["dns"] or obs["tls"] or obs["certificate"] else "unknown", [r["evidence_id"] for r in dns_bad + tls_bad], "DNS resolution and TLS/certificate validation to IdP/JWKS endpoints"),
        _stage("oidc_discovery", "fail" if discovery_bad else "pass" if obs["discovery"] else "unknown", [r["evidence_id"] for r in obs["discovery"]], "OIDC discovery reachability and metadata availability"),
        _stage("token_issuance", "fail" if idp_bad else "pass" if obs["idp"] else "unknown", [r["evidence_id"] for r in obs["idp"]], "IdP/token endpoint availability and latency"),
        _stage("jwks_signature_validation", "fail" if jwks_bad or sig_bad else "pass" if any(r.get("valid") is True for r in obs["signature"]) or any(r.get("reachable") is True and not r.get("missing_key") for r in obs["jwks"]) else "unknown", [r["evidence_id"] for r in obs["jwks"] + obs["signature"]], "JWKS reachability/key resolution and cryptographic signature validation"),
        _stage("claims", "fail" if claims_bad else "pass" if obs["issuer"] or obs["audience"] or obs["algorithm"] or obs["token_time"] else "unknown", [r["evidence_id"] for r in obs["issuer"] + obs["audience"] + obs["algorithm"] + obs["token_time"]], "issuer, audience, algorithm, exp and nbf checks"),
        _stage("authorization_role_mapping", "fail" if authz_bad or obs["http_403"] else "pass" if obs["role_mapping"] and not authz_bad else "unknown", obs["http_403"] + [r["evidence_id"] for r in obs["role_mapping"]], "scope/role/group/RBAC mapping after identity validation"),
    ]
    return chain


def _rotation_timeline(obs: Mapping[str, Any], context: Mapping[str, Any]) -> Dict[str, Any]:
    incident = _parse_time(context.get("incident_start") or context.get("started_at"))
    rows: List[Dict[str, Any]] = []
    for row in obs.get("jwks_rotation", []):
        rotated = _parse_time(row.get("rotated_at"))
        if not rotated:
            continue
        delta = (rotated - incident).total_seconds() if incident else None
        if delta is None:
            ordering = "incident_start_unknown"
        elif delta < -300:
            ordering = "rotation_precedes_incident"
        elif delta > 300:
            ordering = "rotation_follows_incident"
        else:
            ordering = "near_incident_start"
        rows.append({
            "evidence_id": row["evidence_id"],
            "rotated_at": rotated.isoformat(),
            "incident_start": incident.isoformat() if incident else None,
            "delta_seconds_rotation_minus_incident": delta,
            "ordering": ordering,
            "causal_policy": "rotation timing is correlation evidence and requires key-resolution/signature corroboration",
        })
    return {"events": rows}


def build_identity_reliability_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    ctx = context if isinstance(context, Mapping) else {}
    metrics = _collect_metrics(items)
    obs = _build_observations(items, metrics)
    candidates = _cause_candidates(obs)
    chain = _authentication_chain(obs)
    rotation = _rotation_timeline(obs, ctx)

    crypto_codes = {
        "expired_token", "token_not_yet_valid", "clock_skew", "invalid_signature", "missing_signing_key",
        "jwks_unavailable", "wrong_audience", "issuer_mismatch", "signature_algorithm_mismatch",
        "oidc_discovery_unavailable", "identity_provider_outage", "tls_certificate_failure", "dns_dependency",
    }
    crypto_faults = [row for row in candidates if row["code"] in crypto_codes]
    authz_only = [row for row in candidates if row["code"] == "insufficient_role"]
    healthy_auth = any(row["code"] == "healthy_auth" for row in candidates)
    if crypto_faults:
        attribution = "identity_authentication_or_validation_fault_candidate"
    elif authz_only:
        attribution = "authorization_mapping_or_policy_candidate"
    elif healthy_auth:
        attribution = "authentication_healthy_authorization_denied"
    else:
        attribution = "insufficient_evidence_to_attribute_identity"

    handoffs: List[str] = []
    for row in candidates:
        target = row.get("handoff")
        if target and target != "identity" and target not in handoffs:
            handoffs.append(str(target))
    if attribution == "authentication_healthy_authorization_denied":
        for target in ("security", "application"):
            if target not in handoffs:
                handoffs.append(target)

    gaps: List[Dict[str, Any]] = []
    if not obs["discovery"]:
        gaps.append({"evidence": "OIDC discovery reachability and issuer metadata", "information_gain": 0.9})
    if not obs["jwks"]:
        gaps.append({"evidence": "JWKS reachability, key ID resolution and rotation metadata", "information_gain": 0.97})
    if not obs["signature"]:
        gaps.append({"evidence": "signature validation result and algorithm metadata without token material", "information_gain": 0.96})
    if not obs["issuer"] or not obs["audience"]:
        gaps.append({"evidence": "expected versus observed issuer/audience metadata", "information_gain": 0.94})
    if not obs["certificate"] and not obs["tls"]:
        gaps.append({"evidence": "TLS handshake and certificate expiry/trust-chain metadata", "information_gain": 0.84})
    if not obs["dns"]:
        gaps.append({"evidence": "DNS resolution evidence for IdP and JWKS endpoints", "information_gain": 0.8})
    if not obs["role_mapping"]:
        gaps.append({"evidence": "required and effective scope/role/group mapping", "information_gain": 0.86})
    if not obs["jwks_rotation"]:
        gaps.append({"evidence": "JWKS/key rotation timestamp for incident correlation", "information_gain": 0.72})
    gaps.sort(key=lambda row: float(row["information_gain"]), reverse=True)

    return {
        "policy": "identity alerts and 401/403 responses are symptoms until the authentication chain localizes the failing stage",
        "credential_policy": "full tokens, secrets, private keys, Authorization headers and credentials are forbidden from prompt/audit projections",
        "service": service_name,
        "time_window": _time_window(items, ctx),
        "rates": {
            "authentication_failure_rate": obs.get("authentication_failure_rate"),
            "authorization_denial_rate": obs.get("authorization_denial_rate"),
            "http_401_count": len(obs["http_401"]),
            "http_403_count": len(obs["http_403"]),
        },
        "authentication_chain": chain,
        "oidc_analysis": {
            "discovery": obs["discovery"],
            "issuer": obs["issuer"],
            "audience": obs["audience"],
            "algorithm": obs["algorithm"],
            "idp": obs["idp"],
            "callback": obs["callback"],
            "idp_latency_ms": obs.get("idp_latency_ms"),
        },
        "jwks_signature_analysis": {
            "jwks": obs["jwks"],
            "signature": obs["signature"],
            "jwks_latency_ms": obs.get("jwks_latency_ms"),
            "rotation_timeline": rotation,
        },
        "token_claim_analysis": {
            "token_time": obs["token_time"],
            "clock_skew_seconds": obs.get("clock_skew_seconds"),
            "role_mapping": obs["role_mapping"],
        },
        "tls_dns_analysis": {
            "certificate": obs["certificate"],
            "tls": obs["tls"],
            "dns": obs["dns"],
            "dns_latency_ms": obs.get("dns_latency_ms"),
        },
        "cause_candidates": candidates,
        "causal_attribution": attribution,
        "handoff_candidates": handoffs,
        "next_best_evidence": gaps[:10],
        "analysis_stages": [
            "credential_safe_evidence_projection",
            "401_403_and_rate_classification",
            "client_dns_tls",
            "oidc_discovery_and_idp",
            "jwks_and_signature_validation",
            "claims_time_and_audience",
            "authorization_role_mapping",
            "jwks_rotation_timeline",
            "llm_synthesis_bounded_by_live_evidence",
        ],
    }
