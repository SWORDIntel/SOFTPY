"""AWS Signature Version 4 request signer (stdlib only)."""

from __future__ import annotations

import datetime as _dt
from typing import Mapping, Optional
from urllib.parse import quote, urlsplit, parse_qsl
from urllib.request import Request, urlopen

try:
    from ..hashing.sha2 import sha256_hex, hmac_sha256
except ImportError:
    try:
        from hashes import sha256_hex, hmac_sha256
    except ImportError:
        from sha2 import sha256_hex, hmac_sha256


def _canonicalize_uri(path: str) -> str:
    # Preserve '/' separators, percent-encode everything else per AWS rules.
    return quote(path or "/", safe="/~")


def _canonicalize_query(params: Mapping[str, object] | None, raw_query: str) -> str:
    items: list[tuple[str, str]] = []
    if params:
        for k, v in params.items():
            if isinstance(v, (tuple, list)):
                for val in v:
                    items.append((str(k), str(val)))
            else:
                items.append((str(k), str(v)))
    else:
        items.extend((k, v) for k, v in parse_qsl(raw_query, keep_blank_values=True))

    items.sort(key=lambda x: (x[0], x[1]))
    return "&".join(
        f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in items
    )


def _canonicalize_headers(headers: dict[str, str]) -> tuple[str, str]:
    items = []
    for k, v in headers.items():
        lk = k.lower().strip()
        # Collapse contiguous spaces, trim edges
        lv = " ".join(str(v).strip().split())
        items.append((lk, lv))
    items.sort(key=lambda t: t[0])
    canonical = "".join(f"{k}:{v}\n" for k, v in items)
    signed = ";".join(k for k, _ in items)
    return canonical, signed


def _hash(data: bytes) -> str:
    return sha256_hex(data)


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac_sha256(key, msg.encode("utf-8"))


def _kdf(date_stamp: str, secret_key: str, region: str, service: str) -> bytes:
    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = hmac_sha256(k_date, region.encode("utf-8"))
    k_service = hmac_sha256(k_region, service.encode("utf-8"))
    return hmac_sha256(k_service, b"aws4_request")


def sign_aws_request(
    method: str,
    url: str,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    *,
    query_params: Optional[Mapping[str, object]] = None,
    headers: Optional[Mapping[str, object]] = None,
    payload: bytes | None = None,
    session_token: Optional[str] = None,
    request_dt: Optional[_dt.datetime] = None,
) -> dict[str, str]:
    """Return a signed-header dict for a request, without issuing a network call."""

    if payload is None:
        payload = b""

    u = urlsplit(url)
    host = u.hostname or ""
    if u.port:
        host = f"{host}:{u.port}"

    now = request_dt or _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    merged_headers = {
        "Host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": _hash(payload),
    }
    if session_token:
        merged_headers["x-amz-security-token"] = session_token
    if headers:
        for k, v in headers.items():
            merged_headers[k] = str(v)

    canonical_headers, signed_headers = _canonicalize_headers(dict(merged_headers))
    canonical_query = _canonicalize_query(query_params, u.query)
    canonical_uri = _canonicalize_uri(u.path)
    payload_hash = _hash(payload)

    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            _hash(canonical_request.encode("utf-8")),
        ]
    )

    signing_key = _kdf(date_stamp, secret_key, region, service)
    signature = hmac_sha256(signing_key, string_to_sign.encode("utf-8")).hex()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    out = dict((k, v) for k, v in merged_headers.items())
    out["Authorization"] = authorization
    return out


def build_signed_request(
    method: str,
    url: str,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    *,
    query_params: Optional[Mapping[str, object]] = None,
    headers: Optional[Mapping[str, object]] = None,
    payload: bytes | None = None,
    session_token: Optional[str] = None,
) -> tuple[str, dict[str, str]]:
    """Return (url, signed_headers) ready for http.client/urllib requests."""

    query = _canonicalize_query(query_params, urlsplit(url).query)
    full_url = url
    if query_params:
        full_url = f"{url.split('?', 1)[0]}?{query}"

    return full_url, sign_aws_request(
        method=method,
        url=url,
        region=region,
        service=service,
        access_key=access_key,
        secret_key=secret_key,
        query_params=query_params,
        headers=headers,
        payload=payload,
        session_token=session_token,
    )


def send_signed_request(
    method: str,
    url: str,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    *,
    query_params: Optional[Mapping[str, object]] = None,
    headers: Optional[Mapping[str, object]] = None,
    payload: bytes | None = None,
    session_token: Optional[str] = None,
) -> tuple[int, dict[str, str], bytes]:
    """Sign and send AWS request via urllib, return (status, headers, body)."""
    full_url, signed_headers = build_signed_request(
        method=method,
        url=url,
        region=region,
        service=service,
        access_key=access_key,
        secret_key=secret_key,
        query_params=query_params,
        headers=headers,
        payload=payload,
        session_token=session_token,
    )

    req = Request(full_url, data=payload, method=method)
    for k, v in signed_headers.items():
        req.add_header(k, v)

    with urlopen(req) as resp:
        return resp.status, dict(resp.headers), resp.read()
