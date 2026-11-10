#!/usr/bin/env python3
"""Validate and apply .ion zone registrations opened as GitHub issues.

The public website is a static page. A signed registration is sent as a
GitHub issue. This script is the trusted part of the pipeline:

* it reads the issue body and extracts one signed TOML document;
* it rebuilds the canonical payload and checks the ed25519 signature;
* it enforces the registration rules (one second-level domain per user
  every 48 hours, subdomains only below a domain the same user owns, no
  reserved names);
* it writes the domain file and the public registration ledger;
* it commits and pushes the change, then comments on and closes the issue.

The script uses only the Python standard library plus ``cryptography``.
Run ``zone_admin.py --help`` for the available commands.

Canonical payload compatibility
-------------------------------
The signature is made over compact JSON with a fixed field order. The same
bytes are produced by ``gitdns-core`` (Rust) and by ``web/zone.js``. Any
change here must be mirrored in those two implementations.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - Python < 3.11
    raise SystemExit("Python 3.11 or newer is required (tomllib is missing)") from exc

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA_VERSION = 1
KEY_PREFIX = "ed25519:"
COOLDOWN = dt.timedelta(hours=48)
MAX_FILE_BYTES = 48 * 1024
MAX_RECORDS = 64
MAX_VALUES = 16
MAX_LABELS = 16
MAX_NAME_CHARS = 253
MAX_TEXT_VALUE = 4096
MAX_TTL = 604_800
MAX_OPEN_ISSUES = 1000

MARKER = "<!-- gitdns-registration:v1 -->"
TITLE_PREFIX = "[register]"

TOP_LEVEL_FIELDS = {
    "schema",
    "name",
    "owner",
    "created",
    "updated",
    "ttl",
    "records",
    "signature",
}
REQUIRED_TOP_LEVEL = {"schema", "name", "created", "updated", "records"}
RECORD_FIELDS = {
    "type",
    "ttl",
    "value",
    "values",
    "priority",
    "weight",
    "port",
    "flags",
    "tag",
}
SIGNATURE_FIELDS = {"key", "value", "signed_at"}
SINGLE_VALUE_TYPES = {"CNAME", "NS", "PTR", "MX", "SRV", "CAA"}
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
TARGET_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
FENCED_TOML_RE = re.compile(r"```toml[ \t]*\r?\n(.*?)```", re.DOTALL | re.IGNORECASE)


class ZoneError(ValueError):
    """A user-facing validation error."""


# ---------------------------------------------------------------------------
# Small helpers


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url and reject malformed input."""
    if not text or not B64URL_RE.fullmatch(text):
        raise ZoneError("value is not valid base64url")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (binascii.Error, ValueError) as exc:
        raise ZoneError(f"value is not valid base64url: {exc}") from exc


def b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def utc_now() -> dt.datetime:
    """Current time in UTC with second precision."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_timestamp(value: str, field: str) -> dt.datetime:
    """Parse an RFC 3339 timestamp and require a time zone."""
    if not isinstance(value, str) or len(value) > 40:
        raise ZoneError(f"{field} must be an RFC 3339 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ZoneError(f"{field} is not a valid RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ZoneError(f"{field} must include a time zone (use Z)")
    return parsed.astimezone(dt.timezone.utc)


def format_timestamp(value: dt.datetime) -> str:
    """Format a timestamp the same way the CLI does."""
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def read_json(path: Path) -> Any:
    """Read one JSON document and report the file name on errors."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise ZoneError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ZoneError(f"{path} is not valid JSON: {exc}") from exc


def write_text_atomic(path: Path, text: str) -> None:
    """Write text with LF endings, replacing the file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def require_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    """Validate an integer range, rejecting booleans and floats."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ZoneError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ZoneError(f"{field} must be between {minimum} and {maximum}")
    return value


def require_str(value: Any, field: str, *, allow_empty: bool = False) -> str:
    """Validate a string field and its length."""
    if not isinstance(value, str):
        raise ZoneError(f"{field} must be a string")
    if not allow_empty and not value.strip():
        raise ZoneError(f"{field} must not be empty")
    if len(value) > MAX_TEXT_VALUE:
        raise ZoneError(f"{field} is too long")
    return value


def ensure_no_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    """Reject unknown keys so a typo cannot change the signed meaning."""
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ZoneError(f"unknown field(s) in {where}: {', '.join(unknown)}")


def validate_label(label: str, field: str) -> None:
    """Validate one DNS label used in a domain file name."""
    if not NAME_RE.fullmatch(label):
        raise ZoneError(
            f"{field} label \"{label}\" must use a-z, 0-9 and inner hyphens "
            "(1-63 characters)"
        )


def validate_target_name(raw: str, field: str) -> str:
    """Validate a host name used by CNAME, MX, NS, PTR or SRV records."""
    value = raw.strip()
    if not value:
        raise ZoneError(f"{field} target is empty")
    if value == "@":
        return value
    value = value.rstrip(".")
    if len(value) > MAX_NAME_CHARS:
        raise ZoneError(f"{field} target is too long")
    labels = value.split(".")
    if len(labels) > MAX_LABELS:
        raise ZoneError(f"{field} target has too many labels")
    for label in labels:
        if not TARGET_RE.fullmatch(label.lower()):
            raise ZoneError(f"{field} target \"{value}\" is not a valid ASCII host name")
    return value


# ---------------------------------------------------------------------------
# Canonical payload (must match gitdns-core and web/zone.js)


def canonical_record(record: dict[str, Any]) -> dict[str, Any]:
    """Build one record object in the field order used by the Rust struct."""
    out: dict[str, Any] = {"type": str(record["type"]).strip().upper()}
    for key in ("ttl", "value", "values", "priority", "weight", "port", "flags", "tag"):
        if key in record and record[key] is not None:
            out[key] = record[key]
    return out


def compact_json(value: Any) -> str:
    """Serialize JSON exactly like serde_json with stable field order."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonical_payload(zone: str, domain: dict[str, Any]) -> bytes:
    """Return the bytes covered by the owner signature."""
    records = [canonical_record(item) for item in domain.get("records", [])]
    records.sort(key=lambda item: compact_json(item).encode("utf-8"))

    payload: dict[str, Any] = {
        "schema": domain["schema"],
        "zone": zone.strip().rstrip(".").lower(),
        "name": str(domain["name"]).strip(),
        "owner": domain.get("owner") or "",
        "created": str(domain["created"]).strip(),
        "updated": str(domain["updated"]).strip(),
    }
    if domain.get("ttl") is not None:
        payload["ttl"] = domain["ttl"]
    payload["records"] = records
    return compact_json(payload).encode("utf-8")


def public_key_from_string(text: str) -> tuple[str, Ed25519PublicKey]:
    """Decode ``ed25519:<base64url>`` and return the canonical text and key."""
    if not isinstance(text, str):
        raise ZoneError("owner must be a string")
    value = text.strip()
    if not value.startswith(KEY_PREFIX):
        raise ZoneError(f"owner must start with \"{KEY_PREFIX}\"")
    raw = b64url_decode(value[len(KEY_PREFIX) :])
    if len(raw) != 32:
        raise ZoneError("owner public key must be 32 bytes")
    canonical = KEY_PREFIX + b64url_encode(raw)
    if value != canonical:
        raise ZoneError("owner public key is not in canonical base64url form")
    try:
        return canonical, Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ZoneError(f"invalid owner public key: {exc}") from exc


# ---------------------------------------------------------------------------
# Domain document validation


def validate_record(record: Any, allowed_types: set[str]) -> dict[str, Any]:
    """Validate one record and return a normalized copy."""
    if not isinstance(record, dict):
        raise ZoneError("each record must be a TOML table")
    ensure_no_unknown(record, RECORD_FIELDS, "record")
    rtype_raw = require_str(record.get("type"), "record.type")
    rtype = rtype_raw.strip().upper()
    if rtype == "SOA":
        raise ZoneError("SOA is defined in zone.toml and cannot be registered")
    if rtype not in allowed_types:
        raise ZoneError(f"record type {rtype} is not allowed by the zone manifest")

    if "ttl" in record:
        require_int(record["ttl"], "record.ttl", 1, MAX_TTL)

    has_value = record.get("value") is not None
    has_values = record.get("values") is not None
    if has_value == has_values:
        raise ZoneError("each record must have exactly one of value or values")

    if has_value:
        values = [require_str(record["value"], "record.value", allow_empty=(rtype == "TXT"))]
        if rtype != "TXT" and not values[0].strip():
            raise ZoneError("record.value must not be empty")
    else:
        raw_values = record["values"]
        if not isinstance(raw_values, list) or not raw_values:
            raise ZoneError("record.values must be a non-empty array")
        if len(raw_values) > MAX_VALUES:
            raise ZoneError(f"record.values cannot have more than {MAX_VALUES} items")
        values = [require_str(item, "record.values[]") for item in raw_values]

    numbers: dict[str, int] = {}
    for key in ("priority", "weight", "port", "flags"):
        if key in record:
            numbers[key] = require_int(record[key], f"record.{key}", 0, 65_535)
    if "tag" in record:
        require_str(record["tag"], "record.tag")

    def single() -> str:
        if len(values) != 1:
            raise ZoneError(f"record {rtype} must have exactly one value")
        return values[0].strip()

    if rtype == "A":
        for value in values:
            try:
                ipaddress.IPv4Address(value)
            except ValueError as exc:
                raise ZoneError(f"invalid IPv4 address \"{value}\"") from exc
    elif rtype == "AAAA":
        for value in values:
            try:
                ipaddress.IPv6Address(value)
            except ValueError as exc:
                raise ZoneError(f"invalid IPv6 address \"{value}\"") from exc
    elif rtype in {"CNAME", "NS", "PTR"}:
        validate_target_name(single(), rtype)
    elif rtype == "MX":
        validate_target_name(single(), "MX")
    elif rtype == "SRV":
        validate_target_name(single(), "SRV")
        if "port" not in numbers:
            raise ZoneError("record SRV requires port")
    elif rtype == "TXT":
        total = sum(len(item.encode("utf-8")) for item in values)
        if total > 8192:
            raise ZoneError("TXT record is too large")
    elif rtype == "CAA":
        value = single()
        if len(value.encode("utf-8")) > 255:
            raise ZoneError("CAA value is longer than 255 bytes")
        tag = str(record.get("tag", "issue")).strip()
        if not tag or len(tag) > 15 or not tag.isalnum() or not tag.isascii():
            raise ZoneError("CAA tag must be 1-15 ASCII letters or digits")

    if rtype not in {"MX", "SRV"}:
        numbers.pop("priority", None)
        numbers.pop("weight", None)
    if rtype != "SRV":
        numbers.pop("port", None)
    if rtype != "CAA":
        numbers.pop("flags", None)
        if "tag" in record:
            raise ZoneError("record.tag is only used by CAA")

    normalized: dict[str, Any] = {"type": rtype}
    if "ttl" in record:
        normalized["ttl"] = record["ttl"]
    if has_value:
        normalized["value"] = record["value"]
    else:
        normalized["values"] = values
    for key in ("priority", "weight", "port", "flags"):
        if key in numbers:
            normalized[key] = numbers[key]
    if rtype == "CAA" and "tag" in record:
        normalized["tag"] = str(record["tag"]).strip()
    return normalized


def validate_domain_document(
    document: Any,
    zone: str,
    allowed_types: set[str],
    *,
    allow_apex: bool = False,
    require_signature: bool = True,
) -> dict[str, Any]:
    """Validate a full domain file. Returns a normalized copy."""
    if not isinstance(document, dict):
        raise ZoneError("the registration must be one TOML document")
    ensure_no_unknown(document, TOP_LEVEL_FIELDS, "document")
    missing = sorted(REQUIRED_TOP_LEVEL - set(document))
    if missing:
        raise ZoneError(f"missing required field(s): {', '.join(missing)}")

    schema = require_int(document["schema"], "schema", 1, 1)
    name_raw = require_str(document["name"], "name")
    name = name_raw.strip()
    if name != name_raw:
        raise ZoneError("name must not have leading or trailing spaces")
    if name == "@":
        if not allow_apex:
            raise ZoneError("the zone apex is managed by the maintainers")
    else:
        if name.startswith(".") or name.endswith(".") or ".." in name:
            raise ZoneError("name must be relative to the zone (for example shop or a.b)")
        labels = name.split(".")
        if len(labels) > MAX_LABELS:
            raise ZoneError(f"name has more than {MAX_LABELS} labels")
        for label in labels:
            validate_label(label, "name")
        if len(name) > MAX_NAME_CHARS:
            raise ZoneError("name is too long")

    created = require_str(document["created"], "created")
    updated = require_str(document["updated"], "updated")
    created_at = parse_timestamp(created, "created")
    updated_at = parse_timestamp(updated, "updated")
    if updated_at < created_at:
        raise ZoneError("updated must not be earlier than created")
    if "ttl" in document:
        require_int(document["ttl"], "ttl", 1, MAX_TTL)

    records_raw = document["records"]
    if not isinstance(records_raw, list):
        raise ZoneError("records must be an array of tables")
    if len(records_raw) > MAX_RECORDS:
        raise ZoneError(f"a domain cannot have more than {MAX_RECORDS} records")
    records = [validate_record(item, allowed_types) for item in records_raw]
    if not records and not allow_apex:
        raise ZoneError("a domain needs at least one record")
    if any(item["type"] == "CNAME" for item in records) and len(records) > 1:
        raise ZoneError("CNAME cannot coexist with other records for the same name")

    owner_raw = document.get("owner")
    owner: str | None = None
    if owner_raw is not None:
        owner, _ = public_key_from_string(owner_raw)
    if require_signature and not allow_apex and owner is None:
        raise ZoneError("owner is required for non-apex names")

    signature_raw = document.get("signature")
    signature: dict[str, Any] | None = None
    if signature_raw is not None:
        if not isinstance(signature_raw, dict):
            raise ZoneError("signature must be a TOML table")
        ensure_no_unknown(signature_raw, SIGNATURE_FIELDS, "signature")
        key, key_object = public_key_from_string(signature_raw.get("key"))
        if owner != key:
            raise ZoneError("signature key does not match the domain owner")
        if not isinstance(signature_raw.get("value"), str):
            raise ZoneError("signature.value must be a string")
        raw_signature = b64url_decode(signature_raw["value"])
        if len(raw_signature) != 64:
            raise ZoneError("signature.value must be 64 bytes")
        if "signed_at" in signature_raw:
            parse_timestamp(signature_raw["signed_at"], "signature.signed_at")
        signature = {
            "key": key,
            "value": b64url_encode(raw_signature),
        }
        if "signed_at" in signature_raw:
            signature["signed_at"] = signature_raw["signed_at"]

    normalized: dict[str, Any] = {
        "schema": schema,
        "name": name,
        "created": created,
        "updated": updated,
        "records": records,
    }
    if owner is not None:
        normalized["owner"] = owner
    if "ttl" in document:
        normalized["ttl"] = document["ttl"]
    if signature is not None:
        normalized["signature"] = signature

    if signature is not None and owner is not None:
        payload = canonical_payload(zone, normalized)
        raw_signature = b64url_decode(signature["value"])
        _, key_object = public_key_from_string(owner)
        try:
            key_object.verify(raw_signature, payload)
        except InvalidSignature as exc:
            raise ZoneError("signature verification failed") from exc
    elif require_signature and not allow_apex:
        raise ZoneError("owner signature is missing")

    return normalized


def enforce_size(document: dict[str, Any]) -> None:
    """Reject oversized documents before parsing/writing."""
    encoded = json.dumps(document, ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_FILE_BYTES:
        raise ZoneError("the domain document is too large")


# ---------------------------------------------------------------------------
# TOML output


def toml_string(value: str) -> str:
    """Quote a string as a TOML basic string."""
    return json.dumps(value, ensure_ascii=False)


def dump_domain_toml(domain: dict[str, Any]) -> str:
    """Serialize a validated domain document in a stable order."""
    lines = [
        f"schema = {domain['schema']}",
        f"name = {toml_string(domain['name'])}",
    ]
    if "owner" in domain:
        lines.append(f"owner = {toml_string(domain['owner'])}")
    lines.extend(
        [
            f"created = {toml_string(domain['created'])}",
            f"updated = {toml_string(domain['updated'])}",
        ]
    )
    if "ttl" in domain:
        lines.append(f"ttl = {domain['ttl']}")
    for record in domain["records"]:
        lines.append("")
        lines.append("[[records]]")
        lines.append(f"type = {toml_string(record['type'])}")
        for key in ("ttl", "value", "values", "priority", "weight", "port", "flags", "tag"):
            if key not in record:
                continue
            if key == "values":
                lines.append(
                    "values = [" + ", ".join(toml_string(item) for item in record[key]) + "]"
                )
            elif isinstance(record[key], str):
                lines.append(f"{key} = {toml_string(record[key])}")
            else:
                lines.append(f"{key} = {record[key]}")
    if "signature" in domain:
        signature = domain["signature"]
        lines.extend(
            [
                "",
                "[signature]",
                f"key = {toml_string(signature['key'])}",
                f"value = {toml_string(signature['value'])}",
            ]
        )
        if "signed_at" in signature:
            lines.append(f"signed_at = {toml_string(signature['signed_at'])}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Issue body parsing


@dataclass(frozen=True)
class Issue:
    """The subset of a GitHub issue used by this script."""

    number: int
    user: str
    title: str
    body: str


def parse_issue_body(body: str) -> dict[str, Any]:
    """Extract the single signed TOML document from an issue body."""
    if MARKER not in body:
        raise ZoneError("this issue does not contain a .ion registration")
    blocks = FENCED_TOML_RE.findall(body)
    if len(blocks) != 1:
        raise ZoneError("the issue must contain exactly one ```toml block")
    payload = blocks[0].strip()
    if len(payload.encode("utf-8")) > MAX_FILE_BYTES:
        raise ZoneError("the TOML block is too large")
    try:
        document = tomllib.loads(payload)
    except tomllib.TOMLDecodeError as exc:
        raise ZoneError(f"TOML syntax error: {exc}") from exc
    return document


# ---------------------------------------------------------------------------
# Zone, ledger and reservations


def load_zone(root: Path) -> tuple[str, set[str]]:
    """Read zone.toml and return the zone name and allowed record types."""
    manifest = read_json_or_toml(root / "zone.toml")
    zone = manifest.get("zone")
    if not isinstance(zone, str) or not zone.strip():
        raise ZoneError("zone.toml has no zone name")
    allowed = manifest.get("allowed_types")
    if not isinstance(allowed, list) or not allowed:
        raise ZoneError("zone.toml has no allowed_types")
    return zone.strip().rstrip(".").lower(), {str(item).upper() for item in allowed}


def read_json_or_toml(path: Path) -> dict[str, Any]:
    """Read a TOML manifest."""
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ZoneError(f"missing file: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ZoneError(f"{path} is not valid TOML: {exc}") from exc


def load_ledger(root: Path, zone: str) -> dict[str, Any]:
    """Load and check registry/registrations.json."""
    path = root / "registry" / "registrations.json"
    ledger = read_json(path)
    if not isinstance(ledger, dict):
        raise ZoneError("the registration ledger must be a JSON object")
    if ledger.get("version") != 1:
        raise ZoneError("unsupported registration ledger version")
    if str(ledger.get("zone", "")).lower() != zone:
        raise ZoneError("registration ledger belongs to another zone")
    entries = ledger.get("registrations")
    if not isinstance(entries, list):
        raise ZoneError("the registration ledger has no registrations array")

    seen: set[str] = set()
    seen_issues: set[int] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ZoneError("every ledger entry must be an object")
        domain = entry.get("domain")
        if not isinstance(domain, str) or not domain:
            raise ZoneError("a ledger entry has an invalid domain")
        for label in domain.split("."):
            if not NAME_RE.fullmatch(label):
                raise ZoneError("a ledger entry has an invalid domain")
        if domain in seen:
            raise ZoneError(f"duplicate ledger entry for {domain}")
        seen.add(domain)
        issue = entry.get("issue")
        if isinstance(issue, int):
            if issue in seen_issues:
                raise ZoneError(f"duplicate ledger entry for issue #{issue}")
            seen_issues.add(issue)
    return ledger


def load_reserved(root: Path) -> set[str]:
    """Read reserved second-level names."""
    path = root / "registry" / "reserved.json"
    data = read_json(path)
    names = data.get("names") if isinstance(data, dict) else None
    if not isinstance(names, list):
        raise ZoneError("registry/reserved.json must contain a names array")
    return {str(item).strip().lower() for item in names if str(item).strip()}


def save_ledger(root: Path, ledger: dict[str, Any]) -> None:
    """Write the ledger with stable formatting."""
    path = root / "registry" / "registrations.json"
    text = json.dumps(ledger, ensure_ascii=False, indent=2) + "\n"
    write_text_atomic(path, text)


def domain_file_path(root: Path, name: str) -> Path:
    """Map a relative name to domains/<label>/.../_records.toml."""
    parts = name.split(".")
    for label in parts:
        validate_label(label, "name")
    return root.joinpath("domains", *parts, "_records.toml")


def load_existing_domain(
    path: Path, zone: str, allowed: set[str], *, is_apex: bool = False
) -> dict[str, Any]:
    """Read an existing domain file, including the apex."""
    if not path.exists():
        raise ZoneError(f"domain file is missing: {path}")
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ZoneError(f"{path} is not valid TOML: {exc}") from exc
    return validate_domain_document(
        raw,
        zone,
        allowed,
        allow_apex=is_apex,
        require_signature=not is_apex,
    )


def entry_for_domain(ledger: dict[str, Any], name: str) -> dict[str, Any] | None:
    """Find the ledger entry for one relative name."""
    for entry in ledger["registrations"]:
        if str(entry.get("domain", "")).lower() == name.lower():
            return entry
    return None


def entry_for_issue(ledger: dict[str, Any], number: int) -> dict[str, Any] | None:
    """Find the ledger entry created by one issue number."""
    for entry in ledger["registrations"]:
        if entry.get("issue") == number:
            return entry
    return None


def domain_kind(name: str) -> str:
    """Return second_level or subdomain for a relative name."""
    return "second_level" if "." not in name else "subdomain"


def latest_second_level(
    ledger: dict[str, Any], user: str, *, exclude_issue: int | None = None
) -> dt.datetime | None:
    """Latest second-level registration time for one GitHub user."""
    times: list[dt.datetime] = []
    for entry in ledger["registrations"]:
        if str(entry.get("kind")) != "second_level":
            continue
        if str(entry.get("user", "")).lower() != user.lower():
            continue
        if exclude_issue is not None and entry.get("issue") == exclude_issue:
            continue
        try:
            times.append(parse_timestamp(entry.get("registered_at", ""), "registered_at"))
        except ZoneError:
            continue
    return max(times) if times else None


def cooldown_remaining(
    ledger: dict[str, Any], user: str, now: dt.datetime, *, exclude_issue: int | None = None
) -> dt.timedelta:
    """How long this user must still wait before another second-level name."""
    latest = latest_second_level(ledger, user, exclude_issue=exclude_issue)
    if latest is None:
        return dt.timedelta(0)
    remaining = latest + COOLDOWN - now
    return remaining if remaining > dt.timedelta(0) else dt.timedelta(0)


def format_remaining(delta: dt.timedelta) -> str:
    """Humane duration for comments."""
    total_minutes = int(delta.total_seconds() // 60)
    hours, minutes = divmod(total_minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def check_owner_user_link(ledger: dict[str, Any], owner: str, user: str) -> None:
    """A key used by one GitHub account cannot be claimed by another."""
    for entry in ledger["registrations"]:
        if entry.get("owner") == owner and str(entry.get("user", "")).lower() != user.lower():
            raise ZoneError(
                "this owner key is already linked to another GitHub account"
            )


# ---------------------------------------------------------------------------
# Applying a registration


@dataclass
class ApplyResult:
    """Outcome of one registration."""

    number: int
    domain: str
    action: str
    path: Path
    comment: str


def process_issue(
    root: Path,
    issue: Issue,
    *,
    now: dt.datetime | None = None,
    write: bool = True,
) -> ApplyResult:
    """Validate an issue and optionally write the file and ledger."""
    now = (now or utc_now()).astimezone(dt.timezone.utc).replace(microsecond=0)
    zone, allowed = load_zone(root)
    document = parse_issue_body(issue.body)
    enforce_size(document)
    domain = validate_domain_document(document, zone, allowed, allow_apex=False)
    name = domain["name"]
    kind = domain_kind(name)
    second_level = name.split(".")[-1]

    ledger = load_ledger(root, zone)
    reserved = load_reserved(root)
    if second_level in reserved:
        raise ZoneError(f"the name \"{second_level}.{zone}\" is reserved")

    same_issue = entry_for_issue(ledger, issue.number)
    if same_issue is not None and str(same_issue.get("domain", "")).lower() != name.lower():
        raise ZoneError(
            "this issue already registered another name; open a new issue for a new name"
        )
    existing_entry = entry_for_domain(ledger, name)
    if (
        existing_entry is not None
        and same_issue is not None
        and existing_entry is not same_issue
    ):
        raise ZoneError("inconsistent ledger: this issue and name point to different entries")

    path = domain_file_path(root, name)
    existing_file: dict[str, Any] | None = None
    if path.exists():
        existing_file = load_existing_domain(path, zone, allowed)
        if existing_file.get("owner") != domain["owner"]:
            raise ZoneError("this domain is owned by a different key")
        if existing_file["created"] != domain["created"]:
            raise ZoneError("created must match the existing domain file")
        if existing_entry is not None and existing_entry.get("created") != existing_file["created"]:
            raise ZoneError("inconsistent ledger: created does not match the domain file")
    if existing_file is not None and existing_entry is None:
        raise ZoneError(
            "a domain file exists but is not in the ledger; ask the maintainers to check it"
        )

    owner = str(domain["owner"])
    check_owner_user_link(ledger, owner, issue.user)

    if kind == "second_level":
        if existing_entry is not None:
            if str(existing_entry.get("user", "")).lower() != issue.user.lower():
                raise ZoneError("this domain is registered by another GitHub account")
            if existing_entry.get("owner") != owner:
                raise ZoneError("this domain is registered with a different owner key")
        else:
            remaining = cooldown_remaining(ledger, issue.user, now)
            if remaining > dt.timedelta(0):
                next_time = (now + remaining).replace(microsecond=0)
                raise ZoneError(
                    "one second-level domain per 48 hours: "
                    f"try again in {format_remaining(remaining)} "
                    f"(after {format_timestamp(next_time)})"
                )
    else:
        parent = entry_for_domain(ledger, second_level)
        if parent is None:
            raise ZoneError(
                f"register {second_level}.{zone} first; subdomains need an owned parent"
            )
        if str(parent.get("kind")) != "second_level":
            raise ZoneError("the parent registration is not a second-level domain")
        if str(parent.get("user", "")).lower() != issue.user.lower():
            raise ZoneError("only the owner of the parent domain can add subdomains")
        if parent.get("owner") != owner:
            raise ZoneError("subdomain owner key must match the parent domain owner key")
        parent_path = domain_file_path(root, second_level)
        if not parent_path.exists():
            raise ZoneError("the parent domain file is missing; ask the maintainers")
        parent_file = load_existing_domain(parent_path, zone, allowed)
        if parent_file.get("owner") != owner:
            raise ZoneError("the parent domain file has a different owner key")

    action = "update" if existing_file is not None else "register"
    file_text = dump_domain_toml(domain)
    if write:
        write_text_atomic(path, file_text)

    record = {
        "domain": name,
        "fqdn": f"{name}.{zone}",
        "kind": kind,
        "user": issue.user,
        "owner": owner,
        "created": domain["created"],
        "registered_at": (
            existing_entry.get("registered_at")
            if existing_entry is not None
            else format_timestamp(now)
        ),
        "updated_at": format_timestamp(now),
        "issue": issue.number,
        "records": domain["records"],
    }
    if write:
        if existing_entry is None:
            ledger["registrations"].append(record)
        else:
            existing_entry.clear()
            existing_entry.update(record)
        ledger["registrations"].sort(key=lambda item: str(item.get("domain", "")))
        save_ledger(root, ledger)

    fqdn = f"{name}.{zone}"
    if action == "register":
        comment = (
            f"Registered **{fqdn}** to @{issue.user}.\n\n"
            f"- Domain file: `domains/{name.replace('.', '/')}/_records.toml`\n"
            f"- Owner key: `{owner}`\n"
            f"- Records: {len(domain['records'])}"
        )
        if kind == "second_level":
            comment += (
                "\n\nThe 48-hour limit for the next second-level domain starts now. "
                "Subdomains of this domain are unlimited."
            )
    else:
        comment = (
            f"Updated **{fqdn}** for @{issue.user}.\n\n"
            f"- Domain file: `domains/{name.replace('.', '/')}/_records.toml`\n"
            f"- Records: {len(domain['records'])}"
        )
    return ApplyResult(
        number=issue.number,
        domain=fqdn,
        action=action,
        path=path.relative_to(root),
        comment=comment,
    )


# ---------------------------------------------------------------------------
# git and GitHub helpers


def run(
    command: list[str],
    *,
    cwd: Path,
    check: bool = True,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command and capture text output."""
    return subprocess.run(
        command,
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env,
    )


def git_commit_and_push(root: Path, message: str, *, branch: str) -> None:
    """Commit the changed zone files and push with a rebase retry."""
    run(["git", "add", "zone.toml", "domains", "registry"], cwd=root)
    status = run(["git", "status", "--porcelain"], cwd=root)
    if not status.stdout.strip():
        print("no file changes to commit")
        return

    identity = [
        "-c",
        "user.name=gitdns-registry-bot",
        "-c",
        "user.email=gitdns-registry-bot@users.noreply.github.com",
    ]
    run(["git", *identity, "commit", "-m", message], cwd=root)

    last_error: Exception | None = None
    for attempt in range(3):
        pushed = run(["git", "push", "origin", f"HEAD:{branch}"], cwd=root, check=False)
        if pushed.returncode == 0:
            print(f"pushed to {branch}")
            return
        last_error = ZoneError(pushed.stderr.strip() or "git push failed")
        if attempt == 2:
            break
        run(["git", "pull", "--rebase", "--autostash", "origin", branch], cwd=root, check=False)
        time.sleep(2)
    raise ZoneError(f"could not push the change: {last_error}")


def gh_last_comment(root: Path, number: int) -> str:
    """Return the last comment body, or an empty string when unknown."""
    result = run(
        [
            "gh",
            "issue",
            "view",
            str(number),
            "--json",
            "comments",
            "--jq",
            '.comments[-1].body // ""',
        ],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def gh_issue_comment(root: Path, number: int, body: str) -> None:
    """Post a comment through the GitHub CLI, skipping an identical repeat."""
    if gh_last_comment(root, number) == body.strip():
        print(f"#{number}: identical comment already posted")
        return
    result = run(["gh", "issue", "comment", str(number), "--body", body], cwd=root, check=False)
    if result.returncode != 0:
        print(f"warning: could not comment on #{number}: {result.stderr.strip()}")


def gh_issue_close(root: Path, number: int) -> None:
    """Close an issue through the GitHub CLI."""
    result = run(["gh", "issue", "close", str(number)], cwd=root, check=False)
    if result.returncode != 0:
        print(f"warning: could not close #{number}: {result.stderr.strip()}")


def gh_open_registration_issues(root: Path) -> list[Issue]:
    """List open issues that look like registrations."""
    result = run(
        [
            "gh",
            "issue",
            "list",
            "--state",
            "open",
            "--limit",
            str(MAX_OPEN_ISSUES),
            "--json",
            "number,title,body,author",
        ],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        raise ZoneError(f"gh issue list failed: {result.stderr.strip()}")
    try:
        raw = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ZoneError(f"gh returned invalid JSON: {exc}") from exc
    issues: list[Issue] = []
    for item in raw:
        body = str(item.get("body") or "")
        title = str(item.get("title") or "")
        if MARKER not in body or not title.startswith(TITLE_PREFIX):
            continue
        author = item.get("author") or {}
        login = author.get("login") if isinstance(author, dict) else None
        if not login:
            continue
        issues.append(
            Issue(
                number=int(item["number"]),
                user=str(login),
                title=title,
                body=body,
            )
        )
    issues.sort(key=lambda item: item.number)
    return issues


def bump_soa_serial(root: Path) -> None:
    """Increment the SOA serial in zone.toml after a committed change."""
    path = root / "zone.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    lines = text.splitlines()
    in_soa = False
    changed = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_soa = stripped == "[soa]"
            continue
        if not in_soa:
            continue
        match = re.match(r"^(\s*serial\s*=\s*)(\d+)(.*)$", line)
        if match:
            current = int(match.group(2))
            if current >= 4_294_967_295:
                current = 0
            lines[index] = f"{match.group(1)}{current + 1}{match.group(3)}"
            changed = True
            break
    if changed:
        write_text_atomic(path, "\n".join(lines) + "\n")


def apply_and_publish(
    root: Path, issue: Issue, *, branch: str, write: bool, publish: bool
) -> ApplyResult:
    """Process one issue, then commit, comment and close."""
    result = process_issue(root, issue, write=write)
    print(f"#{issue.number}: {result.action} {result.domain}")
    if publish:
        publish_results(root, [result], branch=branch)
    return result


def publish_results(root: Path, results: list[ApplyResult], *, branch: str) -> None:
    """Publish a batch with one commit, then comment on and close each issue."""
    if not results:
        print("no registrations to publish")
        return
    bump_soa_serial(root)
    if len(results) == 1:
        result = results[0]
        message = f"{result.action.capitalize()} {result.domain} (#{result.number})"
    else:
        names = [result.domain for result in results]
        summary = ", ".join(names[:3])
        if len(names) > 3:
            summary += f" and {len(names) - 3} more"
        message = f"Apply {len(results)} registrations: {summary}"
    git_commit_and_push(root, message, branch=branch)
    for result in results:
        gh_issue_comment(root, result.number, result.comment)
        gh_issue_close(root, result.number)


# ---------------------------------------------------------------------------
# verify-zone


def relative_name_from_path(root: Path, path: Path) -> str:
    """Convert domains/a/b/_records.toml to a.b, and the apex to @."""
    relative = path.relative_to(root / "domains")
    labels = [part for part in relative.parts if part.lower() != "_records.toml"]
    if not labels:
        return "@"
    out: list[str] = []
    for label in labels:
        if label.lower() == "_wildcard":
            out.append("*")
        else:
            validate_label(label.lower(), "directory")
            out.append(label.lower())
    return ".".join(out)


def name_matches(field: str, relative: str, zone: str, is_apex: bool) -> bool:
    """Mirror the Rust name/path consistency rule."""
    value = field.strip().rstrip(".")
    if value.lower() == relative.lower():
        return True
    if is_apex:
        return value in {"@", ""} or value.lower() == zone.lower()
    return value.lower() == f"{relative.lower()}.{zone.lower()}"


def verify_zone(root: Path) -> dict[str, int]:
    """Verify every domain file and check ledger consistency."""
    zone, allowed = load_zone(root)
    ledger = load_ledger(root, zone)
    domains_dir = root / "domains"
    if not domains_dir.is_dir():
        raise ZoneError("the domains directory is missing")

    files = sorted(domains_dir.rglob("_records.toml"))
    checked = 0
    seen: set[str] = set()
    for path in files:
        relative = relative_name_from_path(root, path)
        is_apex = relative == "@"
        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ZoneError(f"{path}: TOML syntax error: {exc}") from exc
        document = validate_domain_document(
            raw,
            zone,
            allowed,
            allow_apex=is_apex,
            require_signature=not is_apex,
        )
        if not name_matches(document["name"], relative, zone, is_apex):
            raise ZoneError(f"{path}: name does not match the file path")
        if not is_apex:
            entry = entry_for_domain(ledger, relative)
            if entry is None:
                raise ZoneError(f"{path}: domain is not in the registration ledger")
            if entry.get("owner") != document.get("owner"):
                raise ZoneError(f"{path}: owner does not match the ledger")
            if entry.get("created") != document["created"]:
                raise ZoneError(f"{path}: created does not match the ledger")
            if entry.get("records") != document["records"]:
                raise ZoneError(f"{path}: records do not match the ledger")
            if entry.get("fqdn") not in (None, f"{relative}.{zone}"):
                raise ZoneError(f"{path}: fqdn does not match the ledger")
        seen.add(relative)
        checked += 1

    for entry in ledger["registrations"]:
        name = str(entry.get("domain", ""))
        if name not in seen:
            raise ZoneError(f"ledger entry {name} has no domain file")
        if entry.get("kind") != domain_kind(name):
            raise ZoneError(f"ledger entry {name} has an invalid kind")
        if not isinstance(entry.get("records"), list):
            raise ZoneError(f"ledger entry {name} has no records array")
    return {"domains": checked, "registrations": len(ledger["registrations"])}


# ---------------------------------------------------------------------------
# Command line


def issue_from_event(path: Path) -> Issue:
    """Read GITHUB_EVENT_PATH and return the issue that triggered the run."""
    event = read_json(path)
    issue = event.get("issue") if isinstance(event, dict) else None
    if not isinstance(issue, dict):
        raise ZoneError("the event payload has no issue")
    user = issue.get("user") or {}
    login = user.get("login") if isinstance(user, dict) else None
    if not login:
        raise ZoneError("the issue has no author")
    return Issue(
        number=int(issue["number"]),
        user=str(login),
        title=str(issue.get("title") or ""),
        body=str(issue.get("body") or ""),
    )


def cmd_apply(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "main")
    if args.event:
        issue = issue_from_event(Path(args.event))
    else:
        if not args.issue_number or not args.user or not args.body_file:
            raise ZoneError("use --event or --issue-number/--user/--body-file")
        issue = Issue(
            number=args.issue_number,
            user=args.user,
            title="",
            body=Path(args.body_file).read_text(encoding="utf-8"),
        )
    if MARKER not in issue.body:
        print(f"#{issue.number}: not a registration issue, nothing to do")
        return 0
    try:
        result = apply_and_publish(
            root,
            issue,
            branch=branch,
            write=not args.dry_run,
            publish=not args.dry_run,
        )
    except (ZoneError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if not args.dry_run:
            gh_issue_comment(
                root,
                issue.number,
                "Registration was not applied:\n\n"
                f"> {exc}\n\n"
                "Edit this issue to fix the problem, or open a new issue.",
            )
        return 2
    print(result.comment)
    if not args.dry_run:
        print(f"recorded in the ledger and wrote {result.path}")
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "main")
    issues = gh_open_registration_issues(root)
    print(f"found {len(issues)} open registration issue(s)")
    failures = 0
    results: list[ApplyResult] = []
    for issue in issues:
        try:
            result = process_issue(root, issue, write=True)
            print(f"#{issue.number}: {result.action} {result.domain}")
            results.append(result)
        except (ZoneError, OSError, subprocess.SubprocessError) as exc:
            failures += 1
            print(f"#{issue.number}: {exc}", file=sys.stderr)
            if args.comment_errors:
                gh_issue_comment(
                    root,
                    issue.number,
                    "Registration was not applied:\n\n"
                    f"> {exc}\n\n"
                    "Edit this issue to fix the problem, or open a new issue.",
                )
    try:
        publish_results(root, results, branch=branch)
    except (ZoneError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1 if failures else 0


def cmd_verify(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    summary = verify_zone(root)
    print(f"OK: {summary['domains']} domain file(s), {summary['registrations']} ledger entr(ies)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zone_admin.py",
        description="Validate and apply .ion registrations from GitHub issues.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    apply_parser = subparsers.add_parser("apply", help="apply one issue")
    apply_parser.add_argument("--root", default=".", help="zone repository root")
    apply_parser.add_argument("--event", help="GitHub event JSON file")
    apply_parser.add_argument("--issue-number", type=int)
    apply_parser.add_argument("--user")
    apply_parser.add_argument("--body-file")
    apply_parser.add_argument("--branch", default="")
    apply_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate without writing, committing or commenting",
    )
    apply_parser.set_defaults(func=cmd_apply)

    sweep_parser = subparsers.add_parser("sweep", help="process all open registration issues")
    sweep_parser.add_argument("--root", default=".")
    sweep_parser.add_argument("--branch", default="")
    sweep_parser.add_argument(
        "--comment-errors",
        action="store_true",
        help="comment on issues that could not be applied",
    )
    sweep_parser.set_defaults(func=cmd_sweep)

    verify_parser = subparsers.add_parser("verify-zone", help="verify files and ledger")
    verify_parser.add_argument("--root", default=".")
    verify_parser.set_defaults(func=cmd_verify)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except ZoneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
