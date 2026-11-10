"""Tests for the .ion registration validator.

Run with:
    python -m unittest discover -s zone-ion/tests -p "test_*.py"
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import zone_admin  # noqa: E402

UTC = dt.timezone.utc
START = dt.datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
SEED = bytes(range(1, 33))
PRIVATE = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC = "ed25519:ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"
OTHER_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(40, 72)))
OTHER_PUBLIC = "ed25519:" + zone_admin.b64url_encode(
    OTHER_PRIVATE.public_key().public_bytes_raw()
)

ZONE_MANIFEST = """schema = 1
zone = "ion"
description = "Test zone"
default_ttl = 300
negative_ttl = 60
policy = "open"
allowed_types = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR"]
ns = ["ns1.ion", "ns2.ion"]
"""

APEX = """schema = 1
name = "@"
created = "2026-01-01T00:00:00Z"
updated = "2026-01-01T00:00:00Z"
records = []
"""


def make_root() -> tempfile.TemporaryDirectory:
    """Create a temporary zone repository."""
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    (root / "domains").mkdir()
    (root / "registry").mkdir()
    (root / "zone.toml").write_text(ZONE_MANIFEST, encoding="utf-8", newline="\n")
    (root / "domains" / "_records.toml").write_text(APEX, encoding="utf-8", newline="\n")
    (root / "registry" / "registrations.json").write_text(
        json.dumps({"version": 1, "zone": "ion", "registrations": []}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "registry" / "reserved.json").write_text(
        json.dumps({"names": ["ion", "ns1", "ns2", "registry"]}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return temporary


def domain_document(
    name: str,
    *,
    created: str = "2026-05-01T12:00:00Z",
    updated: str | None = None,
    records: list[dict] | None = None,
    private: Ed25519PrivateKey = PRIVATE,
    public: str = PUBLIC,
    sign: bool = True,
) -> dict:
    """Build a signed domain document like the website does."""
    document = {
        "schema": 1,
        "name": name,
        "owner": public,
        "created": created,
        "updated": updated or created,
        "records": records
        or [
            {"type": "A", "value": "192.0.2.10"},
            {"type": "TXT", "value": f"hello from {name}"},
        ],
    }
    if sign:
        payload = zone_admin.canonical_payload("ion", document)
        signature = private.sign(payload)
        document["signature"] = {
            "key": public,
            "value": zone_admin.b64url_encode(signature),
            "signed_at": updated or created,
        }
    return document


def issue_body(document: dict) -> str:
    """Wrap a signed document in the issue body format."""
    return (
        "Please register this domain.\n\n"
        f"{zone_admin.MARKER}\n\n"
        "```toml\n"
        f"{zone_admin.dump_domain_toml(document)}"
        "```\n"
    )


def make_issue(number: int, user: str, document: dict) -> zone_admin.Issue:
    """Build an Issue value for tests."""
    return zone_admin.Issue(
        number=number,
        user=user,
        title=f"[register] {document['name']}.ion",
        body=issue_body(document),
    )


class FixtureTests(unittest.TestCase):
    def test_rust_fixture_matches_canonical_payload(self):
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "canonical-shop.json").read_text(encoding="utf-8")
        )
        payload = zone_admin.canonical_payload(fixture["zone"], fixture["domain"])
        self.assertEqual(payload.decode("utf-8"), fixture["payload"])
        zone, allowed = zone_admin.load_zone(ROOT)
        validated = zone_admin.validate_domain_document(fixture["domain"], zone, allowed)
        self.assertEqual(validated["signature"]["value"], fixture["signature"])

    def test_tampered_fixture_is_rejected(self):
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "canonical-shop.json").read_text(encoding="utf-8")
        )
        document = json.loads(json.dumps(fixture["domain"]))
        document["records"][0]["value"] = "192.0.2.99"
        zone, allowed = zone_admin.load_zone(ROOT)
        with self.assertRaisesRegex(zone_admin.ZoneError, "signature verification failed"):
            zone_admin.validate_domain_document(document, zone, allowed)


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = make_root()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def apply(self, number, user, document, *, now=START, write=True):
        return zone_admin.process_issue(
            self.root,
            make_issue(number, user, document),
            now=now,
            write=write,
        )

    def test_register_second_level_writes_file_and_ledger(self):
        result = self.apply(1, "alice", domain_document("shop"))
        self.assertEqual(result.action, "register")
        path = self.root / "domains" / "shop" / "_records.toml"
        self.assertTrue(path.exists())
        ledger = json.loads((self.root / "registry" / "registrations.json").read_text(encoding="utf-8"))
        self.assertEqual(len(ledger["registrations"]), 1)
        entry = ledger["registrations"][0]
        self.assertEqual(entry["domain"], "shop")
        self.assertEqual(entry["fqdn"], "shop.ion")
        self.assertEqual(entry["kind"], "second_level")
        self.assertEqual(entry["user"], "alice")
        self.assertEqual(entry["owner"], PUBLIC)
        self.assertEqual(entry["registered_at"], "2026-05-01T12:00:00Z")
        self.assertEqual(zone_admin.verify_zone(self.root)["registrations"], 1)

    def test_same_issue_is_idempotent(self):
        self.apply(1, "alice", domain_document("shop"))
        ledger_before = (self.root / "registry" / "registrations.json").read_text(encoding="utf-8")
        self.apply(1, "alice", domain_document("shop", updated="2026-05-01T12:30:00Z"), now=START + dt.timedelta(minutes=30))
        ledger = json.loads((self.root / "registry" / "registrations.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["registrations"][0]["registered_at"], "2026-05-01T12:00:00Z")
        self.assertEqual(ledger["registrations"][0]["updated_at"], "2026-05-01T12:30:00Z")
        self.assertNotEqual(ledger_before, (self.root / "registry" / "registrations.json").read_text(encoding="utf-8"))

    def test_cooldown_blocks_a_second_second_level_domain(self):
        self.apply(1, "alice", domain_document("shop"))
        with self.assertRaisesRegex(zone_admin.ZoneError, "one second-level domain per 48 hours"):
            self.apply(
                2,
                "alice",
                domain_document("blog"),
                now=START + dt.timedelta(hours=1),
            )
        self.apply(3, "alice", domain_document("blog"), now=START + dt.timedelta(hours=49))

    def test_cooldown_is_per_github_user(self):
        self.apply(1, "alice", domain_document("shop"))
        self.apply(
            2,
            "bob",
            domain_document(
                "blog",
                private=OTHER_PRIVATE,
                public=OTHER_PUBLIC,
            ),
            now=START + dt.timedelta(minutes=1),
        )

    def test_subdomains_are_unlimited_and_need_the_parent(self):
        self.apply(1, "alice", domain_document("shop"))
        for index in range(5):
            self.apply(
                10 + index,
                "alice",
                domain_document(f"www{index}.shop"),
                now=START + dt.timedelta(minutes=index + 1),
            )
        with self.assertRaisesRegex(zone_admin.ZoneError, "subdomains need an owned parent"):
            self.apply(
                20,
                "alice",
                domain_document("www.unknown"),
                now=START + dt.timedelta(hours=2),
            )
        self.assertEqual(zone_admin.verify_zone(self.root)["registrations"], 6)

    def test_subdomain_requires_the_parent_key(self):
        self.apply(1, "alice", domain_document("shop"))
        with self.assertRaisesRegex(zone_admin.ZoneError, "owner key must match"):
            self.apply(
                2,
                "alice",
                domain_document(
                    "www.shop",
                    private=OTHER_PRIVATE,
                    public=OTHER_PUBLIC,
                ),
            )

    def test_another_user_cannot_add_a_subdomain(self):
        self.apply(1, "alice", domain_document("shop"))
        with self.assertRaisesRegex(zone_admin.ZoneError, "only the owner of the parent"):
            self.apply(
                2,
                "bob",
                domain_document(
                    "www.shop",
                    private=OTHER_PRIVATE,
                    public=OTHER_PUBLIC,
                ),
            )

    def test_another_user_cannot_update_a_domain(self):
        self.apply(1, "alice", domain_document("shop"))
        with self.assertRaisesRegex(zone_admin.ZoneError, "another GitHub account"):
            self.apply(
                2,
                "bob",
                domain_document("shop", updated="2026-05-02T12:00:00Z"),
                now=START + dt.timedelta(days=1),
            )

    def test_update_does_not_start_a_new_cooldown(self):
        self.apply(1, "alice", domain_document("shop"))
        self.apply(
            2,
            "alice",
            domain_document(
                "shop",
                updated="2026-05-01T13:00:00Z",
                records=[{"type": "A", "value": "192.0.2.20"}],
            ),
            now=START + dt.timedelta(hours=1),
        )
        self.apply(
            3,
            "alice",
            domain_document("blog"),
            now=START + dt.timedelta(hours=48, minutes=1),
        )

    def test_reserved_names_are_rejected(self):
        with self.assertRaisesRegex(zone_admin.ZoneError, "reserved"):
            self.apply(1, "alice", domain_document("ns1"))

    def test_owner_key_cannot_be_linked_to_two_users(self):
        self.apply(1, "alice", domain_document("shop"))
        with self.assertRaisesRegex(zone_admin.ZoneError, "linked to another GitHub account"):
            self.apply(2, "bob", domain_document("blog"), now=START + dt.timedelta(hours=49))

    def test_unknown_fields_are_rejected(self):
        document = domain_document("shop")
        text = zone_admin.dump_domain_toml(document).replace(
            "schema = 1\n", "schema = 1\nsurprise = true\n", 1
        )
        issue = zone_admin.Issue(
            number=1,
            user="alice",
            title="[register] shop.ion",
            body=f"{zone_admin.MARKER}\n\n```toml\n{text}```\n",
        )
        with self.assertRaisesRegex(zone_admin.ZoneError, "unknown field"):
            zone_admin.process_issue(self.root, issue, now=START)

    def test_unsigned_document_is_rejected(self):
        document = domain_document("shop", sign=False)
        with self.assertRaisesRegex(zone_admin.ZoneError, "signature is missing"):
            self.apply(1, "alice", document)

    def test_tampered_document_is_rejected(self):
        document = domain_document("shop")
        document["records"][0]["value"] = "192.0.2.99"
        with self.assertRaisesRegex(zone_admin.ZoneError, "signature verification failed"):
            self.apply(1, "alice", document)

    def test_verify_zone_detects_a_missing_ledger_entry(self):
        self.apply(1, "alice", domain_document("shop"))
        path = self.root / "registry" / "registrations.json"
        path.write_text(
            json.dumps({"version": 1, "zone": "ion", "registrations": []}, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(zone_admin.ZoneError, "not in the registration ledger"):
            zone_admin.verify_zone(self.root)

    def test_verify_zone_detects_ledger_records_out_of_sync(self):
        self.apply(1, "alice", domain_document("shop"))
        path = self.root / "registry" / "registrations.json"
        ledger = json.loads(path.read_text(encoding="utf-8"))
        ledger["registrations"][0]["records"][0]["value"] = "192.0.2.99"
        path.write_text(
            json.dumps(ledger, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(zone_admin.ZoneError, "records do not match"):
            zone_admin.verify_zone(self.root)

    def test_dry_run_does_not_write(self):
        self.apply(1, "alice", domain_document("shop"), write=False)
        self.assertFalse((self.root / "domains" / "shop" / "_records.toml").exists())
        ledger = json.loads((self.root / "registry" / "registrations.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["registrations"], [])

    def test_cname_cannot_be_combined(self):
        document = domain_document(
            "shop",
            records=[
                {"type": "CNAME", "value": "example.com."},
                {"type": "A", "value": "192.0.2.10"},
            ],
        )
        with self.assertRaisesRegex(zone_admin.ZoneError, "CNAME cannot coexist"):
            self.apply(1, "alice", document)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temporary = make_root()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_batch_publish_pushes_once(self):
        results = [
            zone_admin.process_issue(
                self.root,
                make_issue(1, "alice", domain_document("shop")),
                now=START,
            ),
            zone_admin.process_issue(
                self.root,
                make_issue(
                    2,
                    "bob",
                    domain_document("blog", private=OTHER_PRIVATE, public=OTHER_PUBLIC),
                ),
                now=START,
            ),
        ]
        with (
            mock.patch.object(zone_admin, "git_commit_and_push") as push,
            mock.patch.object(zone_admin, "gh_issue_comment") as comment,
            mock.patch.object(zone_admin, "gh_issue_close") as close,
        ):
            zone_admin.publish_results(self.root, results, branch="main")
        self.assertEqual(push.call_count, 1)
        self.assertIn("2 registrations", push.call_args.args[1])
        self.assertEqual([item.args[1] for item in comment.call_args_list], [1, 2])
        self.assertEqual([item.args[1] for item in close.call_args_list], [1, 2])
        self.assertEqual(zone_admin.verify_zone(self.root)["registrations"], 2)

    def test_empty_batch_does_not_commit(self):
        with mock.patch.object(zone_admin, "git_commit_and_push") as push:
            zone_admin.publish_results(self.root, [], branch="main")
        push.assert_not_called()


if __name__ == "__main__":
    unittest.main()
