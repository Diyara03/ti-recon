"""Build warninglist snapshots on disk, for tests.

Uses the real production builder's output *format* — manifest, per-list files,
checksums, dataset fingerprint — because a fixture that diverged from the format
under test would prove the wrong thing. What it does not do is invoke the
operator tool: tests build snapshots in a tmp_path directly, so nothing here
needs a git checkout.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ti_recon.providers.misp_warninglists.snapshot import LISTS_DIRNAME, MANIFEST_FILENAME

__all__ = ["SnapshotBuilder", "build_snapshot", "realistic_lists"]

UPSTREAM = "https://github.com/MISP/misp-warninglists"
COMMIT = "84f0610aaf3b32159285c9b85510d0f415ea6b27"


def _canonical(payload: dict[str, Any]) -> bytes:
    """Byte-identical to what the production builder writes."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class SnapshotBuilder:
    """Assemble a snapshot directory list by list."""

    root: Path
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    omitted: list[dict[str, Any]] = field(default_factory=list)
    _lists: dict[str, dict[str, Any]] = field(default_factory=dict)
    _raw_bodies: dict[str, bytes] = field(default_factory=dict)

    def add(
        self,
        slug: str,
        *,
        matcher: str,
        entries: list[str],
        matching_attributes: list[str] | None,
        name: str | None = None,
        version: int = 1,
        description: str | None = None,
    ) -> SnapshotBuilder:
        """Add one well-formed list."""
        payload: dict[str, Any] = {
            "name": name or slug,
            "version": version,
            "description": description or f"fixture list {slug}",
            "type": matcher,
            "list": entries,
        }
        if matching_attributes is not None:
            payload["matching_attributes"] = matching_attributes
        self._lists[slug] = payload
        return self

    def add_raw(self, slug: str, body: bytes, *, matcher: str = "string") -> SnapshotBuilder:
        """Add a file whose *bytes* are chosen by the test.

        For the data-quality cases: malformed JSON, a schema-invalid document, an
        unknown matcher type. The manifest still describes it, so the loader meets
        it the way it would meet a corrupted real file.
        """
        self._raw_bodies[slug] = body
        self._lists[slug] = {"__raw__": True, "type": matcher}
        return self

    def omit(self, slug: str, *, reason: str, entry_count: int) -> SnapshotBuilder:
        """Record a list the build left out."""
        self.omitted.append({"slug": slug, "reason": reason, "entry_count": entry_count})
        return self

    def write(self, *, corrupt_checksum: str | None = None) -> Path:
        """Write the snapshot and return its root.

        ``corrupt_checksum`` records a deliberately wrong SHA-256 for one slug,
        so the verification path can be exercised without hand-editing a file.
        """
        lists_dir = self.root / LISTS_DIRNAME
        lists_dir.mkdir(parents=True, exist_ok=True)
        records: list[dict[str, Any]] = []
        total = 0
        for slug in sorted(self._lists):
            payload = self._lists[slug]
            if payload.get("__raw__"):
                body = self._raw_bodies[slug]
                entry_count = 0
                name, version, matcher, attributes = slug, 1, payload["type"], None
            else:
                body = _canonical(payload)
                entry_count = len(payload["list"])
                name = payload["name"]
                version = payload["version"]
                matcher = payload["type"]
                attributes = payload.get("matching_attributes")
            (lists_dir / f"{slug}.json").write_bytes(body)
            digest = hashlib.sha256(body).hexdigest()
            if corrupt_checksum == slug:
                digest = "0" * 64
            records.append(
                {
                    "slug": slug,
                    "name": name,
                    "version": version,
                    "matcher": matcher,
                    "entry_count": entry_count,
                    "matching_attributes": attributes,
                    "sha256": digest,
                }
            )
            total += entry_count

        fingerprint = hashlib.sha256()
        for record in records:
            fingerprint.update(f"{record['slug']}:{record['sha256']}\n".encode())
        manifest: dict[str, Any] = {
            "snapshot_format": 1,
            "upstream_repository": UPSTREAM,
            "upstream_commit": COMMIT,
            "generated_at": self.generated_at.isoformat(),
            "generator": "tests/fixtures/warninglists",
            "schema_fingerprint": "a" * 64,
            "dataset_fingerprint": fingerprint.hexdigest(),
            "list_count": len(records),
            "entry_count": total,
            "lists": records,
            "omitted": self.omitted,
            "license": "CC0-1.0",
        }
        manifest_body = {key: value for key, value in manifest.items() if value is not None}
        (self.root / MANIFEST_FILENAME).write_text(
            json.dumps(manifest_body, indent=2, sort_keys=True), encoding="utf-8"
        )
        return self.root


def realistic_lists(builder: SnapshotBuilder) -> SnapshotBuilder:
    """A small snapshot modelled on the real lists, with the real values.

    Every entry here appears in the pinned upstream snapshot; a separate test
    asserts that, so these fixtures cannot drift into fiction.
    """
    return (
        builder.add(
            "rfc1918",
            matcher="cidr",
            entries=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            matching_attributes=["ip-src", "ip-dst", "domain|ip"],
            description="private address ranges",
        )
        .add(
            "public-dns-v4",
            matcher="cidr",
            entries=["8.8.8.8", "1.1.1.1", "9.9.9.0/24"],
            matching_attributes=["ip-src", "ip-dst", "domain|ip"],
        )
        .add(
            "public-dns-v6",
            matcher="cidr",
            entries=["2001:4860:4860::8888", "2606:4700:4700::/48"],
            matching_attributes=["ip-src", "ip-dst"],
        )
        .add(
            "censys-scanning",
            matcher="cidr",
            entries=["162.142.125.0/24", "167.94.138.0/24"],
            matching_attributes=["ip-src", "ip-dst"],
        )
        .add(
            "rfc6761",
            matcher="string",
            entries=["example.com", "example.net", "invalid", "localhost"],
            matching_attributes=["hostname", "domain", "domain|ip"],
        )
        .add(
            "cloudflare-top10k",
            matcher="string",
            entries=["example.com", "github.com", "google.com"],
            matching_attributes=["hostname", "domain", "url", "domain|ip"],
        )
        .add(
            "lots-project",
            matcher="hostname",
            entries=["github.com", ".amazonaws.com", ".appspot.com"],
            matching_attributes=["domain", "hostname", "url", "domain|ip"],
        )
        .add(
            "dynamic-dns",
            matcher="hostname",
            entries=[".dynv6.net", ".ddns.net"],
            matching_attributes=["domain", "hostname", "domain|ip"],
        )
        .add(
            "automated-malware-analysis",
            matcher="substring",
            entries=["app.any.run", "analyze.intezer.com"],
            matching_attributes=["domain", "hostname", "domain|ip", "url"],
        )
        .add(
            "empty-hashes",
            matcher="string",
            entries=[
                "d41d8cd98f00b204e9800998ecf8427e",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ],
            matching_attributes=["md5", "sha1", "sha256", "filename|md5"],
        )
        .add(
            "eicar.com",
            matcher="string",
            entries=[
                "44d88612fea8a8f36de82e1278abb02f",
                "3395856ce81f2b7382dee72602f798b642f14140",
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ],
            matching_attributes=["md5", "sha1", "sha256"],
        )
        .add(
            "phone_numbers",
            matcher="regex",
            entries=[r"/((?:\+|00)1)?([0-9]{3})55501([0-9]{2})/g"],
            matching_attributes=["phone-number", "whois-registrant-phone"],
        )
        .add(
            "common-contact-emails",
            matcher="regex",
            entries=[r"/^(security|noc|soc|abuse)\@.*\..*$/i"],
            matching_attributes=["email-src", "email-dst", "target-email"],
        )
    )


def build_snapshot(
    root: Path,
    *,
    realistic: bool = True,
    generated_at: datetime | None = None,
    age: timedelta | None = None,
) -> Path:
    """Write a snapshot at ``root`` and return it."""
    stamp = generated_at or datetime.now(UTC)
    if age is not None:
        stamp = datetime.now(UTC) - age
    builder = SnapshotBuilder(root=root, generated_at=stamp)
    if realistic:
        realistic_lists(builder)
    return builder.write()
