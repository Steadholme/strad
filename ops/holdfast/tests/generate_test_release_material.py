#!/usr/bin/env python3
"""Generate ephemeral signed test-only release material outside the repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


IMAGE_KEYS = (
    "ACCESS_GOVERNANCE_IMAGE",
    "ACCESS_GOVERNANCE_ROLLBACK_IMAGE",
    "RIKUNE_ANALYZER_IMAGE",
    "STRAD_ANALYZER_IMAGE",
    "STRAD_IMAGE",
    "STRAD_VOLUME_INIT_IMAGE",
    "STRAD_RUST_BUILDER_IMAGE",
    "STRAD_RUNTIME_IMAGE",
    "STRAD_NODE_BUILDER_IMAGE",
    "VERDICT_IMAGE",
    "NEWAPI_IMAGE",
    "SLUICE_IMAGE",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-release-env", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=False)
    private_key = args.output / "test-authority.key"
    public_key = args.output / "test-authority.pub"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    release = parse_env(args.base_release_env)
    release["AUTHORITY_PUBLIC_KEY_SHA256"] = sha256(public_key)
    release["SUPPLY_CHAIN_PUBLIC_KEY_SHA256"] = sha256(public_key)
    canonical = "".join(
        f"{key}={release[key]}\n"
        for key in sorted(release)
        if key not in {"SUPPLY_CHAIN_EVIDENCE_SHA256", "SUPPLY_CHAIN_SIGNATURE_SHA256"}
    )
    images = {}
    for key in IMAGE_KEYS:
        image = release[key]
        digest = image.rsplit("@", 1)[1]
        images[key] = {
            "image": image,
            "manifest_digest": digest,
            "registry": image.split("/", 1)[0],
            "subject_digest": digest,
            "sbom": {"uri": f"oci://test.invalid/{key}/sbom", "sha256": "1" * 64},
            "provenance": {"uri": f"oci://test.invalid/{key}/provenance", "sha256": "2" * 64, "builder_id": "test-builder-v1"},
            "attestation": {"uri": f"oci://test.invalid/{key}/attestation", "sha256": "3" * 64},
            "signature": {"identity": "test-release@example.invalid", "issuer": "https://issuer.test.invalid", "rekor_log_index": 1},
        }
    evidence = {
        "schema_version": 1,
        "issued_at": "2026-08-22T00:00:00Z",
        "platform": "linux/amd64",
        "release_pins_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "registry_verification": {"verified_at": "2026-08-22T00:00:00Z", "verifier": "test-cosign-policy-v1", "images": images},
        "analyzer_overlay": {
            "base_image": release["RIKUNE_ANALYZER_IMAGE"],
            "overlay_image": release["STRAD_ANALYZER_IMAGE"],
            "dockerfile_sha256": sha256(Path(__file__).resolve().parents[3] / "Dockerfile.analyzer"),
            "bridge_lock_sha256": sha256(Path(__file__).resolve().parents[3] / "bridge/package-lock.json"),
            "static_lock_sha256": "32e3ea5103ff73c413062b17ad3bb4e7270fbcd6fd1325f6a7f3dc831bee83ef",
            "source_revision": release["STRAD_REVISION"],
        },
        "access_candidate": {
            "image": release["ACCESS_GOVERNANCE_IMAGE"],
            "build_input_sha256": release["ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"],
            "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
            "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
            "source_revision": release["STRAD_REVISION"],
        },
    }
    evidence_path = args.output / "SUPPLY-CHAIN.json"
    evidence_path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    signature = args.output / "SUPPLY-CHAIN.sig"
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature), str(evidence_path)],
        check=True,
    )
    release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = sha256(evidence_path)
    release["SUPPLY_CHAIN_SIGNATURE_SHA256"] = sha256(signature)
    release_path = args.output / "release.env"
    release_path.write_text("".join(f"{key}={value}\n" for key, value in release.items()), encoding="utf-8")
    secret_path = args.output / "secrets.env"
    secret_path.write_text(
        "STRAD_DATABASE_URL=postgres://strad_test:password@postgres/strad_test\n"
        "STRAD_BRIDGE_TOKEN=" + "b" * 40 + "\n"
        "RIKUNE_FILE_SERVER_API_KEY=" + "r" * 40 + "\n"
        "STRAD_NEWAPI_KEY=" + "n" * 40 + "\n",
        encoding="utf-8",
    )
    for path in args.output.iterdir():
        path.chmod(0o600)
    print(release_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
