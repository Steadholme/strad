from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ops.holdfast import recovery_completion_attestation as attestation_tool


OPS_ROOT = Path(__file__).resolve().parents[1]
TOOL = OPS_ROOT / "recovery_completion_attestation.py"
ATTESTATION = "RECOVERY-COMPLETION-ATTESTATION.json"
SIGNATURE = "RECOVERY-COMPLETION-ATTESTATION.sig"
PUBLIC_KEY = "RECOVERY-COMPLETION-ATTESTATION.pub"
ATTEMPT = "20260828T120000Z-4242"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class RecoveryCompletionAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="holdfast-recovery-completion-attestation-"
        )
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.release = self.root / "release-next"
        self.release.mkdir(mode=0o700)
        self.private_key = self.root / "authority.key"
        self.source_public_key = self.root / "authority.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(self.private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.source_public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.private_key.chmod(0o600)
        self.source_public_key.chmod(0o600)
        self.public_key_sha256 = sha256_bytes(self.source_public_key.read_bytes())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def issue_command(self, release: Path | None = None) -> list[str]:
        target = release or self.release
        return [
            "python3",
            str(TOOL),
            "issue",
            "--release-root",
            str(target),
            "--private-key",
            str(self.private_key),
            "--source-public-key",
            str(self.source_public_key),
            "--public-key-sha256",
            self.public_key_sha256,
            "--recovery-attempt-id",
            ATTEMPT,
            "--prior-failure-receipt",
            "APPLY-ACTIVATION-FAILED-20260828T115900Z-123.receipt",
            "--prior-failure-receipt-sha256",
            "c" * 64,
            "--apply-armed-at",
            "2026-08-28T11:58:00Z",
            "--recovery-armed-at",
            "2026-08-28T12:00:00Z",
            "--recovery-completed-at",
            "2026-08-28T12:00:30Z",
            "--estate-root",
            str(self.root / "estate"),
            "--backup-dir",
            str(self.root / "backup"),
            "--current-sha256",
            "1" * 64,
            "--completion-receipt",
            f"APPLY-RECOVERY-COMPLETE-{ATTEMPT}.receipt",
            "--completion-receipt-sha256",
            "2" * 64,
            "--completion-archive",
            f"APPLY-RECOVERY-COMPLETE-{ATTEMPT}.json",
            "--completion-archive-sha256",
            "3" * 64,
            "--recovery-armed-receipt",
            f"APPLY-RECOVERY-ARMED-{ATTEMPT}.receipt",
            "--recovery-armed-receipt-sha256",
            "4" * 64,
            "--control-sha256",
            "5" * 64,
            "--release-env-sha256",
            "6" * 64,
            "--release-evidence-sha256",
            "7" * 64,
            "--transaction-sha256",
            "8" * 64,
            "--applied-targets-sha256",
            "9" * 64,
            "--runtime-receipt-sha256",
            "a" * 64,
            "--runtime-manifest-sha256",
            "b" * 64,
            "--predecessor-release-generation",
            "2",
            "--release-generation",
            "3",
        ]

    def run_command(
        self, command: list[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

    def issue(self, release: Path | None = None) -> subprocess.CompletedProcess[str]:
        return self.run_command(self.issue_command(release))

    def verify_command(
        self,
        release: Path | None = None,
        *,
        public_key_sha256: str | None = None,
    ) -> list[str]:
        target = release or self.release
        return [
            "python3",
            str(TOOL),
            "verify",
            "--attestation",
            str(target / ATTESTATION),
            "--signature",
            str(target / SIGNATURE),
            "--public-key",
            str(target / PUBLIC_KEY),
            "--public-key-sha256",
            public_key_sha256 or self.public_key_sha256,
        ]

    def publish_command(self, source: Path, release: Path) -> list[str]:
        return [
            "python3",
            str(TOOL),
            "publish",
            "--source-root",
            str(source),
            "--release-root",
            str(release),
            "--public-key-sha256",
            self.public_key_sha256,
        ]

    def generate_key_pair(self, name: str, bits: int) -> tuple[Path, Path]:
        private_key = self.root / f"{name}.key"
        public_key = self.root / f"{name}.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                f"rsa_keygen_bits:{bits}",
                "-out",
                str(private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        private_key.chmod(0o600)
        public_key.chmod(0o600)
        return private_key, public_key

    def sign(self, raw: bytes) -> bytes:
        return self.sign_with(raw, self.private_key)

    @staticmethod
    def sign_with(raw: bytes, private_key: Path) -> bytes:
        return subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-sigopt",
                "rsa_padding_mode:pkcs1",
            ],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout

    def replace_signed_attestation(self, raw: bytes) -> None:
        attestation = self.release / ATTESTATION
        signature = self.release / SIGNATURE
        attestation.write_bytes(raw)
        signature.write_bytes(self.sign(raw))
        attestation.chmod(0o600)
        signature.chmod(0o600)

    def canonical_document(self) -> dict[str, object]:
        return json.loads((self.release / ATTESTATION).read_text(encoding="utf-8"))

    @staticmethod
    def canonical_bytes(value: dict[str, object]) -> bytes:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )

    def test_issue_is_exact_signed_private_and_idempotent(self) -> None:
        issued = self.issue()
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        result = json.loads(issued.stdout)
        self.assertEqual(result["attestation"], ATTESTATION)
        self.assertEqual(result["signature"], SIGNATURE)
        self.assertEqual(result["public_key"], PUBLIC_KEY)

        expected_files = {ATTESTATION, SIGNATURE, PUBLIC_KEY}
        self.assertEqual(
            {path.name for path in self.release.iterdir()}, expected_files
        )
        for name in expected_files:
            path = self.release / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        raw = (self.release / ATTESTATION).read_bytes()
        document = self.canonical_document()
        self.assertEqual(raw, self.canonical_bytes(document))
        self.assertEqual(document["kind"], "recovery-completion-attestation-v1")
        self.assertEqual(document["signature_algorithm"], "rsa-pkcs1v15-sha256")
        self.assertTrue(document["successor"])
        self.assertEqual(document["release_generation"], 3)
        self.assertEqual(document["predecessor_release_generation"], 2)
        self.assertEqual(document["recovery_prior_state"], "apply_activation_failed")
        self.assertEqual(document["prior_failure_kind"], "activation")
        self.assertEqual(document["apply_armed_at"], "2026-08-28T11:58:00Z")
        self.assertEqual(document["recovery_armed_at"], "2026-08-28T12:00:00Z")
        self.assertEqual(
            document["recovery_completed_at"], "2026-08-28T12:00:30Z"
        )
        self.assertGreaterEqual(document["issued_at"], document["recovery_completed_at"])
        self.assertTrue(document["services_activated"])
        self.assertTrue(document["runtime_verified"])
        self.assertFalse(document["ingress_opened"])

        verified = self.run_command(self.verify_command())
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        before = {
            name: (
                (self.release / name).read_bytes(),
                (self.release / name).stat().st_mtime_ns,
            )
            for name in expected_files
        }
        time.sleep(0.01)
        retried = self.issue()
        self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
        after = {
            name: (
                (self.release / name).read_bytes(),
                (self.release / name).stat().st_mtime_ns,
            )
            for name in expected_files
        }
        self.assertEqual(after, before)

    def test_committed_idempotent_retry_fsyncs_the_release_directory(self) -> None:
        issued = self.issue()
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        content = {
            ATTESTATION: (self.release / ATTESTATION).read_bytes(),
            SIGNATURE: (self.release / SIGNATURE).read_bytes(),
            PUBLIC_KEY: (self.release / PUBLIC_KEY).read_bytes(),
        }
        document = self.canonical_document()
        directory = os.open(self.release, os.O_RDONLY | os.O_DIRECTORY)
        real_fsync = os.fsync
        try:
            with mock.patch.object(
                attestation_tool.os, "fsync", side_effect=real_fsync
            ) as fsync:
                result = attestation_tool.commit_prepared_bundle(
                    directory,
                    content,
                    document,
                    self.public_key_sha256,
                )
            self.assertEqual(result["attestation"], ATTESTATION)
            fsync.assert_called_once_with(directory)
        finally:
            os.close(directory)

    def test_exact_schema_and_canonical_bytes_fail_closed(self) -> None:
        self.assertEqual(self.issue().returncode, 0)
        original = self.canonical_document()
        cases: tuple[tuple[str, bytes, str], ...] = (
            (
                "unknown",
                self.canonical_bytes({**original, "unexpected": True}),
                "field set is not exact",
            ),
            (
                "mode",
                self.canonical_bytes({**original, "mode": "restore"}),
                "mode differs",
            ),
            (
                "generation",
                self.canonical_bytes({**original, "release_generation": 4}),
                "generation linkage",
            ),
            (
                "non-successor",
                self.canonical_bytes({**original, "successor": False}),
                "successor differs",
            ),
            (
                "integer-successor",
                self.canonical_bytes({**original, "successor": 1}),
                "successor differs",
            ),
            (
                "other-lineage",
                self.canonical_bytes(
                    {
                        **original,
                        "predecessor_release_generation": 1,
                        "release_generation": 2,
                    }
                ),
                "current-production successor generation",
            ),
            (
                "bracket",
                self.canonical_bytes(
                    {**original, "db_public_db_bracket": "absent-404-present"}
                ),
                "db_public_db_bracket differs",
            ),
            (
                "producer",
                self.canonical_bytes(
                    {**original, "recovery_prior_state": "apply_armed"}
                ),
                "recovery_prior_state differs",
            ),
            (
                "apply-arm-time-order",
                self.canonical_bytes(
                    {**original, "apply_armed_at": "2099-01-01T00:00:00Z"}
                ),
                "timestamp ordering",
            ),
            (
                "recovery-arm-time-order",
                self.canonical_bytes(
                    {**original, "recovery_armed_at": "2099-01-01T00:00:00Z"}
                ),
                "timestamp ordering",
            ),
            (
                "completion-issued-time-order",
                self.canonical_bytes(
                    {**original, "recovery_completed_at": "2099-01-01T00:00:00Z"}
                ),
                "timestamp ordering",
            ),
            (
                "noncanonical",
                json.dumps(original, sort_keys=False, indent=2).encode("utf-8") + b"\n",
                "not exact canonical JSON",
            ),
            (
                "crlf",
                self.canonical_bytes(original).replace(b"\n", b"\r\n"),
                "must not contain CR",
            ),
            (
                "duplicate",
                self.canonical_bytes(original).replace(
                    b'{"applied_targets_file":',
                    b'{"schema_version":1,"applied_targets_file":',
                    1,
                ),
                "duplicate JSON key",
            ),
        )
        for name, raw, error in cases:
            with self.subTest(name=name):
                self.replace_signed_attestation(raw)
                rejected = self.run_command(self.verify_command())
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(error, rejected.stderr)
                self.replace_signed_attestation(self.canonical_bytes(original))

    def test_signature_key_and_file_boundaries_fail_closed(self) -> None:
        self.assertEqual(self.issue().returncode, 0)
        signature = self.release / SIGNATURE
        signature.write_bytes(signature.read_bytes()[:-1] + b"x")
        signature.chmod(0o600)
        rejected_signature = self.run_command(self.verify_command())
        self.assertNotEqual(rejected_signature.returncode, 0)
        self.assertIn("OpenSSL ceremony failed", rejected_signature.stderr)

        self.tearDown()
        self.setUp()
        self.assertEqual(self.issue().returncode, 0)
        rejected_pin = self.run_command(
            self.verify_command(public_key_sha256="f" * 64)
        )
        self.assertNotEqual(rejected_pin.returncode, 0)
        self.assertIn("public key pin differs", rejected_pin.stderr)

        self.tearDown()
        self.setUp()
        self.assertEqual(self.issue().returncode, 0)
        public_key = self.release / PUBLIC_KEY
        external = self.root / "external.pub"
        external.write_bytes(public_key.read_bytes())
        external.chmod(0o600)
        public_key.unlink()
        public_key.symlink_to(external)
        rejected_symlink = self.run_command(self.verify_command())
        self.assertNotEqual(rejected_symlink.returncode, 0)

        public_key.unlink()
        os.link(external, public_key)
        rejected_hardlink = self.run_command(self.verify_command())
        self.assertNotEqual(rejected_hardlink.returncode, 0)
        self.assertIn("single-link", rejected_hardlink.stderr)

    def test_partial_output_converges_and_complete_retry_is_read_only(self) -> None:
        partial = self.root / "partial-release"
        partial.mkdir(mode=0o700)
        (partial / ATTESTATION).write_bytes(b"{}\n")
        (partial / ATTESTATION).chmod(0o600)
        converged = self.issue(partial)
        self.assertEqual(converged.returncode, 0, converged.stdout + converged.stderr)
        self.assertEqual(
            {path.name for path in partial.iterdir()},
            {ATTESTATION, SIGNATURE, PUBLIC_KEY},
        )
        verified_partial = self.run_command(self.verify_command(partial))
        self.assertEqual(
            verified_partial.returncode,
            0,
            verified_partial.stdout + verified_partial.stderr,
        )

        complete = self.issue()
        self.assertEqual(complete.returncode, 0, complete.stdout + complete.stderr)
        changed_command = self.issue_command()
        index = changed_command.index("--current-sha256") + 1
        changed_command[index] = "e" * 64
        mismatched_retry = self.run_command(changed_command)
        self.assertNotEqual(mismatched_retry.returncode, 0)
        self.assertIn("differs from prepared authority", mismatched_retry.stderr)

    def test_issue_converges_matching_unsigned_pub_json_subsets(self) -> None:
        subsets = (
            {PUBLIC_KEY},
            {ATTESTATION},
            {PUBLIC_KEY, ATTESTATION},
        )
        for index, keep in enumerate(subsets):
            with self.subTest(keep=sorted(keep)):
                if index:
                    self.tearDown()
                    self.setUp()
                issued = self.issue()
                self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
                for name in {ATTESTATION, SIGNATURE, PUBLIC_KEY} - keep:
                    (self.release / name).unlink()

                retried = self.issue()
                self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
                self.assertEqual(
                    {path.name for path in self.release.iterdir()},
                    {ATTESTATION, SIGNATURE, PUBLIC_KEY},
                )
                verified = self.run_command(self.verify_command())
                self.assertEqual(
                    verified.returncode, 0, verified.stdout + verified.stderr
                )

    def test_unsigned_mismatch_converges_and_partial_commit_marker_fails_closed(self) -> None:
        issued = self.issue()
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        (self.release / SIGNATURE).unlink()
        document = self.canonical_document()
        document["current_sha256"] = "e" * 64
        (self.release / ATTESTATION).write_bytes(self.canonical_bytes(document))
        (self.release / ATTESTATION).chmod(0o600)
        mismatched = self.issue()
        self.assertEqual(mismatched.returncode, 0, mismatched.stdout + mismatched.stderr)
        self.assertTrue((self.release / SIGNATURE).is_file())
        verified = self.run_command(self.verify_command())
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)

        self.tearDown()
        self.setUp()
        issued = self.issue()
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        (self.release / PUBLIC_KEY).unlink()
        committed_partial = self.issue()
        self.assertNotEqual(committed_partial.returncode, 0)
        self.assertIn("committed recovery-completion output set is not exact", committed_partial.stderr)

    def test_publish_moves_only_an_exact_verified_staged_bundle(self) -> None:
        staged = self.root / "staged"
        published = self.root / "published"
        staged.mkdir(mode=0o700)
        published.mkdir(mode=0o700)
        issued = self.issue(staged)
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)

        first = self.run_command(self.publish_command(staged, published))
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        expected = {ATTESTATION, SIGNATURE, PUBLIC_KEY}
        self.assertEqual({path.name for path in published.iterdir()}, expected)
        before = {
            name: ((published / name).read_bytes(), (published / name).stat().st_mtime_ns)
            for name in expected
        }
        retried = self.run_command(self.publish_command(staged, published))
        self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
        after = {
            name: ((published / name).read_bytes(), (published / name).stat().st_mtime_ns)
            for name in expected
        }
        self.assertEqual(after, before)

        later = self.root / "staged-later"
        later.mkdir(mode=0o700)
        later_document = json.loads((staged / ATTESTATION).read_text(encoding="utf-8"))
        later_document["issued_at"] = "2026-08-28T13:00:00Z"
        later_attestation = self.canonical_bytes(later_document)
        (later / ATTESTATION).write_bytes(later_attestation)
        (later / SIGNATURE).write_bytes(self.sign(later_attestation))
        (later / PUBLIC_KEY).write_bytes((staged / PUBLIC_KEY).read_bytes())
        for name in expected:
            (later / name).chmod(0o600)
        later_retry = self.run_command(self.publish_command(later, published))
        self.assertEqual(
            later_retry.returncode, 0, later_retry.stdout + later_retry.stderr
        )
        self.assertEqual(
            {
                name: (
                    (published / name).read_bytes(),
                    (published / name).stat().st_mtime_ns,
                )
                for name in expected
            },
            before,
        )

        partial = self.root / "partial-published"
        partial.mkdir(mode=0o700)
        (partial / ATTESTATION).write_bytes(b"{}\n")
        (partial / ATTESTATION).chmod(0o600)
        converged = self.run_command(self.publish_command(staged, partial))
        self.assertEqual(converged.returncode, 0, converged.stdout + converged.stderr)
        self.assertEqual({path.name for path in partial.iterdir()}, expected)

        extra = staged / "unexpected"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(0o600)
        exact_destination = self.root / "exact-destination"
        exact_destination.mkdir(mode=0o700)
        exact_rejected = self.run_command(
            self.publish_command(staged, exact_destination)
        )
        self.assertNotEqual(exact_rejected.returncode, 0)
        self.assertIn("file set is not exact", exact_rejected.stderr)
        self.assertFalse(any(exact_destination.iterdir()))

        different = self.root / "staged-different"
        different.mkdir(mode=0o700)
        different_command = self.issue_command(different)
        different_command[different_command.index("--current-sha256") + 1] = "e" * 64
        different_issue = self.run_command(different_command)
        self.assertEqual(
            different_issue.returncode,
            0,
            different_issue.stdout + different_issue.stderr,
        )
        rejected_committed = self.run_command(
            self.publish_command(different, published)
        )
        self.assertNotEqual(rejected_committed.returncode, 0)
        self.assertIn("differs from prepared authority", rejected_committed.stderr)

    def test_structure_check_rejects_duplicate_json_and_receipt_keys(self) -> None:
        duplicate_json = self.root / "duplicate.json"
        duplicate_json.write_text('{"state":"first","state":"second"}\n', encoding="utf-8")
        duplicate_json.chmod(0o600)
        rejected_json = self.run_command(
            [
                "python3",
                str(TOOL),
                "structure",
                "--json-file",
                str(duplicate_json),
            ]
        )
        self.assertNotEqual(rejected_json.returncode, 0)
        self.assertIn("duplicate JSON key", rejected_json.stderr)

        duplicate_receipt = self.root / "duplicate.receipt"
        duplicate_receipt.write_text("state=first\nstate=second\n", encoding="utf-8")
        duplicate_receipt.chmod(0o600)
        rejected_receipt = self.run_command(
            [
                "python3",
                str(TOOL),
                "structure",
                "--receipt-file",
                str(duplicate_receipt),
            ]
        )
        self.assertNotEqual(rejected_receipt.returncode, 0)
        self.assertIn("duplicate receipt key", rejected_receipt.stderr)

        control_json = self.root / "control.json"
        control_json.write_bytes(b'{"state":"applied\\u0000closed"}\n')
        control_json.chmod(0o600)
        rejected_control_json = self.run_command(
            [
                "python3",
                str(TOOL),
                "structure",
                "--json-file",
                str(control_json),
            ]
        )
        self.assertNotEqual(rejected_control_json.returncode, 0)
        self.assertIn("control character", rejected_control_json.stderr)

        control_receipt = self.root / "control.receipt"
        control_receipt.write_bytes(b"state=applied\x00closed\n")
        control_receipt.chmod(0o600)
        rejected_control_receipt = self.run_command(
            [
                "python3",
                str(TOOL),
                "structure",
                "--receipt-file",
                str(control_receipt),
            ]
        )
        self.assertNotEqual(rejected_control_receipt.returncode, 0)
        self.assertIn("control character", rejected_control_receipt.stderr)

        historical_control = self.root / "historical-apply-armed.receipt"
        historical_lines = [
            f"{key}=value\n"
            for key in attestation_tool.HISTORICAL_APPLY_ARMED_KEYS
        ]
        historical_lines[1] = "armed_at=value\x00drift\n"
        historical_control.write_bytes("".join(historical_lines).encode("utf-8"))
        historical_control.chmod(0o600)
        rejected_historical_control = self.run_command(
            [
                "python3",
                str(TOOL),
                "structure",
                "--historical-apply-armed-file",
                str(historical_control),
            ]
        )
        self.assertNotEqual(rejected_historical_control.returncode, 0)
        self.assertIn("control character", rejected_historical_control.stderr)

    def test_publish_rejects_unsafe_uncommitted_symlink_and_hardlink(self) -> None:
        staged = self.root / "unsafe-staged"
        destination = self.root / "unsafe-destination"
        staged.mkdir(mode=0o700)
        destination.mkdir(mode=0o700)
        issued = self.issue(staged)
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        external = self.root / "uncommitted-external"
        external.write_bytes(b"uncommitted\n")
        external.chmod(0o600)
        (destination / ATTESTATION).symlink_to(external)
        rejected_symlink = self.run_command(self.publish_command(staged, destination))
        self.assertNotEqual(rejected_symlink.returncode, 0)
        self.assertIn("uncommitted recovery-completion output is unsafe", rejected_symlink.stderr)
        (destination / ATTESTATION).unlink()

        os.link(external, destination / ATTESTATION)
        rejected_hardlink = self.run_command(self.publish_command(staged, destination))
        self.assertNotEqual(rejected_hardlink.returncode, 0)
        self.assertIn("uncommitted recovery-completion output is unsafe", rejected_hardlink.stderr)
        self.assertFalse((destination / SIGNATURE).exists())

    def test_source_and_staged_bundle_fifos_fail_without_blocking(self) -> None:
        issued = self.issue()
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        trio = (ATTESTATION, SIGNATURE, PUBLIC_KEY)

        for reader, name in (
            (reader, name) for reader in ("source", "staged") for name in trio
        ):
            with self.subTest(reader=reader, name=name):
                bundle = self.root / f"{reader}-{name}.bundle"
                bundle.mkdir(mode=0o700)
                for member in trio:
                    target = bundle / member
                    target.write_bytes((self.release / member).read_bytes())
                    target.chmod(0o600)
                (bundle / name).unlink()
                os.mkfifo(bundle / name, 0o600)

                if reader == "source":
                    command = self.verify_command(bundle)
                    expected = "safe root-owned single-link regular file"
                else:
                    destination = self.root / f"published-{name}"
                    destination.mkdir(mode=0o700)
                    command = self.publish_command(bundle, destination)
                    expected = "mode-0600 root-owned single-link regular file"
                try:
                    rejected = self.run_command(command, timeout=2.0)
                except subprocess.TimeoutExpired as error:
                    self.fail(f"{reader} FIFO reader blocked: {error}")
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected, rejected.stderr)

    def test_signature_commit_marker_crash_boundaries_are_safe_and_retryable(self) -> None:
        issued = self.issue()
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        boundaries = (
            "fsync:cleanup",
            f"stage:{PUBLIC_KEY}",
            f"rename:{PUBLIC_KEY}",
            f"stage:{ATTESTATION}",
            f"rename:{ATTESTATION}",
            "fsync:payload",
            f"stage:{SIGNATURE}",
            f"rename:{SIGNATURE}",
            "fsync:commit",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                destination = self.root / f"crash-{index}"
                destination.mkdir(mode=0o700)
                environment = os.environ.copy()
                environment.update(
                    {
                        "HOLDFAST_TEST_MODE": "1",
                        "HOLDFAST_TEST_PUBLISH_DEATH_BOUNDARY": boundary,
                    }
                )
                crashed = subprocess.run(
                    self.publish_command(self.release, destination),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
                self.assertEqual(crashed.returncode, 79, crashed.stdout + crashed.stderr)
                if boundary not in {f"rename:{SIGNATURE}", "fsync:commit"}:
                    self.assertFalse((destination / SIGNATURE).exists())

                retried = self.run_command(
                    self.publish_command(self.release, destination)
                )
                self.assertEqual(
                    retried.returncode, 0, retried.stdout + retried.stderr
                )
                self.assertEqual(
                    {path.name for path in destination.iterdir()},
                    {ATTESTATION, SIGNATURE, PUBLIC_KEY},
                )
                verified = self.run_command(self.verify_command(destination))
                self.assertEqual(
                    verified.returncode, 0, verified.stdout + verified.stderr
                )

    def test_stage_failure_cleans_identity_and_reserved_name_is_escaped(self) -> None:
        failed_stage = self.root / "failed-stage"
        failed_stage.mkdir(mode=0o700)
        directory = os.open(failed_stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(
                attestation_tool.os,
                "write",
                side_effect=OSError("injected write failure"),
            ):
                with self.assertRaises(OSError):
                    attestation_tool.stage_file(
                        directory, ATTESTATION, b"attestation\n"
                    )
        finally:
            os.close(directory)
        self.assertFalse(any(failed_stage.iterdir()))

        stale = self.release / f".{ATTESTATION}.unsafe\n\x1b.tmp"
        stale.write_bytes(b"stale\n")
        stale.chmod(0o600)
        rejected = self.issue()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("unexpected recovery-completion output", rejected.stderr)
        self.assertNotIn("\x1b", rejected.stderr)
        self.assertNotIn("unsafe\n", rejected.stderr)
        self.assertIn("unsafe\\n\\u001b", rejected.stderr)
        self.assertEqual({path.name for path in self.release.iterdir()}, {stale.name})

    def test_source_key_symlink_hardlink_and_wrong_pair_are_rejected(self) -> None:
        source = self.root / "source-copy.pub"
        source.write_bytes(self.source_public_key.read_bytes())
        source.chmod(0o600)
        self.source_public_key.unlink()
        self.source_public_key.symlink_to(source)
        symlink = self.issue()
        self.assertNotEqual(symlink.returncode, 0)

        self.source_public_key.unlink()
        os.link(source, self.source_public_key)
        hardlink = self.issue()
        self.assertNotEqual(hardlink.returncode, 0)
        self.assertIn("single-link", hardlink.stderr)

        self.source_public_key.unlink()
        second_private = self.root / "second.key"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(second_private),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        second_private.chmod(0o600)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(second_private),
                "-pubout",
                "-out",
                str(self.source_public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.source_public_key.chmod(0o600)
        self.public_key_sha256 = sha256_bytes(self.source_public_key.read_bytes())
        wrong_pair = self.issue()
        self.assertNotEqual(wrong_pair.returncode, 0)
        self.assertIn("do not match", wrong_pair.stderr)

    def test_issue_and_verify_require_a_2048_bit_rsa_modulus(self) -> None:
        small_private, small_public = self.generate_key_pair("small-authority", 1024)
        small_pin = sha256_bytes(small_public.read_bytes())
        command = self.issue_command()
        command[command.index("--private-key") + 1] = str(small_private)
        command[command.index("--source-public-key") + 1] = str(small_public)
        command[command.index("--public-key-sha256") + 1] = small_pin
        rejected_issue = self.run_command(command)
        self.assertNotEqual(rejected_issue.returncode, 0)
        self.assertIn("modulus must be at least 2048 bits", rejected_issue.stderr)
        self.assertFalse(any(self.release.iterdir()))

        issued = self.issue()
        self.assertEqual(issued.returncode, 0, issued.stdout + issued.stderr)
        document = self.canonical_document()
        document["public_key_sha256"] = small_pin
        raw = self.canonical_bytes(document)
        (self.release / ATTESTATION).write_bytes(raw)
        (self.release / SIGNATURE).write_bytes(self.sign_with(raw, small_private))
        (self.release / PUBLIC_KEY).write_bytes(small_public.read_bytes())
        for name in (ATTESTATION, SIGNATURE, PUBLIC_KEY):
            (self.release / name).chmod(0o600)
        rejected_verify = self.run_command(
            self.verify_command(public_key_sha256=small_pin)
        )
        self.assertNotEqual(rejected_verify.returncode, 0)
        self.assertIn("modulus must be at least 2048 bits", rejected_verify.stderr)

        self.tearDown()
        self.setUp()
        accepted_2048 = self.issue()
        self.assertEqual(
            accepted_2048.returncode,
            0,
            accepted_2048.stdout + accepted_2048.stderr,
        )
        verified_2048 = self.run_command(self.verify_command())
        self.assertEqual(
            verified_2048.returncode,
            0,
            verified_2048.stdout + verified_2048.stderr,
        )

    def test_unverified_json_key_and_openssl_errors_are_safely_escaped(self) -> None:
        with self.assertRaises(ValueError) as duplicate:
            attestation_tool.unique_object(
                [("unsafe\n\x1bkey", 1), ("unsafe\n\x1bkey", 2)]
            )
        self.assertNotIn("\x1b", str(duplicate.exception))
        self.assertNotIn("unsafe\n", str(duplicate.exception))
        self.assertIn("\\n\\u001b", str(duplicate.exception))

        failed = subprocess.CompletedProcess(
            args=["openssl"],
            returncode=1,
            stdout=b"",
            stderr=b"unsafe\n\x1b[31mkey",
        )
        with mock.patch.object(attestation_tool.subprocess, "run", return_value=failed):
            with self.assertRaises(ValueError) as openssl_error:
                attestation_tool.run_openssl([], input_bytes=b"", pass_fds=())
        self.assertNotIn("\x1b", str(openssl_error.exception))
        self.assertNotIn("unsafe\n", str(openssl_error.exception))
        self.assertIn("\\n\\u001b", str(openssl_error.exception))

    def test_rsa_pss_key_cannot_issue_pkcs1v15_attestation(self) -> None:
        pss_private = self.root / "authority-pss.key"
        pss_public = self.root / "authority-pss.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA-PSS",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(pss_private),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(pss_private),
                "-pubout",
                "-out",
                str(pss_public),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pss_private.chmod(0o600)
        pss_public.chmod(0o600)
        command = self.issue_command()
        command[command.index("--private-key") + 1] = str(pss_private)
        command[command.index("--source-public-key") + 1] = str(pss_public)
        command[command.index("--public-key-sha256") + 1] = sha256_bytes(
            pss_public.read_bytes()
        )
        rejected = self.run_command(command)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(any(self.release.iterdir()))


if __name__ == "__main__":
    unittest.main()
