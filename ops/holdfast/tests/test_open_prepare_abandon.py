from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


@unittest.skipUnless(os.geteuid() == 0, "root-owned receipt contract requires root")
class OpenPrepareAbandonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.backup = self.root / "successor-backup"
        self.predecessor_backup = self.root / "predecessor-backup"
        for directory in (self.state, self.backup, self.predecessor_backup):
            directory.mkdir(mode=0o700)
        self.successor_authority = self.backup / "successor-authority"
        self.predecessor_runtime = self.predecessor_backup / "runtime"
        self.successor_authority.mkdir(mode=0o700)
        self.predecessor_runtime.mkdir(mode=0o700)

        predecessor_release_sha = self.install_gen4_predecessor()
        self.successor_release = self.backup / "RELEASE-EVIDENCE.json"
        write_private(self.successor_release, '{"release":"successor"}\n')
        self.successor_dry_receipt = self.backup / "DRY-RUN.receipt"
        write_private(self.successor_dry_receipt, "schema_version=2\n")
        self.successor_policy = self.successor_authority / "successor-policy.json"
        policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        policy["predecessor"].update(
            {
                "current_state_sha256": sha256(self.predecessor_current),
                "control_sha256": sha256(self.predecessor_control),
                "apply_receipt_sha256": sha256(self.predecessor_apply),
                "release_evidence_sha256": predecessor_release_sha,
                "runtime_manifest_sha256": sha256(
                    self.predecessor_runtime_manifest
                ),
            }
        )
        write_private(self.successor_policy, json.dumps(policy, sort_keys=True) + "\n")
        self.successor_arm = self.backup / "SUCCESSOR-ARMED.receipt"
        write_private(
            self.successor_arm,
            "\n".join(
                (
                    "schema_version=1",
                    "armed_at=2026-08-29T21:00:00Z",
                    f"estate_root={self.root / 'estate'}",
                    f"successor_backup_dir={self.backup}",
                    "candidate_dry_run_receipt_sha256="
                    f"{sha256(self.successor_dry_receipt)}",
                    "candidate_release_evidence_sha256="
                    f"{sha256(self.successor_release)}",
                    f"successor_policy_sha256={sha256(self.successor_policy)}",
                    "predecessor_current_file=PREDECESSOR-CURRENT.json",
                    f"predecessor_current_sha256={sha256(self.predecessor_current)}",
                    f"predecessor_backup_dir={self.predecessor_backup}",
                    f"predecessor_control_sha256={sha256(self.predecessor_control)}",
                    f"predecessor_apply_receipt_sha256={sha256(self.predecessor_apply)}",
                    f"predecessor_release_evidence_sha256={predecessor_release_sha}",
                    "predecessor_runtime_backup_receipt_sha256="
                    f"{sha256(self.predecessor_runtime_receipt)}",
                    "predecessor_runtime_backup_manifest_sha256="
                    f"{sha256(self.predecessor_runtime_manifest)}",
                    "predecessor_release_generation=4",
                    "release_generation=5",
                    "route_database_state=absent",
                    "public_ipv4_ipv6_closed_status=404",
                    "predecessor_runtime_verified=true",
                    "ingress_opened=false",
                )
            )
            + "\n",
        )

        self.control = self.backup / "CONTROL.sha256"
        write_private(
            self.control,
            "".join(
                f"{sha256(self.backup / name)}  {name}\n"
                for name in (
                    "RELEASE-EVIDENCE.json",
                    "DRY-RUN.receipt",
                    "PREDECESSOR-CURRENT.json",
                    "SUCCESSOR-ARMED.receipt",
                )
            ),
        )
        with self.control.open("a", encoding="utf-8") as handle:
            handle.write(
                f"{sha256(self.successor_policy)}  successor-authority/successor-policy.json\n"
            )

        self.apply_receipt = self.backup / "APPLY.receipt"
        gen5_shared = {
            "closed_verified_at": "2026-08-29T21:30:00Z",
            "release_env_sha256": "d" * 64,
            "render_inputs_sha256": "e" * 64,
            "apply_armed_receipt_sha256": "f" * 64,
            "transaction_sha256": "0" * 64,
            "applied_targets_sha256": "1" * 64,
            "runtime_backup_receipt_sha256": "2" * 64,
            "runtime_backup_manifest_sha256": "3" * 64,
        }
        write_private(
            self.apply_receipt,
            "\n".join(
                (
                    "schema_version=2",
                    "completion_state=applied_ingress_closed",
                    "applied_at=2026-08-29T21:31:00Z",
                    f"closed_verified_at={gen5_shared['closed_verified_at']}",
                    f"estate_root={self.root / 'estate'}",
                    f"backup_dir={self.backup}",
                    f"release_env_sha256={gen5_shared['release_env_sha256']}",
                    f"release_evidence_sha256={sha256(self.successor_release)}",
                    f"render_inputs_sha256={gen5_shared['render_inputs_sha256']}",
                    "apply_armed_receipt_sha256="
                    f"{gen5_shared['apply_armed_receipt_sha256']}",
                    f"control_sha256={sha256(self.control)}",
                    f"transaction_sha256={gen5_shared['transaction_sha256']}",
                    "applied_targets_sha256="
                    f"{gen5_shared['applied_targets_sha256']}",
                    "cargo_gate=passed",
                    "runtime_backup=passed",
                    "closed_bracket=passed",
                    "route_database_state=absent",
                    "public_ipv4_ipv6_closed_status=404",
                    "ingress_opened=false",
                    "services_activated=true",
                    "runtime_verified=true",
                    "successor=true",
                    "successor_armed_receipt=SUCCESSOR-ARMED.receipt",
                    f"successor_armed_receipt_sha256={sha256(self.successor_arm)}",
                    "predecessor_current_file=PREDECESSOR-CURRENT.json",
                    f"predecessor_current_sha256={sha256(self.predecessor_current)}",
                    f"predecessor_backup_dir={self.predecessor_backup}",
                    f"predecessor_control_sha256={sha256(self.predecessor_control)}",
                    f"predecessor_apply_receipt_sha256={sha256(self.predecessor_apply)}",
                    f"predecessor_release_evidence_sha256={predecessor_release_sha}",
                    "predecessor_runtime_backup_receipt_sha256="
                    f"{sha256(self.predecessor_runtime_receipt)}",
                    "predecessor_runtime_backup_manifest_sha256="
                    f"{sha256(self.predecessor_runtime_manifest)}",
                    "predecessor_release_generation=4",
                    "release_generation=5",
                    "runtime_backup_receipt_sha256="
                    f"{gen5_shared['runtime_backup_receipt_sha256']}",
                    "runtime_backup_manifest_sha256="
                    f"{gen5_shared['runtime_backup_manifest_sha256']}",
                )
            )
            + "\n",
        )

        self.current = self.state / "CURRENT.json"
        write_private(
            self.current,
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "applied_ingress_closed",
                    "successor": True,
                    "ingress_opened": False,
                    "route_database_state": "absent",
                    "estate_root": str(self.root / "estate"),
                    "backup_dir": str(self.backup),
                    "predecessor_backup_dir": str(self.predecessor_backup),
                    "predecessor_current_file": "PREDECESSOR-CURRENT.json",
                    "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
                    "predecessor_release_generation": 4,
                    "release_generation": 5,
                    "release_evidence_sha256": sha256(self.successor_release),
                    "control_sha256": sha256(self.control),
                    "apply_receipt_sha256": sha256(self.apply_receipt),
                    "apply_armed_receipt_sha256": gen5_shared[
                        "apply_armed_receipt_sha256"
                    ],
                    "transaction_sha256": gen5_shared["transaction_sha256"],
                    "applied_targets_sha256": gen5_shared[
                        "applied_targets_sha256"
                    ],
                    "closed_verified_at": gen5_shared["closed_verified_at"],
                    "public_ipv4_ipv6_closed_status": 404,
                    "services_activated": True,
                    "runtime_verified": True,
                    "successor_armed_receipt_sha256": sha256(self.successor_arm),
                    "predecessor_current_sha256": sha256(self.predecessor_current),
                    "predecessor_control_sha256": sha256(
                        self.predecessor_control
                    ),
                    "predecessor_apply_receipt_sha256": sha256(
                        self.predecessor_apply
                    ),
                    "predecessor_release_evidence_sha256": predecessor_release_sha,
                    "predecessor_runtime_backup_receipt_sha256": sha256(
                        self.predecessor_runtime_receipt
                    ),
                    "predecessor_runtime_backup_manifest_sha256": sha256(
                        self.predecessor_runtime_manifest
                    ),
                    "runtime_backup_receipt_sha256": gen5_shared[
                        "runtime_backup_receipt_sha256"
                    ],
                    "runtime_backup_manifest_sha256": gen5_shared[
                        "runtime_backup_manifest_sha256"
                    ],
                },
                sort_keys=True,
            )
            + "\n",
        )

        self.prepare = self.state / "OPEN-PREPARE.receipt"
        write_private(
            self.prepare,
            "\n".join(
                (
                    "prepared_at=2026-08-29T20:00:00Z",
                    f"release_evidence_sha256={predecessor_release_sha}",
                    f"open_evidence_sha256={'a' * 64}",
                    "source_grant_id=source-grant-predecessor",
                    "route_state=absent",
                    "public_host=analyze.w33d.xyz",
                    "edge_owner=existing-w33d-sluice",
                    "public_ipv4_ipv6_closed_status=404",
                    "db_public_db_bracket=absent-404-absent",
                    "external_edge_mutation=none",
                )
            )
            + "\n",
        )
        self.prepare_bytes = self.prepare.read_bytes()
        self.prepare_sha = sha256(self.prepare)
        self.reason = self.root / "abandon-reason.sealed"
        write_private(self.reason, "canonical-host-migration-after-successor-apply\n")

    def install_gen4_predecessor(self) -> str:
        estate = self.root / "estate"
        estate.mkdir(mode=0o700)

        gen3_backup = self.root / "gen3-backup"
        gen3_runtime = gen3_backup / "runtime"
        gen3_runtime.mkdir(parents=True, mode=0o700)
        gen3_backup.chmod(0o700)
        gen3_release = gen3_backup / "RELEASE-EVIDENCE.json"
        gen3_runtime_receipt = gen3_runtime / "BACKUP.receipt"
        gen3_runtime_manifest = gen3_runtime / "SHA256SUMS"
        gen3_control = gen3_backup / "CONTROL.sha256"
        write_private(gen3_release, '{"release":"gen3-predecessor"}\n')
        write_private(gen3_runtime_receipt, "schema_version=1\n")
        write_private(
            gen3_runtime_manifest,
            f"{sha256(gen3_runtime_receipt)}  BACKUP.receipt\n",
        )
        write_private(
            gen3_control,
            "".join(
                (
                    f"{sha256(gen3_release)}  RELEASE-EVIDENCE.json\n",
                    f"{sha256(gen3_runtime_receipt)}  runtime/BACKUP.receipt\n",
                    f"{sha256(gen3_runtime_manifest)}  runtime/SHA256SUMS\n",
                )
            ),
        )
        gen3_current = self.predecessor_backup / "PREDECESSOR-CURRENT.json"
        write_private(
            gen3_current,
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "applied_ingress_closed",
                    "estate_root": str(estate),
                    "backup_dir": str(gen3_backup),
                    "control_sha256": sha256(gen3_control),
                    "release_evidence_sha256": sha256(gen3_release),
                    "successor": True,
                    "predecessor_release_generation": 2,
                    "release_generation": 3,
                    "services_activated": True,
                    "runtime_verified": True,
                    "ingress_opened": False,
                },
                sort_keys=True,
            )
            + "\n",
        )

        self.predecessor_release = (
            self.predecessor_backup / "RELEASE-EVIDENCE.json"
        )
        predecessor_release_env = self.predecessor_backup / "release.env"
        predecessor_render_inputs = (
            self.predecessor_backup / "RENDER-INPUTS.sha256"
        )
        predecessor_apply_armed = (
            self.predecessor_backup / "APPLY-ARMED.receipt"
        )
        predecessor_transaction = (
            self.predecessor_backup / "estate/TRANSACTION.json"
        )
        predecessor_applied_targets = (
            self.predecessor_backup / "estate/APPLIED-TARGETS.sha256"
        )
        predecessor_successor_arm = (
            self.predecessor_backup / "SUCCESSOR-ARMED.receipt"
        )
        self.predecessor_runtime_receipt = (
            self.predecessor_runtime / "BACKUP.receipt"
        )
        self.predecessor_runtime_manifest = (
            self.predecessor_runtime / "SHA256SUMS"
        )
        predecessor_completion_attestation = (
            self.predecessor_backup / "RECOVERY-COMPLETION-ATTESTATION.json"
        )
        predecessor_completion_signature = (
            self.predecessor_backup / "RECOVERY-COMPLETION-ATTESTATION.sig"
        )
        predecessor_completion_public_key = (
            self.predecessor_backup / "RECOVERY-COMPLETION-ATTESTATION.pub"
        )
        predecessor_transaction.parent.mkdir(mode=0o700)
        for path, content in (
            (self.predecessor_release, '{"release":"gen4-predecessor"}\n'),
            (predecessor_release_env, "HOLDFAST_RELEASE=gen4\n"),
            (predecessor_render_inputs, f"{'a' * 64}  release.env\n"),
            (predecessor_apply_armed, "schema_version=1\n"),
            (predecessor_transaction, '{"state":"committed"}\n'),
            (predecessor_applied_targets, f"{'b' * 64}  target\n"),
            (predecessor_successor_arm, "schema_version=1\n"),
            (self.predecessor_runtime_receipt, "schema_version=1\n"),
            (
                predecessor_completion_attestation,
                '{"kind":"recovery-completion-attestation-v1"}\n',
            ),
            (predecessor_completion_signature, "fixture-signature\n"),
            (predecessor_completion_public_key, "fixture-public-key\n"),
        ):
            write_private(path, content)
        write_private(
            self.predecessor_runtime_manifest,
            f"{sha256(self.predecessor_runtime_receipt)}  BACKUP.receipt\n",
        )

        self.predecessor_control = self.predecessor_backup / "CONTROL.sha256"
        predecessor_control_artifacts = (
            self.predecessor_release,
            predecessor_release_env,
            predecessor_render_inputs,
            predecessor_apply_armed,
            predecessor_transaction,
            predecessor_applied_targets,
            predecessor_successor_arm,
            self.predecessor_runtime_receipt,
            self.predecessor_runtime_manifest,
            gen3_current,
            predecessor_completion_attestation,
            predecessor_completion_signature,
            predecessor_completion_public_key,
        )
        write_private(
            self.predecessor_control,
            "".join(
                f"{sha256(path)}  {path.relative_to(self.predecessor_backup)}\n"
                for path in predecessor_control_artifacts
            ),
        )

        apply_values = {
            "schema_version": "2",
            "completion_state": "applied_ingress_closed",
            "applied_at": "2026-08-29T20:40:00Z",
            "closed_verified_at": "2026-08-29T20:40:45Z",
            "estate_root": str(estate),
            "backup_dir": str(self.predecessor_backup),
            "release_env_sha256": sha256(predecessor_release_env),
            "release_evidence_sha256": sha256(self.predecessor_release),
            "render_inputs_sha256": sha256(predecessor_render_inputs),
            "apply_armed_receipt_sha256": sha256(predecessor_apply_armed),
            "control_sha256": sha256(self.predecessor_control),
            "transaction_sha256": sha256(predecessor_transaction),
            "applied_targets_sha256": sha256(predecessor_applied_targets),
            "cargo_gate": "passed",
            "runtime_backup": "passed",
            "closed_bracket": "passed",
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": "404",
            "ingress_opened": "false",
            "services_activated": "true",
            "runtime_verified": "true",
            "successor": "true",
            "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
            "successor_armed_receipt_sha256": sha256(
                predecessor_successor_arm
            ),
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": sha256(gen3_current),
            "predecessor_backup_dir": str(gen3_backup),
            "predecessor_control_sha256": sha256(gen3_control),
            "predecessor_completion_kind": (
                "recovery-completion-attestation-v1"
            ),
            "predecessor_completion_attestation_sha256": sha256(
                predecessor_completion_attestation
            ),
            "predecessor_completion_signature_sha256": sha256(
                predecessor_completion_signature
            ),
            "predecessor_completion_public_key_sha256": sha256(
                predecessor_completion_public_key
            ),
            "predecessor_release_evidence_sha256": sha256(gen3_release),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                gen3_runtime_receipt
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                gen3_runtime_manifest
            ),
            "predecessor_release_generation": "3",
            "release_generation": "4",
            "runtime_backup_receipt_sha256": sha256(
                self.predecessor_runtime_receipt
            ),
            "runtime_backup_manifest_sha256": sha256(
                self.predecessor_runtime_manifest
            ),
        }
        self.predecessor_apply = self.predecessor_backup / "APPLY.receipt"
        write_private(
            self.predecessor_apply,
            "".join(f"{key}={value}\n" for key, value in apply_values.items()),
        )

        self.predecessor_current = self.backup / "PREDECESSOR-CURRENT.json"
        current_values = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "estate_root": str(estate),
            "backup_dir": str(self.predecessor_backup),
            "apply_receipt_sha256": sha256(self.predecessor_apply),
            "apply_armed_receipt_sha256": apply_values[
                "apply_armed_receipt_sha256"
            ],
            "control_sha256": apply_values["control_sha256"],
            "release_evidence_sha256": apply_values[
                "release_evidence_sha256"
            ],
            "transaction_sha256": apply_values["transaction_sha256"],
            "applied_targets_sha256": apply_values[
                "applied_targets_sha256"
            ],
            "closed_verified_at": apply_values["closed_verified_at"],
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": 404,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
            "successor": True,
            "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
            "successor_armed_receipt_sha256": apply_values[
                "successor_armed_receipt_sha256"
            ],
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": apply_values[
                "predecessor_current_sha256"
            ],
            "predecessor_backup_dir": str(gen3_backup),
            "predecessor_control_sha256": apply_values[
                "predecessor_control_sha256"
            ],
            "predecessor_completion_kind": apply_values[
                "predecessor_completion_kind"
            ],
            "predecessor_completion_attestation_sha256": apply_values[
                "predecessor_completion_attestation_sha256"
            ],
            "predecessor_completion_signature_sha256": apply_values[
                "predecessor_completion_signature_sha256"
            ],
            "predecessor_completion_public_key_sha256": apply_values[
                "predecessor_completion_public_key_sha256"
            ],
            "predecessor_release_evidence_sha256": apply_values[
                "predecessor_release_evidence_sha256"
            ],
            "predecessor_runtime_backup_receipt_sha256": apply_values[
                "predecessor_runtime_backup_receipt_sha256"
            ],
            "predecessor_runtime_backup_manifest_sha256": apply_values[
                "predecessor_runtime_backup_manifest_sha256"
            ],
            "predecessor_release_generation": 3,
            "release_generation": 4,
            "runtime_backup_receipt_sha256": apply_values[
                "runtime_backup_receipt_sha256"
            ],
            "runtime_backup_manifest_sha256": apply_values[
                "runtime_backup_manifest_sha256"
            ],
        }
        write_private(
            self.predecessor_current,
            json.dumps(current_values, sort_keys=True) + "\n",
        )
        return sha256(self.predecessor_release)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_abandon(
        self, **environment: str
    ) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_LOCK_PATH": str(self.root / "holdfast.lock"),
            **environment,
        }
        env.pop("ROUTES_DATABASE_URL", None)
        return subprocess.run(
            [
                str(OPS_ROOT / "open-ingress.sh"),
                "--execute",
                "--abandon-prepare",
                "--reason-file",
                str(self.reason),
                "--state-dir",
                str(self.state),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def refresh_successor_bindings(self) -> None:
        write_private(
            self.control,
            "".join(
                f"{sha256(self.backup / name)}  {name}\n"
                for name in (
                    "RELEASE-EVIDENCE.json",
                    "DRY-RUN.receipt",
                    "PREDECESSOR-CURRENT.json",
                    "SUCCESSOR-ARMED.receipt",
                )
            )
            + f"{sha256(self.successor_policy)}  successor-authority/successor-policy.json\n",
        )
        apply_values = dict(
            line.split("=", 1)
            for line in self.apply_receipt.read_text(encoding="utf-8").splitlines()
        )
        apply_values["control_sha256"] = sha256(self.control)
        apply_values["successor_armed_receipt_sha256"] = sha256(
            self.successor_arm
        )
        write_private(
            self.apply_receipt,
            "".join(f"{key}={value}\n" for key, value in apply_values.items()),
        )
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["control_sha256"] = sha256(self.control)
        current["apply_receipt_sha256"] = sha256(self.apply_receipt)
        current["successor_armed_receipt_sha256"] = sha256(self.successor_arm)
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")

    def final_artifacts(self) -> tuple[Path, Path]:
        archives = list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt"))
        supersedes = list(self.state.glob("OPEN-PREPARE-SUPERSEDED-*.receipt"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(len(supersedes), 1)
        return archives[0], supersedes[0]

    def test_abandon_archives_original_and_replays_byte_exact(self) -> None:
        abandoned = self.run_abandon()
        self.assertEqual(abandoned.returncode, 0, abandoned.stdout + abandoned.stderr)
        self.assertFalse(self.prepare.exists())
        archive, supersede = self.final_artifacts()
        self.assertEqual(archive.read_bytes(), self.prepare_bytes)
        self.assertEqual(sha256(archive), self.prepare_sha)

        receipt = dict(
            line.split("=", 1)
            for line in supersede.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(receipt["source_prepare_receipt_sha256"], self.prepare_sha)
        self.assertEqual(receipt["archive_sha256"], self.prepare_sha)
        self.assertEqual(receipt["source_prepare_schema"], "legacy-analyze-v2")
        self.assertEqual(receipt["source_public_host"], "analyze.w33d.xyz")
        self.assertEqual(receipt["predecessor_release_generation"], "4")
        self.assertEqual(receipt["successor_release_generation"], "5")
        self.assertEqual(
            receipt["authority_binding"],
            "frozen-successor-current-hash-chain",
        )
        self.assertEqual(
            receipt["predecessor_control_sha256"],
            sha256(self.predecessor_control),
        )
        self.assertEqual(
            receipt["predecessor_apply_receipt_sha256"],
            sha256(self.predecessor_apply),
        )
        self.assertEqual(
            receipt["successor_policy_sha256"], sha256(self.successor_policy)
        )
        self.assertEqual(receipt["reason_file_sha256"], sha256(self.reason))
        self.assertNotIn(self.reason.read_text(encoding="utf-8").strip(), supersede.read_text(encoding="utf-8"))

        frozen = {path: path.read_bytes() for path in (archive, supersede)}
        replay = self.run_abandon()
        self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
        for path, content in frozen.items():
            self.assertEqual(path.read_bytes(), content)

    def test_rejects_conflicting_archive_or_supersede_replay(self) -> None:
        abandoned = self.run_abandon()
        self.assertEqual(abandoned.returncode, 0, abandoned.stdout + abandoned.stderr)
        archive, supersede = self.final_artifacts()
        archive_bytes = archive.read_bytes()
        supersede_bytes = supersede.read_bytes()

        write_private(archive, archive_bytes.decode("utf-8") + "conflict=true\n")
        archive_conflict = self.run_abandon()
        self.assertNotEqual(archive_conflict.returncode, 0)

        write_private(archive, archive_bytes.decode("utf-8"))
        write_private(
            supersede,
            supersede_bytes.decode("utf-8").replace(
                f"reason_file_sha256={sha256(self.reason)}",
                f"reason_file_sha256={'f' * 64}",
            ),
        )
        receipt_conflict = self.run_abandon()
        self.assertNotEqual(receipt_conflict.returncode, 0)

    def test_rejects_live_pointer_with_completed_supersede(self) -> None:
        abandoned = self.run_abandon()
        self.assertEqual(abandoned.returncode, 0, abandoned.stdout + abandoned.stderr)
        archive, supersede = self.final_artifacts()
        archive_bytes = archive.read_bytes()
        supersede_bytes = supersede.read_bytes()
        write_private(self.prepare, archive_bytes.decode("utf-8"))

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("cannot coexist with a supersede receipt", rejected.stderr)
        self.assertEqual(archive.read_bytes(), archive_bytes)
        self.assertEqual(supersede.read_bytes(), supersede_bytes)
        self.assertEqual(self.prepare.read_bytes(), archive_bytes)

    def test_accepts_exact_rikune_v3_predecessor_receipt(self) -> None:
        write_private(
            self.prepare,
            "\n".join(
                (
                    "schema_version=3",
                    "prepared_at=2026-08-29T20:00:00Z",
                    "release_generation=4",
                    f"release_evidence_sha256={sha256(self.predecessor_release)}",
                    f"open_evidence_sha256={'a' * 64}",
                    "source_grant_id=source-grant-predecessor",
                    "route_state=absent",
                    "public_host=rikune.w33d.xyz",
                    "legacy_public_host=analyze.w33d.xyz",
                    "legacy_route_state=absent",
                    "legacy_public_ipv4_ipv6_closed_status=404",
                    "edge_owner=existing-w33d-sluice",
                    "public_ipv4_ipv6_closed_status=404",
                    "db_public_db_bracket=absent-404-absent",
                    "external_edge_mutation=none",
                )
            )
            + "\n",
        )
        abandoned = self.run_abandon()
        self.assertEqual(abandoned.returncode, 0, abandoned.stdout + abandoned.stderr)
        _, supersede = self.final_artifacts()
        receipt = dict(
            line.split("=", 1)
            for line in supersede.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(receipt["source_prepare_schema"], "rikune-v3")
        self.assertEqual(receipt["source_public_host"], "rikune.w33d.xyz")

    def test_requires_exact_gen5_successor_generation(self) -> None:
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["release_generation"] = 6
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("exact closed successor CURRENT", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_schema4_arm_requires_successor_policy_hash(self) -> None:
        lines = self.successor_arm.read_text(encoding="utf-8").splitlines()
        write_private(
            self.successor_arm,
            "\n".join(
                line
                for line in lines
                if not line.startswith("successor_policy_sha256=")
            )
            + "\n",
        )
        self.refresh_successor_bindings()
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("field set is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_schema4_arm_requires_predecessor_apply_hash(self) -> None:
        lines = self.successor_arm.read_text(encoding="utf-8").splitlines()
        write_private(
            self.successor_arm,
            "\n".join(
                line
                for line in lines
                if not line.startswith("predecessor_apply_receipt_sha256=")
            )
            + "\n",
        )
        self.refresh_successor_bindings()
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("field set is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_schema4_arm_rejects_completion_namespace(self) -> None:
        write_private(
            self.successor_arm,
            self.successor_arm.read_text(encoding="utf-8")
            + "predecessor_completion_kind=recovery-completion-attestation-v1\n",
        )
        self.refresh_successor_bindings()
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("field set is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_schema4_current_rejects_completion_namespace(self) -> None:
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["predecessor_completion_kind"] = (
            "recovery-completion-attestation-v1"
        )
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("exact closed successor CURRENT", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_schema4_current_rejects_unknown_namespace(self) -> None:
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["unexpected_authority"] = "forbidden"
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("authority namespace is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_schema4_rejects_frozen_current_apply_hash_mismatch_before_archive(
        self,
    ) -> None:
        predecessor_current = json.loads(
            self.predecessor_current.read_text(encoding="utf-8")
        )
        predecessor_current["apply_receipt_sha256"] = "0" * 64
        write_private(
            self.predecessor_current,
            json.dumps(predecessor_current, sort_keys=True) + "\n",
        )
        predecessor_current_sha = sha256(self.predecessor_current)

        policy = json.loads(self.successor_policy.read_text(encoding="utf-8"))
        policy["predecessor"]["current_state_sha256"] = predecessor_current_sha
        write_private(
            self.successor_policy,
            json.dumps(policy, sort_keys=True) + "\n",
        )

        arm_values = dict(
            line.split("=", 1)
            for line in self.successor_arm.read_text(
                encoding="utf-8"
            ).splitlines()
        )
        arm_values["predecessor_current_sha256"] = predecessor_current_sha
        arm_values["successor_policy_sha256"] = sha256(self.successor_policy)
        write_private(
            self.successor_arm,
            "".join(f"{key}={value}\n" for key, value in arm_values.items()),
        )

        apply_values = dict(
            line.split("=", 1)
            for line in self.apply_receipt.read_text(
                encoding="utf-8"
            ).splitlines()
        )
        apply_values["predecessor_current_sha256"] = predecessor_current_sha
        write_private(
            self.apply_receipt,
            "".join(f"{key}={value}\n" for key, value in apply_values.items()),
        )
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["predecessor_current_sha256"] = predecessor_current_sha
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")
        self.refresh_successor_bindings()

        live_pointer = self.prepare.read_bytes()
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(
            "schema-v4 predecessor CURRENT/APPLY lineage differs",
            rejected.stderr,
        )
        self.assertEqual(self.prepare.read_bytes(), live_pointer)
        self.assertEqual(
            list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), []
        )
        self.assertEqual(
            list(self.state.glob("OPEN-PREPARE-SUPERSEDED-*.receipt")), []
        )
        self.assertEqual(
            list(self.state.glob(".OPEN-PREPARE-SUPERSEDED-*.pending")), []
        )

    def test_schema4_apply_rejects_completion_namespace(self) -> None:
        write_private(
            self.apply_receipt,
            self.apply_receipt.read_text(encoding="utf-8")
            + "predecessor_completion_kind=recovery-completion-attestation-v1\n",
        )
        self.refresh_successor_bindings()
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("authority namespace is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_requires_distinct_predecessor_and_successor_release_hashes(self) -> None:
        old_successor_sha = sha256(self.successor_release)
        write_private(
            self.successor_release,
            self.predecessor_release.read_text(encoding="utf-8"),
        )
        successor_sha = sha256(self.successor_release)
        write_private(
            self.successor_arm,
            self.successor_arm.read_text(encoding="utf-8").replace(
                f"candidate_release_evidence_sha256={old_successor_sha}",
                f"candidate_release_evidence_sha256={successor_sha}",
            ),
        )
        apply_values = dict(
            line.split("=", 1)
            for line in self.apply_receipt.read_text(encoding="utf-8").splitlines()
        )
        apply_values["release_evidence_sha256"] = successor_sha
        write_private(
            self.apply_receipt,
            "".join(f"{key}={value}\n" for key, value in apply_values.items()),
        )
        self.refresh_successor_bindings()
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["release_evidence_sha256"] = successor_sha
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("lineage is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_archive_move_crash_recovers_without_overwrite(self) -> None:
        interrupted = self.run_abandon(
            HOLDFAST_TEST_STOP_AFTER_PREPARE_ARCHIVE_MOVE="1"
        )
        self.assertEqual(interrupted.returncode, 75, interrupted.stdout + interrupted.stderr)
        self.assertFalse(self.prepare.exists())
        archives = list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), self.prepare_bytes)
        pending = list(self.state.glob(".OPEN-PREPARE-SUPERSEDED-*.pending"))
        self.assertEqual(len(pending), 1)

        recovered = self.run_abandon()
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        archive, supersede = self.final_artifacts()
        self.assertEqual(archive.read_bytes(), self.prepare_bytes)
        self.assertFalse(pending[0].exists())
        self.assertEqual(
            dict(
                line.split("=", 1)
                for line in supersede.read_text(encoding="utf-8").splitlines()
            )["source_prepare_receipt_sha256"],
            self.prepare_sha,
        )

    def test_rejects_hybrid_receipt_without_moving_original(self) -> None:
        with self.prepare.open("a", encoding="utf-8") as handle:
            handle.write("release_generation=2\n")
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("hybrid", rejected.stderr)
        self.assertTrue(self.prepare.is_file())
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), [])

    def test_rejects_final_open_receipt_hybrid(self) -> None:
        write_private(self.state / "OPEN.receipt", "route_state=present\n")
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("hybrid final OPEN receipt", rejected.stderr)
        self.assertTrue(self.prepare.is_file())
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), [])

    def test_rejects_non_predecessor_release_and_unsealed_reason(self) -> None:
        original = self.prepare.read_text(encoding="utf-8")
        self.prepare.write_text(
            original.replace(
                f"release_evidence_sha256={sha256(self.predecessor_release)}",
                f"release_evidence_sha256={sha256(self.successor_release)}",
            ),
            encoding="utf-8",
        )
        self.prepare.chmod(0o600)
        wrong_release = self.run_abandon()
        self.assertNotEqual(wrong_release.returncode, 0)
        self.assertIn("immediate predecessor release", wrong_release.stderr)
        self.assertTrue(self.prepare.is_file())

        write_private(self.prepare, original)
        self.reason.chmod(0o644)
        unsealed = self.run_abandon()
        self.assertNotEqual(unsealed.returncode, 0)
        self.assertIn("mode 0600", unsealed.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_rejects_mixed_abandon_and_open_invocation(self) -> None:
        for extra in (
            ("--phase", "prepare"),
            ("--phase", ""),
            ("--estate-root", ""),
        ):
            with self.subTest(extra=extra):
                mixed = subprocess.run(
                    [
                        str(OPS_ROOT / "open-ingress.sh"),
                        "--execute",
                        "--abandon-prepare",
                        "--reason-file",
                        str(self.reason),
                        *extra,
                        "--state-dir",
                        str(self.state),
                    ],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(mixed.returncode, 2)
        self.assertTrue(self.prepare.is_file())


if __name__ == "__main__":
    unittest.main()
