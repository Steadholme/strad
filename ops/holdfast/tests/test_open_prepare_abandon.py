from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
GEN1_CONTROL_NAMES = (
    "APPLY-ABSENT.paths",
    "APPLY-ARMED.receipt",
    "APPLY-PREIMAGES.sha256",
    "DRY-RUN.receipt",
    "RELEASE-EVIDENCE.json",
    "RENDER-INPUTS.sha256",
    "RUNTIME-BACKUP-CALLER-ARMED.receipt",
    "SUPPLY-CHAIN.json",
    "SUPPLY-CHAIN.pub",
    "SUPPLY-CHAIN.sig",
    "TARGETS.sha256",
    "release.env",
    "rollback.override.yml",
    "runtime/BACKUP.receipt",
    "runtime/RUNNING-SERVICES.before",
    "runtime/RUNTIME-BACKUP-ARMED.receipt",
    "runtime/SHA256SUMS",
)
GEN2_CONTROL_EXTRA = (
    "PREDECESSOR-CURRENT.json",
    "SUCCESSOR-ARMED.receipt",
    "SUCCESSOR-DELTA.sha256",
    "successor-authority/Dockerfile.analyzer",
    "successor-authority/bridge-package-lock.json",
    "successor-authority/assets/20260823_rikune_root_up.sql",
    "successor-authority/assets/20260823_rikune_root_down.sql",
    "successor-authority/successor-absent.paths",
    "successor-authority/successor-frozen-targets.json",
    "successor-authority/successor-policy.json",
    "successor-authority/successor-preimages.sha256",
    "successor-authority/successor-static-targets.sha256",
    "successor-authority/successor-supporting-targets.sha256",
)
GEN1_RUNTIME_NAMES = (
    "RUNNING-SERVICES.before",
    "RUNTIME-BACKUP-ARMED.receipt",
    "VOLUMES.tsv",
    "compose-config.json",
    "strad.dump",
)
GEN2_RUNTIME_EXTRA = (
    "rikune_audit.tar",
    "rikune_cache.tar",
    "rikune_state.tar",
    "rikune_storage.tar",
    "rikune_workspaces.tar",
    "strad_uploads.tar",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def write_receipt(path: Path, values: dict[str, object]) -> None:
    write_private(path, "".join(f"{key}={value}\n" for key, value in values.items()))


def write_manifest(path: Path, root: Path, names: tuple[str, ...]) -> None:
    write_private(
        path,
        "".join(f"{sha256(root / name)}  {name}\n" for name in names),
    )


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
        policy["schema_version"] = 4
        policy["ceremony"] = "holdfast-rikune-successor-v4"
        policy["predecessor"].pop("recovery_completion", None)
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
        if hasattr(self, "historical_release_validator"):
            env["HOLDFAST_HISTORICAL_RELEASE_VALIDATOR_BIN"] = str(
                self.historical_release_validator
            )
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

    def install_recovered_resume_authority(self) -> None:
        self.normal_apply_bytes = self.apply_receipt.read_bytes()
        self.apply_receipt.unlink()
        successor_runtime = self.backup / "runtime"
        successor_estate = self.backup / "estate"
        successor_runtime.mkdir(mode=0o700)
        successor_estate.mkdir(mode=0o700)
        self.successor_apply_armed = self.backup / "APPLY-ARMED.receipt"
        self.successor_runtime_caller = (
            self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        )
        self.successor_runtime_stop = (
            successor_runtime / "RUNTIME-BACKUP-ARMED.receipt"
        )
        self.successor_transaction = successor_estate / "TRANSACTION.json"
        self.successor_applied_targets = (
            successor_estate / "APPLIED-TARGETS.sha256"
        )
        for path, content in (
            (self.successor_apply_armed, "schema_version=1\narmed_at=2026-08-29T21:29:00Z\n"),
            (self.successor_runtime_caller, "schema_version=2\n"),
            (self.successor_runtime_stop, "schema_version=2\n"),
            (self.successor_transaction, '{"schema_version":1,"state":"applied"}\n'),
            (self.successor_applied_targets, f"{'b' * 64}  target\n"),
        ):
            write_private(path, content)

        self.recovery_attempt = "20260829T213200Z-4242"
        self.recovery_failure = (
            self.state / "APPLY-ACTIVATION-FAILED-20260829T213100Z-4141.receipt"
        )
        failure_values = {
            "failed_at": "2026-08-29T21:31:00Z",
            "phase": "activation",
            "activation_step": "runtime_verify",
            "status": "1",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(self.backup),
            "apply_armed_receipt_sha256": sha256(self.successor_apply_armed),
            "control_sha256": sha256(self.control),
            "transaction_sha256": sha256(self.successor_transaction),
            "ingress_opened": "false",
        }
        write_private(
            self.recovery_failure,
            "".join(f"{key}={value}\n" for key, value in failure_values.items()),
        )

        route_values = {
            "route_state": "absent",
            "route_conflict_cleanup": "same-name-or-rikune-root-or-analyze-host",
            "public_host": "rikune.w33d.xyz",
            "public_ipv4_ipv6_closed_status": "404",
            "legacy_public_host": "analyze.w33d.xyz",
            "legacy_route_state": "absent",
            "legacy_public_ipv4_ipv6_closed_status": "404",
            "db_public_db_bracket": "absent-404-absent",
        }
        lineage_values = {
            "successor": "true",
            "successor_armed_receipt_sha256": sha256(self.successor_arm),
            "predecessor_current_sha256": sha256(self.predecessor_current),
            "predecessor_backup_dir": str(self.predecessor_backup),
            "predecessor_control_sha256": sha256(self.predecessor_control),
            "predecessor_apply_receipt_sha256": sha256(self.predecessor_apply),
            "predecessor_release_evidence_sha256": sha256(
                self.predecessor_release
            ),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                self.predecessor_runtime_receipt
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                self.predecessor_runtime_manifest
            ),
            "predecessor_release_generation": "4",
            "release_generation": "5",
        }
        self.recovery_arm = (
            self.state
            / f"APPLY-RECOVERY-ARMED-{self.recovery_attempt}.receipt"
        )
        recovery_arm_values = {
            "schema_version": "3",
            "armed_at": "2026-08-29T21:32:00Z",
            "attempt_id": self.recovery_attempt,
            "mode": "resume",
            "prior_state": "apply_activation_failed",
            "legacy_orphan_adopted": "false",
            "legacy_empty_strad": "false",
            "runtime_backup_schema": "2",
            "estate_transaction_state": "applied",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(self.backup),
            "control_sha256": sha256(self.control),
            "transaction_sha256": sha256(self.successor_transaction),
            "applied_targets_sha256": sha256(self.successor_applied_targets),
            "apply_armed_receipt_sha256": sha256(self.successor_apply_armed),
            "release_evidence_sha256": sha256(self.successor_release),
            "dry_run_receipt_sha256": sha256(self.successor_dry_receipt),
            "live_disposition": "applied",
            "restore_running_writers_manifest": "not-applicable",
            "restore_running_writers_sha256": "none",
            "writer_set_reconciled": "false",
            "writer_set_source_attempt": "none",
            "writer_set_source_failure_receipt_sha256": "none",
            "writer_set_source_state_sha256": "none",
            "writer_set_source_manifest_sha256": "none",
            "writer_set_preimage_compose_sha256": "none",
            "writer_set_quarantined": "none",
            "pre_restored_retry": "false",
            "pre_restored_source_attempt": "none",
            "pre_restored_runtime_snapshot_sha256": "none",
            "pre_restored_estate_snapshot_sha256": "none",
            "pre_restored_superseded_attempt": "none",
            "pre_restored_superseded_failure_receipt_sha256": "none",
            "pre_restored_superseded_state_sha256": "none",
            "pre_restored_runtime_disposition": "not-applicable",
            **route_values,
            **lineage_values,
        }
        write_private(
            self.recovery_arm,
            "".join(
                f"{key}={value}\n" for key, value in recovery_arm_values.items()
            ),
        )

        self.recovery_receipt = (
            self.state
            / f"APPLY-RECOVERY-COMPLETE-{self.recovery_attempt}.receipt"
        )
        recovery_receipt_values = {
            "schema_version": "3",
            "completed_at": "2026-08-29T21:33:00Z",
            "attempt_id": self.recovery_attempt,
            "mode": "resume",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(self.backup),
            "control_sha256": sha256(self.control),
            "original_estate_transaction_state": "applied",
            "original_estate_transaction_sha256": sha256(
                self.successor_transaction
            ),
            "applied_targets_sha256": sha256(self.successor_applied_targets),
            "legacy_empty_strad": "false",
            "recovery_armed_receipt_sha256": sha256(self.recovery_arm),
            "release_evidence_sha256": sha256(self.successor_release),
            "dry_run_receipt_sha256": sha256(self.successor_dry_receipt),
            "runtime_restore_receipt_sha256": "none",
            "estate_restore_state_sha256": "none",
            "pre_restored_retry": "false",
            "pre_restored_source_attempt": "none",
            "pre_restored_superseded_attempt": "none",
            "pre_restored_superseded_failure_receipt_sha256": "none",
            "pre_restored_superseded_state_sha256": "none",
            "pre_restored_runtime_disposition": "not-applicable",
            "restore_running_writers_manifest": "not-applicable",
            "restore_running_writers_sha256": "none",
            "writer_set_reconciled": "false",
            "writer_set_source_attempt": "none",
            "writer_set_source_failure_receipt_sha256": "none",
            "writer_set_source_state_sha256": "none",
            "writer_set_source_manifest_sha256": "none",
            "writer_set_preimage_compose_sha256": "none",
            "writer_set_quarantined": "none",
            "writers_reactivated": "not-applicable",
            "uncaptured_writers_inactive": "not-applicable",
            "quarantined_writers_inactive": "not-applicable",
            "runtime_verified": "passed",
            "live_estate_disposition": "applied",
            **route_values,
            "apply_receipt_created": "false",
            **lineage_values,
        }
        write_private(
            self.recovery_receipt,
            "".join(
                f"{key}={value}\n" for key, value in recovery_receipt_values.items()
            ),
        )

        self.recovery_archive = (
            self.state / f"APPLY-RECOVERY-COMPLETE-{self.recovery_attempt}.json"
        )
        archive_values: dict[str, object] = {
            "schema_version": 2,
            "state": "apply_recovered_resumed",
            "apply_armed_at": "2026-08-29T21:29:00Z",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(self.backup),
            "apply_armed_receipt_sha256": sha256(self.successor_apply_armed),
            "release_evidence_sha256": sha256(self.successor_release),
            "dry_run_receipt_sha256": sha256(self.successor_dry_receipt),
            "control_sha256": sha256(self.control),
            "runtime_backup_caller_armed_sha256": sha256(
                self.successor_runtime_caller
            ),
            "runtime_backup_stop_authority_sha256": sha256(
                self.successor_runtime_stop
            ),
            "ingress_opened": False,
            "successor": True,
            "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
            "successor_armed_receipt_sha256": sha256(self.successor_arm),
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": sha256(self.predecessor_current),
            "predecessor_backup_dir": str(self.predecessor_backup),
            "predecessor_control_sha256": sha256(self.predecessor_control),
            "predecessor_apply_receipt_sha256": sha256(self.predecessor_apply),
            "predecessor_release_evidence_sha256": sha256(
                self.predecessor_release
            ),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                self.predecessor_runtime_receipt
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                self.predecessor_runtime_manifest
            ),
            "predecessor_release_generation": 4,
            "release_generation": 5,
            "apply_failure_receipt": self.recovery_failure.name,
            "apply_failure_receipt_sha256": sha256(self.recovery_failure),
            "recovery_prior_state": "apply_activation_failed",
            "recovery_mode": "resume",
            "recovery_attempt_id": self.recovery_attempt,
            "recovery_armed_receipt": self.recovery_arm.name,
            "recovery_armed_receipt_sha256": sha256(self.recovery_arm),
            "restore_running_writers_manifest": "not-applicable",
            "restore_running_writers_sha256": "none",
            "legacy_empty_strad": False,
            "pre_restored_retry": False,
            "pre_restored_source_attempt": "none",
            "pre_restored_runtime_snapshot_sha256": "none",
            "pre_restored_estate_snapshot_sha256": "none",
            "pre_restored_superseded_attempt": "none",
            "pre_restored_superseded_failure_receipt_sha256": "none",
            "pre_restored_superseded_state_sha256": "none",
            "pre_restored_runtime_disposition": "not-applicable",
            "writer_set_reconciled": False,
            "writer_set_source_attempt": "none",
            "writer_set_source_failure_receipt_sha256": "none",
            "writer_set_source_state_sha256": "none",
            "writer_set_source_manifest_sha256": "none",
            "writer_set_preimage_compose_sha256": "none",
            "writer_set_quarantined": "none",
            "transaction_sha256": sha256(self.successor_transaction),
            "applied_targets_sha256": sha256(self.successor_applied_targets),
            "recovery_receipt": self.recovery_receipt.name,
            "recovery_receipt_sha256": sha256(self.recovery_receipt),
        }
        write_private(
            self.recovery_archive,
            json.dumps(archive_values, sort_keys=True) + "\n",
        )
        current_values = {
            **archive_values,
            "state": "applied_ingress_closed",
            "services_activated": True,
            "runtime_verified": True,
        }
        write_private(self.current, json.dumps(current_values, sort_keys=True) + "\n")

    def install_historical_gen1_anchor(self) -> dict[str, object]:
        backup = self.root / "historical-gen1-backup"
        runtime = backup / "runtime"
        estate = backup / "estate"
        runtime.mkdir(parents=True, mode=0o700)
        estate.mkdir(mode=0o700)
        backup.chmod(0o700)
        release_env = backup / "release.env"
        release = backup / "RELEASE-EVIDENCE.json"
        apply_armed = backup / "APPLY-ARMED.receipt"
        transaction = estate / "TRANSACTION.json"
        targets = estate / "APPLIED-TARGETS.sha256"
        runtime_receipt = runtime / "BACKUP.receipt"
        runtime_manifest = runtime / "SHA256SUMS"
        write_private(release_env, "HOLDFAST_RELEASE=historical-gen1\n")
        write_private(
            release,
            json.dumps({"release_env_sha256": sha256(release_env)}, sort_keys=True)
            + "\n",
        )
        write_private(apply_armed, "schema_version=1\n")
        write_private(transaction, '{"state":"applied"}\n')
        write_private(targets, f"{'1' * 64}  gen1-target\n")
        write_private(runtime_receipt, "schema_version=1\n")
        for relative in (
            "APPLY-ABSENT.paths",
            "APPLY-PREIMAGES.sha256",
            "DRY-RUN.receipt",
            "RENDER-INPUTS.sha256",
            "RUNTIME-BACKUP-CALLER-ARMED.receipt",
            "SUPPLY-CHAIN.json",
            "SUPPLY-CHAIN.pub",
            "SUPPLY-CHAIN.sig",
            "TARGETS.sha256",
            "rollback.override.yml",
            "runtime/RUNNING-SERVICES.before",
            "runtime/RUNTIME-BACKUP-ARMED.receipt",
            "runtime/VOLUMES.tsv",
            "runtime/compose-config.json",
            "runtime/strad.dump",
        ):
            write_private(backup / relative, f"fixture={relative}\n")
        write_manifest(runtime_manifest, runtime, GEN1_RUNTIME_NAMES)
        control = backup / "CONTROL.sha256"
        write_manifest(control, backup, GEN1_CONTROL_NAMES)
        apply = backup / "APPLY.receipt"
        apply_values = {
            "schema_version": "2",
            "completion_state": "applied_ingress_closed",
            "applied_at": "2026-08-29T19:00:00Z",
            "closed_verified_at": "2026-08-29T19:00:30Z",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(backup),
            "release_env_sha256": sha256(release_env),
            "release_evidence_sha256": sha256(release),
            "render_inputs_sha256": sha256(backup / "RENDER-INPUTS.sha256"),
            "apply_armed_receipt_sha256": sha256(apply_armed),
            "control_sha256": sha256(control),
            "transaction_sha256": sha256(transaction),
            "applied_targets_sha256": sha256(targets),
            "cargo_gate": "passed",
            "runtime_backup": "passed",
            "closed_bracket": "passed",
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": "404",
            "ingress_opened": "false",
            "services_activated": "true",
            "runtime_verified": "true",
        }
        write_receipt(apply, apply_values)
        current = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(backup),
            "apply_receipt_sha256": sha256(apply),
            "apply_armed_receipt_sha256": sha256(apply_armed),
            "control_sha256": sha256(control),
            "release_evidence_sha256": sha256(release),
            "transaction_sha256": sha256(transaction),
            "applied_targets_sha256": sha256(targets),
            "closed_verified_at": apply_values["closed_verified_at"],
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": 404,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
        }
        return {
            "backup": backup,
            "current": current,
            "current_bytes": (json.dumps(current, sort_keys=True) + "\n").encode(),
            "control": control,
            "apply": apply,
            "release": release,
            "runtime_receipt": runtime_receipt,
            "runtime_manifest": runtime_manifest,
        }

    def install_historical_gen2_candidate(
        self,
        name: str,
        anchor: dict[str, object],
        release_tag: str,
        *,
        authority_public_key_sha: str = "0" * 64,
    ) -> dict[str, object]:
        backup = self.root / name
        runtime = backup / "runtime"
        estate = backup / "estate"
        successor_authority = backup / "successor-authority"
        runtime.mkdir(parents=True, mode=0o700)
        estate.mkdir(mode=0o700)
        successor_authority.mkdir(mode=0o700)
        (successor_authority / "assets").mkdir(mode=0o700)
        (estate / "tree/deploy").mkdir(parents=True, mode=0o700)
        project_tree = estate / "tree/access-governance"
        project_tree.mkdir(mode=0o755)
        project_file = project_tree / "README.fixture"
        write_private(project_file, "captured project payload\n")
        project_file.chmod(0o644)
        backup.chmod(0o700)
        release_env = backup / "release.env"
        release_values = {
            "AUTHORITY_PUBLIC_KEY_SHA256": authority_public_key_sha,
            "ACCESS_GOVERNANCE_IMAGE": "registry.example/access@sha256:" + "3" * 64,
            "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": "4" * 64,
            "PERMISSION_CATALOG_SHA256": "5" * 64,
            "PACKAGE_CATALOG_SHA256": "6" * 64,
            "RIKUNE_ACCEPTANCE_SUBJECT": "user:usr_" + "A" * 43,
            "HOLDFAST_RELEASE": release_tag,
        }
        write_private(
            release_env,
            "".join(f"{key}={value}\n" for key, value in release_values.items()),
        )
        release = backup / "RELEASE-EVIDENCE.json"
        write_private(
            release,
            json.dumps(
                {
                    "release_env_sha256": sha256(release_env),
                    "release": release_tag,
                },
                sort_keys=True,
            )
            + "\n",
        )
        dry = backup / "DRY-RUN.receipt"
        apply_armed = backup / "APPLY-ARMED.receipt"
        transaction = estate / "TRANSACTION.json"
        applied_targets = estate / "APPLIED-TARGETS.sha256"
        for path, content in (
            (dry, "schema_version=1\n"),
            (apply_armed, "schema_version=1\n"),
            (transaction, '{"state":"applied"}\n'),
            (applied_targets, f"{'7' * 64}  target\n"),
            (backup / "TARGETS.sha256", f"{'8' * 64}  target\n"),
            (backup / "APPLY-PREIMAGES.sha256", f"{'9' * 64}  target\n"),
            (backup / "APPLY-ABSENT.paths", "absent-target\n"),
            (estate / "PREIMAGES.sha256", f"{'a' * 64}  target\n"),
            (estate / "ABSENT.before", "absent-target\n"),
            (runtime / "BACKUP.receipt", "schema_version=1\n"),
            (runtime / "RUNNING-SERVICES.before", "strad\nrikune-analyzer\n"),
            (runtime / "RESTORE.receipt", "schema_version=2\n"),
            (runtime / "compose-config.json", '{"name":"historical-test"}\n'),
        ):
            write_private(path, content)
        for relative in (
            "RENDER-INPUTS.sha256",
            "RUNTIME-BACKUP-CALLER-ARMED.receipt",
            "SUPPLY-CHAIN.json",
            "SUPPLY-CHAIN.pub",
            "SUPPLY-CHAIN.sig",
            "rollback.override.yml",
            "SUCCESSOR-DELTA.sha256",
            "runtime/RUNTIME-BACKUP-ARMED.receipt",
            "runtime/VOLUMES.tsv",
            "runtime/strad.dump",
            *(f"runtime/{name}" for name in GEN2_RUNTIME_EXTRA),
            "successor-authority/Dockerfile.analyzer",
            "successor-authority/bridge-package-lock.json",
            "successor-authority/assets/20260823_rikune_root_up.sql",
            "successor-authority/assets/20260823_rikune_root_down.sql",
            "successor-authority/successor-absent.paths",
            "successor-authority/successor-frozen-targets.json",
            "successor-authority/successor-preimages.sha256",
            "successor-authority/successor-static-targets.sha256",
            "successor-authority/successor-supporting-targets.sha256",
        ):
            write_private(backup / relative, f"fixture={relative}\n")
        write_manifest(
            runtime / "SHA256SUMS", runtime, GEN1_RUNTIME_NAMES + GEN2_RUNTIME_EXTRA
        )
        anchor_backup = anchor["backup"]
        assert isinstance(anchor_backup, Path)
        predecessor_current = backup / "PREDECESSOR-CURRENT.json"
        predecessor_current.write_bytes(anchor["current_bytes"])
        predecessor_current.chmod(0o600)
        predecessor = {
            "current_state_sha256": sha256(predecessor_current),
            "control_sha256": sha256(anchor["control"]),
            "apply_receipt_sha256": sha256(anchor["apply"]),
            "release_evidence_sha256": sha256(anchor["release"]),
            "runtime_manifest_sha256": sha256(anchor["runtime_manifest"]),
            "candidate_evidence_sha256": "b" * 64,
            "candidate_targets_sha256": "c" * 64,
            "access_image": "registry.example/access@sha256:" + "3" * 64,
            "access_build_input_schema": "access-build-input/2",
            "access_build_input_sha256": "4" * 64,
            "permission_catalog_sha256": "5" * 64,
            "package_catalog_sha256": "6" * 64,
        }
        policy = successor_authority / "successor-policy.json"
        write_private(
            policy,
            json.dumps(
                {
                    "schema_version": 1,
                    "ceremony": "holdfast-rikune-successor-v1",
                    "predecessor": predecessor,
                    "successor": {},
                    "overlay": {},
                },
                sort_keys=True,
            )
            + "\n",
        )
        successor_arm = backup / "SUCCESSOR-ARMED.receipt"
        successor_arm_values = {
            "schema_version": "1",
            "armed_at": "2026-08-29T19:30:00Z",
            "estate_root": str(self.root / "estate"),
            "successor_backup_dir": str(backup),
            "candidate_dry_run_receipt_sha256": sha256(dry),
            "candidate_release_evidence_sha256": sha256(release),
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": sha256(predecessor_current),
            "predecessor_backup_dir": str(anchor_backup),
            "predecessor_control_sha256": sha256(anchor["control"]),
            "predecessor_apply_receipt_sha256": sha256(anchor["apply"]),
            "predecessor_release_evidence_sha256": sha256(anchor["release"]),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                anchor["runtime_receipt"]
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                anchor["runtime_manifest"]
            ),
            "predecessor_release_generation": "1",
            "release_generation": "2",
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": "404",
            "predecessor_runtime_verified": "true",
            "ingress_opened": "false",
        }
        write_receipt(successor_arm, successor_arm_values)
        control = backup / "CONTROL.sha256"
        write_manifest(
            control,
            backup,
            GEN1_CONTROL_NAMES + GEN2_CONTROL_EXTRA,
        )
        apply = backup / "APPLY.receipt"
        apply_values = {
            "schema_version": "2",
            "completion_state": "applied_ingress_closed",
            "applied_at": "2026-08-29T19:31:00Z",
            "closed_verified_at": "2026-08-29T19:31:30Z",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(backup),
            "release_env_sha256": sha256(release_env),
            "release_evidence_sha256": sha256(release),
            "render_inputs_sha256": "d" * 64,
            "apply_armed_receipt_sha256": sha256(apply_armed),
            "control_sha256": sha256(control),
            "transaction_sha256": sha256(transaction),
            "applied_targets_sha256": sha256(applied_targets),
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
            "successor_armed_receipt_sha256": sha256(successor_arm),
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": sha256(predecessor_current),
            "predecessor_backup_dir": str(anchor_backup),
            "predecessor_control_sha256": sha256(anchor["control"]),
            "predecessor_apply_receipt_sha256": sha256(anchor["apply"]),
            "predecessor_release_evidence_sha256": sha256(anchor["release"]),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                anchor["runtime_receipt"]
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                anchor["runtime_manifest"]
            ),
            "predecessor_release_generation": "1",
            "release_generation": "2",
            "runtime_backup_receipt_sha256": sha256(runtime / "BACKUP.receipt"),
            "runtime_backup_manifest_sha256": sha256(runtime / "SHA256SUMS"),
        }
        write_receipt(apply, apply_values)
        current = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(backup),
            "apply_receipt_sha256": sha256(apply),
            "apply_armed_receipt_sha256": sha256(apply_armed),
            "control_sha256": sha256(control),
            "release_evidence_sha256": sha256(release),
            "transaction_sha256": sha256(transaction),
            "applied_targets_sha256": sha256(applied_targets),
            "closed_verified_at": apply_values["closed_verified_at"],
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": 404,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
            "successor": True,
            "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
            "successor_armed_receipt_sha256": sha256(successor_arm),
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": sha256(predecessor_current),
            "predecessor_backup_dir": str(anchor_backup),
            "predecessor_control_sha256": sha256(anchor["control"]),
            "predecessor_apply_receipt_sha256": sha256(anchor["apply"]),
            "predecessor_release_evidence_sha256": sha256(anchor["release"]),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                anchor["runtime_receipt"]
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                anchor["runtime_manifest"]
            ),
            "predecessor_release_generation": 1,
            "release_generation": 2,
            "runtime_backup_receipt_sha256": sha256(runtime / "BACKUP.receipt"),
            "runtime_backup_manifest_sha256": sha256(runtime / "SHA256SUMS"),
        }
        return {
            "backup": backup,
            "release_env": release_env,
            "release": release,
            "dry": dry,
            "apply_armed": apply_armed,
            "transaction": transaction,
            "applied_targets": applied_targets,
            "runtime_receipt": runtime / "BACKUP.receipt",
            "runtime_manifest": runtime / "SHA256SUMS",
            "runtime_running": runtime / "RUNNING-SERVICES.before",
            "runtime_restore": runtime / "RESTORE.receipt",
            "policy": policy,
            "successor_arm": successor_arm,
            "control": control,
            "apply": apply,
            "current": current,
            "current_bytes": (json.dumps(current, sort_keys=True) + "\n").encode(),
        }

    def install_active_gen2_to_gen4_lineage(
        self,
        active_gen2: dict[str, object],
        *,
        active_gen3_extra_field: bool = False,
    ) -> None:
        gen3_snapshot = self.predecessor_backup / "PREDECESSOR-CURRENT.json"
        old_gen3 = json.loads(gen3_snapshot.read_text(encoding="utf-8"))
        gen3_backup = Path(old_gen3["backup_dir"])
        gen3_runtime = gen3_backup / "runtime"
        gen3_predecessor = gen3_backup / "PREDECESSOR-CURRENT.json"
        gen3_predecessor.write_bytes(active_gen2["current_bytes"])
        gen3_predecessor.chmod(0o600)
        gen3_release = gen3_backup / "RELEASE-EVIDENCE.json"
        gen3_runtime_receipt = gen3_runtime / "BACKUP.receipt"
        gen3_runtime_manifest = gen3_runtime / "SHA256SUMS"
        write_private(gen3_runtime / "RUNNING-SERVICES.before", "strad\n")
        write_manifest(
            gen3_runtime_manifest, gen3_runtime, ("RUNNING-SERVICES.before",)
        )
        gen3_control = gen3_backup / "CONTROL.sha256"
        write_manifest(
            gen3_control,
            gen3_backup,
            (
                "RELEASE-EVIDENCE.json",
                "PREDECESSOR-CURRENT.json",
                "runtime/BACKUP.receipt",
                "runtime/SHA256SUMS",
            ),
        )
        active_backup = active_gen2["backup"]
        assert isinstance(active_backup, Path)
        gen3_current = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "apply_armed_at": "2026-08-29T19:39:00Z",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(gen3_backup),
            "control_sha256": sha256(gen3_control),
            "release_evidence_sha256": sha256(gen3_release),
            "dry_run_receipt_sha256": "1" * 64,
            "apply_armed_receipt_sha256": "2" * 64,
            "transaction_sha256": "3" * 64,
            "applied_targets_sha256": "4" * 64,
            "runtime_backup_caller_armed_sha256": "5" * 64,
            "runtime_backup_stop_authority_sha256": "6" * 64,
            "successor": True,
            "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
            "successor_armed_receipt_sha256": "7" * 64,
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": sha256(gen3_predecessor),
            "predecessor_backup_dir": str(active_backup),
            "predecessor_control_sha256": sha256(active_gen2["control"]),
            "predecessor_apply_receipt_sha256": sha256(active_gen2["apply"]),
            "predecessor_release_evidence_sha256": sha256(active_gen2["release"]),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                active_gen2["runtime_receipt"]
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                active_gen2["runtime_manifest"]
            ),
            "predecessor_release_generation": 2,
            "release_generation": 3,
            "apply_failure_receipt": (
                "APPLY-ACTIVATION-FAILED-20260829T194000Z-3301.receipt"
            ),
            "apply_failure_receipt_sha256": "8" * 64,
            "recovery_prior_state": "apply_activation_failed",
            "recovery_mode": "resume",
            "recovery_attempt_id": "20260829T194100Z-3302",
            "recovery_armed_receipt": (
                "APPLY-RECOVERY-ARMED-20260829T194100Z-3302.receipt"
            ),
            "recovery_armed_receipt_sha256": "9" * 64,
            "recovery_receipt": (
                "APPLY-RECOVERY-COMPLETE-20260829T194100Z-3302.receipt"
            ),
            "recovery_receipt_sha256": "a" * 64,
            "legacy_empty_strad": False,
            "pre_restored_retry": False,
            "pre_restored_source_attempt": "none",
            "pre_restored_runtime_snapshot_sha256": "none",
            "pre_restored_estate_snapshot_sha256": "none",
            "pre_restored_superseded_attempt": "none",
            "pre_restored_superseded_failure_receipt_sha256": "none",
            "pre_restored_superseded_state_sha256": "none",
            "pre_restored_runtime_disposition": "not-applicable",
            "restore_running_writers_manifest": "not-applicable",
            "restore_running_writers_sha256": "none",
            "writer_set_reconciled": False,
            "writer_set_source_attempt": "none",
            "writer_set_source_failure_receipt_sha256": "none",
            "writer_set_source_state_sha256": "none",
            "writer_set_source_manifest_sha256": "none",
            "writer_set_preimage_compose_sha256": "none",
            "writer_set_quarantined": "none",
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
        }
        if active_gen3_extra_field:
            gen3_current["unexpected_hybrid_authority"] = "present"
        write_private(gen3_snapshot, json.dumps(gen3_current, sort_keys=True) + "\n")

        control_names = tuple(
            line.split("  ", 1)[1]
            for line in self.predecessor_control.read_text(
                encoding="utf-8"
            ).splitlines()
        )
        write_manifest(
            self.predecessor_control,
            self.predecessor_backup,
            control_names,
        )
        gen4_apply = dict(
            line.split("=", 1)
            for line in self.predecessor_apply.read_text(
                encoding="utf-8"
            ).splitlines()
        )
        gen4_apply.update(
            {
                "control_sha256": sha256(self.predecessor_control),
                "predecessor_current_sha256": sha256(gen3_snapshot),
                "predecessor_backup_dir": str(gen3_backup),
                "predecessor_control_sha256": sha256(gen3_control),
                "predecessor_release_evidence_sha256": sha256(gen3_release),
                "predecessor_runtime_backup_receipt_sha256": sha256(
                    gen3_runtime_receipt
                ),
                "predecessor_runtime_backup_manifest_sha256": sha256(
                    gen3_runtime_manifest
                ),
            }
        )
        write_receipt(self.predecessor_apply, gen4_apply)
        gen4_current = json.loads(self.predecessor_current.read_text(encoding="utf-8"))
        gen4_current.update(
            {
                "apply_receipt_sha256": sha256(self.predecessor_apply),
                "control_sha256": sha256(self.predecessor_control),
                "predecessor_current_sha256": sha256(gen3_snapshot),
                "predecessor_backup_dir": str(gen3_backup),
                "predecessor_control_sha256": sha256(gen3_control),
                "predecessor_release_evidence_sha256": sha256(gen3_release),
                "predecessor_runtime_backup_receipt_sha256": sha256(
                    gen3_runtime_receipt
                ),
                "predecessor_runtime_backup_manifest_sha256": sha256(
                    gen3_runtime_manifest
                ),
            }
        )
        write_private(
            self.predecessor_current,
            json.dumps(gen4_current, sort_keys=True) + "\n",
        )
        policy = json.loads(self.successor_policy.read_text(encoding="utf-8"))
        policy["predecessor"].update(
            {
                "current_state_sha256": sha256(self.predecessor_current),
                "control_sha256": sha256(self.predecessor_control),
                "apply_receipt_sha256": sha256(self.predecessor_apply),
                "release_evidence_sha256": sha256(self.predecessor_release),
                "runtime_manifest_sha256": sha256(
                    self.predecessor_runtime_manifest
                ),
            }
        )
        write_private(self.successor_policy, json.dumps(policy, sort_keys=True) + "\n")
        for key, value in {
            "successor_policy_sha256": sha256(self.successor_policy),
            "predecessor_current_sha256": sha256(self.predecessor_current),
            "predecessor_backup_dir": str(self.predecessor_backup),
            "predecessor_control_sha256": sha256(self.predecessor_control),
            "predecessor_apply_receipt_sha256": sha256(self.predecessor_apply),
            "predecessor_release_evidence_sha256": sha256(self.predecessor_release),
            "predecessor_runtime_backup_receipt_sha256": sha256(
                self.predecessor_runtime_receipt
            ),
            "predecessor_runtime_backup_manifest_sha256": sha256(
                self.predecessor_runtime_manifest
            ),
        }.items():
            self.replace_receipt_value(self.successor_arm, key, value)
        self.refresh_successor_bindings()

    def sign_historical_evidence(self, evidence: Path, output: Path) -> None:
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(self.historical_private_key),
                "-out",
                str(output),
                str(evidence),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        output.chmod(0o600)

    def install_historical_rollback_bundle(
        self, candidate: dict[str, object]
    ) -> None:
        attempt = "20260829T200600Z-2202"
        backup = candidate["backup"]
        assert isinstance(backup, Path)
        permissions = (
            "rikune.analysis.create",
            "rikune.analysis.delete",
            "rikune.analysis.promote",
            "rikune.analysis.read",
            "rikune.console.enter",
            "rikune.conversation.use",
            "rikune.upload.cancel",
        )
        open_evidence = self.state / f"ROLLBACK-OPEN-EVIDENCE-{attempt}.json"
        open_signature = self.state / f"ROLLBACK-OPEN-SIGNATURE-{attempt}.sig"
        public_key = self.state / f"ROLLBACK-AUTHORITY-PUBLIC-KEY-{attempt}.pub"
        public_key.write_bytes(self.historical_public_key.read_bytes())
        public_key.chmod(0o600)
        open_values = {
            "schema_version": 2,
            "ceremony": "holdfast-rikune-open-v2",
            "issued_at": "2026-08-29T19:58:00Z",
            "expires_at": "2026-09-28T19:58:00Z",
            "release_env_sha256": sha256(candidate["release_env"]),
            "release_evidence_sha256": sha256(candidate["release"]),
            "dry_run_receipt_sha256": sha256(candidate["dry"]),
            "signature_key_sha256": sha256(public_key),
            "candidate_image_digest": "registry.example/access@sha256:" + "3" * 64,
            "build_input_sha256": "4" * 64,
            "permission_catalog_sha256": "5" * 64,
            "package_catalog_sha256": "6" * 64,
            "bootstrap_version": 7,
            "package_id": "pkg_rikune_analyst",
            "requestable_version": 2,
            "beneficiary": "user:usr_" + "A" * 43,
            "promotion_ceremony_id": "promotion-ceremony-historical-0001",
            "package_request_id": "package-request-historical-0001",
            "source_grant_id": "source-grant-historical-0001",
            "projection_edges": [
                {
                    "permission": permission,
                    "epoch": 1,
                    "ack": True,
                    "acknowledged_at": "2026-08-29T19:57:00Z",
                }
                for permission in permissions
            ],
        }
        write_private(open_evidence, json.dumps(open_values, sort_keys=True) + "\n")
        self.sign_historical_evidence(open_evidence, open_signature)
        write_private(
            self.prepare,
            "\n".join(
                (
                    "prepared_at=2026-08-29T20:00:00Z",
                    f"release_evidence_sha256={sha256(candidate['release'])}",
                    f"open_evidence_sha256={sha256(open_evidence)}",
                    "source_grant_id=source-grant-historical-0001",
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

        route_preimage = self.state / (
            f"ROUTE-CLOSE-PREIMAGE-{sha256(candidate['control'])}.jsonl"
        )
        route_receipt = self.state / (
            f"ROUTE-CLOSE-{sha256(candidate['control'])}.receipt"
        )
        write_private(route_preimage, '{"route":"historical-preimage"}\n')
        route_values = {
            "schema_version": "2",
            "route_closed_at": "2026-08-29T20:02:00Z",
            "source_state": "edge_prepared_route_closed",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(backup),
            "control_sha256": sha256(candidate["control"]),
            "state_before_sha256": "e" * 64,
            "route_down_sha256": "f" * 64,
            "route_down_execution_evidence_sha256": sha256(route_preimage),
            "route_preimage_sha256": sha256(route_preimage),
            "route_conflict_cleanup": "same-name-or-analyze-root",
            "open_evidence_sha256": sha256(open_evidence),
            "source_grant_id": "source-grant-historical-0001",
            "was_public_open": "false",
            "preopen_edge_evidence_sha256": "none",
            "route_state": "absent",
            "public_host": "analyze.w33d.xyz",
            "edge_owner": "existing-w33d-sluice",
            "public_ipv4_ipv6_closed_status": "404",
            "db_public_db_bracket": "absent-404-absent",
            "external_edge_mutation": "none",
        }
        write_receipt(route_receipt, route_values)
        interrupted = self.state / "OPEN-INTERRUPTED-20260829T200100Z-2201.receipt"
        interrupted_execution = (
            self.state / "OPEN-ROUTE-DOWN-20260829T200030Z-2201.log"
        )
        write_private(interrupted_execution, "historical interrupted close execution\n")
        write_receipt(
            interrupted,
            {
                "interrupted_at": "2026-08-29T20:01:00Z",
                "reason": "finalize-error-compensated",
                "prior_state": "finalizing_route_armed",
                "open_prepare_receipt_sha256": self.prepare_sha,
                "preopen_edge_evidence_sha256": "d" * 64,
                "route_down_sha256": "f" * 64,
                "route_down_execution_evidence_sha256": sha256(
                    interrupted_execution
                ),
                "route_state": "absent",
                "public_host": "analyze.w33d.xyz",
                "edge_owner": "existing-w33d-sluice",
                "db_public_db_bracket": "absent-404-absent",
                "external_edge_mutation": "none",
            },
        )
        revocation_evidence = (
            self.state / f"ROLLBACK-REVOCATION-EVIDENCE-{attempt}.json"
        )
        revocation_signature = (
            self.state / f"ROLLBACK-REVOCATION-SIGNATURE-{attempt}.sig"
        )
        revocation_values = {
            "schema_version": 2,
            "ceremony": "holdfast-rikune-rollback-v2",
            "issued_at": "2026-08-29T20:05:00Z",
            "release_env_sha256": sha256(candidate["release_env"]),
            "release_evidence_sha256": sha256(candidate["release"]),
            "signature_key_sha256": sha256(public_key),
            "package_id": "pkg_rikune_analyst",
            "beneficiary": "user:usr_" + "A" * 43,
            "source_grant_id": "source-grant-historical-0001",
            "open_evidence_sha256": sha256(open_evidence),
            "route_close_receipt_sha256": sha256(route_receipt),
            "route_closed_at": "2026-08-29T20:02:00Z",
            "grant_revoked_at": "2026-08-29T20:03:00Z",
            "revocation_ceremony_id": "revocation-ceremony-historical-0001",
            "projection_tombstones": [
                {
                    "permission": permission,
                    "epoch": 2,
                    "ack": True,
                    "acknowledged_at": "2026-08-29T20:04:00Z",
                }
                for permission in permissions
            ],
        }
        write_private(
            revocation_evidence,
            json.dumps(revocation_values, sort_keys=True) + "\n",
        )
        self.sign_historical_evidence(revocation_evidence, revocation_signature)

        running = self.state / f"ROLLBACK-RUNNING-SERVICES-{attempt}.before"
        write_private(
            running,
            "access-governance\nverdict\nnewapi\nrikune-analyzer\nstrad\nsluice\n"
            "sluice-internal\n",
        )
        rollback_arm = self.state / f"ROLLBACK-EXECUTE-ARMED-{attempt}.receipt"
        current = candidate["current"]
        assert isinstance(current, dict)
        arm_values = {
            "schema_version": "2",
            "armed_at": "2026-08-29T20:06:00Z",
            "attempt_id": attempt,
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(backup),
            "control_sha256": sha256(candidate["control"]),
            "transaction_sha256": current["transaction_sha256"],
            "applied_targets_sha256": current["applied_targets_sha256"],
            "targets_sha256": sha256(backup / "TARGETS.sha256"),
            "apply_preimages_sha256": sha256(backup / "APPLY-PREIMAGES.sha256"),
            "apply_absent_sha256": sha256(backup / "APPLY-ABSENT.paths"),
            "route_close_receipt": route_receipt.name,
            "route_close_receipt_sha256": sha256(route_receipt),
            "route_close_preimage": route_preimage.name,
            "route_close_preimage_sha256": sha256(route_preimage),
            "open_evidence_file": open_evidence.name,
            "open_evidence_sha256": sha256(open_evidence),
            "open_signature_file": open_signature.name,
            "open_signature_sha256": sha256(open_signature),
            "authority_public_key_file": public_key.name,
            "authority_public_key_sha256": sha256(public_key),
            "revocation_evidence_file": revocation_evidence.name,
            "revocation_evidence_sha256": sha256(revocation_evidence),
            "revocation_signature_file": revocation_signature.name,
            "revocation_signature_sha256": sha256(revocation_signature),
            "edge_rollback_evidence_file": "none",
            "edge_rollback_evidence_sha256": "none",
            "edge_rollback_signature_file": "none",
            "edge_rollback_signature_sha256": "none",
            "open_edge_evidence_file": "none",
            "open_edge_evidence_sha256": "none",
            "compose_project": "historical-test",
            "release_service_count": "7",
            "release_services": (
                "access-governance,verdict,newapi,rikune-analyzer,strad,sluice,"
                "sluice-internal"
            ),
            "running_services_manifest": running.name,
            "running_services_sha256": sha256(running),
            "runtime_prior_services_sha256": sha256(candidate["runtime_running"]),
            "activate_services_requested": "false",
            "activation_policy": "restore-exact-prior-running",
            "ingress_opened": "false",
            "successor": "true",
            "successor_armed_receipt_sha256": current[
                "successor_armed_receipt_sha256"
            ],
            "predecessor_current_sha256": current["predecessor_current_sha256"],
            "predecessor_backup_dir": current["predecessor_backup_dir"],
            "predecessor_control_sha256": current["predecessor_control_sha256"],
            "predecessor_apply_receipt_sha256": current[
                "predecessor_apply_receipt_sha256"
            ],
            "predecessor_release_evidence_sha256": current[
                "predecessor_release_evidence_sha256"
            ],
            "predecessor_runtime_backup_receipt_sha256": current[
                "predecessor_runtime_backup_receipt_sha256"
            ],
            "predecessor_runtime_backup_manifest_sha256": current[
                "predecessor_runtime_backup_manifest_sha256"
            ],
            "predecessor_release_generation": "1",
            "release_generation": "2",
        }
        write_receipt(rollback_arm, arm_values)
        runtime_phase = (
            self.state / f"ROLLBACK-RUNTIME-RESTORE-DONE-{attempt}.receipt"
        )
        write_receipt(
            runtime_phase,
            {
                "schema_version": "2",
                "phase": "runtime_restore_done",
                "completed_at": "2026-08-29T20:07:00Z",
                "attempt_id": attempt,
                "rollback_armed_receipt_sha256": sha256(rollback_arm),
                "runtime_restore_receipt_sha256": sha256(candidate["runtime_restore"]),
                "runtime_backup_receipt_sha256": current[
                    "runtime_backup_receipt_sha256"
                ],
                "runtime_backup_manifest_sha256": current[
                    "runtime_backup_manifest_sha256"
                ],
                "transaction_before_sha256": current["transaction_sha256"],
                "applied_targets_sha256": current["applied_targets_sha256"],
                "ingress_opened": "false",
            },
        )
        estate_phase = (
            self.state / f"ROLLBACK-ESTATE-RESTORE-DONE-{attempt}.receipt"
        )
        write_receipt(
            estate_phase,
            {
                "schema_version": "2",
                "phase": "estate_restore_done",
                "completed_at": "2026-08-29T20:08:00Z",
                "attempt_id": attempt,
                "rollback_armed_receipt_sha256": sha256(rollback_arm),
                "runtime_restore_phase_receipt_sha256": sha256(runtime_phase),
                "estate_transaction_sha256": sha256(candidate["transaction"]),
                "applied_targets_sha256": current["applied_targets_sha256"],
                "preimages_sha256": sha256(backup / "estate/PREIMAGES.sha256"),
                "absent_sha256": sha256(backup / "estate/ABSENT.before"),
                "live_estate_disposition": "preimage",
                "ingress_opened": "false",
            },
        )
        services_phase = (
            self.state / f"ROLLBACK-SERVICES-REACTIVATED-DONE-{attempt}.receipt"
        )
        write_receipt(
            services_phase,
            {
                "schema_version": "2",
                "phase": "services_reactivated_done",
                "completed_at": "2026-08-29T20:09:00Z",
                "attempt_id": attempt,
                "rollback_armed_receipt_sha256": sha256(rollback_arm),
                "estate_restore_phase_receipt_sha256": sha256(estate_phase),
                "reactivated_services": (
                    "access-governance,verdict,newapi,rikune-analyzer,strad,sluice,"
                    "sluice-internal"
                ),
                "excluded_services_inactive": "passed",
                "ingress_opened": "false",
            },
        )
        rollback_receipt = backup / "ROLLBACK.receipt"
        rollback_values = {
            "schema_version": "2",
            "rolled_back_at": "2026-08-29T20:10:00Z",
            "rollback_armed_receipt_sha256": sha256(rollback_arm),
            "running_services_sha256": sha256(running),
            "runtime_prior_services_sha256": sha256(candidate["runtime_running"]),
            "runtime_restore_phase_receipt_sha256": sha256(runtime_phase),
            "estate_restore_phase_receipt_sha256": sha256(estate_phase),
            "services_reactivated_phase_receipt_sha256": sha256(services_phase),
            "route_close_receipt": route_receipt.name,
            "route_close_receipt_sha256": sha256(route_receipt),
            "route_close_preimage": route_preimage.name,
            "route_close_preimage_sha256": sha256(route_preimage),
            "revocation_evidence_sha256": sha256(revocation_evidence),
            "open_evidence_sha256": sha256(open_evidence),
            "runtime_restore_receipt_sha256": sha256(candidate["runtime_restore"]),
            "estate_transaction_sha256": sha256(candidate["transaction"]),
            "runtime_restore": "passed",
            "mixed_estate_restore": "passed",
            "orphan_cleanup": "passed",
            "service_reactivation": "passed",
            "reactivated_services": (
                "access-governance,verdict,newapi,rikune-analyzer,strad,sluice,"
                "sluice-internal"
            ),
            "excluded_services_inactive": "passed",
            "activation_policy": "restore-exact-prior-running",
            "activate_services_requested": "false",
            "public_route_state": "dual-stack-404",
            "ingress_opened": "false",
            "successor": "true",
            "successor_armed_receipt_sha256": current[
                "successor_armed_receipt_sha256"
            ],
            "predecessor_current_sha256": current["predecessor_current_sha256"],
            "predecessor_backup_dir": current["predecessor_backup_dir"],
            "predecessor_control_sha256": current["predecessor_control_sha256"],
            "predecessor_apply_receipt_sha256": current[
                "predecessor_apply_receipt_sha256"
            ],
            "predecessor_release_evidence_sha256": current[
                "predecessor_release_evidence_sha256"
            ],
            "predecessor_runtime_backup_receipt_sha256": current[
                "predecessor_runtime_backup_receipt_sha256"
            ],
            "predecessor_runtime_backup_manifest_sha256": current[
                "predecessor_runtime_backup_manifest_sha256"
            ],
            "predecessor_release_generation": "1",
            "release_generation": "2",
        }
        write_receipt(rollback_receipt, rollback_values)
        completion = {
            **current,
            "state": "rolled_back",
            "open_prepare_receipt_sha256": self.prepare_sha,
            "last_open_interrupted_receipt_sha256": sha256(interrupted),
            "route_close_receipt": route_receipt.name,
            "route_close_receipt_sha256": sha256(route_receipt),
            "route_close_preimage": route_preimage.name,
            "route_close_preimage_sha256": sha256(route_preimage),
            "rollback_attempt_id": attempt,
            "rollback_running_services_manifest": running.name,
            "rollback_running_services_sha256": sha256(running),
            "rollback_armed_receipt": rollback_arm.name,
            "rollback_armed_receipt_sha256": sha256(rollback_arm),
            "rollback_runtime_restore_phase_receipt": runtime_phase.name,
            "rollback_runtime_restore_phase_receipt_sha256": sha256(runtime_phase),
            "rollback_estate_restore_phase_receipt": estate_phase.name,
            "rollback_estate_restore_phase_receipt_sha256": sha256(estate_phase),
            "rollback_estate_transaction_sha256": sha256(candidate["transaction"]),
            "rollback_services_reactivated_phase_receipt": services_phase.name,
            "rollback_services_reactivated_phase_receipt_sha256": sha256(
                services_phase
            ),
            "rollback_receipt_sha256": sha256(rollback_receipt),
        }
        self.historical_completion = (
            self.state / f"ROLLBACK-COMPLETE-{attempt}.json"
        )
        write_private(
            self.historical_completion,
            json.dumps(completion, sort_keys=True) + "\n",
        )
        self.historical_interrupted = interrupted
        self.historical_interrupted_execution = interrupted_execution
        self.historical_rollback_arm = rollback_arm
        self.historical_rollback_receipt = rollback_receipt
        self.historical_route_receipt = route_receipt
        self.historical_route_preimage = route_preimage
        self.historical_open_evidence = open_evidence
        self.historical_revocation_evidence = revocation_evidence

    def install_historical_rollback_authority(
        self,
        *,
        source_is_active_gen2: bool = False,
        active_gen3_extra_field: bool = False,
    ) -> None:
        (self.root / "estate").chmod(0o755)
        self.historical_private_key = self.root / "historical-authority-private.pem"
        self.historical_public_key = self.root / "historical-authority-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(self.historical_private_key),
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
                str(self.historical_private_key),
                "-pubout",
                "-out",
                str(self.historical_public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.historical_private_key.chmod(0o600)
        self.historical_public_key.chmod(0o600)
        anchor = self.install_historical_gen1_anchor()
        active_gen2 = self.install_historical_gen2_candidate(
            "active-gen2-backup", anchor, "active-gen2"
        )
        historical_gen2 = self.install_historical_gen2_candidate(
            "historical-gen2-backup",
            anchor,
            "historical-gen2",
            authority_public_key_sha=sha256(self.historical_public_key),
        )
        self.active_gen2 = active_gen2
        self.historical_candidate = historical_gen2
        self.install_active_gen2_to_gen4_lineage(
            historical_gen2 if source_is_active_gen2 else active_gen2,
            active_gen3_extra_field=active_gen3_extra_field,
        )
        self.install_recovered_resume_authority()
        self.install_historical_rollback_bundle(historical_gen2)
        self.historical_release_validator = self.root / "release-validator-stub.py"
        write_private(
            self.historical_release_validator,
            "#!/usr/bin/env python3\nraise SystemExit(0)\n",
        )

    def replace_receipt_value(self, path: Path, key: str, value: str) -> None:
        prefix = f"{key}="
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith(prefix) for line in lines), 1)
        write_private(
            path,
            "\n".join(
                f"{prefix}{value}" if line.startswith(prefix) else line
                for line in lines
            )
            + "\n",
        )

    def refresh_recovery_receipt_pointer(self) -> None:
        receipt_sha = sha256(self.recovery_receipt)
        for path in (self.recovery_archive, self.current):
            value = json.loads(path.read_text(encoding="utf-8"))
            value["recovery_receipt_sha256"] = receipt_sha
            write_private(path, json.dumps(value, sort_keys=True) + "\n")

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

        normal_keys = supersede.read_text(encoding="utf-8").splitlines()
        self.assertIn(
            "ceremony=holdfast-rikune-open-prepare-abandon-v1", normal_keys
        )
        self.assertFalse(
            any(line.startswith("successor_recovery_") for line in normal_keys)
        )

    def test_recovery_abandon_archives_and_replays_without_apply_receipt(
        self,
    ) -> None:
        self.install_recovered_resume_authority()
        abandoned = self.run_abandon()
        self.assertEqual(abandoned.returncode, 0, abandoned.stdout + abandoned.stderr)
        self.assertFalse(self.prepare.exists())
        self.assertFalse(self.apply_receipt.exists())
        self.assertFalse((self.backup / "APPLY-PENDING.receipt").exists())
        archive, supersede = self.final_artifacts()
        self.assertEqual(archive.read_bytes(), self.prepare_bytes)
        receipt = dict(
            line.split("=", 1)
            for line in supersede.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(
            receipt["ceremony"],
            "holdfast-rikune-open-prepare-abandon-recovery-v1",
        )
        self.assertEqual(
            receipt["authority_binding"],
            "frozen-successor-recovery-completion-hash-chain",
        )
        self.assertEqual(
            receipt["successor_completion_authority"],
            "recovery-resume-completion-v1",
        )
        self.assertEqual(
            receipt["successor_recovery_attempt_id"], self.recovery_attempt
        )
        self.assertEqual(
            receipt["successor_recovery_completion_receipt_sha256"],
            sha256(self.recovery_receipt),
        )
        self.assertEqual(
            receipt["successor_recovery_completion_archive_sha256"],
            sha256(self.recovery_archive),
        )
        self.assertEqual(receipt["successor_apply_receipt_created"], "false")
        self.assertNotIn("successor_apply_receipt_sha256", receipt)

        frozen = {path: path.read_bytes() for path in (archive, supersede)}
        replay = self.run_abandon()
        self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
        self.assertFalse(self.apply_receipt.exists())
        for path, content in frozen.items():
            self.assertEqual(path.read_bytes(), content)

    def test_recovery_abandon_rejects_apply_hybrid_without_moving_prepare(
        self,
    ) -> None:
        self.install_recovered_resume_authority()
        write_private(self.apply_receipt, self.normal_apply_bytes.decode("utf-8"))
        original = self.prepare.read_bytes()

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("APPLY/recovery hybrid", rejected.stderr)
        self.assertEqual(self.prepare.read_bytes(), original)
        self.assertEqual(
            list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), []
        )

    def test_recovery_abandon_requires_exact_current_field_set(self) -> None:
        self.install_recovered_resume_authority()
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["route_database_state"] = "absent"
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("recovery completion authority is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_recovery_abandon_rejects_unsafe_attempt_before_archive(self) -> None:
        self.install_recovered_resume_authority()
        current = json.loads(self.current.read_text(encoding="utf-8"))
        current["recovery_attempt_id"] = "../unsafe"
        write_private(self.current, json.dumps(current, sort_keys=True) + "\n")

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("attempt namespace is unsafe", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_recovery_abandon_requires_schema3_order_and_false_apply_claim(
        self,
    ) -> None:
        for mutation in ("schema", "order", "apply-created"):
            with self.subTest(mutation=mutation):
                if mutation != "schema":
                    self.tearDown()
                    self.setUp()
                self.install_recovered_resume_authority()
                if mutation == "schema":
                    self.replace_receipt_value(
                        self.recovery_receipt, "schema_version", "2"
                    )
                elif mutation == "order":
                    lines = self.recovery_receipt.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    lines[0], lines[1] = lines[1], lines[0]
                    write_private(self.recovery_receipt, "\n".join(lines) + "\n")
                else:
                    self.replace_receipt_value(
                        self.recovery_receipt, "apply_receipt_created", "true"
                    )
                self.refresh_recovery_receipt_pointer()

                rejected = self.run_abandon()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(
                    "recovery completion authority is not exact", rejected.stderr
                )
                self.assertTrue(self.prepare.is_file())
                self.assertFalse(self.apply_receipt.exists())

    def test_recovery_abandon_rejects_receipt_and_projection_drift(self) -> None:
        self.install_recovered_resume_authority()
        original = self.prepare.read_bytes()
        self.replace_receipt_value(
            self.recovery_receipt, "runtime_verified", "not-passed"
        )
        receipt_drift = self.run_abandon()
        self.assertNotEqual(receipt_drift.returncode, 0)
        self.assertEqual(self.prepare.read_bytes(), original)

        self.tearDown()
        self.setUp()
        self.install_recovered_resume_authority()
        archive = json.loads(self.recovery_archive.read_text(encoding="utf-8"))
        archive["transaction_sha256"] = "9" * 64
        write_private(
            self.recovery_archive, json.dumps(archive, sort_keys=True) + "\n"
        )
        projection_drift = self.run_abandon()
        self.assertNotEqual(projection_drift.returncode, 0)
        self.assertIn(
            "recovery completion authority is not exact", projection_drift.stderr
        )
        self.assertTrue(self.prepare.is_file())

    def test_recovery_abandon_rejects_transaction_authority_drift(self) -> None:
        self.install_recovered_resume_authority()
        write_private(
            self.successor_transaction,
            '{"schema_version":1,"state":"tampered"}\n',
        )

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("differs from CURRENT", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_recovery_abandon_allows_unrelated_history_but_rejects_two_matches(
        self,
    ) -> None:
        self.install_recovered_resume_authority()
        unrelated = (
            self.state
            / "APPLY-RECOVERY-COMPLETE-20260828T120000Z-7.json"
        )
        write_private(
            unrelated,
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "apply_recovered_resumed",
                    "backup_dir": str(self.root / "unrelated-backup"),
                },
                sort_keys=True,
            )
            + "\n",
        )
        accepted = self.run_abandon()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

        self.tearDown()
        self.setUp()
        self.install_recovered_resume_authority()
        duplicate = (
            self.state
            / "APPLY-RECOVERY-COMPLETE-20260829T213300Z-5252.json"
        )
        write_private(
            duplicate,
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "apply_recovered_resumed",
                    "backup_dir": str(self.backup),
                },
                sort_keys=True,
            )
            + "\n",
        )
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("recovery completion authority is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_recovery_abandon_rejects_unsafe_candidate_namespace(self) -> None:
        self.install_recovered_resume_authority()
        unsafe = (
            self.state
            / "APPLY-RECOVERY-COMPLETE-20260829T213300Z-5252.json"
        )
        unsafe.symlink_to(self.recovery_archive)

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("namespace is unsafe", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_recovery_abandon_crash_replay_rejects_authority_drift(self) -> None:
        self.install_recovered_resume_authority()
        interrupted = self.run_abandon(
            HOLDFAST_TEST_STOP_AFTER_PREPARE_ARCHIVE_MOVE="1"
        )
        self.assertEqual(
            interrupted.returncode, 75, interrupted.stdout + interrupted.stderr
        )
        self.assertFalse(self.prepare.exists())
        pending = list(self.state.glob(".OPEN-PREPARE-SUPERSEDED-*.pending"))
        self.assertEqual(len(pending), 1)
        self.replace_receipt_value(
            self.recovery_receipt, "runtime_verified", "not-passed"
        )

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(
            list(self.state.glob("OPEN-PREPARE-SUPERSEDED-*.receipt")), []
        )
        self.assertTrue(pending[0].is_file())
        self.assertFalse(self.apply_receipt.exists())

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

    def test_schema5_open_reuses_dual_host_contract_without_widening_abandon(
        self,
    ) -> None:
        script = (OPS_ROOT / "open-ingress.sh").read_text(encoding="utf-8")
        normal_open = script[script.index("validate_armed_open_contract()") :]
        self.assertIn('.schema_version | select(type == "number"', normal_open)
        self.assertIn(". >= 1 and . <= 5", normal_open)
        self.assertIn('policy_schema" -ge 4', normal_open)
        self.assertIn('frozen_policy_schema" -ge 4', normal_open)
        self.assertIn(
            "expected_release_generation=$((frozen_policy_schema + 1))",
            normal_open,
        )
        self.assertIn('open_edge_contract="rikune-dual-v3"', normal_open)

        self.assertIn("validate_schema4_successor_policy", script)

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

    def test_historical_rollback_abandon_archives_and_replays(self) -> None:
        self.install_historical_rollback_authority()

        self.assertEqual((self.root / "estate").stat().st_mode & 0o777, 0o755)
        candidate_backup = self.historical_candidate["backup"]
        assert isinstance(candidate_backup, Path)
        self.assertEqual(
            (candidate_backup / "estate/tree/access-governance").stat().st_mode
            & 0o777,
            0o755,
        )
        control_names = {
            line.split("  ", 1)[1]
            for line in self.historical_candidate["control"]
            .read_text(encoding="utf-8")
            .splitlines()
        }
        runtime_names = {
            line.split("  ", 1)[1]
            for line in self.historical_candidate["runtime_manifest"]
            .read_text(encoding="utf-8")
            .splitlines()
        }
        self.assertEqual(control_names, set(GEN1_CONTROL_NAMES + GEN2_CONTROL_EXTRA))
        self.assertEqual(runtime_names, set(GEN1_RUNTIME_NAMES + GEN2_RUNTIME_EXTRA))
        interrupted_values = dict(
            line.split("=", 1)
            for line in self.historical_interrupted.read_text(
                encoding="utf-8"
            ).splitlines()
        )
        route_values = dict(
            line.split("=", 1)
            for line in self.historical_route_receipt.read_text(
                encoding="utf-8"
            ).splitlines()
        )
        self.assertNotEqual(
            interrupted_values["route_down_execution_evidence_sha256"],
            route_values["route_down_execution_evidence_sha256"],
        )

        abandoned = self.run_abandon()
        self.assertEqual(abandoned.returncode, 0, abandoned.stdout + abandoned.stderr)
        archive, supersede = self.final_artifacts()
        self.assertIn("OPEN-PREPARE-ABANDONED-G2-BY-G5-", archive.name)
        self.assertEqual(archive.read_bytes(), self.prepare_bytes)
        self.assertFalse((self.backup / "APPLY.receipt").exists())
        receipt = dict(
            line.split("=", 1)
            for line in supersede.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(
            receipt["ceremony"],
            "holdfast-rikune-open-prepare-abandon-historical-rollback-v1",
        )
        self.assertEqual(receipt["source_release_generation"], "2")
        self.assertEqual(receipt["rollback_anchor_release_generation"], "1")
        self.assertEqual(receipt["rollback_completion"], self.historical_completion.name)
        self.assertEqual(
            receipt["rollback_completion_sha256"], sha256(self.historical_completion)
        )
        self.assertEqual(receipt["successor_apply_receipt_created"], "false")

        frozen = {path: path.read_bytes() for path in (archive, supersede)}
        replay = self.run_abandon()
        self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
        for path, content in frozen.items():
            self.assertEqual(path.read_bytes(), content)

    def test_historical_rollback_rejects_multiple_completion_matches(self) -> None:
        self.install_historical_rollback_authority()
        duplicate = self.state / "ROLLBACK-COMPLETE-20260829T200600Z-9999.json"
        duplicate.write_bytes(self.historical_completion.read_bytes())
        duplicate.chmod(0o600)

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), [])

    def test_historical_rollback_rejects_multiple_interrupted_executions(self) -> None:
        self.install_historical_rollback_authority()
        duplicate = self.state / "OPEN-ROUTE-DOWN-20260829T200040Z-2201.log"
        duplicate.write_bytes(self.historical_interrupted_execution.read_bytes())
        duplicate.chmod(0o600)

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_source_still_in_active_lineage(self) -> None:
        self.install_historical_rollback_authority(source_is_active_gen2=True)

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), [])

    def test_historical_rollback_rejects_cross_host_schema_v3_with_refreshed_unsigned_hashes(
        self,
    ) -> None:
        self.install_historical_rollback_authority()
        write_private(
            self.prepare,
            "\n".join(
                (
                    "schema_version=3",
                    "prepared_at=2026-08-29T20:00:00Z",
                    "release_generation=2",
                    "release_evidence_sha256="
                    f"{sha256(self.historical_candidate['release'])}",
                    "open_evidence_sha256="
                    f"{sha256(self.historical_open_evidence)}",
                    "source_grant_id=source-grant-historical-0001",
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
        cross_host_prepare = self.prepare.read_bytes()
        cross_host_prepare_sha = sha256(self.prepare)
        self.replace_receipt_value(
            self.historical_interrupted,
            "open_prepare_receipt_sha256",
            cross_host_prepare_sha,
        )
        completion = json.loads(
            self.historical_completion.read_text(encoding="utf-8")
        )
        completion["open_prepare_receipt_sha256"] = cross_host_prepare_sha
        completion["last_open_interrupted_receipt_sha256"] = sha256(
            self.historical_interrupted
        )
        write_private(
            self.historical_completion,
            json.dumps(completion, sort_keys=True) + "\n",
        )

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("only accepts legacy analyze", rejected.stderr)
        self.assertTrue(self.prepare.is_file())
        self.assertEqual(self.prepare.read_bytes(), cross_host_prepare)
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), [])
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-SUPERSEDED-*.receipt")), [])

    def test_historical_rollback_python_validator_rejects_interrupted_host_drift(
        self,
    ) -> None:
        self.install_historical_rollback_authority()
        original_prepare = self.prepare.read_bytes()
        self.replace_receipt_value(
            self.historical_interrupted,
            "public_host",
            "rikune.w33d.xyz",
        )
        completion = json.loads(
            self.historical_completion.read_text(encoding="utf-8")
        )
        completion["last_open_interrupted_receipt_sha256"] = sha256(
            self.historical_interrupted
        )
        write_private(
            self.historical_completion,
            json.dumps(completion, sort_keys=True) + "\n",
        )

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback abandonment authority is not exact", rejected.stderr)
        self.assertTrue(self.prepare.is_file())
        self.assertEqual(self.prepare.read_bytes(), original_prepare)
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-ABANDONED-*.receipt")), [])
        self.assertEqual(list(self.state.glob("OPEN-PREPARE-SUPERSEDED-*.receipt")), [])

    def test_historical_rollback_rejects_hybrid_active_gen3_current(self) -> None:
        self.install_historical_rollback_authority(active_gen3_extra_field=True)

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_route_path_alias(self) -> None:
        self.install_historical_rollback_authority()
        completion = json.loads(
            self.historical_completion.read_text(encoding="utf-8")
        )
        completion["route_close_receipt"] = (
            "../" + str(completion["route_close_receipt"])
        )
        write_private(
            self.historical_completion,
            json.dumps(completion, sort_keys=True) + "\n",
        )

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_writable_captured_subtree(self) -> None:
        self.install_historical_rollback_authority()
        candidate_backup = self.historical_candidate["backup"]
        assert isinstance(candidate_backup, Path)
        (candidate_backup / "estate/tree/access-governance").chmod(0o775)

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_missing_or_unsafe_authority(self) -> None:
        self.install_historical_rollback_authority()
        self.historical_rollback_arm.unlink()

        missing = self.run_abandon()
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("historical rollback", missing.stderr)
        self.assertTrue(self.prepare.is_file())

        self.historical_rollback_arm.write_text("unsafe\n", encoding="utf-8")
        self.historical_rollback_arm.chmod(0o666)
        unsafe = self.run_abandon()
        self.assertNotEqual(unsafe.returncode, 0)
        self.assertIn("historical rollback", unsafe.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_exact_field_and_hash_drift(self) -> None:
        self.install_historical_rollback_authority()
        completion = json.loads(
            self.historical_completion.read_text(encoding="utf-8")
        )
        completion["unexpected"] = True
        write_private(
            self.historical_completion,
            json.dumps(completion, sort_keys=True) + "\n",
        )
        field_drift = self.run_abandon()
        self.assertNotEqual(field_drift.returncode, 0)
        self.assertIn("historical rollback", field_drift.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_frozen_bundle_hash_drift(self) -> None:
        self.install_historical_rollback_authority()
        with self.historical_rollback_receipt.open("a", encoding="utf-8") as handle:
            handle.write("drift=true\n")

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_recovery_apply_hybrid(self) -> None:
        self.install_historical_rollback_authority()
        write_private(self.backup / "APPLY.receipt", "schema_version=2\n")

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("hybrid authority", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_apply_projection_drift(self) -> None:
        self.install_historical_rollback_authority()
        candidate_apply = self.historical_candidate["apply"]
        assert isinstance(candidate_apply, Path)
        self.replace_receipt_value(
            candidate_apply, "predecessor_release_generation", "2"
        )
        completion = json.loads(
            self.historical_completion.read_text(encoding="utf-8")
        )
        completion["apply_receipt_sha256"] = sha256(candidate_apply)
        write_private(
            self.historical_completion,
            json.dumps(completion, sort_keys=True) + "\n",
        )

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_rejects_active_anchor_drift(self) -> None:
        self.install_historical_rollback_authority()
        active_backup = self.active_gen2["backup"]
        assert isinstance(active_backup, Path)
        with (active_backup / "PREDECESSOR-CURRENT.json").open(
            "a", encoding="utf-8"
        ) as handle:
            handle.write(" \n")

        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(self.prepare.is_file())

    def test_historical_rollback_crash_replay_rechecks_authority(self) -> None:
        self.install_historical_rollback_authority()
        interrupted = self.run_abandon(
            HOLDFAST_TEST_STOP_AFTER_PREPARE_ARCHIVE_MOVE="1"
        )
        self.assertEqual(interrupted.returncode, 75, interrupted.stdout + interrupted.stderr)
        self.assertFalse(self.prepare.exists())
        archives = list(self.state.glob("OPEN-PREPARE-ABANDONED-G2-BY-G5-*.receipt"))
        pending = list(self.state.glob(".OPEN-PREPARE-SUPERSEDED-G5.receipt.pending"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(len(pending), 1)

        with self.historical_rollback_receipt.open("a", encoding="utf-8") as handle:
            handle.write("drift=true\n")
        rejected = self.run_abandon()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("historical rollback", rejected.stderr)
        self.assertTrue(archives[0].is_file())
        self.assertTrue(pending[0].is_file())
        self.assertFalse((self.state / "OPEN-PREPARE-SUPERSEDED-G5.receipt").exists())


if __name__ == "__main__":
    unittest.main()
