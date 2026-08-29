from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS_ROOT))

import recovery_completion_attestation  # noqa: E402


RECOVER = OPS_ROOT / "apply-recover.sh"
POSTGRES_CONTAINER_ID = "1" * 64
POSTGRES_CONFIG_HASH = "c" * 64

HISTORICAL_APPLY_ARMED_KEYS = (
    "schema_version",
    "armed_at",
    "estate_root",
    "backup_dir",
    "dry_run_dir",
    "release_env_sha256",
    "release_evidence_sha256",
    "dry_run_receipt_sha256",
    "targets_sha256",
    "apply_preimages_sha256",
    "apply_absent_sha256",
    "render_inputs_sha256",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
    "runtime_backup_caller_armed_sha256",
    "runtime_backup_stop_authority_sha256",
    "ingress_opened",
    "successor",
    "successor_armed_receipt",
    "successor_armed_receipt_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
)

PRODUCTION_PREDECESSOR_CURRENT_KEYS = {
    "schema_version",
    "state",
    "estate_root",
    "backup_dir",
    "apply_receipt_sha256",
    "apply_armed_receipt_sha256",
    "control_sha256",
    "release_evidence_sha256",
    "transaction_sha256",
    "applied_targets_sha256",
    "closed_verified_at",
    "route_database_state",
    "public_ipv4_ipv6_closed_status",
    "services_activated",
    "runtime_verified",
    "ingress_opened",
    "successor",
    "successor_armed_receipt",
    "successor_armed_receipt_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
}

PRODUCTION_PREDECESSOR_APPLY_KEYS = (
    "schema_version",
    "completion_state",
    "applied_at",
    "closed_verified_at",
    "estate_root",
    "backup_dir",
    "release_env_sha256",
    "release_evidence_sha256",
    "render_inputs_sha256",
    "apply_armed_receipt_sha256",
    "control_sha256",
    "transaction_sha256",
    "applied_targets_sha256",
    "cargo_gate",
    "runtime_backup",
    "closed_bracket",
    "route_database_state",
    "public_ipv4_ipv6_closed_status",
    "ingress_opened",
    "services_activated",
    "runtime_verified",
    "successor",
    "successor_armed_receipt",
    "successor_armed_receipt_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
)

ACTIVATION_FAILURE_KEYS = (
    "failed_at",
    "phase",
    "activation_step",
    "status",
    "estate_root",
    "backup_dir",
    "apply_armed_receipt_sha256",
    "control_sha256",
    "transaction_sha256",
    "ingress_opened",
)

SUCCESSOR_ARMED_KEYS = (
    "schema_version",
    "armed_at",
    "estate_root",
    "successor_backup_dir",
    "candidate_dry_run_receipt_sha256",
    "candidate_release_evidence_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "route_database_state",
    "public_ipv4_ipv6_closed_status",
    "predecessor_runtime_verified",
    "ingress_opened",
)

RECOVERY_ARMED_KEYS = (
    "schema_version",
    "armed_at",
    "attempt_id",
    "mode",
    "prior_state",
    "legacy_orphan_adopted",
    "legacy_empty_strad",
    "runtime_backup_schema",
    "estate_transaction_state",
    "estate_root",
    "backup_dir",
    "control_sha256",
    "transaction_sha256",
    "applied_targets_sha256",
    "apply_armed_receipt_sha256",
    "release_evidence_sha256",
    "dry_run_receipt_sha256",
    "live_disposition",
    "restore_running_writers_manifest",
    "restore_running_writers_sha256",
    "writer_set_reconciled",
    "writer_set_source_attempt",
    "writer_set_source_failure_receipt_sha256",
    "writer_set_source_state_sha256",
    "writer_set_source_manifest_sha256",
    "writer_set_preimage_compose_sha256",
    "writer_set_quarantined",
    "pre_restored_retry",
    "pre_restored_source_attempt",
    "pre_restored_runtime_snapshot_sha256",
    "pre_restored_estate_snapshot_sha256",
    "pre_restored_superseded_attempt",
    "pre_restored_superseded_failure_receipt_sha256",
    "pre_restored_superseded_state_sha256",
    "pre_restored_runtime_disposition",
    "route_state",
    "public_host",
    "db_public_db_bracket",
    "successor",
    "successor_armed_receipt_sha256",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
)

RECOVERY_COMPLETION_KEYS = (
    "schema_version",
    "completed_at",
    "attempt_id",
    "mode",
    "estate_root",
    "backup_dir",
    "control_sha256",
    "original_estate_transaction_state",
    "original_estate_transaction_sha256",
    "applied_targets_sha256",
    "legacy_empty_strad",
    "recovery_armed_receipt_sha256",
    "release_evidence_sha256",
    "dry_run_receipt_sha256",
    "runtime_restore_receipt_sha256",
    "estate_restore_state_sha256",
    "pre_restored_retry",
    "pre_restored_source_attempt",
    "pre_restored_superseded_attempt",
    "pre_restored_superseded_failure_receipt_sha256",
    "pre_restored_superseded_state_sha256",
    "pre_restored_runtime_disposition",
    "restore_running_writers_manifest",
    "restore_running_writers_sha256",
    "writer_set_reconciled",
    "writer_set_source_attempt",
    "writer_set_source_failure_receipt_sha256",
    "writer_set_source_state_sha256",
    "writer_set_source_manifest_sha256",
    "writer_set_preimage_compose_sha256",
    "writer_set_quarantined",
    "writers_reactivated",
    "uncaptured_writers_inactive",
    "quarantined_writers_inactive",
    "runtime_verified",
    "live_estate_disposition",
    "route_state",
    "public_host",
    "db_public_db_bracket",
    "apply_receipt_created",
    "successor",
    "successor_armed_receipt_sha256",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
)

RECOVERY_ARCHIVE_KEYS = {
    "schema_version",
    "state",
    "apply_armed_at",
    "estate_root",
    "backup_dir",
    "apply_armed_receipt_sha256",
    "release_evidence_sha256",
    "dry_run_receipt_sha256",
    "control_sha256",
    "runtime_backup_caller_armed_sha256",
    "runtime_backup_stop_authority_sha256",
    "ingress_opened",
    "successor",
    "successor_armed_receipt",
    "successor_armed_receipt_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "apply_failure_receipt",
    "apply_failure_receipt_sha256",
    "recovery_prior_state",
    "recovery_mode",
    "recovery_attempt_id",
    "recovery_armed_receipt",
    "recovery_armed_receipt_sha256",
    "restore_running_writers_manifest",
    "restore_running_writers_sha256",
    "legacy_empty_strad",
    "pre_restored_retry",
    "pre_restored_source_attempt",
    "pre_restored_runtime_snapshot_sha256",
    "pre_restored_estate_snapshot_sha256",
    "pre_restored_superseded_attempt",
    "pre_restored_superseded_failure_receipt_sha256",
    "pre_restored_superseded_state_sha256",
    "pre_restored_runtime_disposition",
    "writer_set_reconciled",
    "writer_set_source_attempt",
    "writer_set_source_failure_receipt_sha256",
    "writer_set_source_state_sha256",
    "writer_set_source_manifest_sha256",
    "writer_set_preimage_compose_sha256",
    "writer_set_quarantined",
    "transaction_sha256",
    "applied_targets_sha256",
    "recovery_receipt",
    "recovery_receipt_sha256",
}
RECOVERY_CURRENT_KEYS = RECOVERY_ARCHIVE_KEYS | {
    "services_activated",
    "runtime_verified",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def legacy_successor_policy(policy: dict[str, object]) -> dict[str, object]:
    legacy = json.loads(json.dumps(policy))
    legacy["schema_version"] = 2
    legacy["ceremony"] = "holdfast-rikune-successor-v2"
    predecessor = legacy["predecessor"]
    assert isinstance(predecessor, dict)
    predecessor.pop("completion", None)
    predecessor["apply_receipt_sha256"] = hashlib.sha256(
        b"holdfast-test-legacy-apply-receipt"
    ).hexdigest()
    return legacy


def issue_recovery_completion_bundle(
    output: Path,
    key_root: Path,
    *,
    estate: Path,
    predecessor_backup: Path,
    predecessor_current_sha: str,
    predecessor_control_sha: str,
    predecessor_release_sha: str,
    predecessor_runtime_receipt_sha: str,
    predecessor_runtime_manifest_sha: str,
) -> dict[str, str]:
    private_key = key_root / "consumer-recovery-completion-private.pem"
    public_key = output / recovery_completion_attestation.PUBLIC_KEY_NAME
    attestation = output / recovery_completion_attestation.ATTESTATION_NAME
    signature = output / recovery_completion_attestation.SIGNATURE_NAME
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
    public_key.chmod(0o600)
    attempt = "20260828T000100Z-100"
    document: dict[str, object] = {
        "schema_version": 1,
        "kind": recovery_completion_attestation.KIND,
        "ceremony": recovery_completion_attestation.CEREMONY,
        "signature_algorithm": recovery_completion_attestation.SIGNATURE_ALGORITHM,
        "canonicalization_algorithm": recovery_completion_attestation.CANONICALIZATION_ALGORITHM,
        "issued_at": "2026-08-28T00:04:00Z",
        "mode": "resume",
        "successor": True,
        "recovery_schema_version": 2,
        "recovery_attempt_id": attempt,
        "recovery_prior_state": "apply_activation_failed",
        "prior_failure_kind": "activation",
        "prior_failure_receipt": "APPLY-ACTIVATION-FAILED-20260828T000000Z-99.receipt",
        "prior_failure_receipt_sha256": "1" * 64,
        "apply_armed_at": "2026-08-28T00:00:00Z",
        "recovery_armed_at": "2026-08-28T00:01:00Z",
        "recovery_completed_at": "2026-08-28T00:03:00Z",
        "estate_root": str(estate),
        "backup_dir": str(predecessor_backup),
        "current_file": "CURRENT.json",
        "current_sha256": predecessor_current_sha,
        "completion_receipt": f"APPLY-RECOVERY-COMPLETE-{attempt}.receipt",
        "completion_receipt_sha256": "2" * 64,
        "completion_archive": f"APPLY-RECOVERY-COMPLETE-{attempt}.json",
        "completion_archive_sha256": "3" * 64,
        "recovery_armed_receipt": f"APPLY-RECOVERY-ARMED-{attempt}.receipt",
        "recovery_armed_receipt_sha256": "4" * 64,
        "control_file": "CONTROL.sha256",
        "control_sha256": predecessor_control_sha,
        "release_env_file": "release.env",
        "release_env_sha256": "5" * 64,
        "release_evidence_file": "RELEASE-EVIDENCE.json",
        "release_evidence_sha256": predecessor_release_sha,
        "transaction_file": "estate/TRANSACTION.json",
        "transaction_sha256": "6" * 64,
        "applied_targets_file": "estate/APPLIED-TARGETS.sha256",
        "applied_targets_sha256": "7" * 64,
        "runtime_backup_schema": 2,
        "runtime_receipt_file": "runtime/BACKUP.receipt",
        "runtime_receipt_sha256": predecessor_runtime_receipt_sha,
        "runtime_manifest_file": "runtime/SHA256SUMS",
        "runtime_manifest_sha256": predecessor_runtime_manifest_sha,
        "predecessor_release_generation": 2,
        "release_generation": 3,
        "services_activated": True,
        "runtime_verified": True,
        "route_database_state": "absent",
        "public_ipv4_ipv6_closed_status": 404,
        "db_public_db_bracket": "absent-404-absent",
        "ingress_opened": False,
        "apply_receipt_created": False,
        "public_key_sha256": sha256(public_key),
    }
    recovery_completion_attestation.validate_document(document)
    attestation.write_bytes(recovery_completion_attestation.canonical_bytes(document))
    attestation.chmod(0o600)
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature), str(attestation)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    signature.chmod(0o600)
    return {
        "kind": recovery_completion_attestation.KIND,
        "attestation_sha256": sha256(attestation),
        "signature_sha256": sha256(signature),
        "public_key_sha256": sha256(public_key),
    }


def receipt_keys(path: Path) -> tuple[str, ...]:
    return tuple(
        line.split("=", 1)[0]
        for line in path.read_text(encoding="utf-8").splitlines()
    )


class ApplyRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-apply-recovery-")
        self.root = Path(self.temp.name)
        self.estate = self.root / "estate"
        self.backup = self.root / "backup"
        self.state = self.root / "state"
        self.bin = self.root / "bin"
        self.log = self.root / "calls.log"
        for directory in (
            self.estate / "deploy",
            self.estate / "access-governance",
            self.backup / "estate/tree/deploy",
            self.backup / "runtime",
            self.state,
            self.bin,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in (self.estate, self.backup, self.state, self.bin):
            directory.chmod(0o700)

        self.old_content = b"name: old-estate\n"
        self.new_content = b"name: applied-estate\n"
        live_target = self.estate / "deploy/docker-compose.yml"
        live_target.write_bytes(self.new_content)
        backup_target = self.backup / "estate/tree/deploy/docker-compose.yml"
        backup_target.write_bytes(self.old_content)

        targets = self.backup / "estate/APPLIED-TARGETS.sha256"
        preimages = self.backup / "estate/PREIMAGES.sha256"
        absent = self.backup / "estate/ABSENT.before"
        targets.write_text(f"{sha256(live_target)}  deploy/docker-compose.yml\n", encoding="utf-8")
        preimages.write_text(f"{sha256(backup_target)}  deploy/docker-compose.yml\n", encoding="utf-8")
        absent.write_text("", encoding="utf-8")
        (self.backup / "estate/TRANSACTION.json").write_text(
            json.dumps({"schema_version": 1, "state": "applied", "target_count": 1}) + "\n",
            encoding="utf-8",
        )
        (self.backup / "APPLY-PREIMAGES.sha256").write_bytes(preimages.read_bytes())
        (self.backup / "APPLY-ABSENT.paths").write_bytes(absent.read_bytes())
        (self.backup / "RENDER-INPUTS.sha256").write_text(
            f"{'1' * 64}  frozen-input\n", encoding="utf-8"
        )
        (self.backup / "release.env").write_text("SAFE_RELEASE=1\n", encoding="utf-8")
        release_env_sha = sha256(self.backup / "release.env")
        (self.backup / "RELEASE-EVIDENCE.json").write_text(
            json.dumps({"schema_version": 1, "release_env_sha256": release_env_sha}) + "\n",
            encoding="utf-8",
        )
        for name, content in (
            ("SUPPLY-CHAIN.json", b"{}\n"),
            ("SUPPLY-CHAIN.sig", b"signature\n"),
            ("SUPPLY-CHAIN.pub", b"public-key\n"),
        ):
            (self.backup / name).write_bytes(content)

        runtime = self.backup / "runtime"
        (runtime / "strad.dump").write_bytes(b"strad-pg-dump\n")
        (runtime / "RUNNING-SERVICES.before").write_text("", encoding="utf-8")
        (runtime / "VOLUMES.tsv").write_text(
            "\n".join(
                f"{name}\tabsent\ttest_{name}"
                for name in (
                    "strad_uploads",
                    "rikune_workspaces",
                    "rikune_storage",
                    "rikune_state",
                    "rikune_cache",
                    "rikune_audit",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        (runtime / "compose-config.json").write_text(
            json.dumps({"name": "test", "services": {}, "volumes": {}}) + "\n",
            encoding="utf-8",
        )
        (runtime / "RUNTIME-BACKUP-ARMED.receipt").write_text(
            "".join(
                [
                    "schema_version=2\n",
                    f"backup_dir={runtime}\n",
                    "compose_project=test\n",
                    f"compose_config_sha256={sha256(runtime / 'compose-config.json')}\n",
                    "database_identity=postgres:5432/strad\n",
                    "prior_running_services_manifest=RUNNING-SERVICES.before\n",
                    f"prior_running_services_sha256={sha256(runtime / 'RUNNING-SERVICES.before')}\n",
                    "runtime_writer_count=3\n",
                    "runtime_writers=strad,rikune-analyzer,rikune-volume-init\n",
                    "stop_authority=armed-before-writer-stop\n",
                    "volume_init_prior_state=absent\n",
                ]
            ),
            encoding="utf-8",
        )
        runtime_files = [
            "strad.dump",
            "RUNNING-SERVICES.before",
            "VOLUMES.tsv",
            "compose-config.json",
            "RUNTIME-BACKUP-ARMED.receipt",
        ]
        (runtime / "SHA256SUMS").write_text(
            "".join(f"{sha256(runtime / name)}  {name}\n" for name in runtime_files),
            encoding="utf-8",
        )
        (runtime / "BACKUP.receipt").write_text(
            "".join(
                [
                    "schema_version=2\n",
                    "postgres_database=strad\n",
                    "database_identity=postgres:5432/strad\n",
                    "runtime_writers=strad,rikune-analyzer,rikune-volume-init\n",
                    "runtime_writers_stopped=passed\n",
                    "writers_left_quiesced=passed\n",
                    "prior_running_services_manifest=RUNNING-SERVICES.before\n",
                    f"prior_running_services_sha256={sha256(runtime / 'RUNNING-SERVICES.before')}\n",
                    "runtime_backup_armed_receipt=RUNTIME-BACKUP-ARMED.receipt\n",
                    f"runtime_backup_armed_sha256={sha256(runtime / 'RUNTIME-BACKUP-ARMED.receipt')}\n",
                    "isolated_restore_probe=passed\n",
                ]
            ),
            encoding="utf-8",
        )

        dry_values = {
            "cargo_gate": "passed",
            "targets_sha256": sha256(targets),
            "release_evidence_sha256": sha256(self.backup / "RELEASE-EVIDENCE.json"),
            "release_env_sha256": release_env_sha,
            "apply_preimages_sha256": sha256(self.backup / "APPLY-PREIMAGES.sha256"),
            "apply_absent_sha256": sha256(self.backup / "APPLY-ABSENT.paths"),
            "render_inputs_sha256": sha256(self.backup / "RENDER-INPUTS.sha256"),
            "supply_chain_evidence_sha256": sha256(self.backup / "SUPPLY-CHAIN.json"),
            "supply_chain_signature_sha256": sha256(self.backup / "SUPPLY-CHAIN.sig"),
            "supply_chain_public_key_sha256": sha256(self.backup / "SUPPLY-CHAIN.pub"),
        }
        (self.backup / "DRY-RUN.receipt").write_text(
            "".join(f"{key}={value}\n" for key, value in dry_values.items()), encoding="utf-8"
        )
        self.write_control()
        self.write_fakes()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_control(self) -> None:
        names = [
            "RELEASE-EVIDENCE.json",
            "release.env",
            "DRY-RUN.receipt",
            "SUPPLY-CHAIN.json",
            "SUPPLY-CHAIN.sig",
            "SUPPLY-CHAIN.pub",
            "APPLY-PREIMAGES.sha256",
            "APPLY-ABSENT.paths",
            "RENDER-INPUTS.sha256",
            "runtime/SHA256SUMS",
            "runtime/BACKUP.receipt",
        ]
        if (self.backup / "TARGETS.sha256").exists():
            names.append("TARGETS.sha256")
        else:
            names.extend(
                [
                    "estate/APPLIED-TARGETS.sha256",
                    "estate/PREIMAGES.sha256",
                    "estate/ABSENT.before",
                    "estate/TRANSACTION.json",
                ]
            )
        if (self.backup / "APPLY-ARMED.receipt").exists():
            names.append("APPLY-ARMED.receipt")
        if (self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt").exists():
            names.append("RUNTIME-BACKUP-CALLER-ARMED.receipt")
        if (self.backup / "PREDECESSOR-CURRENT.json").exists():
            names.append("PREDECESSOR-CURRENT.json")
        if (self.backup / "SUCCESSOR-ARMED.receipt").exists():
            names.append("SUCCESSOR-ARMED.receipt")
        if (self.backup / "SUCCESSOR-DELTA.sha256").exists():
            names.append("SUCCESSOR-DELTA.sha256")
        for completion_name in (
            recovery_completion_attestation.ATTESTATION_NAME,
            recovery_completion_attestation.SIGNATURE_NAME,
            recovery_completion_attestation.PUBLIC_KEY_NAME,
        ):
            if (self.backup / completion_name).exists():
                names.append(completion_name)
        successor_authority = self.backup / "successor-authority"
        if successor_authority.exists():
            names.extend(
                f"successor-authority/{line.split('  ', 1)[1]}"
                for line in (self.backup / "RENDER-INPUTS.sha256")
                .read_text(encoding="utf-8")
                .splitlines()
            )
            names.extend(
                (
                    "successor-authority/Dockerfile.analyzer",
                    "successor-authority/bridge-package-lock.json",
                    "successor-authority/assets/20260823_rikune_root_up.sql",
                    "successor-authority/assets/20260823_rikune_root_down.sql",
                )
            )
        (self.backup / "CONTROL.sha256").write_text(
            "".join(f"{sha256(self.backup / name)}  {name}\n" for name in names),
            encoding="utf-8",
        )

    @staticmethod
    def replace_receipt_value(path: Path, key: str, value: str) -> None:
        lines = path.read_text(encoding="utf-8").splitlines()
        matches = [index for index, line in enumerate(lines) if line.startswith(f"{key}=")]
        if len(matches) != 1:
            raise AssertionError(f"receipt key is not unique: {key}")
        lines[matches[0]] = f"{key}={value}"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def install_modern_stage_authority(self) -> Path:
        dry = self.root / "dry-run-modern"
        stage = dry / "stage"
        deploy = stage / "deploy"
        deploy.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in (dry, stage, deploy):
            directory.chmod(0o700)

        live_env = self.estate / "deploy/.env"
        preimage_env = self.backup / "estate/tree/deploy/.env"
        live_env.write_text("SAFE_STAGE=1\n", encoding="utf-8")
        preimage_env.write_text("SAFE_STAGE=0\n", encoding="utf-8")
        (deploy / "docker-compose.yml").write_bytes(self.new_content)
        (deploy / ".env").write_bytes(live_env.read_bytes())

        applied = self.backup / "estate/APPLIED-TARGETS.sha256"
        preimages = self.backup / "estate/PREIMAGES.sha256"
        applied.write_text(
            f"{sha256(self.estate / 'deploy/docker-compose.yml')}  deploy/docker-compose.yml\n"
            f"{sha256(live_env)}  deploy/.env\n",
            encoding="utf-8",
        )
        preimages.write_text(
            f"{sha256(self.backup / 'estate/tree/deploy/docker-compose.yml')}  deploy/docker-compose.yml\n"
            f"{sha256(preimage_env)}  deploy/.env\n",
            encoding="utf-8",
        )
        (self.backup / "estate/TRANSACTION.json").write_text(
            json.dumps({"schema_version": 1, "state": "applied", "target_count": 2})
            + "\n",
            encoding="utf-8",
        )
        (self.backup / "TARGETS.sha256").write_bytes(applied.read_bytes())
        (self.backup / "APPLY-PREIMAGES.sha256").write_bytes(preimages.read_bytes())
        (stage / "TARGETS.sha256").write_bytes(applied.read_bytes())
        (dry / "DRY-RUN.receipt").write_bytes(
            (self.backup / "DRY-RUN.receipt").read_bytes()
        )

        self.replace_receipt_value(
            self.backup / "DRY-RUN.receipt", "targets_sha256", sha256(applied)
        )
        self.replace_receipt_value(
            self.backup / "DRY-RUN.receipt",
            "apply_preimages_sha256",
            sha256(self.backup / "APPLY-PREIMAGES.sha256"),
        )
        (dry / "DRY-RUN.receipt").write_bytes(
            (self.backup / "DRY-RUN.receipt").read_bytes()
        )

        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        caller_values = {
            "schema_version": "2",
            "armed_at": "2026-08-25T00:00:00Z",
            "estate_root": str(self.estate),
            "dry_run_dir": str(dry),
            "backup_dir": str(self.backup),
            "runtime_backup_dir": str(self.backup / "runtime"),
            "release_env_sha256": sha256(self.backup / "release.env"),
            "release_evidence_sha256": sha256(self.backup / "RELEASE-EVIDENCE.json"),
            "dry_run_receipt_sha256": sha256(self.backup / "DRY-RUN.receipt"),
            "targets_sha256": sha256(self.backup / "TARGETS.sha256"),
            "apply_preimages_sha256": sha256(self.backup / "APPLY-PREIMAGES.sha256"),
            "apply_absent_sha256": sha256(self.backup / "APPLY-ABSENT.paths"),
            "render_inputs_sha256": sha256(self.backup / "RENDER-INPUTS.sha256"),
            "runtime_backup_armed_receipt": "runtime/RUNTIME-BACKUP-ARMED.receipt",
            "stop_authority_contract": "absence-means-stop-not-started",
            "ingress_opened": "false",
        }
        caller.write_text(
            "".join(f"{key}={value}\n" for key, value in caller_values.items()),
            encoding="utf-8",
        )
        return dry

    def install_legacy_runtime(self) -> None:
        runtime = self.backup / "runtime"
        (runtime / "strad.dump").unlink()
        (runtime / "RUNNING-SERVICES.before").unlink()
        (runtime / "RUNTIME-BACKUP-ARMED.receipt").unlink()
        (runtime / "postgres.dump").write_bytes(b"unsafe-shared-db-dump\n")
        runtime_files = ["postgres.dump", "VOLUMES.tsv", "compose-config.json"]
        (runtime / "SHA256SUMS").write_text(
            "".join(f"{sha256(runtime / name)}  {name}\n" for name in runtime_files),
            encoding="utf-8",
        )
        (runtime / "BACKUP.receipt").write_text(
            "schema_version=1\nisolated_restore_probe=passed\n", encoding="utf-8"
        )
        self.write_control()

    def install_runtime_caller_state(
        self, *, stop_started: bool, backup_succeeded: bool = False
    ) -> None:
        dry = self.root / "dry-run"
        stage = dry / "stage"
        stage.mkdir(parents=True, mode=0o700)
        dry.chmod(0o700)
        (stage / "TARGETS.sha256").write_bytes(
            (self.backup / "estate/APPLIED-TARGETS.sha256").read_bytes()
        )
        for name in (
            "APPLY-PREIMAGES.sha256",
            "APPLY-ABSENT.paths",
            "RENDER-INPUTS.sha256",
            "RELEASE-EVIDENCE.json",
        ):
            shutil.copyfile(self.backup / name, stage / name)
        shutil.copyfile(self.backup / "DRY-RUN.receipt", dry / "DRY-RUN.receipt")

        runtime = self.backup / "runtime"
        if not stop_started:
            shutil.rmtree(runtime)
        else:
            (runtime / "RUNNING-SERVICES.before").write_text("strad\n", encoding="utf-8")
            (runtime / "RUNTIME-BACKUP-ARMED.receipt").write_text(
                "".join(
                    [
                        "schema_version=2\n",
                        f"backup_dir={runtime}\n",
                        "compose_project=test\n",
                        f"compose_config_sha256={sha256(runtime / 'compose-config.json')}\n",
                        "database_identity=postgres:5432/strad\n",
                        "prior_running_services_manifest=RUNNING-SERVICES.before\n",
                        f"prior_running_services_sha256={sha256(runtime / 'RUNNING-SERVICES.before')}\n",
                        "runtime_writer_count=3\n",
                        "runtime_writers=strad,rikune-analyzer,rikune-volume-init\n",
                        "stop_authority=armed-before-writer-stop\n",
                        "volume_init_prior_state=absent\n",
                    ]
                ),
                encoding="utf-8",
            )
            for name in (
                "BACKUP.receipt",
                "SHA256SUMS",
                "RUNTIME-BACKUP-COMPENSATED.receipt",
                "RUNTIME-BACKUP-COMPENSATION-FAILED.receipt",
            ):
                path = runtime / name
                if path.exists():
                    path.unlink()
            if backup_succeeded:
                checksum_names = [
                    "strad.dump",
                    "VOLUMES.tsv",
                    "compose-config.json",
                    "RUNNING-SERVICES.before",
                    "RUNTIME-BACKUP-ARMED.receipt",
                ]
                (runtime / "SHA256SUMS").write_text(
                    "".join(f"{sha256(runtime / name)}  {name}\n" for name in checksum_names),
                    encoding="utf-8",
                )
                (runtime / "BACKUP.receipt").write_text(
                    "".join(
                        [
                            "schema_version=2\n",
                            "postgres_database=strad\n",
                            "database_identity=postgres:5432/strad\n",
                            "runtime_writers=strad,rikune-analyzer,rikune-volume-init\n",
                            "runtime_writers_stopped=passed\n",
                            "writers_left_quiesced=passed\n",
                            "prior_running_services_manifest=RUNNING-SERVICES.before\n",
                            f"prior_running_services_sha256={sha256(runtime / 'RUNNING-SERVICES.before')}\n",
                            "runtime_backup_armed_receipt=RUNTIME-BACKUP-ARMED.receipt\n",
                            f"runtime_backup_armed_sha256={sha256(runtime / 'RUNTIME-BACKUP-ARMED.receipt')}\n",
                            "isolated_restore_probe=passed\n",
                        ]
                    ),
                    encoding="utf-8",
                )

        values = {
            "schema_version": "2",
            "armed_at": "2026-08-25T00:00:00Z",
            "estate_root": str(self.estate),
            "dry_run_dir": str(dry),
            "backup_dir": str(self.backup),
            "runtime_backup_dir": str(runtime),
            "release_env_sha256": sha256(self.backup / "release.env"),
            "release_evidence_sha256": sha256(stage / "RELEASE-EVIDENCE.json"),
            "dry_run_receipt_sha256": sha256(dry / "DRY-RUN.receipt"),
            "targets_sha256": sha256(stage / "TARGETS.sha256"),
            "apply_preimages_sha256": sha256(stage / "APPLY-PREIMAGES.sha256"),
            "apply_absent_sha256": sha256(stage / "APPLY-ABSENT.paths"),
            "render_inputs_sha256": sha256(stage / "RENDER-INPUTS.sha256"),
            "runtime_backup_armed_receipt": "runtime/RUNTIME-BACKUP-ARMED.receipt",
            "stop_authority_contract": "absence-means-stop-not-started",
            "ingress_opened": "false",
        }
        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        caller.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8"
        )
        (self.state / "CURRENT.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "runtime_backup_armed",
                    "runtime_backup_armed_at": values["armed_at"],
                    "estate_root": str(self.estate),
                    "backup_dir": str(self.backup),
                    "dry_run_dir": str(dry),
                    "runtime_backup_dir": str(runtime),
                    "runtime_backup_caller_armed_receipt": caller.name,
                    "runtime_backup_caller_armed_receipt_sha256": sha256(caller),
                    "runtime_backup_armed_receipt": "runtime/RUNTIME-BACKUP-ARMED.receipt",
                    "release_env_sha256": values["release_env_sha256"],
                    "release_evidence_sha256": values["release_evidence_sha256"],
                    "dry_run_receipt_sha256": values["dry_run_receipt_sha256"],
                    "targets_sha256": values["targets_sha256"],
                    "apply_preimages_sha256": values["apply_preimages_sha256"],
                    "apply_absent_sha256": values["apply_absent_sha256"],
                    "render_inputs_sha256": values["render_inputs_sha256"],
                    "stop_authority_contract": values["stop_authority_contract"],
                    "ingress_opened": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def install_activation_failed_state(self) -> Path:
        dry = self.install_modern_stage_authority()
        armed = self.backup / "APPLY-ARMED.receipt"
        armed.write_text(
            "".join(
                [
                    "schema_version=1\n",
                    "armed_at=2026-08-25T00:00:00Z\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={self.backup}\n",
                    f"dry_run_dir={dry}\n",
                    f"release_env_sha256={sha256(self.backup / 'release.env')}\n",
                    f"release_evidence_sha256={sha256(self.backup / 'RELEASE-EVIDENCE.json')}\n",
                    f"dry_run_receipt_sha256={sha256(self.backup / 'DRY-RUN.receipt')}\n",
                    f"targets_sha256={sha256(self.backup / 'TARGETS.sha256')}\n",
                    f"apply_preimages_sha256={sha256(self.backup / 'APPLY-PREIMAGES.sha256')}\n",
                    f"apply_absent_sha256={sha256(self.backup / 'APPLY-ABSENT.paths')}\n",
                    f"render_inputs_sha256={sha256(self.backup / 'RENDER-INPUTS.sha256')}\n",
                    f"runtime_backup_receipt_sha256={sha256(self.backup / 'runtime/BACKUP.receipt')}\n",
                    f"runtime_backup_manifest_sha256={sha256(self.backup / 'runtime/SHA256SUMS')}\n",
                    f"runtime_backup_caller_armed_sha256={sha256(self.backup / 'RUNTIME-BACKUP-CALLER-ARMED.receipt')}\n",
                    f"runtime_backup_stop_authority_sha256={sha256(self.backup / 'runtime/RUNTIME-BACKUP-ARMED.receipt')}\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        self.write_control()
        failure = self.state / "APPLY-ACTIVATION-FAILED-20260825T000000Z-1.receipt"
        failure.write_text(
            "".join(
                [
                    "failed_at=2026-08-25T00:00:00Z\n",
                    "phase=activation\n",
                    "activation_step=runtime_verify\n",
                    "status=1\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={self.backup}\n",
                    f"apply_armed_receipt_sha256={sha256(armed)}\n",
                    f"control_sha256={sha256(self.backup / 'CONTROL.sha256')}\n",
                    f"transaction_sha256={sha256(self.backup / 'estate/TRANSACTION.json')}\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        failure.chmod(0o600)
        (self.state / "CURRENT.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "apply_activation_failed",
                    "apply_armed_at": "2026-08-25T00:00:00Z",
                    "estate_root": str(self.estate),
                    "backup_dir": str(self.backup),
                    "apply_armed_receipt_sha256": sha256(armed),
                    "release_evidence_sha256": sha256(self.backup / "RELEASE-EVIDENCE.json"),
                    "dry_run_receipt_sha256": sha256(self.backup / "DRY-RUN.receipt"),
                    "control_sha256": sha256(self.backup / "CONTROL.sha256"),
                    "runtime_backup_caller_armed_sha256": sha256(
                        self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
                    ),
                    "runtime_backup_stop_authority_sha256": sha256(
                        self.backup / "runtime/RUNTIME-BACKUP-ARMED.receipt"
                    ),
                    "apply_failure_receipt": failure.name,
                    "apply_failure_receipt_sha256": sha256(failure),
                    "ingress_opened": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return failure

    def install_exact_production_predecessor_authority(
        self, predecessor: Path, release_generation: int
    ) -> bytes:
        prior = self.root / "predecessor-generation-1-backup"
        prior_runtime = prior / "runtime"
        prior_estate = prior / "estate"
        prior_runtime.mkdir(parents=True, mode=0o700)
        prior_estate.mkdir(mode=0o700)
        prior.chmod(0o700)
        for name in (
            "strad.dump",
            "RUNNING-SERVICES.before",
            "VOLUMES.tsv",
            "compose-config.json",
            "RUNTIME-BACKUP-ARMED.receipt",
            "SHA256SUMS",
            "BACKUP.receipt",
        ):
            shutil.copyfile(self.backup / "runtime" / name, prior_runtime / name)
        for name in ("TRANSACTION.json", "APPLIED-TARGETS.sha256"):
            shutil.copyfile(self.backup / "estate" / name, prior_estate / name)
        shutil.copyfile(self.backup / "release.env", prior / "release.env")
        shutil.copyfile(
            self.backup / "RENDER-INPUTS.sha256", prior / "RENDER-INPUTS.sha256"
        )
        prior_release_env_sha = sha256(prior / "release.env")
        (prior / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "release_env_sha256": prior_release_env_sha,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prior_armed = prior / "APPLY-ARMED.receipt"
        prior_armed.write_text(
            "".join(
                [
                    "schema_version=1\n",
                    "armed_at=2026-08-23T00:00:00Z\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={prior}\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        prior_control_names = (
            "RELEASE-EVIDENCE.json",
            "release.env",
            "RENDER-INPUTS.sha256",
            "APPLY-ARMED.receipt",
            "runtime/SHA256SUMS",
            "runtime/BACKUP.receipt",
        )
        (prior / "CONTROL.sha256").write_text(
            "".join(
                f"{sha256(prior / name)}  {name}\n" for name in prior_control_names
            ),
            encoding="utf-8",
        )
        prior_control_sha = sha256(prior / "CONTROL.sha256")
        prior_release_sha = sha256(prior / "RELEASE-EVIDENCE.json")
        prior_runtime_receipt_sha = sha256(prior_runtime / "BACKUP.receipt")
        prior_runtime_manifest_sha = sha256(prior_runtime / "SHA256SUMS")
        prior_apply = prior / "APPLY.receipt"
        prior_apply.write_text(
            "".join(
                [
                    "schema_version=2\n",
                    "completion_state=applied_ingress_closed\n",
                    "applied_at=2026-08-23T00:00:02Z\n",
                    "closed_verified_at=2026-08-23T00:00:01Z\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={prior}\n",
                    f"release_env_sha256={prior_release_env_sha}\n",
                    f"release_evidence_sha256={prior_release_sha}\n",
                    f"render_inputs_sha256={sha256(prior / 'RENDER-INPUTS.sha256')}\n",
                    f"apply_armed_receipt_sha256={sha256(prior_armed)}\n",
                    f"control_sha256={prior_control_sha}\n",
                    f"transaction_sha256={sha256(prior_estate / 'TRANSACTION.json')}\n",
                    f"applied_targets_sha256={sha256(prior_estate / 'APPLIED-TARGETS.sha256')}\n",
                    "cargo_gate=passed\n",
                    "runtime_backup=passed\n",
                    "closed_bracket=passed\n",
                    "route_database_state=absent\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "ingress_opened=false\n",
                    "services_activated=true\n",
                    "runtime_verified=true\n",
                ]
            ),
            encoding="utf-8",
        )
        prior_current = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "estate_root": str(self.estate),
            "backup_dir": str(prior),
            "apply_receipt_sha256": sha256(prior_apply),
            "apply_armed_receipt_sha256": sha256(prior_armed),
            "control_sha256": prior_control_sha,
            "release_evidence_sha256": prior_release_sha,
            "transaction_sha256": sha256(prior_estate / "TRANSACTION.json"),
            "applied_targets_sha256": sha256(
                prior_estate / "APPLIED-TARGETS.sha256"
            ),
            "closed_verified_at": "2026-08-23T00:00:01Z",
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": 404,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
        }
        nested_current = predecessor / "PREDECESSOR-CURRENT.json"
        nested_current.write_text(
            json.dumps(prior_current) + "\n", encoding="utf-8"
        )
        nested_current_sha = sha256(nested_current)

        predecessor_estate = predecessor / "estate"
        predecessor_estate.mkdir(mode=0o700)
        for name in ("TRANSACTION.json", "APPLIED-TARGETS.sha256"):
            shutil.copyfile(self.backup / "estate" / name, predecessor_estate / name)
        shutil.copyfile(
            self.backup / "RENDER-INPUTS.sha256",
            predecessor / "RENDER-INPUTS.sha256",
        )
        (predecessor / "DRY-RUN.receipt").write_text(
            "schema_version=1\n", encoding="utf-8"
        )
        predecessor_release_env_sha = sha256(predecessor / "release.env")
        predecessor_release = {
            "schema_version": 2,
            "release_mode": "successor",
            "release_env_sha256": predecessor_release_env_sha,
            "predecessor_binding": {
                "current_state_sha256": nested_current_sha,
                "control_sha256": prior_control_sha,
                "apply_receipt_sha256": sha256(prior_apply),
                "release_evidence_sha256": prior_release_sha,
                "runtime_manifest_sha256": prior_runtime_manifest_sha,
            },
        }
        (predecessor / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(predecessor_release) + "\n", encoding="utf-8"
        )
        predecessor_successor_arm = predecessor / "SUCCESSOR-ARMED.receipt"
        predecessor_successor_arm.write_text(
            "".join(
                [
                    "schema_version=1\n",
                    "armed_at=2026-08-24T00:00:00Z\n",
                    f"estate_root={self.estate}\n",
                    f"successor_backup_dir={predecessor}\n",
                    f"candidate_dry_run_receipt_sha256={sha256(predecessor / 'DRY-RUN.receipt')}\n",
                    f"candidate_release_evidence_sha256={sha256(predecessor / 'RELEASE-EVIDENCE.json')}\n",
                    "predecessor_current_file=PREDECESSOR-CURRENT.json\n",
                    f"predecessor_current_sha256={nested_current_sha}\n",
                    f"predecessor_backup_dir={prior}\n",
                    f"predecessor_control_sha256={prior_control_sha}\n",
                    f"predecessor_apply_receipt_sha256={sha256(prior_apply)}\n",
                    f"predecessor_release_evidence_sha256={prior_release_sha}\n",
                    f"predecessor_runtime_backup_receipt_sha256={prior_runtime_receipt_sha}\n",
                    f"predecessor_runtime_backup_manifest_sha256={prior_runtime_manifest_sha}\n",
                    "predecessor_release_generation=1\n",
                    f"release_generation={release_generation}\n",
                    "route_database_state=absent\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "predecessor_runtime_verified=true\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        predecessor_armed = predecessor / "APPLY-ARMED.receipt"
        predecessor_armed.write_text(
            "".join(
                [
                    "schema_version=1\n",
                    "armed_at=2026-08-24T00:00:00Z\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={predecessor}\n",
                    f"successor_armed_receipt_sha256={sha256(predecessor_successor_arm)}\n",
                    f"predecessor_current_sha256={nested_current_sha}\n",
                    f"predecessor_backup_dir={prior}\n",
                    f"predecessor_release_generation=1\n",
                    f"release_generation={release_generation}\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        predecessor_control_names = (
            "RELEASE-EVIDENCE.json",
            "release.env",
            "DRY-RUN.receipt",
            "RENDER-INPUTS.sha256",
            "APPLY-ARMED.receipt",
            "runtime/SHA256SUMS",
            "runtime/BACKUP.receipt",
            "PREDECESSOR-CURRENT.json",
            "SUCCESSOR-ARMED.receipt",
        )
        (predecessor / "CONTROL.sha256").write_text(
            "".join(
                f"{sha256(predecessor / name)}  {name}\n"
                for name in predecessor_control_names
            ),
            encoding="utf-8",
        )
        predecessor_control_sha = sha256(predecessor / "CONTROL.sha256")
        predecessor_release_sha = sha256(predecessor / "RELEASE-EVIDENCE.json")
        predecessor_runtime_receipt_sha = sha256(
            predecessor / "runtime/BACKUP.receipt"
        )
        predecessor_runtime_manifest_sha = sha256(
            predecessor / "runtime/SHA256SUMS"
        )
        predecessor_apply = predecessor / "APPLY.receipt"
        predecessor_apply.write_text(
            "".join(
                [
                    "schema_version=2\n",
                    "completion_state=applied_ingress_closed\n",
                    "applied_at=2026-08-24T00:00:02Z\n",
                    "closed_verified_at=2026-08-24T00:00:01Z\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={predecessor}\n",
                    f"release_env_sha256={predecessor_release_env_sha}\n",
                    f"release_evidence_sha256={predecessor_release_sha}\n",
                    f"render_inputs_sha256={sha256(predecessor / 'RENDER-INPUTS.sha256')}\n",
                    f"apply_armed_receipt_sha256={sha256(predecessor_armed)}\n",
                    f"control_sha256={predecessor_control_sha}\n",
                    f"transaction_sha256={sha256(predecessor_estate / 'TRANSACTION.json')}\n",
                    f"applied_targets_sha256={sha256(predecessor_estate / 'APPLIED-TARGETS.sha256')}\n",
                    "cargo_gate=passed\n",
                    "runtime_backup=passed\n",
                    "closed_bracket=passed\n",
                    "route_database_state=absent\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "ingress_opened=false\n",
                    "services_activated=true\n",
                    "runtime_verified=true\n",
                    "successor=true\n",
                    "successor_armed_receipt=SUCCESSOR-ARMED.receipt\n",
                    f"successor_armed_receipt_sha256={sha256(predecessor_successor_arm)}\n",
                    "predecessor_current_file=PREDECESSOR-CURRENT.json\n",
                    f"predecessor_current_sha256={nested_current_sha}\n",
                    f"predecessor_backup_dir={prior}\n",
                    f"predecessor_control_sha256={prior_control_sha}\n",
                    f"predecessor_apply_receipt_sha256={sha256(prior_apply)}\n",
                    f"predecessor_release_evidence_sha256={prior_release_sha}\n",
                    f"predecessor_runtime_backup_receipt_sha256={prior_runtime_receipt_sha}\n",
                    f"predecessor_runtime_backup_manifest_sha256={prior_runtime_manifest_sha}\n",
                    "predecessor_release_generation=1\n",
                    f"release_generation={release_generation}\n",
                    f"runtime_backup_receipt_sha256={predecessor_runtime_receipt_sha}\n",
                    f"runtime_backup_manifest_sha256={predecessor_runtime_manifest_sha}\n",
                ]
            ),
            encoding="utf-8",
        )
        predecessor_current = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "estate_root": str(self.estate),
            "backup_dir": str(predecessor),
            "apply_receipt_sha256": sha256(predecessor_apply),
            "apply_armed_receipt_sha256": sha256(predecessor_armed),
            "control_sha256": predecessor_control_sha,
            "release_evidence_sha256": predecessor_release_sha,
            "transaction_sha256": sha256(predecessor_estate / "TRANSACTION.json"),
            "applied_targets_sha256": sha256(
                predecessor_estate / "APPLIED-TARGETS.sha256"
            ),
            "closed_verified_at": "2026-08-24T00:00:01Z",
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": 404,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
            "successor": True,
            "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
            "successor_armed_receipt_sha256": sha256(predecessor_successor_arm),
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": nested_current_sha,
            "predecessor_backup_dir": str(prior),
            "predecessor_control_sha256": prior_control_sha,
            "predecessor_apply_receipt_sha256": sha256(prior_apply),
            "predecessor_release_evidence_sha256": prior_release_sha,
            "predecessor_runtime_backup_receipt_sha256": prior_runtime_receipt_sha,
            "predecessor_runtime_backup_manifest_sha256": prior_runtime_manifest_sha,
            "predecessor_release_generation": 1,
            "release_generation": release_generation,
            "runtime_backup_receipt_sha256": predecessor_runtime_receipt_sha,
            "runtime_backup_manifest_sha256": predecessor_runtime_manifest_sha,
        }
        return (json.dumps(predecessor_current) + "\n").encode()

    def install_successor_activation_failed_state(
        self,
        *,
        predecessor_generation: int = 1,
        release_generation: int = 2,
        historical_apply_armed_duplicates: bool = False,
        production_predecessor_shape: bool = False,
    ) -> bytes:
        failure = self.install_activation_failed_state()
        dry = self.root / "dry-run-modern"
        predecessor = self.root / "predecessor-backup"
        predecessor_runtime = predecessor / "runtime"
        predecessor_runtime.mkdir(parents=True, mode=0o700)
        predecessor.chmod(0o700)
        for name in (
            "strad.dump",
            "RUNNING-SERVICES.before",
            "VOLUMES.tsv",
            "compose-config.json",
            "RUNTIME-BACKUP-ARMED.receipt",
            "SHA256SUMS",
            "BACKUP.receipt",
        ):
            shutil.copyfile(self.backup / "runtime" / name, predecessor_runtime / name)
        shutil.copyfile(
            self.backup / "RELEASE-EVIDENCE.json",
            predecessor / "RELEASE-EVIDENCE.json",
        )
        shutil.copyfile(self.backup / "release.env", predecessor / "release.env")
        predecessor_control_names = (
            "RELEASE-EVIDENCE.json",
            "release.env",
            "runtime/SHA256SUMS",
            "runtime/BACKUP.receipt",
        )
        (predecessor / "CONTROL.sha256").write_text(
            "".join(
                f"{sha256(predecessor / name)}  {name}\n"
                for name in predecessor_control_names
            ),
            encoding="utf-8",
        )
        predecessor_control_sha = sha256(predecessor / "CONTROL.sha256")
        predecessor_release_sha = sha256(predecessor / "RELEASE-EVIDENCE.json")
        predecessor_runtime_receipt_sha = sha256(predecessor_runtime / "BACKUP.receipt")
        predecessor_runtime_manifest_sha = sha256(predecessor_runtime / "SHA256SUMS")
        predecessor_apply = predecessor / "APPLY.receipt"
        predecessor_apply.write_text(
            "".join(
                [
                    "schema_version=2\n",
                    "completion_state=applied_ingress_closed\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={predecessor}\n",
                    f"control_sha256={predecessor_control_sha}\n",
                    f"release_evidence_sha256={predecessor_release_sha}\n",
                    "runtime_backup=passed\n",
                    "closed_bracket=passed\n",
                    "route_database_state=absent\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "services_activated=true\n",
                    "runtime_verified=true\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        predecessor_apply_sha = sha256(predecessor_apply)
        predecessor_current = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "estate_root": str(self.estate),
            "backup_dir": str(predecessor),
            "control_sha256": predecessor_control_sha,
            "apply_receipt_sha256": predecessor_apply_sha,
            "release_evidence_sha256": predecessor_release_sha,
            "runtime_backup_receipt_sha256": predecessor_runtime_receipt_sha,
            "runtime_backup_manifest_sha256": predecessor_runtime_manifest_sha,
            "release_generation": predecessor_generation,
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": 404,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
        }
        predecessor_bytes = (json.dumps(predecessor_current) + "\n").encode()
        if production_predecessor_shape:
            predecessor_bytes = self.install_exact_production_predecessor_authority(
                predecessor, predecessor_generation
            )
            predecessor_control_sha = sha256(predecessor / "CONTROL.sha256")
            predecessor_release_sha = sha256(
                predecessor / "RELEASE-EVIDENCE.json"
            )
            predecessor_runtime_receipt_sha = sha256(
                predecessor_runtime / "BACKUP.receipt"
            )
            predecessor_runtime_manifest_sha = sha256(
                predecessor_runtime / "SHA256SUMS"
            )
            predecessor_apply_sha = sha256(predecessor / "APPLY.receipt")
        (self.backup / "PREDECESSOR-CURRENT.json").write_bytes(predecessor_bytes)
        predecessor_current_sha = sha256(self.backup / "PREDECESSOR-CURRENT.json")

        successor_evidence = {
            "schema_version": 2,
            "release_mode": "successor",
            "release_env_sha256": sha256(self.backup / "release.env"),
            "predecessor_binding": {
                "current_state_sha256": predecessor_current_sha,
                "control_sha256": predecessor_control_sha,
                "apply_receipt_sha256": predecessor_apply_sha,
                "release_evidence_sha256": predecessor_release_sha,
                "runtime_manifest_sha256": predecessor_runtime_manifest_sha,
            },
        }
        successor_delta = self.backup / "SUCCESSOR-DELTA.sha256"
        successor_delta.write_text(f"{'d' * 64}  successor-overlay\n", encoding="utf-8")
        shutil.copyfile(successor_delta, dry / "stage/SUCCESSOR-DELTA.sha256")
        successor_authority = self.backup / "successor-authority"
        successor_authority.mkdir(mode=0o700)
        generation_authorities = (
            "successor-static-targets.sha256",
            "successor-frozen-targets.json",
            "successor-preimages.sha256",
            "successor-absent.paths",
            "successor-supporting-targets.sha256",
            "successor-policy.json",
        )
        for name in generation_authorities:
            shutil.copyfile(OPS_ROOT / name, successor_authority / name)
        legacy_policy_path = successor_authority / "successor-policy.json"
        legacy_policy = legacy_successor_policy(
            json.loads(legacy_policy_path.read_text(encoding="utf-8"))
        )
        legacy_policy_path.write_text(
            json.dumps(legacy_policy) + "\n", encoding="utf-8"
        )
        (self.backup / "RENDER-INPUTS.sha256").write_text(
            "".join(
                f"{sha256(successor_authority / name)}  {name}\n"
                for name in generation_authorities
            ),
            encoding="utf-8",
        )
        (successor_authority / "assets").mkdir(mode=0o700)
        for name in (
            "20260823_rikune_root_up.sql",
            "20260823_rikune_root_down.sql",
        ):
            shutil.copyfile(
                OPS_ROOT / "assets" / name,
                successor_authority / "assets" / name,
            )
        render_inputs_sha = sha256(self.backup / "RENDER-INPUTS.sha256")
        self.replace_receipt_value(
            self.backup / "DRY-RUN.receipt",
            "render_inputs_sha256",
            render_inputs_sha,
        )
        shutil.copyfile(
            OPS_ROOT.parents[1] / "Dockerfile.analyzer",
            successor_authority / "Dockerfile.analyzer",
        )
        shutil.copyfile(
            OPS_ROOT.parents[1] / "bridge/package-lock.json",
            successor_authority / "bridge-package-lock.json",
        )
        successor_evidence["successor_delta_sha256"] = sha256(successor_delta)
        (self.backup / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(successor_evidence) + "\n", encoding="utf-8"
        )
        shutil.copyfile(
            self.backup / "RELEASE-EVIDENCE.json",
            dry / "stage/RELEASE-EVIDENCE.json",
        )
        self.replace_receipt_value(
            self.backup / "DRY-RUN.receipt",
            "release_evidence_sha256",
            sha256(self.backup / "RELEASE-EVIDENCE.json"),
        )
        with (self.backup / "DRY-RUN.receipt").open("a", encoding="utf-8") as handle:
            handle.write(f"successor_delta_sha256={sha256(successor_delta)}\n")
        shutil.copyfile(self.backup / "DRY-RUN.receipt", dry / "DRY-RUN.receipt")

        successor_arm = self.backup / "SUCCESSOR-ARMED.receipt"
        successor_arm.write_text(
            "".join(
                [
                    "schema_version=1\n",
                    "armed_at=2026-08-25T00:00:00Z\n",
                    f"estate_root={self.estate}\n",
                    f"successor_backup_dir={self.backup}\n",
                    f"candidate_dry_run_receipt_sha256={sha256(self.backup / 'DRY-RUN.receipt')}\n",
                    f"candidate_release_evidence_sha256={sha256(self.backup / 'RELEASE-EVIDENCE.json')}\n",
                    "predecessor_current_file=PREDECESSOR-CURRENT.json\n",
                    f"predecessor_current_sha256={predecessor_current_sha}\n",
                    f"predecessor_backup_dir={predecessor}\n",
                    f"predecessor_control_sha256={predecessor_control_sha}\n",
                    f"predecessor_apply_receipt_sha256={predecessor_apply_sha}\n",
                    f"predecessor_release_evidence_sha256={predecessor_release_sha}\n",
                    f"predecessor_runtime_backup_receipt_sha256={predecessor_runtime_receipt_sha}\n",
                    f"predecessor_runtime_backup_manifest_sha256={predecessor_runtime_manifest_sha}\n",
                    f"predecessor_release_generation={predecessor_generation}\n",
                    f"release_generation={release_generation}\n",
                    "route_database_state=absent\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "predecessor_runtime_verified=true\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        successor_arm_sha = sha256(successor_arm)
        lineage = {
            "successor": True,
            "successor_armed_receipt": successor_arm.name,
            "successor_armed_receipt_sha256": successor_arm_sha,
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_current_sha256": predecessor_current_sha,
            "predecessor_backup_dir": str(predecessor),
            "predecessor_control_sha256": predecessor_control_sha,
            "predecessor_apply_receipt_sha256": predecessor_apply_sha,
            "predecessor_release_evidence_sha256": predecessor_release_sha,
            "predecessor_runtime_backup_receipt_sha256": predecessor_runtime_receipt_sha,
            "predecessor_runtime_backup_manifest_sha256": predecessor_runtime_manifest_sha,
            "predecessor_release_generation": predecessor_generation,
            "release_generation": release_generation,
        }
        lineage_receipt = [
            "successor=true\n",
            f"successor_armed_receipt=SUCCESSOR-ARMED.receipt\n",
            f"successor_armed_receipt_sha256={successor_arm_sha}\n",
            "predecessor_current_file=PREDECESSOR-CURRENT.json\n",
            f"predecessor_current_sha256={predecessor_current_sha}\n",
            f"predecessor_backup_dir={predecessor}\n",
            f"predecessor_control_sha256={predecessor_control_sha}\n",
            f"predecessor_apply_receipt_sha256={predecessor_apply_sha}\n",
            f"predecessor_release_evidence_sha256={predecessor_release_sha}\n",
            f"predecessor_runtime_backup_receipt_sha256={predecessor_runtime_receipt_sha}\n",
            f"predecessor_runtime_backup_manifest_sha256={predecessor_runtime_manifest_sha}\n",
            f"predecessor_release_generation={predecessor_generation}\n",
            f"release_generation={release_generation}\n",
        ]
        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        self.replace_receipt_value(
            caller,
            "release_evidence_sha256",
            sha256(self.backup / "RELEASE-EVIDENCE.json"),
        )
        self.replace_receipt_value(
            caller,
            "dry_run_receipt_sha256",
            sha256(self.backup / "DRY-RUN.receipt"),
        )
        self.replace_receipt_value(
            caller, "render_inputs_sha256", render_inputs_sha
        )
        caller.write_text(
            caller.read_text(encoding="utf-8") + "".join(lineage_receipt),
            encoding="utf-8",
        )
        armed = self.backup / "APPLY-ARMED.receipt"
        self.replace_receipt_value(
            armed,
            "release_evidence_sha256",
            sha256(self.backup / "RELEASE-EVIDENCE.json"),
        )
        self.replace_receipt_value(
            armed,
            "dry_run_receipt_sha256",
            sha256(self.backup / "DRY-RUN.receipt"),
        )
        self.replace_receipt_value(
            armed, "render_inputs_sha256", render_inputs_sha
        )
        self.replace_receipt_value(
            armed, "runtime_backup_caller_armed_sha256", sha256(caller)
        )
        historical_duplicates = []
        if historical_apply_armed_duplicates:
            historical_duplicates = [
                f"runtime_backup_receipt_sha256={sha256(self.backup / 'runtime/BACKUP.receipt')}\n",
                f"runtime_backup_manifest_sha256={sha256(self.backup / 'runtime/SHA256SUMS')}\n",
            ]
        armed.write_text(
            armed.read_text(encoding="utf-8")
            + "".join(lineage_receipt)
            + "".join(historical_duplicates),
            encoding="utf-8",
        )
        self.write_control()

        failure_values = failure.read_text(encoding="utf-8")
        failure_values = failure_values.replace(
            next(
                line
                for line in failure_values.splitlines()
                if line.startswith("apply_armed_receipt_sha256=")
            ),
            f"apply_armed_receipt_sha256={sha256(armed)}",
        ).replace(
            next(
                line
                for line in failure_values.splitlines()
                if line.startswith("control_sha256=")
            ),
            f"control_sha256={sha256(self.backup / 'CONTROL.sha256')}",
        )
        failure.write_text(failure_values, encoding="utf-8")
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current.update(lineage)
        current.update(
            {
                "apply_armed_receipt_sha256": sha256(armed),
                "release_evidence_sha256": sha256(
                    self.backup / "RELEASE-EVIDENCE.json"
                ),
                "dry_run_receipt_sha256": sha256(self.backup / "DRY-RUN.receipt"),
                "control_sha256": sha256(self.backup / "CONTROL.sha256"),
                "runtime_backup_caller_armed_sha256": sha256(caller),
                "apply_failure_receipt_sha256": sha256(failure),
            }
        )
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        return predecessor_bytes

    def install_recovered_successor_v3_activation_failed_state(
        self,
    ) -> tuple[bytes, Path]:
        self.install_successor_activation_failed_state(
            predecessor_generation=3,
            release_generation=4,
        )
        predecessor_backup = self.root / "predecessor-backup"
        predecessor_snapshot = self.backup / "PREDECESSOR-CURRENT.json"
        predecessor = json.loads(predecessor_snapshot.read_text(encoding="utf-8"))
        predecessor.pop("apply_receipt_sha256")
        predecessor.pop("route_database_state")
        predecessor.pop("public_ipv4_ipv6_closed_status")
        predecessor_runtime_receipt_sha = predecessor.pop(
            "runtime_backup_receipt_sha256"
        )
        predecessor_runtime_manifest_sha = predecessor.pop(
            "runtime_backup_manifest_sha256"
        )
        predecessor.update(
            {
                "successor": True,
                "predecessor_release_generation": 2,
                "release_generation": 3,
            }
        )
        predecessor_bytes = (json.dumps(predecessor) + "\n").encode()
        predecessor_snapshot.write_bytes(predecessor_bytes)
        predecessor_current_sha = sha256(predecessor_snapshot)
        completion = issue_recovery_completion_bundle(
            self.backup,
            self.root,
            estate=self.estate,
            predecessor_backup=predecessor_backup,
            predecessor_current_sha=predecessor_current_sha,
            predecessor_control_sha=predecessor["control_sha256"],
            predecessor_release_sha=predecessor["release_evidence_sha256"],
            predecessor_runtime_receipt_sha=predecessor_runtime_receipt_sha,
            predecessor_runtime_manifest_sha=predecessor_runtime_manifest_sha,
        )

        authority = self.backup / "successor-authority"
        policy_path = authority / "successor-policy.json"
        policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        policy["predecessor"].update(
            {
                "current_state_sha256": predecessor_current_sha,
                "control_sha256": predecessor["control_sha256"],
                "release_evidence_sha256": predecessor[
                    "release_evidence_sha256"
                ],
                "runtime_manifest_sha256": predecessor_runtime_manifest_sha,
                "completion": completion,
            }
        )
        policy_path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        generation_authorities = tuple(
            line.split("  ", 1)[1]
            for line in (self.backup / "RENDER-INPUTS.sha256")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        render_inputs = self.backup / "RENDER-INPUTS.sha256"
        render_inputs.write_text(
            "".join(
                f"{sha256(authority / name)}  {name}\n"
                for name in generation_authorities
            ),
            encoding="utf-8",
        )

        evidence_path = self.backup / "RELEASE-EVIDENCE.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["predecessor_binding"] = policy["predecessor"]
        evidence["route_up_sha256"] = sha256(
            authority / "assets/20260823_rikune_root_up.sql"
        )
        evidence["route_down_sha256"] = sha256(
            authority / "assets/20260823_rikune_root_down.sql"
        )
        evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
        dry_path = self.backup / "DRY-RUN.receipt"
        dry_values = dict(
            line.split("=", 1)
            for line in dry_path.read_text(encoding="utf-8").splitlines()
        )
        dry_values.update(
            {
                "release_evidence_sha256": sha256(evidence_path),
                "render_inputs_sha256": sha256(render_inputs),
                "successor_delta_sha256": sha256(
                    self.backup / "SUCCESSOR-DELTA.sha256"
                ),
                "predecessor_completion_kind": completion["kind"],
                "predecessor_completion_attestation_sha256": completion[
                    "attestation_sha256"
                ],
                "predecessor_completion_signature_sha256": completion[
                    "signature_sha256"
                ],
                "predecessor_completion_public_key_sha256": completion[
                    "public_key_sha256"
                ],
                "supply_chain_evidence_sha256": sha256(
                    self.backup / "SUPPLY-CHAIN.json"
                ),
                "supply_chain_signature_sha256": sha256(
                    self.backup / "SUPPLY-CHAIN.sig"
                ),
                "supply_chain_public_key_sha256": sha256(
                    self.backup / "SUPPLY-CHAIN.pub"
                ),
            }
        )
        dry_path.write_text(
            "".join(f"{key}={value}\n" for key, value in dry_values.items()),
            encoding="utf-8",
        )

        dry = self.root / "dry-run-modern"
        (dry / "DRY-RUN.receipt").write_bytes(dry_path.read_bytes())
        (dry / "stage/RELEASE-EVIDENCE.json").write_bytes(
            evidence_path.read_bytes()
        )
        for name in (
            recovery_completion_attestation.ATTESTATION_NAME,
            recovery_completion_attestation.SIGNATURE_NAME,
            recovery_completion_attestation.PUBLIC_KEY_NAME,
        ):
            shutil.copy2(self.backup / name, dry / "stage" / name)

        def rewrite_lineage(path: Path) -> None:
            values = dict(
                line.split("=", 1)
                for line in path.read_text(encoding="utf-8").splitlines()
            )
            values.pop("predecessor_apply_receipt_sha256")
            values.update(
                {
                    "predecessor_current_sha256": predecessor_current_sha,
                    "predecessor_backup_dir": str(predecessor_backup),
                    "predecessor_control_sha256": predecessor["control_sha256"],
                    "predecessor_completion_kind": completion["kind"],
                    "predecessor_completion_attestation_sha256": completion[
                        "attestation_sha256"
                    ],
                    "predecessor_completion_signature_sha256": completion[
                        "signature_sha256"
                    ],
                    "predecessor_completion_public_key_sha256": completion[
                        "public_key_sha256"
                    ],
                    "predecessor_release_evidence_sha256": predecessor[
                        "release_evidence_sha256"
                    ],
                    "predecessor_runtime_backup_receipt_sha256": (
                        predecessor_runtime_receipt_sha
                    ),
                    "predecessor_runtime_backup_manifest_sha256": (
                        predecessor_runtime_manifest_sha
                    ),
                    "predecessor_release_generation": "3",
                    "release_generation": "4",
                }
            )
            path.write_text(
                "".join(f"{key}={value}\n" for key, value in values.items()),
                encoding="utf-8",
            )

        successor_arm = self.backup / "SUCCESSOR-ARMED.receipt"
        rewrite_lineage(successor_arm)
        successor_arm_lines = successor_arm.read_text(encoding="utf-8").splitlines()
        policy_line = next(
            index
            for index, line in enumerate(successor_arm_lines)
            if line.startswith("candidate_release_evidence_sha256=")
        )
        successor_arm_lines.insert(
            policy_line + 1, f"successor_policy_sha256={sha256(policy_path)}"
        )
        successor_arm.write_text(
            "\n".join(successor_arm_lines) + "\n", encoding="utf-8"
        )
        self.replace_receipt_value(
            successor_arm, "candidate_dry_run_receipt_sha256", sha256(dry_path)
        )
        self.replace_receipt_value(
            successor_arm,
            "candidate_release_evidence_sha256",
            sha256(evidence_path),
        )
        successor_armed_sha = sha256(successor_arm)

        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        rewrite_lineage(caller)
        self.replace_receipt_value(caller, "release_evidence_sha256", sha256(evidence_path))
        self.replace_receipt_value(caller, "dry_run_receipt_sha256", sha256(dry_path))
        self.replace_receipt_value(caller, "render_inputs_sha256", sha256(render_inputs))

        armed = self.backup / "APPLY-ARMED.receipt"
        rewrite_lineage(armed)
        self.replace_receipt_value(armed, "release_evidence_sha256", sha256(evidence_path))
        self.replace_receipt_value(armed, "dry_run_receipt_sha256", sha256(dry_path))
        self.replace_receipt_value(armed, "render_inputs_sha256", sha256(render_inputs))
        self.replace_receipt_value(
            armed, "runtime_backup_caller_armed_sha256", sha256(caller)
        )
        self.write_control()

        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current.pop("predecessor_apply_receipt_sha256")
        current.update(
            {
                "successor_armed_receipt_sha256": successor_armed_sha,
                "predecessor_current_sha256": predecessor_current_sha,
                "predecessor_backup_dir": str(predecessor_backup),
                "predecessor_control_sha256": predecessor["control_sha256"],
                "predecessor_completion_kind": completion["kind"],
                "predecessor_completion_attestation_sha256": completion[
                    "attestation_sha256"
                ],
                "predecessor_completion_signature_sha256": completion[
                    "signature_sha256"
                ],
                "predecessor_completion_public_key_sha256": completion[
                    "public_key_sha256"
                ],
                "predecessor_release_evidence_sha256": predecessor[
                    "release_evidence_sha256"
                ],
                "predecessor_runtime_backup_receipt_sha256": (
                    predecessor_runtime_receipt_sha
                ),
                "predecessor_runtime_backup_manifest_sha256": (
                    predecessor_runtime_manifest_sha
                ),
                "predecessor_release_generation": 3,
                "release_generation": 4,
                "apply_armed_receipt_sha256": sha256(armed),
                "release_evidence_sha256": sha256(evidence_path),
                "dry_run_receipt_sha256": sha256(dry_path),
                "control_sha256": sha256(self.backup / "CONTROL.sha256"),
                "runtime_backup_caller_armed_sha256": sha256(caller),
            }
        )
        failure = self.state / current["apply_failure_receipt"]
        self.replace_receipt_value(
            failure, "apply_armed_receipt_sha256", sha256(armed)
        )
        self.replace_receipt_value(
            failure, "control_sha256", sha256(self.backup / "CONTROL.sha256")
        )
        failure.write_text(
            failure.read_text(encoding="utf-8")
            + "".join(
                (
                    f"predecessor_completion_kind={completion['kind']}\n",
                    "predecessor_completion_attestation_sha256="
                    f"{completion['attestation_sha256']}\n",
                    "predecessor_completion_signature_sha256="
                    f"{completion['signature_sha256']}\n",
                    "predecessor_completion_public_key_sha256="
                    f"{completion['public_key_sha256']}\n",
                )
            ),
            encoding="utf-8",
        )
        current["apply_failure_receipt_sha256"] = sha256(failure)
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        return predecessor_bytes, predecessor_backup

    def install_recovered_successor_v3_runtime_caller_state(
        self,
    ) -> tuple[bytes, Path, Path]:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        caller_values = dict(
            line.split("=", 1)
            for line in caller.read_text(encoding="utf-8").splitlines()
        )
        full_current = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        current = {
            "schema_version": 2,
            "state": "runtime_backup_armed",
            "runtime_backup_armed_at": caller_values["armed_at"],
            "estate_root": str(self.estate),
            "backup_dir": str(self.backup),
            "dry_run_dir": caller_values["dry_run_dir"],
            "runtime_backup_dir": caller_values["runtime_backup_dir"],
            "runtime_backup_caller_armed_receipt": caller.name,
            "runtime_backup_caller_armed_receipt_sha256": sha256(caller),
            "runtime_backup_armed_receipt": caller_values[
                "runtime_backup_armed_receipt"
            ],
            "release_env_sha256": caller_values["release_env_sha256"],
            "release_evidence_sha256": caller_values[
                "release_evidence_sha256"
            ],
            "dry_run_receipt_sha256": caller_values["dry_run_receipt_sha256"],
            "targets_sha256": caller_values["targets_sha256"],
            "apply_preimages_sha256": caller_values[
                "apply_preimages_sha256"
            ],
            "apply_absent_sha256": caller_values["apply_absent_sha256"],
            "render_inputs_sha256": caller_values["render_inputs_sha256"],
            "stop_authority_contract": caller_values["stop_authority_contract"],
            "ingress_opened": False,
        }
        for key in (
            "successor",
            "successor_armed_receipt",
            "successor_armed_receipt_sha256",
            "predecessor_current_file",
            "predecessor_current_sha256",
            "predecessor_backup_dir",
            "predecessor_control_sha256",
            "predecessor_completion_kind",
            "predecessor_completion_attestation_sha256",
            "predecessor_completion_signature_sha256",
            "predecessor_completion_public_key_sha256",
            "predecessor_release_evidence_sha256",
            "predecessor_runtime_backup_receipt_sha256",
            "predecessor_runtime_backup_manifest_sha256",
            "predecessor_release_generation",
            "release_generation",
        ):
            current[key] = full_current[key]
        (self.state / "CURRENT.json").write_text(
            json.dumps(current) + "\n", encoding="utf-8"
        )
        for path in self.state.glob("APPLY-*-FAILED-*.receipt"):
            path.unlink()
        for name in (
            "CONTROL.sha256",
            "TARGETS.sha256",
            "APPLY-PREIMAGES.sha256",
            "APPLY-ABSENT.paths",
            "APPLY-ARMED.receipt",
            "APPLY-PENDING.receipt",
            "APPLY.receipt",
        ):
            path = self.backup / name
            if path.exists():
                path.unlink()
        shutil.rmtree(self.backup / "estate")
        for path in self.backup.rglob("*"):
            if path.is_file() and not path.is_symlink():
                path.chmod(0o600)
        return predecessor_bytes, predecessor_backup, Path(caller_values["dry_run_dir"])

    def install_production_successor_activation_failed_state(self) -> bytes:
        return self.install_successor_activation_failed_state(
            predecessor_generation=2,
            release_generation=3,
            historical_apply_armed_duplicates=True,
            production_predecessor_shape=True,
        )

    def rebind_activation_failed_state(self, failure: Path) -> None:
        armed = self.backup / "APPLY-ARMED.receipt"
        self.write_control()
        self.replace_receipt_value(
            failure, "apply_armed_receipt_sha256", sha256(armed)
        )
        self.replace_receipt_value(
            failure, "control_sha256", sha256(self.backup / "CONTROL.sha256")
        )
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current.update(
            {
                "apply_armed_receipt_sha256": sha256(armed),
                "control_sha256": sha256(self.backup / "CONTROL.sha256"),
                "apply_failure_receipt_sha256": sha256(failure),
            }
        )
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")

    def install_successor_runtime_caller_state(self) -> tuple[bytes, bytes]:
        predecessor_bytes = self.install_successor_activation_failed_state()
        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        caller_values = dict(
            line.split("=", 1)
            for line in caller.read_text(encoding="utf-8").splitlines()
        )
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current.update(
            {
                "state": "runtime_backup_armed",
                "runtime_backup_armed_at": caller_values["armed_at"],
                "dry_run_dir": caller_values["dry_run_dir"],
                "runtime_backup_dir": caller_values["runtime_backup_dir"],
                "runtime_backup_caller_armed_receipt": caller.name,
                "runtime_backup_caller_armed_receipt_sha256": sha256(caller),
                "runtime_backup_armed_receipt": caller_values[
                    "runtime_backup_armed_receipt"
                ],
                "release_env_sha256": caller_values["release_env_sha256"],
                "release_evidence_sha256": caller_values[
                    "release_evidence_sha256"
                ],
                "dry_run_receipt_sha256": caller_values[
                    "dry_run_receipt_sha256"
                ],
                "targets_sha256": caller_values["targets_sha256"],
                "apply_preimages_sha256": caller_values[
                    "apply_preimages_sha256"
                ],
                "apply_absent_sha256": caller_values["apply_absent_sha256"],
                "render_inputs_sha256": caller_values["render_inputs_sha256"],
                "stop_authority_contract": caller_values[
                    "stop_authority_contract"
                ],
                "ingress_opened": False,
            }
        )
        runtime_bytes = (json.dumps(current) + "\n").encode()
        current_path.write_bytes(runtime_bytes)
        return predecessor_bytes, runtime_bytes

    def install_estate_rollback_recovery_state(self) -> Path:
        (self.backup / "TARGETS.sha256").write_bytes(
            (self.backup / "estate/APPLIED-TARGETS.sha256").read_bytes()
        )
        failure = self.install_activation_failed_state()
        (self.estate / "deploy/docker-compose.yml").write_bytes(self.old_content)
        (self.estate / "deploy/.env").write_bytes(
            (self.backup / "estate/tree/deploy/.env").read_bytes()
        )
        (self.backup / "estate/TRANSACTION.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "state": "rolled_back_after_failure",
                    "error": "injected apply failure",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        failure.write_text(
            "".join(
                [
                    "failed_at=2026-08-25T00:00:00Z\n",
                    "phase=estate_apply\n",
                    "status=1\n",
                    "transaction_state=rolled_back_after_failure\n",
                    f"transaction_sha256={sha256(self.backup / 'estate/TRANSACTION.json')}\n",
                    f"backup_dir={self.backup}\n",
                    f"apply_armed_receipt_sha256={sha256(self.backup / 'APPLY-ARMED.receipt')}\n",
                    f"control_sha256={sha256(self.backup / 'CONTROL.sha256')}\n",
                    f"targets_sha256={sha256(self.backup / 'TARGETS.sha256')}\n",
                    f"runtime_backup_receipt_sha256={sha256(self.backup / 'runtime/BACKUP.receipt')}\n",
                    f"runtime_backup_manifest_sha256={sha256(self.backup / 'runtime/SHA256SUMS')}\n",
                    f"prior_running_manifest_sha256={sha256(self.backup / 'runtime/RUNNING-SERVICES.before')}\n",
                    "prior_running_restore=failed\n",
                ]
            ),
            encoding="utf-8",
        )
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        current.update(
            {
                "state": "apply_estate_recovery_required",
                "apply_failure_receipt": failure.name,
                "apply_failure_receipt_sha256": sha256(failure),
                "estate_transaction_state": "rolled_back_after_failure",
                "estate_transaction_sha256": sha256(self.backup / "estate/TRANSACTION.json"),
                "prior_running_manifest_sha256": sha256(
                    self.backup / "runtime/RUNNING-SERVICES.before"
                ),
                "prior_running_restore": "failed",
            }
        )
        (self.state / "CURRENT.json").write_text(json.dumps(current) + "\n", encoding="utf-8")
        return failure

    def install_interrupted_finalization(self, shape: str) -> None:
        (self.backup / "TARGETS.sha256").write_bytes(
            (self.backup / "estate/APPLIED-TARGETS.sha256").read_bytes()
        )
        failure = self.install_activation_failed_state()
        failure.unlink()
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        pending = self.backup / "APPLY-PENDING.receipt"
        pending.write_text(
            "".join(
                [
                    "schema_version=2\n",
                    "completion_state=applied_ingress_closed\n",
                    "applied_at=2026-08-25T00:00:00Z\n",
                    "closed_verified_at=2026-08-25T00:00:00Z\n",
                    f"estate_root={self.estate}\n",
                    f"backup_dir={self.backup}\n",
                    f"release_env_sha256={sha256(self.backup / 'release.env')}\n",
                    f"release_evidence_sha256={sha256(self.backup / 'RELEASE-EVIDENCE.json')}\n",
                    f"render_inputs_sha256={sha256(self.backup / 'RENDER-INPUTS.sha256')}\n",
                    f"apply_armed_receipt_sha256={sha256(self.backup / 'APPLY-ARMED.receipt')}\n",
                    f"control_sha256={sha256(self.backup / 'CONTROL.sha256')}\n",
                    f"transaction_sha256={sha256(self.backup / 'estate/TRANSACTION.json')}\n",
                    f"applied_targets_sha256={sha256(self.backup / 'estate/APPLIED-TARGETS.sha256')}\n",
                    "cargo_gate=passed\n",
                    "runtime_backup=passed\n",
                    "closed_bracket=passed\n",
                    "route_database_state=absent\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "ingress_opened=false\n",
                    "services_activated=true\n",
                    "runtime_verified=true\n",
                ]
            ),
            encoding="utf-8",
        )
        pending.chmod(0o600)
        current.update(
            {
                "state": "apply_activation_armed",
                "transaction_sha256": sha256(self.backup / "estate/TRANSACTION.json"),
                "applied_targets_sha256": sha256(
                    self.backup / "estate/APPLIED-TARGETS.sha256"
                ),
                "services_activated": True,
                "runtime_verified": True,
            }
        )
        current.pop("apply_failure_receipt", None)
        current.pop("apply_failure_receipt_sha256", None)
        if shape in {"finalizing_pending", "finalizing_promoted"}:
            current.update(
                {
                    "state": "apply_finalizing_ingress_closed",
                    "pending_apply_receipt": pending.name,
                    "pending_apply_receipt_sha256": sha256(pending),
                    "closed_verified_at": "2026-08-25T00:00:00Z",
                    "route_database_state": "absent",
                    "public_ipv4_ipv6_closed_status": 404,
                    "ingress_opened": False,
                }
            )
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        if shape == "finalizing_promoted":
            pending.rename(self.backup / "APPLY.receipt")

    def make_fake(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def environment_with_cross_device_stat(self, target: Path) -> dict[str, str]:
        real_stat = shutil.which("stat")
        self.assertIsNotNone(real_stat)
        self.make_fake(
            "stat",
            'if [[ "${1:-}" == "-c" && "${2:-}" == "%d" && '
            '"${4:-}" == "$HOLDFAST_TEST_CROSS_DEVICE_PATH" ]]; then\n'
            '  printf "999999999\\n"\n'
            '  exit 0\n'
            'fi\n'
            f'exec "{real_stat}" "$@"\n',
        )
        return self.environment(
            PATH=f"{self.bin}:{os.environ['PATH']}",
            HOLDFAST_TEST_CROSS_DEVICE_PATH=str(target),
        )

    def write_fakes(self) -> None:
        self.validator = self.make_fake(
            "release-validator",
            'printf "validator %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n',
        )
        self.supply_validator = self.make_fake(
            "supply-validator",
            'printf "supply-validator %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n',
        )
        self.render_validator = self.make_fake(
            "render-validator",
            'printf "render-validator %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n',
        )
        self.psql = self.make_fake(
            "psql",
            'printf "psql %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\nprintf "ok\\n"\n',
        )
        self.public = self.make_fake(
            "public-verify",
            'printf "public %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n'
            'if [[ -n "${HOLDFAST_TEST_MUTATE_DURING_PUBLIC:-}" ]]; then printf "drift\\n" >>"$HOLDFAST_TEST_MUTATE_DURING_PUBLIC"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_REMOVE_DURING_PUBLIC:-}" ]]; then rm -f -- "$HOLDFAST_TEST_REMOVE_DURING_PUBLIC"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_REPLACE_SAME_DURING_PUBLIC:-}" && ! -e "$HOLDFAST_TEST_LOG.same-target-replaced" ]]; then target=$HOLDFAST_TEST_REPLACE_SAME_DURING_PUBLIC; replacement="$target.replacement.$$"; cp -p -- "$target" "$replacement"; mv -fT -- "$replacement" "$target"; touch "$HOLDFAST_TEST_LOG.same-target-replaced"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_CHMOD_DURING_PUBLIC:-}" && ! -e "$HOLDFAST_TEST_LOG.target-mode-changed" ]]; then chmod 0640 -- "$HOLDFAST_TEST_CHMOD_DURING_PUBLIC"; touch "$HOLDFAST_TEST_LOG.target-mode-changed"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_TOUCH_ANCESTOR_DURING_PUBLIC:-}" && ! -e "$HOLDFAST_TEST_LOG.target-ancestor-touched" ]]; then touch -- "$HOLDFAST_TEST_TOUCH_ANCESTOR_DURING_PUBLIC"; touch "$HOLDFAST_TEST_LOG.target-ancestor-touched"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_RECREATE_ANCESTOR_DURING_PUBLIC:-}" && ! -e "$HOLDFAST_TEST_LOG.target-ancestor-recreated" ]]; then target=$HOLDFAST_TEST_RECREATE_ANCESTOR_DURING_PUBLIC; old="$target.recreated.$$"; mode=$(stat -c %a -- "$target"); mv -- "$target" "$old"; mkdir -m "$mode" -- "$target"; shopt -s dotglob nullglob; entries=("$old"/*); if ((${#entries[@]})); then mv -- "${entries[@]}" "$target"/; fi; rmdir -- "$old"; touch "$HOLDFAST_TEST_LOG.target-ancestor-recreated"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_CREATE_DURING_PUBLIC:-}" ]]; then printf "hybrid\\n" >"$HOLDFAST_TEST_CREATE_DURING_PUBLIC"; chmod 0600 "$HOLDFAST_TEST_CREATE_DURING_PUBLIC"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_SYMLINK_DURING_PUBLIC:-}" ]]; then ln -s /dev/null "$HOLDFAST_TEST_SYMLINK_DURING_PUBLIC"; fi\n'
            'if [[ -n "${HOLDFAST_TEST_REPLACE_BACKUP_ROOT_DURING_PUBLIC:-}" && ! -e "$HOLDFAST_TEST_LOG.backup-root-replaced" ]]; then old="$HOLDFAST_TEST_REPLACE_BACKUP_ROOT_DURING_PUBLIC.replaced"; mv "$HOLDFAST_TEST_REPLACE_BACKUP_ROOT_DURING_PUBLIC" "$old"; mkdir -m 0700 "$HOLDFAST_TEST_REPLACE_BACKUP_ROOT_DURING_PUBLIC"; shopt -s dotglob nullglob; entries=("$old"/*); ((${#entries[@]})); mv -- "${entries[@]}" "$HOLDFAST_TEST_REPLACE_BACKUP_ROOT_DURING_PUBLIC"/; rmdir "$old"; touch "$HOLDFAST_TEST_LOG.backup-root-replaced"; fi\n'
            '[[ "${HOLDFAST_TEST_ROUTE_OPEN:-0}" != "1" ]]\n',
        )
        self.docker = self.make_fake(
            "docker",
            'printf "docker %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n'
            'if [[ -n "${HOLDFAST_TEST_MUTATE_DURING_DOCKER:-}" && ! -e "$HOLDFAST_TEST_LOG.docker-mutated" && " $* " == *" compose "* && " $* " == *" config --quiet "* ]]; then printf "drift\\n" >>"$HOLDFAST_TEST_MUTATE_DURING_DOCKER"; touch "$HOLDFAST_TEST_LOG.docker-mutated"; fi\n'
            'if [[ "${1:-}" == "volume" && "${2:-}" == "ls" ]]; then\n'
            '  printf "%s" "${HOLDFAST_TEST_EXISTING_VOLUMES:-}"\n'
            '  exit 0\n'
            'fi\n'
            'if [[ " $* " == *" compose "* && " $* " == *" exec -T postgres "* ]]; then\n'
            '  query=$(cat)\n'
            '  if [[ "$query" == *"FROM pg_database"* ]]; then printf "1\\n"; else printf "0\\n"; fi\n'
            '  exit 0\n'
            'fi\n'
            'if [[ " $* " == *" compose "* && " $* " == *" config --no-interpolate --services "* ]]; then\n'
            '  [[ "${HOLDFAST_TEST_PREIMAGE_COMPOSE_FAIL:-0}" != "1" ]] || exit 46\n'
            '  services=${HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES:-"access-governance verdict newapi rikune-analyzer strad sluice sluice-internal"}\n'
            '  for service in $services; do printf "%s\\n" "$service"; done\n'
            '  exit 0\n'
            'fi\n'
            'if [[ " $* " == *" compose "* && " $* " == *" config --format json "* ]]; then\n'
            '  if [[ "${HOLDFAST_TEST_RESOLVED_CONFIG_DRIFT:-0}" == "1" ]]; then printf "{\\"name\\":\\"drift\\",\\"services\\":{},\\"volumes\\":{}}\\n"; else cat "$HOLDFAST_TEST_RUNTIME_CONFIG"; fi\n'
            '  exit 0\n'
            'fi\n'
            'if [[ " $* " == *" compose "* && " $* " == *" ps -aq "* ]]; then\n'
            '  service=${!#}\n'
            '  [[ "${HOLDFAST_TEST_DOCKER_PS_FAIL_SERVICE:-}" != "$service" ]] || exit 44\n'
            '  [[ ! -e "$HOLDFAST_TEST_LOG.removed-$service" ]] || exit 0\n'
            '  if [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" && " ${HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES:-} " == *" $service "* ]]; then exit 0; fi\n'
            '  after_up=""\n'
            '  if [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" ]]; then after_up=${HOLDFAST_TEST_RUNNING_AFTER_UP_SERVICES:-}; fi\n'
            '  all=" ${HOLDFAST_TEST_RUNNING_SERVICES:-} ${HOLDFAST_TEST_RESTARTING_SERVICES:-} ${HOLDFAST_TEST_CREATED_SERVICES:-} $after_up "\n'
            '  [[ "$all" == *" $service "* ]] && printf "cid-%s\\n" "$service"\n'
            '  exit 0\n'
            'fi\n'
            'if [[ " $* " == *" compose "* && " $* " == *" up -d "* ]]; then\n'
            '  rm -f "$HOLDFAST_TEST_LOG.requiesced"\n'
            '  for service in "$@"; do rm -f "$HOLDFAST_TEST_LOG.stopped-$service"; done\n'
            '  touch "$HOLDFAST_TEST_LOG.writers-stopped"\n'
            '  exit 0\n'
            'fi\n'
            'if [[ "${1:-}" == "ps" && " $* " == *" -aq "* ]]; then\n'
            '  service=${!#}; service=${service#label=com.docker.compose.service=}\n'
            '  [[ "${HOLDFAST_TEST_DOCKER_PS_FAIL_SERVICE:-}" != "$service" ]] || exit 44\n'
            '  [[ ! -e "$HOLDFAST_TEST_LOG.removed-$service" ]] || exit 0\n'
            '  if [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" && " ${HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES:-} " == *" $service "* ]]; then exit 0; fi\n'
            '  after_up=""\n'
            '  if [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" ]]; then after_up=${HOLDFAST_TEST_RUNNING_AFTER_UP_SERVICES:-}; fi\n'
            '  all=" ${HOLDFAST_TEST_RUNNING_SERVICES:-} ${HOLDFAST_TEST_RESTARTING_SERVICES:-} ${HOLDFAST_TEST_CREATED_SERVICES:-} $after_up "\n'
            '  [[ "$all" == *" $service "* ]] && printf "cid-%s\\n" "$service"\n'
            '  exit 0\n'
            'fi\n'
            'if [[ "${1:-}" == "rm" && "${2:-}" == "-f" ]]; then\n'
            '  shift 2\n'
            '  for container_id in "$@"; do service=${container_id#cid-}; touch "$HOLDFAST_TEST_LOG.removed-$service"; done\n'
            '  exit 0\n'
            'fi\n'
            'if [[ "${1:-}" == "inspect" ]]; then\n'
            '  service=${!#}; service=${service#cid-}\n'
            '  [[ "${HOLDFAST_TEST_DOCKER_INSPECT_FAIL_SERVICE:-}" != "$service" ]] || exit 45\n'
            '  if [[ "$*" == *"State.Health"* ]]; then\n'
            '    if [[ " ${HOLDFAST_TEST_UNHEALTHY_SERVICES:-} " == *" $service "* ]]; then printf "unhealthy\\n"; else printf "healthy\\n"; fi\n'
            '    exit 0\n'
            '  fi\n'
            '  if [[ -e "$HOLDFAST_TEST_LOG.requiesced" ]]; then printf "exited\\n"\n'
            '  elif [[ -e "$HOLDFAST_TEST_LOG.quiesced" && ! -e "$HOLDFAST_TEST_LOG.writers-stopped" ]]; then printf "exited\\n"\n'
            '  elif [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" && " ${HOLDFAST_TEST_STOP_LEAK_SERVICES:-} " == *" $service "* ]]; then printf "running\\n"\n'
            '  elif [[ -e "$HOLDFAST_TEST_LOG.stopped-$service" ]]; then printf "exited\\n"\n'
            '  elif [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" && " ${HOLDFAST_TEST_RUNNING_AFTER_UP_SERVICES:-} " == *" $service "* ]]; then printf "running\\n"\n'
            '  elif [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" && " ${HOLDFAST_TEST_RUNNING_SERVICES:-} " != *" $service "* ]]; then printf "exited\\n"\n'
            '  elif [[ " ${HOLDFAST_TEST_RUNNING_SERVICES:-} " == *" $service "* ]]; then printf "running\\n"\n'
            '  elif [[ " ${HOLDFAST_TEST_RESTARTING_SERVICES:-} " == *" $service "* ]]; then printf "restarting\\n"\n'
            '  elif [[ " ${HOLDFAST_TEST_CREATED_SERVICES:-} " == *" $service "* ]]; then printf "created\\n"\n'
            '  else printf "exited\\n"; fi\n'
            'fi\n'
            'if [[ "${1:-}" == "stop" ]]; then\n'
            '  for container_id in "${@:4}"; do service=${container_id#cid-}; touch "$HOLDFAST_TEST_LOG.stopped-$service"; done\n'
            '  if [[ -e "$HOLDFAST_TEST_LOG.writers-stopped" ]]; then touch "$HOLDFAST_TEST_LOG.requiesced"; fi\n'
            '  touch "$HOLDFAST_TEST_LOG.quiesced"\n'
            '  if [[ "${HOLDFAST_TEST_SIGKILL_ON_STOP:-0}" == "1" ]]; then kill -KILL "$PPID"; exit 137; fi\n'
            'fi\n'
            'exit 0\n',
        )
        self.runtime_restore = self.make_fake(
            "runtime-restore",
            'printf "runtime-restore %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n'
            'if [[ "${HOLDFAST_TEST_SIGKILL_RECOVERY:-0}" == "1" ]]; then kill -KILL "$PPID"; exit 137; fi\n'
            '[[ "${HOLDFAST_TEST_RESTORE_FAIL:-0}" != "1" ]] || exit 37\n'
            'backup=""; legacy="false"\n'
            'while (($#)); do case "$1" in --backup-dir) backup=$2; shift 2;; --legacy-empty-strad) legacy="true"; shift;; *) shift;; esac; done\n'
            'touch "$HOLDFAST_TEST_LOG.writers-stopped"\n'
            'restore_mode="schema-v2"; database_restore="restored"\n'
            'if [[ "$legacy" == "true" ]]; then restore_mode="legacy-empty-strad"; database_restore="skipped_proven_empty"; fi\n'
            'if [[ "${HOLDFAST_TEST_BAD_RESTORE_RECEIPT:-0}" == "1" ]]; then database_restore="shared-database-restored"; fi\n'
            'postgres_started_at="2026-08-25T12:00:00.000000000Z"\n'
            'if [[ "${HOLDFAST_TEST_BAD_RUNTIME_EPOCH_RECEIPT:-0}" == "1" ]]; then postgres_started_at="invalid"; fi\n'
            f'printf "schema_version=2\\nrestore_mode=%s\\ndatabase_identity=postgres:5432/strad\\ndatabase_restore=%s\\nruntime_writers_removed=passed\\npostgres_container_attestation=passed\\npostgres_pgdata_mount=passed\\npostgres_runtime_epoch_attestation=passed\\npostgres_container_id={POSTGRES_CONTAINER_ID}\\npostgres_config_hash={POSTGRES_CONFIG_HASH}\\npostgres_started_at=%s\\npostgres_restart_count=0\\nvolume_mount_release=passed\\nvolume_count=6\\n" "$restore_mode" "$database_restore" "$postgres_started_at" >"$backup/RESTORE.receipt"\n'
            'chmod 0600 "$backup/RESTORE.receipt"\n',
        )
        self.runtime_verify = self.make_fake(
            "runtime-verify",
            'printf "runtime-verify %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n'
            '[[ "${HOLDFAST_TEST_VERIFY_FAIL:-0}" != "1" ]]\n',
        )

    def environment(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_LOCK_PATH": str(self.root / "holdfast.lock"),
            "HOLDFAST_RELEASE_VALIDATOR_BIN": str(self.validator),
            "HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN": str(self.supply_validator),
            "HOLDFAST_RENDER_INPUT_BINDING_BIN": str(self.render_validator),
            "HOLDFAST_PSQL_BIN": str(self.psql),
            "HOLDFAST_PUBLIC_VERIFY_BIN": str(self.public),
            "HOLDFAST_DOCKER_BIN": str(self.docker),
            "HOLDFAST_RUNTIME_RESTORE_BIN": str(self.runtime_restore),
            "HOLDFAST_RUNTIME_VERIFY_BIN": str(self.runtime_verify),
            "HOLDFAST_TEST_LOG": str(self.log),
            "HOLDFAST_TEST_RUNTIME_CONFIG": str(
                self.backup / "runtime/compose-config.json"
            ),
            "ROUTES_DATABASE_URL": "postgres://route-authority.invalid/routes",
            **extra,
        }

    def recover(
        self,
        mode: str,
        *,
        env: dict[str, str] | None = None,
        backup: Path | None = None,
        legacy_empty_strad: bool = False,
        quarantine_access_chain: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [
                "bash",
                str(RECOVER),
                "--execute",
                "--mode",
                mode,
                "--backup-dir",
                str(backup or self.backup),
                "--estate-root",
                str(self.estate),
                "--state-dir",
                str(self.state),
            ]
        if legacy_empty_strad:
            command.append("--legacy-empty-strad")
        if quarantine_access_chain:
            command.append("--quarantine-access-chain")
        return subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env or self.environment(),
        )

    def install_completion_attestation_authority(self) -> tuple[Path, Path, Path]:
        private_key = self.root / "release-authority.key"
        public_key = self.root / "release-authority.pub"
        release_root = self.root / "release-next"
        release_root.mkdir(mode=0o700)
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
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
        release_env = self.backup / "release.env"
        release_env.write_text(
            "SAFE_RELEASE=1\n"
            f"AUTHORITY_PUBLIC_KEY_SHA256={sha256(public_key)}\n",
            encoding="utf-8",
        )
        evidence = self.backup / "RELEASE-EVIDENCE.json"
        evidence_value = json.loads(evidence.read_text(encoding="utf-8"))
        evidence_value["release_env_sha256"] = sha256(release_env)
        evidence.write_text(json.dumps(evidence_value) + "\n", encoding="utf-8")
        self.replace_receipt_value(
            self.backup / "DRY-RUN.receipt", "release_env_sha256", sha256(release_env)
        )
        self.replace_receipt_value(
            self.backup / "DRY-RUN.receipt",
            "release_evidence_sha256",
            sha256(evidence),
        )
        self.write_control()
        return private_key, public_key, release_root

    def verify_completed(
        self,
        private_key: Path,
        public_key: Path,
        release_root: Path,
        *,
        mode: str = "resume",
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                str(RECOVER),
                "--verify-completed",
                "--mode",
                mode,
                "--backup-dir",
                str(self.backup),
                "--estate-root",
                str(self.estate),
                "--state-dir",
                str(self.state),
                "--release-root",
                str(release_root),
                "--signing-key",
                str(private_key),
                "--authority-public-key",
                str(public_key),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env or self.environment(),
            cwd=cwd,
        )

    @staticmethod
    def immutable_tree_manifest(root: Path) -> tuple[tuple[object, ...], ...]:
        result: list[tuple[object, ...]] = []
        for path in sorted((root, *root.rglob("*")), key=lambda item: str(item)):
            metadata = path.lstat()
            relative = "." if path == root else str(path.relative_to(root))
            digest = sha256(path) if path.is_file() and not path.is_symlink() else "-"
            result.append(
                (
                    relative,
                    metadata.st_mode,
                    metadata.st_uid,
                    metadata.st_gid,
                    metadata.st_nlink,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    digest,
                )
            )
        return tuple(result)

    def completed_estate_manifest(self) -> tuple[tuple[tuple[object, ...], ...], ...]:
        roots = [self.state, self.backup, self.estate]
        predecessor = self.root / "predecessor-backup"
        if predecessor.exists():
            roots.append(predecessor)
        return tuple(
            self.immutable_tree_manifest(root)
            for root in roots
        )

    def recovery_mutations(self) -> list[str]:
        if not self.log.exists():
            return []
        mutations = []
        for line in self.log.read_text(encoding="utf-8").splitlines():
            if line.startswith("runtime-restore "):
                mutations.append(line)
                continue
            if line.startswith("docker ") and any(
                marker in f" {line} "
                for marker in (" stop ", " start ", " up ", " rm ")
            ):
                mutations.append(line)
        return mutations

    def install_restore_failed_with_release_only_writer(self) -> dict[str, object]:
        running = "verdict rikune-analyzer sluice sluice-internal"
        result = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES="rikune-analyzer",
            ),
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertEqual(current["recovery_failure_stage"], "restore_prior_running_writers")
        manifest = self.state / str(current["restore_running_writers_manifest"])
        self.assertEqual(manifest.read_text(encoding="utf-8").splitlines(), running.split())
        return current

    def install_activation_restore_failed_with_access_chain(
        self,
        *,
        running: str = "access-governance verdict newapi rikune-analyzer strad sluice sluice-internal",
    ) -> dict[str, object]:
        self.install_activation_failed_state()
        result = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
            ),
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertEqual(current["recovery_prior_state"], "apply_activation_failed")
        self.assertEqual(current["recovery_failure_stage"], "restore_prior_running_writers")
        manifest = self.state / str(current["restore_running_writers_manifest"])
        self.assertIn("access-governance", manifest.read_text(encoding="utf-8").splitlines())
        self.assertIn("newapi", manifest.read_text(encoding="utf-8").splitlines())
        return current

    def test_runtime_caller_arm_without_stop_archives_state_without_runtime_restore(self) -> None:
        self.install_runtime_caller_state(stop_started=False)
        shutil.rmtree(self.root / "dry-run")
        result = self.recover("restore")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.state / "CURRENT.json").exists())
        cleanup = self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt"
        self.assertTrue(cleanup.exists())
        cleanup_text = cleanup.read_text(encoding="utf-8")
        self.assertIn("runtime_stop_authority=not-created", cleanup_text)
        self.assertIn("prior_running_services_restored=not-required", cleanup_text)
        self.assertEqual(len(list(self.state.glob("RUNTIME-BACKUP-ABORTED-*.json"))), 1)
        self.assertEqual(
            len(list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))), 1
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn("docker ", calls)
        self.assertNotIn("runtime-restore ", calls)

        repeated = self.recover("restore")
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("previously completed runtime backup recovery", repeated.stdout)

    def test_successor_restore_sigkill_recovers_exact_immediate_predecessor(self) -> None:
        predecessor_bytes = self.install_successor_activation_failed_state()
        interrupted = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_SIGKILL_RECOVERY="1")
        )
        self.assertEqual(interrupted.returncode, -9, interrupted.stdout + interrupted.stderr)
        armed_current = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(armed_current["state"], "apply_recovery_armed")
        self.assertTrue(armed_current["successor"])
        recovery_arm = self.state / armed_current["recovery_armed_receipt"]
        self.assertIn(
            f"predecessor_current_sha256={armed_current['predecessor_current_sha256']}",
            recovery_arm.read_text(encoding="utf-8"),
        )

        resumed = self.recover("restore")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)
        completion = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        self.assertIn("successor=true", completion.read_text(encoding="utf-8"))
        calls = self.log.read_text(encoding="utf-8")
        self.assertIn(
            f"--successor-policy {self.backup}/successor-authority/successor-policy.json",
            calls,
        )
        self.assertIn(
            f"--dockerfile {self.backup}/successor-authority/Dockerfile.analyzer",
            calls,
        )
        self.assertIn(
            f"validator --evidence {self.backup}/RELEASE-EVIDENCE.json "
            f"--successor-policy {self.backup}/successor-authority/successor-policy.json",
            calls,
        )
        self.assertIn(
            f"render-validator verify --ops-root {self.backup}/successor-authority",
            calls,
        )
        self.assertIn("--expected-mode successor", calls)

        mutations = self.recovery_mutations()
        estate_bytes = (self.estate / "deploy/docker-compose.yml").read_bytes()
        repeated = self.recover("restore")
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("previously completed apply recovery", repeated.stdout)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)
        self.assertEqual(
            (self.estate / "deploy/docker-compose.yml").read_bytes(), estate_bytes
        )
        self.assertEqual(self.recovery_mutations(), mutations)

    def test_schema_v3_restore_uses_only_current_backup_authority(self) -> None:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)

        result = self.recover("restore")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)
        completion = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        completion_text = completion.read_text(encoding="utf-8")
        self.assertIn(
            "predecessor_completion_kind=recovery-completion-attestation-v1",
            completion_text,
        )
        self.assertIn("predecessor_completion_public_key_sha256=", completion_text)
        self.assertNotIn("predecessor_apply_receipt_sha256=", completion_text)

    def test_schema_v3_terminal_snapshots_completion_before_signed_validator(
        self,
    ) -> None:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        completed = self.recover("restore")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        completion_archive = next(
            self.state.glob("APPLY-RECOVERY-COMPLETE-*.json")
        )
        mutations = self.recovery_mutations()
        counter = self.root / "terminal-supply-counter"
        mutating_supply = self.make_fake(
            "supply-mutate-terminal-completion-archive",
            'count=0\n'
            'if [[ -f "$HOLDFAST_TEST_SUPPLY_COUNTER" ]]; then count=$(<"$HOLDFAST_TEST_SUPPLY_COUNTER"); fi\n'
            'count=$((count + 1))\n'
            'printf "%s\\n" "$count" >"$HOLDFAST_TEST_SUPPLY_COUNTER"\n'
            'if [[ "$count" == "1" ]]; then printf " \\n" >>"$HOLDFAST_TEST_SUPPLY_MUTATION_TARGET"; fi\n',
        )

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(completion_archive),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "1")
        self.assertIn("candidate changed during external validation", rejected.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)
        self.assertEqual(self.recovery_mutations(), mutations)

    def test_schema_v3_terminal_snapshots_completion_before_release_validator(
        self,
    ) -> None:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        completed = self.recover("restore")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        completion_archive = next(
            self.state.glob("APPLY-RECOVERY-COMPLETE-*.json")
        )
        mutations = self.recovery_mutations()
        counter = self.root / "terminal-release-counter"
        mutating_release = self.make_fake(
            "release-mutate-terminal-completion-archive",
            'count=0\n'
            'if [[ -f "$HOLDFAST_TEST_RELEASE_COUNTER" ]]; then count=$(<"$HOLDFAST_TEST_RELEASE_COUNTER"); fi\n'
            'count=$((count + 1))\n'
            'printf "%s\\n" "$count" >"$HOLDFAST_TEST_RELEASE_COUNTER"\n'
            'if [[ "$count" == "1" ]]; then printf " \\n" >>"$HOLDFAST_TEST_RELEASE_MUTATION_TARGET"; fi\n',
        )

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_RELEASE_VALIDATOR_BIN=str(mutating_release),
                HOLDFAST_TEST_RELEASE_COUNTER=str(counter),
                HOLDFAST_TEST_RELEASE_MUTATION_TARGET=str(completion_archive),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "1")
        self.assertIn("candidate changed during external validation", rejected.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)
        self.assertEqual(self.recovery_mutations(), mutations)

    def test_schema_v3_terminal_fences_state_directory_identity(self) -> None:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        completed = self.recover("restore")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        mutating_release = self.make_fake(
            "release-replace-terminal-state-root",
            'old="$HOLDFAST_TEST_STATE_DIR.replaced"\n'
            'mv "$HOLDFAST_TEST_STATE_DIR" "$old"\n'
            'mkdir -m 0700 "$HOLDFAST_TEST_STATE_DIR"\n'
            'shopt -s dotglob nullglob\n'
            'entries=("$old"/*)\n'
            '((${#entries[@]}))\n'
            'mv -- "${entries[@]}" "$HOLDFAST_TEST_STATE_DIR"/\n'
            'rmdir "$old"\n',
        )

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_RELEASE_VALIDATOR_BIN=str(mutating_release),
                HOLDFAST_TEST_STATE_DIR=str(self.state),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("state directory changed during external validation", rejected.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)

    def test_schema_v3_terminal_rejects_new_candidate_directory(self) -> None:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        completed = self.recover("restore")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        injected = self.state / "APPLY-RECOVERY-COMPLETE-20990101T000000Z-1.json"
        mutating_release = self.make_fake(
            "release-add-terminal-candidate-directory",
            'mkdir -m 0700 "$HOLDFAST_TEST_COMPLETION_DIRECTORY"\n',
        )

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_RELEASE_VALIDATOR_BIN=str(mutating_release),
                HOLDFAST_TEST_COMPLETION_DIRECTORY=str(injected),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("candidate namespace changed", rejected.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)

    def test_schema_v3_restore_finalization_rechecks_completion_receipt(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        counter = self.root / "supply-counter"
        mutating_supply = self.make_fake(
            "supply-mutate-recovery-completion",
            'count=0\n'
            'if [[ -f "$HOLDFAST_TEST_SUPPLY_COUNTER" ]]; then count=$(<"$HOLDFAST_TEST_SUPPLY_COUNTER"); fi\n'
            'count=$((count + 1))\n'
            'printf "%s\\n" "$count" >"$HOLDFAST_TEST_SUPPLY_COUNTER"\n'
            'if [[ "$count" == "8" ]]; then\n'
            '  shopt -s nullglob\n'
            '  targets=("$HOLDFAST_TEST_COMPLETION_DIR"/APPLY-RECOVERY-COMPLETE-*.receipt)\n'
            '  ((${#targets[@]} == 1))\n'
            '  printf "tamper\\n" >>"${targets[0]}"\n'
            'fi\n',
        )

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_COMPLETION_DIR=str(self.state),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "8")
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-STATE-*.json")))

    def test_schema_v3_resume_finalization_fences_current_candidate(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        counter = self.root / "supply-counter"
        mutating_supply = self.make_fake(
            "supply-mutate-resume-current-candidate",
            'count=0\n'
            'if [[ -f "$HOLDFAST_TEST_SUPPLY_COUNTER" ]]; then count=$(<"$HOLDFAST_TEST_SUPPLY_COUNTER"); fi\n'
            'count=$((count + 1))\n'
            'printf "%s\\n" "$count" >"$HOLDFAST_TEST_SUPPLY_COUNTER"\n'
            'if [[ "$count" == "6" ]]; then\n'
            '  shopt -s nullglob\n'
            '  targets=("$HOLDFAST_TEST_COMPLETION_DIR"/.CURRENT.json.*)\n'
            '  ((${#targets[@]} == 1))\n'
            '  printf "tamper\\n" >>"${targets[0]}"\n'
            'fi\n',
        )

        rejected = self.recover(
            "resume",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_COMPLETION_DIR=str(self.state),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "6")
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "apply_recovery_failed")

    def test_schema_v3_partial_runtime_caller_uses_only_frozen_backup_authority(
        self,
    ) -> None:
        predecessor_bytes, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)

        result = self.recover("restore")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.state / "CURRENT.json").read_bytes(), predecessor_bytes
        )
        receipt = next(
            self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt")
        )
        receipt_text = receipt.read_text(encoding="utf-8")
        self.assertIn(
            "predecessor_completion_kind=recovery-completion-attestation-v1",
            receipt_text,
        )
        self.assertIn("predecessor_completion_public_key_sha256=", receipt_text)
        self.assertNotIn("predecessor_apply_receipt_sha256=", receipt_text)
        calls = self.log.read_text(encoding="utf-8")
        self.assertIn("supply-validator ", calls)
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_schema_v3_partial_backup_rejects_cross_device_subtree(self) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)

        rejected = self.recover(
            "restore",
            env=self.environment_with_cross_device_stat(self.backup / "runtime"),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn(
            "partial schema-v3 backup contains a cross-device subtree",
            rejected.stderr,
        )
        self.assertEqual(self.recovery_mutations(), [])

    def test_schema_v3_partial_runtime_caller_sigkill_retry_and_terminal(
        self,
    ) -> None:
        predecessor_bytes, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)

        interrupted = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_PREDECESSOR_CURRENT_RESTORE="1"
            ),
        )
        self.assertEqual(
            interrupted.returncode, -9, interrupted.stdout + interrupted.stderr
        )
        self.assertEqual(
            (self.state / "CURRENT.json").read_bytes(), predecessor_bytes
        )
        self.assertEqual(
            len(list(self.state.glob("RUNTIME-BACKUP-ABORTED-*.json"))), 1
        )

        resumed = self.recover("restore")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertIn("previously completed runtime backup recovery", resumed.stdout)
        receipt = next(
            self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt")
        )
        receipt_text = receipt.read_text(encoding="utf-8")
        self.assertIn("predecessor_completion_attestation_sha256=", receipt_text)
        self.assertNotIn("predecessor_apply_receipt_sha256=", receipt_text)
        mutations = self.recovery_mutations()

        terminal = self.recover("restore")
        self.assertEqual(terminal.returncode, 0, terminal.stdout + terminal.stderr)
        self.assertIn("previously completed runtime backup recovery", terminal.stdout)
        self.assertEqual(self.recovery_mutations(), mutations)

    def test_schema_v3_partial_runtime_caller_rejects_frozen_dry_run_drift(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        self.replace_receipt_value(caller, "targets_sha256", "0" * 64)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["targets_sha256"] = "0" * 64
        current["runtime_backup_caller_armed_receipt_sha256"] = sha256(caller)
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("differs from frozen dry-run authority", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn(" start ", calls)

    def test_schema_v3_partial_runtime_caller_rechecks_signed_anchor_after_validator(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        mutating_supply, counter = self.schema_v3_mutating_supply(1)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / recovery_completion_attestation.SIGNATURE_NAME
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "1")
        self.assertIn("signed authority changed during validation", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn(" start ", calls)

    def test_schema_v3_partial_runtime_caller_revalidates_after_public_probe(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        signature = self.backup / recovery_completion_attestation.SIGNATURE_NAME

        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_MUTATE_DURING_PUBLIC=str(signature)),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        self.assertFalse(
            list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn(" start ", calls)

    def test_schema_v3_partial_runtime_caller_fences_backup_root_identity(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_REPLACE_BACKUP_ROOT_DURING_PUBLIC=str(self.backup)
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("partial schema-v3 backup root changed", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn("docker compose ", calls)

    def test_schema_v3_partial_runtime_caller_rejects_hybrid_created_by_public(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        hybrid = self.backup / "APPLY.receipt"

        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_CREATE_DURING_PUBLIC=str(hybrid)),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("post-runtime apply authority", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        self.assertFalse(
            list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn(" start ", calls)

    def test_schema_v3_partial_runtime_caller_rejects_targets_created_by_public(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        hybrid = self.backup / "TARGETS.sha256"

        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_CREATE_DURING_PUBLIC=str(hybrid)),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("post-runtime apply authority", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )

    def test_schema_v3_partial_runtime_caller_rejects_symlink_created_by_public(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        injected = self.backup / "successor-authority/injected-link"

        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_SYMLINK_DURING_PUBLIC=str(injected)),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("contains a symlink", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )

    def test_schema_v3_partial_runtime_caller_rejects_unknown_authority_created_by_public(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        injected = self.backup / "successor-authority/injected.json"

        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_CREATE_DURING_PUBLIC=str(injected)),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("unknown successor authority", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )

    def test_schema_v3_partial_runtime_caller_rejects_caller_drift_from_docker(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"

        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_MUTATE_DURING_DOCKER=str(caller)),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("changed during recovery", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn(" stop -t ", calls)
        self.assertNotIn(" start ", calls)

    def test_schema_v3_partial_runtime_caller_revalidates_runtime_after_supply(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        mutating_supply, counter = self.schema_v3_mutating_supply(2)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / "runtime/compose-config.json"
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "2")
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn("docker compose ", calls)

    def test_schema_v3_partial_runtime_terminal_rechecks_completion_receipt(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        completed = self.recover("restore")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        receipt = next(
            self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt")
        )
        mutations = self.recovery_mutations()

        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_MUTATE_DURING_PUBLIC=str(receipt)),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("terminal authority changed during validation", rejected.stderr)
        self.assertEqual(self.recovery_mutations(), mutations)

    def test_schema_v3_partial_runtime_caller_rejects_extra_route_authority(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        extra = self.backup / "successor-authority/assets/unbound.sql"
        extra.write_text("SELECT 1;\n", encoding="utf-8")
        extra.chmod(0o600)

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("route authority set is not exact", rejected.stderr)
        self.assertFalse(self.log.exists())

    def test_schema_v3_partial_runtime_caller_rejects_post_runtime_hybrid(
        self,
    ) -> None:
        _, predecessor_backup, dry_run_dir = (
            self.install_recovered_successor_v3_runtime_caller_state()
        )
        shutil.rmtree(predecessor_backup)
        shutil.rmtree(dry_run_dir)
        (self.backup / "TARGETS.sha256").write_text(
            f"{'0' * 64}  deploy/docker-compose.yml\n", encoding="utf-8"
        )

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("post-runtime apply authority", rejected.stderr)
        self.assertFalse(
            (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists()
        )
        self.assertFalse(self.log.exists())

    def test_schema_v3_restore_sigkill_retry_and_terminal_need_no_old_backup(
        self,
    ) -> None:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        interrupted = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_SIGKILL_RECOVERY="1")
        )
        self.assertEqual(interrupted.returncode, -9, interrupted.stdout + interrupted.stderr)
        armed = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        recovery_arm = self.state / armed["recovery_armed_receipt"]
        arm_text = recovery_arm.read_text(encoding="utf-8")
        self.assertIn("predecessor_completion_attestation_sha256=", arm_text)
        self.assertNotIn("predecessor_apply_receipt_sha256=", arm_text)

        resumed = self.recover("restore")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)
        mutations = self.recovery_mutations()
        repeated = self.recover("restore")
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("previously completed apply recovery", repeated.stdout)
        self.assertEqual(self.recovery_mutations(), mutations)

    def test_schema_v3_current_archive_retry_needs_no_old_backup(self) -> None:
        predecessor_bytes, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        interrupted = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_SUCCESSOR_CURRENT_ARCHIVE="1"
            ),
        )
        self.assertEqual(interrupted.returncode, -9, interrupted.stdout + interrupted.stderr)
        self.assertTrue((self.state / "CURRENT.json").is_file())

        resumed = self.recover("restore")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)

    def test_schema_v3_trio_tamper_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        signature = self.backup / recovery_completion_attestation.SIGNATURE_NAME
        signature.write_bytes(signature.read_bytes() + b"tamper")
        self.assert_schema_v3_rejected_before_mutation()

    def assert_schema_v3_rejected_before_mutation(self) -> None:
        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def schema_v3_mutating_supply(self, mutate_on: int) -> tuple[Path, Path]:
        counter = self.root / "supply-counter"
        mutating_supply = self.make_fake(
            f"supply-mutate-call-{mutate_on}",
            'count=0\n'
            'if [[ -f "$HOLDFAST_TEST_SUPPLY_COUNTER" ]]; then count=$(<"$HOLDFAST_TEST_SUPPLY_COUNTER"); fi\n'
            'count=$((count + 1))\n'
            'printf "%s\\n" "$count" >"$HOLDFAST_TEST_SUPPLY_COUNTER"\n'
            f'if [[ "$count" == "{mutate_on}" ]]; then printf "tamper\\n" >>"$HOLDFAST_TEST_SUPPLY_MUTATION_TARGET"; fi\n',
        )
        return mutating_supply, counter

    def test_schema_v3_missing_trio_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        (self.backup / recovery_completion_attestation.PUBLIC_KEY_NAME).unlink()
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_symlink_trio_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        public_key = self.backup / recovery_completion_attestation.PUBLIC_KEY_NAME
        external = self.root / "replacement-public-key.pem"
        external.write_bytes(public_key.read_bytes())
        public_key.unlink()
        public_key.symlink_to(external)
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_hardlink_trio_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        signature = self.backup / recovery_completion_attestation.SIGNATURE_NAME
        external = self.root / "linked-signature.sig"
        signature.rename(external)
        os.link(external, signature)
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_policy_drift_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        policy_path = self.backup / "successor-authority/successor-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["predecessor"]["completion"]["kind"] = "unsupported"
        policy_path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_control_drift_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        control_path = self.backup / "CONTROL.sha256"
        control_path.write_text(
            control_path.read_text(encoding="utf-8")
            + f"{'0' * 64}  RECOVERY-COMPLETION-ATTESTATION.json\n",
            encoding="utf-8",
        )
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_evidence_drift_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        evidence_path = self.backup / "RELEASE-EVIDENCE.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["predecessor_binding"]["completion"][
            "public_key_sha256"
        ] = "0" * 64
        evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_current_drift_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["predecessor_completion_signature_sha256"] = "0" * 64
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_partial_current_lineage_fails_before_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current.pop("predecessor_completion_signature_sha256")
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_hybrid_current_lineage_fails_before_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["predecessor_apply_receipt_sha256"] = "0" * 64
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_unknown_current_lineage_fails_before_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["predecessor_completion_unknown_sha256"] = "0" * 64
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_receipt_drift_fails_before_recovery_mutation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        self.replace_receipt_value(
            self.backup / "SUCCESSOR-ARMED.receipt",
            "successor_policy_sha256",
            "0" * 64,
        )
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_revalidates_authority_before_recovery_arm(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        mutating_supply, counter = self.schema_v3_mutating_supply(2)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / recovery_completion_attestation.SIGNATURE_NAME
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "2")
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_schema_v3_revalidates_nested_authority_before_recovery_arm(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current_before = current_path.read_bytes()
        mutating_supply, counter = self.schema_v3_mutating_supply(2)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / "runtime/compose-config.json"
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "2")
        self.assertEqual(current_path.read_bytes(), current_before)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-FAILED-*.receipt")))
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_schema_v3_revalidates_authority_before_runtime_restore(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        mutating_supply, counter = self.schema_v3_mutating_supply(5)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / recovery_completion_attestation.SIGNATURE_NAME
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "5")
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_schema_v3_revalidates_runtime_children_after_signed_supply(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        mutating_supply, counter = self.schema_v3_mutating_supply(5)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / "runtime/compose-config.json"
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "5")
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_schema_v3_rejects_stage_symlink_created_by_render_validator(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        armed_values = dict(
            line.split("=", 1)
            for line in (self.backup / "APPLY-ARMED.receipt")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        injected = Path(armed_values["dry_run_dir"]) / "stage/injected-link"
        mutating_render = self.make_fake(
            "render-validator-add-stage-symlink",
            'printf "render-validator %s\\n" "$*" >>"$HOLDFAST_TEST_LOG"\n'
            'ln -s /dev/null "$HOLDFAST_TEST_STAGE_MUTATION_TARGET"\n',
        )

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_RENDER_INPUT_BINDING_BIN=str(mutating_render),
                HOLDFAST_TEST_STAGE_MUTATION_TARGET=str(injected),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("stage gained a symlink", rejected.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_schema_v3_recovery_stage_rejects_cross_device_subtree(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        armed_values = dict(
            line.split("=", 1)
            for line in (self.backup / "APPLY-ARMED.receipt")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        deploy = Path(armed_values["dry_run_dir"]) / "stage/deploy"

        rejected = self.recover(
            "restore",
            env=self.environment_with_cross_device_stat(deploy),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn(
            "schema-v3 recovery stage contains a cross-device subtree",
            rejected.stderr,
        )
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        self.assertEqual(self.recovery_mutations(), [])

    def test_schema_v3_revalidates_authority_before_estate_restore(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        mutating_supply, counter = self.schema_v3_mutating_supply(8)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / recovery_completion_attestation.SIGNATURE_NAME
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "8")
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_schema_v3_revalidates_estate_tree_after_signed_supply(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        mutating_supply, counter = self.schema_v3_mutating_supply(8)
        live_target = self.estate / "deploy/docker-compose.yml"
        applied = live_target.read_bytes()

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.backup / "estate/tree/deploy/docker-compose.yml"
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "8")
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)
        self.assertEqual(live_target.read_bytes(), applied)

    def test_schema_v3_revalidates_live_compose_before_restore_writer_activation(
        self,
    ) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        mutating_supply, counter = self.schema_v3_mutating_supply(7)

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="strad",
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.estate / "deploy/docker-compose.yml"
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "7")
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertTrue(any(line.startswith("runtime-restore ") for line in calls))
        self.assertFalse(any(" up -d " in line for line in calls))

    def test_schema_v3_revalidates_live_compose_before_resume_activation(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        mutating_supply, counter = self.schema_v3_mutating_supply(4)

        rejected = self.recover(
            "resume",
            env=self.environment(
                HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN=str(mutating_supply),
                HOLDFAST_TEST_SUPPLY_COUNTER=str(counter),
                HOLDFAST_TEST_SUPPLY_MUTATION_TARGET=str(
                    self.estate / "deploy/docker-compose.yml"
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual(counter.read_text(encoding="utf-8").strip(), "4")
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(" up -d " in line for line in calls))

    def test_schema_v3_failure_receipt_carries_completion_lineage(self) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        failed = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="access-governance newapi rikune-analyzer strad",
                HOLDFAST_TEST_UNHEALTHY_SERVICES="rikune-analyzer",
            ),
        )
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        failure = self.state / current["apply_failure_receipt"]
        failure_text = failure.read_text(encoding="utf-8")
        self.assertIn("predecessor_completion_kind=", failure_text)
        self.assertIn("predecessor_completion_signature_sha256=", failure_text)
        self.assertNotIn("predecessor_apply_receipt_sha256=", failure_text)

    def test_schema_v3_partial_apply_failure_lineage_fails_before_mutation(
        self,
    ) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        failure = self.state / current["apply_failure_receipt"]
        lines = failure.read_text(encoding="utf-8").splitlines()
        failure.write_text(
            "\n".join(
                line
                for line in lines
                if not line.startswith("predecessor_completion_signature_sha256=")
            )
            + "\n",
            encoding="utf-8",
        )
        current["apply_failure_receipt_sha256"] = sha256(failure)
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_hybrid_apply_failure_lineage_fails_before_mutation(
        self,
    ) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        failure = self.state / current["apply_failure_receipt"]
        failure.write_text(
            failure.read_text(encoding="utf-8")
            + f"predecessor_apply_receipt_sha256={'0' * 64}\n",
            encoding="utf-8",
        )
        current["apply_failure_receipt_sha256"] = sha256(failure)
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_schema_v3_unknown_apply_failure_lineage_fails_before_mutation(
        self,
    ) -> None:
        _, predecessor_backup = (
            self.install_recovered_successor_v3_activation_failed_state()
        )
        shutil.rmtree(predecessor_backup)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        failure = self.state / current["apply_failure_receipt"]
        failure.write_text(
            failure.read_text(encoding="utf-8")
            + f"predecessor_completion_unknown_sha256={'0' * 64}\n",
            encoding="utf-8",
        )
        current["apply_failure_receipt_sha256"] = sha256(failure)
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        self.assert_schema_v3_rejected_before_mutation()

    def test_successor_runtime_caller_restore_boundary_is_adopted(self) -> None:
        predecessor_bytes, _ = self.install_successor_runtime_caller_state()
        current_path = self.state / "CURRENT.json"

        interrupted = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_PREDECESSOR_CURRENT_RESTORE="1"
            ),
        )
        self.assertEqual(
            interrupted.returncode, -9, interrupted.stdout + interrupted.stderr
        )
        self.assertEqual(current_path.read_bytes(), predecessor_bytes)
        self.assertEqual(len(list(self.state.glob("RUNTIME-BACKUP-ABORTED-*.json"))), 1)
        self.assertFalse(
            list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))
        )

        mutations = self.recovery_mutations()
        resumed = self.recover("restore")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertIn("previously completed runtime backup recovery", resumed.stdout)
        self.assertEqual(current_path.read_bytes(), predecessor_bytes)
        self.assertEqual(self.recovery_mutations(), mutations)
        self.assertEqual(
            len(list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))),
            1,
        )

    def test_successor_runtime_caller_archive_boundary_is_adopted(self) -> None:
        predecessor_bytes, runtime_bytes = self.install_successor_runtime_caller_state()
        current_path = self.state / "CURRENT.json"

        interrupted = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_SUCCESSOR_CURRENT_ARCHIVE="1"
            ),
        )
        self.assertEqual(
            interrupted.returncode, -9, interrupted.stdout + interrupted.stderr
        )
        self.assertEqual(current_path.read_bytes(), runtime_bytes)
        archives = list(self.state.glob("RUNTIME-BACKUP-ABORTED-*.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), runtime_bytes)
        self.assertFalse(
            list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))
        )

        mutations = self.recovery_mutations()
        estate_bytes = (self.estate / "deploy/docker-compose.yml").read_bytes()
        resumed = self.recover("restore")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertIn("previously completed runtime backup recovery", resumed.stdout)
        self.assertEqual(current_path.read_bytes(), predecessor_bytes)
        self.assertEqual(
            (self.estate / "deploy/docker-compose.yml").read_bytes(), estate_bytes
        )
        self.assertEqual(self.recovery_mutations(), mutations)
        self.assertEqual(
            len(list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))),
            1,
        )

    def test_successor_runtime_caller_archive_rejects_unrelated_current(self) -> None:
        _, runtime_bytes = self.install_successor_runtime_caller_state()
        current_path = self.state / "CURRENT.json"
        interrupted = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_SUCCESSOR_CURRENT_ARCHIVE="1"
            ),
        )
        self.assertEqual(
            interrupted.returncode, -9, interrupted.stdout + interrupted.stderr
        )
        archive = next(self.state.glob("RUNTIME-BACKUP-ABORTED-*.json"))
        unrelated_bytes = b'{"schema_version":2,"state":"unrelated"}\n'
        current_path.write_bytes(unrelated_bytes)

        mutations = self.recovery_mutations()
        estate_bytes = (self.estate / "deploy/docker-compose.yml").read_bytes()
        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn(
            "CURRENT differs from predecessor and archive", rejected.stderr
        )
        self.assertEqual(current_path.read_bytes(), unrelated_bytes)
        self.assertEqual(archive.read_bytes(), runtime_bytes)
        self.assertFalse(
            list(self.state.glob("RUNTIME-BACKUP-RECOVERY-COMPLETE-*.receipt"))
        )
        self.assertEqual(
            (self.estate / "deploy/docker-compose.yml").read_bytes(), estate_bytes
        )
        self.assertEqual(self.recovery_mutations(), mutations)

    def test_successor_lineage_tamper_fails_before_recovery_mutation(self) -> None:
        self.install_successor_activation_failed_state()
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["predecessor_backup_dir"] = str(self.root / "unrelated-generation")
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("CURRENT linkage differs", rejected.stderr)
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)

    def test_successor_pointer_cannot_downgrade_control_bound_backup(self) -> None:
        self.install_successor_activation_failed_state()
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current.pop("successor")
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("mode is missing or downgraded", rejected.stderr)
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)

    def test_successor_current_archive_boundary_retries_without_pointer_gap(
        self,
    ) -> None:
        predecessor_bytes = self.install_successor_activation_failed_state()
        interrupted = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_SUCCESSOR_CURRENT_ARCHIVE="1"
            ),
        )
        self.assertEqual(interrupted.returncode, -9, interrupted.stdout + interrupted.stderr)
        self.assertTrue((self.state / "CURRENT.json").is_file())
        self.assertEqual(
            len(list(self.state.glob("APPLY-RECOVERY-ARMED-STATE-*.json"))), 1
        )

        resumed = self.recover("restore")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual((self.state / "CURRENT.json").read_bytes(), predecessor_bytes)

    def test_successor_frozen_route_authority_tamper_fails_before_mutation(
        self,
    ) -> None:
        self.install_successor_activation_failed_state()
        route = (
            self.backup
            / "successor-authority/assets/20260823_rikune_root_down.sql"
        )
        route.write_text(route.read_text(encoding="utf-8") + "-- tampered\n")

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        calls = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)

    def test_runtime_caller_arm_after_sigkill_restores_exact_prior_subset_only(self) -> None:
        self.install_runtime_caller_state(stop_started=True)
        shutil.rmtree(self.root / "dry-run")
        result = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES="strad")
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.state / "CURRENT.json").exists())
        cleanup = (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").read_text(
            encoding="utf-8"
        )
        self.assertIn("runtime_stop_authority=present", cleanup)
        self.assertIn("prior_running_services_restored=passed", cleanup)
        calls = self.log.read_text(encoding="utf-8")
        self.assertIn(" start strad", calls)
        self.assertNotIn("start rikune-analyzer", calls)
        self.assertNotIn("runtime-restore ", calls)
        self.assertEqual(
            (self.estate / "deploy/docker-compose.yml").read_bytes(), self.new_content
        )

    def test_runtime_caller_success_before_apply_arm_is_recovered_without_data_restore(self) -> None:
        self.install_runtime_caller_state(stop_started=True, backup_succeeded=True)
        backup_receipt_sha = sha256(self.backup / "runtime/BACKUP.receipt")
        result = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES="strad")
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        cleanup = (self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"runtime_backup_success_receipt_sha256={backup_receipt_sha}", cleanup
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn("runtime-restore ", calls)
        self.assertFalse((self.backup / "runtime/RESTORE.receipt").exists())
        self.assertFalse((self.backup / "APPLY.receipt").exists())

    def test_runtime_caller_state_tampering_fails_before_recovery_mutation(self) -> None:
        self.install_runtime_caller_state(stop_started=True)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["targets_sha256"] = "0" * 64
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")
        result = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES="strad")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("caller state differs", result.stderr)
        self.assertTrue(current_path.exists())
        self.assertFalse((self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists())
        self.assertFalse(self.log.exists())

    def test_runtime_stop_authority_tampering_fails_without_starting_products(self) -> None:
        self.install_runtime_caller_state(stop_started=True)
        arm = self.backup / "runtime/RUNTIME-BACKUP-ARMED.receipt"
        arm.write_text(
            arm.read_text(encoding="utf-8").replace(
                "prior_running_services_sha256=", "prior_running_services_sha256=" + "0" * 64 + "#"
            ),
            encoding="utf-8",
        )
        result = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES="strad")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stop authority differs", result.stderr)
        self.assertTrue((self.state / "CURRENT.json").exists())
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn(" start ", calls)
        self.assertFalse((self.backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").exists())

    def test_apply_arms_before_mutation_and_activation_failure_cannot_claim_success(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        armed_state = script.index('state:"apply_armed"')
        armed_move = script.index('commit_atomic_file "$state_tmp" "$state_file"', armed_state)
        estate_apply = script.index('"$script_dir/estate_transaction.py" apply')
        activation_armed = script.index('.state="apply_activation_armed"')
        compose_up = script.index("up -d --no-build --wait --wait-timeout 300", activation_armed)
        activation_failed = script.index('.state="apply_activation_failed"', compose_up)
        apply_receipt = script.index('apply_receipt="$backup/APPLY.receipt"')
        self.assertLess(armed_move, estate_apply)
        self.assertLess(estate_apply, activation_armed)
        self.assertLess(activation_armed, compose_up)
        self.assertLess(compose_up, activation_failed)
        self.assertLess(activation_failed, apply_receipt)
        self.assertIn('"$script_dir/runtime-verify.sh"', script[compose_up:apply_receipt])

    def test_legacy_restore_is_audited_and_preserves_original_control(self) -> None:
        self.install_legacy_runtime()
        original_control = sha256(self.backup / "CONTROL.sha256")
        original_transaction = sha256(self.backup / "estate/TRANSACTION.json")
        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("explicit --legacy-empty-strad proof is required", rejected.stderr)
        result = self.recover("restore", legacy_empty_strad=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.estate / "deploy/docker-compose.yml").read_bytes(), self.old_content)
        self.assertFalse((self.state / "CURRENT.json").exists())
        self.assertFalse((self.backup / "APPLY.receipt").exists())
        self.assertEqual(sha256(self.backup / "CONTROL.sha256"), original_control)
        self.assertEqual(sha256(self.backup / "estate/TRANSACTION.json"), original_transaction)
        receipts = list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        states = list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(states), 1)
        self.assertIn("mode=restore", receipts[0].read_text(encoding="utf-8"))
        self.assertIn("legacy_empty_strad=true", receipts[0].read_text(encoding="utf-8"))
        self.assertEqual(json.loads(states[0].read_text())["state"], "apply_recovered_restored")
        calls = self.log.read_text(encoding="utf-8")
        self.assertLess(calls.index("public "), calls.index("runtime-restore "))
        self.assertLess(calls.index("runtime-restore "), calls.rindex("public "))

    def test_resume_requires_exact_applied_targets_and_never_forges_apply_receipt(self) -> None:
        result = self.recover("resume")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "applied_ingress_closed")
        self.assertTrue(current["runtime_verified"])
        self.assertEqual(
            current["transaction_sha256"], sha256(self.backup / "estate/TRANSACTION.json")
        )
        self.assertEqual(
            current["applied_targets_sha256"],
            sha256(self.backup / "estate/APPLIED-TARGETS.sha256"),
        )
        self.assertFalse((self.backup / "APPLY.receipt").exists())
        calls = self.log.read_text(encoding="utf-8")
        self.assertLess(calls.index("public "), calls.index("docker compose"))
        self.assertLess(calls.index("docker compose"), calls.index("runtime-verify "))
        self.assertLess(calls.index("runtime-verify "), calls.rindex("public "))

    def test_resume_publishes_the_exact_authority_required_by_rollback(self) -> None:
        result = self.recover("resume")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        transaction_sha = sha256(self.backup / "estate/TRANSACTION.json")
        targets_sha = sha256(self.backup / "estate/APPLIED-TARGETS.sha256")
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["transaction_sha256"], transaction_sha)
        self.assertEqual(current["applied_targets_sha256"], targets_sha)

        armed = next(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt"))
        completed = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        for receipt in (armed, completed):
            values = dict(
                line.split("=", 1)
                for line in receipt.read_text(encoding="utf-8").splitlines()
            )
            if receipt == armed:
                self.assertEqual(values["transaction_sha256"], transaction_sha)
            else:
                self.assertEqual(values["original_estate_transaction_sha256"], transaction_sha)
            self.assertEqual(values["applied_targets_sha256"], targets_sha)

        rollback = (OPS_ROOT / "rollback.sh").read_text(encoding="utf-8")
        self.assertIn(".transaction_sha256", rollback)
        self.assertIn(".applied_targets_sha256", rollback)

    def test_verify_completed_issues_signed_attestation_without_mutating_estate(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        historical_armed = self.backup / "APPLY-ARMED.receipt"
        failure = next(self.state.glob("APPLY-ACTIVATION-FAILED-*.receipt"))
        recovery_armed = next(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt"))
        completion_receipt = next(
            self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")
        )
        completion_archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        self.assertEqual(receipt_keys(historical_armed), HISTORICAL_APPLY_ARMED_KEYS)
        self.assertEqual(len(receipt_keys(historical_armed)), 32)
        self.assertEqual(len(set(receipt_keys(historical_armed))), 30)
        self.assertEqual(
            receipt_keys(self.backup / "SUCCESSOR-ARMED.receipt"),
            SUCCESSOR_ARMED_KEYS,
        )
        self.assertEqual(receipt_keys(failure), ACTIVATION_FAILURE_KEYS)
        self.assertEqual(receipt_keys(recovery_armed), RECOVERY_ARMED_KEYS)
        self.assertEqual(receipt_keys(completion_receipt), RECOVERY_COMPLETION_KEYS)
        archive_value = json.loads(completion_archive.read_text(encoding="utf-8"))
        current_value = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(archive_value), RECOVERY_ARCHIVE_KEYS)
        self.assertEqual(set(current_value), RECOVERY_CURRENT_KEYS)
        self.assertNotIn("services_activated", archive_value)
        self.assertNotIn("runtime_verified", archive_value)
        before = self.completed_estate_manifest()
        self.log.write_text("", encoding="utf-8")

        verified = self.verify_completed(private_key, public_key, release_root)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertIn("verified and attested", verified.stdout)
        self.assertEqual(self.completed_estate_manifest(), before)
        names = {
            "RECOVERY-COMPLETION-ATTESTATION.json",
            "RECOVERY-COMPLETION-ATTESTATION.sig",
            "RECOVERY-COMPLETION-ATTESTATION.pub",
        }
        self.assertEqual({path.name for path in release_root.iterdir()}, names)
        for name in names:
            self.assertEqual((release_root / name).stat().st_mode & 0o777, 0o600)
        attestation = json.loads(
            (release_root / "RECOVERY-COMPLETION-ATTESTATION.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(attestation["mode"], "resume")
        self.assertEqual(attestation["recovery_schema_version"], 2)
        self.assertEqual(attestation["runtime_backup_schema"], 2)
        self.assertTrue(attestation["successor"])
        self.assertEqual(attestation["release_generation"], 3)
        self.assertEqual(attestation["predecessor_release_generation"], 2)
        self.assertEqual(attestation["recovery_prior_state"], "apply_activation_failed")
        self.assertEqual(attestation["prior_failure_kind"], "activation")
        self.assertTrue(
            attestation["prior_failure_receipt"].startswith(
                "APPLY-ACTIVATION-FAILED-"
            )
        )
        self.assertEqual(
            attestation["prior_failure_receipt_sha256"],
            sha256(self.state / attestation["prior_failure_receipt"]),
        )
        apply_armed_values = dict(
            line.split("=", 1)
            for line in (self.backup / "APPLY-ARMED.receipt")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        failure_values = dict(
            line.split("=", 1)
            for line in (self.state / attestation["prior_failure_receipt"])
            .read_text(encoding="utf-8")
            .splitlines()
        )
        self.assertEqual(attestation["apply_armed_at"], apply_armed_values["armed_at"])
        self.assertLessEqual(attestation["apply_armed_at"], failure_values["failed_at"])
        self.assertLessEqual(failure_values["failed_at"], attestation["recovery_armed_at"])
        self.assertLessEqual(
            attestation["recovery_armed_at"],
            attestation["recovery_completed_at"],
        )
        self.assertLessEqual(attestation["recovery_completed_at"], attestation["issued_at"])
        self.assertEqual(attestation["db_public_db_bracket"], "absent-404-absent")
        self.assertEqual(
            attestation["current_sha256"], sha256(self.state / "CURRENT.json")
        )
        calls = self.log.read_text(encoding="utf-8")
        self.assertIn("runtime-verify ", calls)
        self.assertGreaterEqual(calls.count("public "), 2)
        self.assertGreaterEqual(calls.count("psql "), 4)
        self.assertLess(calls.index("psql "), calls.index("public "))
        self.assertLess(calls.index("public "), calls.rindex("psql "))

        bundle_before = {
            path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in release_root.iterdir()
        }
        repeated = self.verify_completed(private_key, public_key, release_root)
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        bundle_after = {
            path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in release_root.iterdir()
        }
        self.assertEqual(bundle_after, bundle_before)
        self.assertEqual(self.completed_estate_manifest(), before)

        signature_path = release_root / "RECOVERY-COMPLETION-ATTESTATION.sig"
        signature_path.unlink()
        converged = self.verify_completed(private_key, public_key, release_root)
        self.assertEqual(converged.returncode, 0, converged.stdout + converged.stderr)
        self.assertTrue(signature_path.is_file())
        self.assertEqual({path.name for path in release_root.iterdir()}, names)
        converged_attestation = json.loads(
            (release_root / "RECOVERY-COMPLETION-ATTESTATION.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            converged_attestation["current_sha256"],
            sha256(self.state / "CURRENT.json"),
        )
        self.assertEqual(self.completed_estate_manifest(), before)

    def test_apply_future_successor_receipts_do_not_duplicate_runtime_hashes(self) -> None:
        source = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        successor_writer = source.split("successor_armed_at=$(date", 1)[1].split(
            '} >"$successor_tmp"', 1
        )[0]
        successor_keys = tuple(
            line.split("printf '", 1)[1].split("=", 1)[0]
            for line in successor_writer.splitlines()
            if "printf '" in line and "=" in line
        )
        self.assertEqual(
            successor_keys,
            SUCCESSOR_ARMED_KEYS[:6]
            + ("successor_policy_sha256",)
            + SUCCESSOR_ARMED_KEYS[6:10]
            + (
                "predecessor_completion_kind",
                "predecessor_completion_attestation_sha256",
                "predecessor_completion_signature_sha256",
                "predecessor_completion_public_key_sha256",
            )
            + SUCCESSOR_ARMED_KEYS[10:],
        )
        helper = source.split("append_successor_receipt_fields() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertNotIn("printf 'runtime_backup_receipt_sha256=", helper)
        self.assertNotIn("printf 'runtime_backup_manifest_sha256=", helper)

        armed_writer = source.split('armed_receipt="$backup/APPLY-ARMED.receipt"', 1)[
            1
        ].split('} >"$armed_tmp"', 1)[0]
        apply_writer = source.split(
            'apply_receipt_tmp="$backup/.APPLY.receipt.$$"', 1
        )[1].split('} >"$apply_receipt_tmp"', 1)[0]
        for key in (
            "runtime_backup_receipt_sha256",
            "runtime_backup_manifest_sha256",
        ):
            self.assertEqual(armed_writer.count(f"printf '{key}="), 1)
            self.assertEqual(apply_writer.count(f"printf '{key}="), 1)

    def test_verify_completed_binds_historical_apply_runtime_authorities(self) -> None:
        source = RECOVER.read_text(encoding="utf-8")
        verifier = source.split(
            "validate_verify_completed_exact_semantics() {", 1
        )[1].split("\n}\n\nif [[ \"$verify_completed\"", 1)[0]
        self.assertIn(
            '"runtime_backup_caller_armed_sha256=$(holdfast_sha256 '
            '\"$runtime_caller_receipt\")"',
            verifier,
        )
        self.assertIn(
            '"runtime_backup_stop_authority_sha256=$(holdfast_sha256 '
            '\"$backup/runtime/RUNTIME-BACKUP-ARMED.receipt\")"',
            verifier,
        )

    def test_production_predecessor_fixture_matches_exact_producer_shape(
        self,
    ) -> None:
        self.install_production_successor_activation_failed_state()
        predecessor_current = json.loads(
            (self.backup / "PREDECESSOR-CURRENT.json").read_text(encoding="utf-8")
        )
        predecessor_apply = self.root / "predecessor-backup/APPLY.receipt"

        self.assertEqual(len(predecessor_current), 31)
        self.assertEqual(
            set(predecessor_current), PRODUCTION_PREDECESSOR_CURRENT_KEYS
        )
        self.assertEqual(
            receipt_keys(predecessor_apply), PRODUCTION_PREDECESSOR_APPLY_KEYS
        )
        self.assertEqual(len(receipt_keys(predecessor_apply)), 36)

    def test_verify_completed_requires_exact_production_predecessor_shapes(
        self,
    ) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        predecessor_current = self.backup / "PREDECESSOR-CURRENT.json"
        predecessor_apply = self.root / "predecessor-backup/APPLY.receipt"
        originals = {
            predecessor_current: predecessor_current.read_bytes(),
            predecessor_apply: predecessor_apply.read_bytes(),
        }
        cases = (
            "current-hybrid",
            "current-minus",
            "current-extra",
            "current-duplicate",
            "apply-hybrid",
            "apply-minus",
            "apply-extra",
            "apply-duplicate",
        )

        for case in cases:
            with self.subTest(case=case):
                for path, raw in originals.items():
                    path.write_bytes(raw)
                if case.startswith("current-"):
                    if case == "current-duplicate":
                        predecessor_current.write_text(
                            predecessor_current.read_text(encoding="utf-8").replace(
                                "{", '{"release_generation":2,', 1
                            ),
                            encoding="utf-8",
                        )
                        expected_error = "duplicate JSON key"
                    else:
                        value = json.loads(
                            predecessor_current.read_text(encoding="utf-8")
                        )
                        if case == "current-hybrid":
                            value.pop("successor_armed_receipt_sha256")
                            value["apply_armed_at"] = "2026-08-24T00:00:00Z"
                        elif case == "current-minus":
                            value.pop("predecessor_release_generation")
                        else:
                            value["unknown_predecessor_authority"] = True
                        predecessor_current.write_text(
                            json.dumps(value) + "\n", encoding="utf-8"
                        )
                        expected_error = "predecessor CURRENT field set is not exact"
                else:
                    lines = predecessor_apply.read_text(
                        encoding="utf-8"
                    ).splitlines(keepends=True)
                    if case == "apply-hybrid":
                        index = next(
                            index
                            for index, line in enumerate(lines)
                            if line.startswith("successor_armed_receipt_sha256=")
                        )
                        lines[index] = "apply_failure_receipt_sha256=" + "f" * 64 + "\n"
                        expected_error = "predecessor APPLY field set is not exact"
                    elif case == "apply-minus":
                        lines.pop(23)
                        expected_error = "predecessor APPLY field set is not exact"
                    elif case == "apply-extra":
                        lines.append("unknown_predecessor_authority=true\n")
                        expected_error = "predecessor APPLY field set is not exact"
                    else:
                        lines.append(lines[33])
                        expected_error = "duplicate receipt key"
                    predecessor_apply.write_text("".join(lines), encoding="utf-8")

                before = self.completed_estate_manifest()
                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected_error, rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_predecessor_lineage_value_drift(
        self,
    ) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        prior_control = (
            self.root / "predecessor-generation-1-backup/CONTROL.sha256"
        )
        lines = prior_control.read_text(encoding="utf-8").splitlines(keepends=True)
        prior_control.write_text("".join(reversed(lines)), encoding="utf-8")
        before = self.completed_estate_manifest()

        rejected = self.verify_completed(private_key, public_key, release_root)

        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("predecessor_control_sha256", rejected.stderr)
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_historical_apply_armed_duplicate_shape_is_exact(
        self,
    ) -> None:
        cases = ("different-value", "wrong-position", "extra-duplicate")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                armed = self.backup / "APPLY-ARMED.receipt"
                failure = next(
                    self.state.glob("APPLY-ACTIVATION-FAILED-*.receipt")
                )
                lines = armed.read_text(encoding="utf-8").splitlines(keepends=True)
                if case == "different-value":
                    lines[-2] = f"runtime_backup_receipt_sha256={'f' * 64}\n"
                elif case == "wrong-position":
                    duplicate_pair = lines[-2:]
                    del lines[-2:]
                    lines[17:17] = duplicate_pair
                else:
                    lines.append(lines[12])
                armed.write_text("".join(lines), encoding="utf-8")
                self.rebind_activation_failed_state(failure)
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )

                before = self.completed_estate_manifest()
                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("historical APPLY-ARMED", rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_wrong_mode_and_stale_current_without_repair(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

        wrong_mode = self.verify_completed(
            private_key, public_key, release_root, mode="restore"
        )
        self.assertEqual(wrong_mode.returncode, 2)
        self.assertIn("usage:", wrong_mode.stderr)
        self.assertIn("recovery retries are unsupported", wrong_mode.stderr)
        self.assertFalse(any(release_root.iterdir()))

        current_path = self.state / "CURRENT.json"
        stale = json.loads(current_path.read_text(encoding="utf-8"))
        stale["state"] = "apply_recovery_armed"
        current_path.write_text(json.dumps(stale) + "\n", encoding="utf-8")
        frozen = current_path.read_bytes()
        before = self.completed_estate_manifest()
        rejected = self.verify_completed(private_key, public_key, release_root)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("active completed resume state", rejected.stderr)
        self.assertEqual(current_path.read_bytes(), frozen)
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_runtime_route_and_input_drift_fail_closed(self) -> None:
        cases = (
            ("runtime", {"HOLDFAST_TEST_VERIFY_FAIL": "1"}, "", None),
            ("route", {"HOLDFAST_TEST_ROUTE_OPEN": "1"}, "", None),
            (
                "input-drift",
                {},
                "completed recovery inputs changed during live verification",
                "current",
            ),
            (
                "predecessor-input-drift",
                {},
                "completed recovery inputs changed during live verification",
                "predecessor",
            ),
        )
        for index, (name, extra, expected_error, drift_source) in enumerate(cases):
            with self.subTest(name=name):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                before = self.completed_estate_manifest()
                if drift_source:
                    drift_path = (
                        self.backup / "runtime/SHA256SUMS"
                        if drift_source == "current"
                        else self.root / "predecessor-backup/APPLY.receipt"
                    )
                    extra = {
                        "HOLDFAST_TEST_MUTATE_DURING_PUBLIC": str(drift_path)
                    }
                rejected = self.verify_completed(
                    private_key,
                    public_key,
                    release_root,
                    env=self.environment(**extra),
                )
                self.assertNotEqual(rejected.returncode, 0)
                if expected_error:
                    self.assertIn(expected_error, rejected.stderr)
                self.assertFalse(any(release_root.iterdir()))
                if not drift_source:
                    self.assertEqual(self.completed_estate_manifest(), before)

    def test_verify_completed_ignores_non_target_estate_siblings_without_scanning_root(
        self,
    ) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        workflow = self.estate / ".workflow"
        workflow.mkdir(mode=0o700)
        sibling = workflow / "search-daemon.json"
        sibling.write_text('{"pid":1}\n', encoding="utf-8")
        sibling.chmod(0o600)
        forbidden_find_marker = self.root / "forbidden-estate-find.marker"
        real_find = shutil.which("find")
        self.assertIsNotNone(real_find)
        self.make_fake(
            "find",
            'for argument in "$@"; do\n'
            '  if [[ "$argument" == "$HOLDFAST_TEST_FORBIDDEN_FIND_ROOT" ]]; then\n'
            '    touch "$HOLDFAST_TEST_FORBIDDEN_FIND_MARKER"\n'
            '    echo "full estate find is forbidden" >&2\n'
            "    exit 91\n"
            "  fi\n"
            "done\n"
            f'exec "{real_find}" "$@"\n',
        )

        verified = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(
                PATH=f"{self.bin}:{os.environ['PATH']}",
                HOLDFAST_TEST_FORBIDDEN_FIND_ROOT=str(self.estate),
                HOLDFAST_TEST_FORBIDDEN_FIND_MARKER=str(forbidden_find_marker),
                HOLDFAST_TEST_REMOVE_DURING_PUBLIC=str(sibling),
            ),
        )

        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertFalse(sibling.exists())
        self.assertFalse(forbidden_find_marker.exists())
        self.assertTrue(
            (release_root / "RECOVERY-COMPLETION-ATTESTATION.sig").is_file()
        )

    def test_verify_completed_target_content_drift_during_probe_fails_closed(
        self,
    ) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        target = self.estate / "deploy/docker-compose.yml"

        rejected = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(HOLDFAST_TEST_MUTATE_DURING_PUBLIC=str(target)),
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("live recovery disposition drift", rejected.stderr)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_tree_find_failure_cannot_form_partial_snapshot(
        self,
    ) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        before = self.completed_estate_manifest()
        marker = self.root / "partial-find.marker"
        real_find = shutil.which("find")
        self.assertIsNotNone(real_find)
        self.make_fake(
            "find",
            'if [[ "$#" == "4" && "$1" == "-P" && '
            '"$2" == "$HOLDFAST_TEST_PARTIAL_FIND_ROOT" && '
            '"$3" == "-xdev" && "$4" == "-print0" ]]; then\n'
            '  printf "%s\\0" "$HOLDFAST_TEST_PARTIAL_FIND_ROOT"\n'
            '  touch "$HOLDFAST_TEST_PARTIAL_FIND_MARKER"\n'
            "  exit 73\n"
            "fi\n"
            f'exec "{real_find}" "$@"\n',
        )

        rejected = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(
                PATH=f"{self.bin}:{os.environ['PATH']}",
                HOLDFAST_TEST_PARTIAL_FIND_ROOT=str(self.state),
                HOLDFAST_TEST_PARTIAL_FIND_MARKER=str(marker),
            ),
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertTrue(marker.exists())
        self.assertIn("could not enumerate completed recovery tree", rejected.stderr)
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_tree_rejects_cross_device_entry(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        target = self.state / "CURRENT.json"
        before = self.completed_estate_manifest()

        rejected = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment_with_cross_device_stat(target),
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("cross-device subtree", rejected.stderr)
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_target_ancestor_recreation_fails_closed(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

        rejected = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(
                HOLDFAST_TEST_RECREATE_ANCESTOR_DURING_PUBLIC=str(
                    self.estate / "deploy"
                )
            ),
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("live verification modified protected storage", rejected.stderr)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_target_ancestor_timestamp_drift_fails_closed(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

        rejected = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(
                HOLDFAST_TEST_TOUCH_ANCESTOR_DURING_PUBLIC=str(
                    self.estate / "deploy"
                )
            ),
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("live verification modified protected storage", rejected.stderr)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_applied_target_parser_rejects_unsafe_shapes(self) -> None:
        source = RECOVER.read_text(encoding="utf-8")
        parser_section = source.split(
            "prepare_verify_completed_estate_fence() {", 1
        )[1].split("snapshot_verify_completed_estate_targets() {", 1)[0]
        parser = parser_section.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        digest = b"a" * 64
        manifest = self.root / "parser-APPLIED-TARGETS.sha256"

        valid = digest + b"  deploy/docker-compose.yml\n"
        manifest.write_bytes(valid)
        accepted = subprocess.run(
            [sys.executable, "-", str(manifest), "1"],
            input=parser,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        cases = (
            (
                "absolute",
                digest + b"  /deploy/docker-compose.yml\n",
                1,
                "unsafe path",
            ),
            ("dot", digest + b"  .\n", 1, "unsafe path"),
            (
                "dotdot",
                digest + b"  deploy/../docker-compose.yml\n",
                1,
                "unsafe path",
            ),
            (
                "duplicate",
                valid + valid,
                2,
                "repeats a path",
            ),
            (
                "non-ascii",
                digest + "  部署/docker-compose.yml\n".encode("utf-8"),
                1,
                "not readable ASCII",
            ),
            ("missing-final-newline", valid[:-1], 1, "lacks its final newline"),
            ("target-count-mismatch", valid, 2, "target count differs"),
        )
        for name, content, expected_count, expected_error in cases:
            with self.subTest(name=name):
                manifest.write_bytes(content)
                rejected = subprocess.run(
                    [sys.executable, "-", str(manifest), str(expected_count)],
                    input=parser,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected_error, rejected.stderr)

    def test_verify_completed_rejects_unsafe_manifest_targets(self) -> None:
        for index, kind in enumerate(("symlink", "hardlink", "fifo")):
            with self.subTest(kind=kind):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                target = self.estate / "deploy/docker-compose.yml"
                content = target.read_bytes()
                target.unlink()
                if kind == "symlink":
                    source = self.root / "symlink-target"
                    source.write_bytes(content)
                    target.symlink_to(source)
                elif kind == "hardlink":
                    source = self.root / "hardlink-target"
                    source.write_bytes(content)
                    os.link(source, target)
                else:
                    os.mkfifo(target, mode=0o600)

                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )

                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_target_identity_and_metadata_drift(
        self,
    ) -> None:
        cases = (
            ("same-content-new-inode", "HOLDFAST_TEST_REPLACE_SAME_DURING_PUBLIC"),
            ("metadata-only", "HOLDFAST_TEST_CHMOD_DURING_PUBLIC"),
        )
        for index, (name, variable) in enumerate(cases):
            with self.subTest(name=name):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                target = self.estate / "deploy/docker-compose.yml"
                original_digest = sha256(target)

                rejected = self.verify_completed(
                    private_key,
                    public_key,
                    release_root,
                    env=self.environment(**{variable: str(target)}),
                )

                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(sha256(target), original_digest)
                self.assertIn(
                    "live verification modified protected storage", rejected.stderr
                )
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_helper_drift_during_probe_fails_closed(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        attestation_wrapper = self.make_fake(
            "recovery-completion-attestation-helper-drift-wrapper",
            'python3 "$HOLDFAST_TEST_REAL_ATTESTATION_TOOL" "$@"\n'
            'if [[ "${1:-}" == "issue" ]]; then\n'
            '  printf "drift\\n" >>"$HOLDFAST_TEST_HELPER_DRIFT"\n'
            "fi\n",
        )

        rejected = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(
                HOLDFAST_RECOVERY_COMPLETION_ATTESTATION_BIN=str(
                    attestation_wrapper
                ),
                HOLDFAST_TEST_REAL_ATTESTATION_TOOL=str(
                    OPS_ROOT / "recovery_completion_attestation.py"
                ),
                HOLDFAST_TEST_HELPER_DRIFT=str(self.runtime_verify),
            ),
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(
            "runtime verification helper changed from its initial fence",
            rejected.stderr,
        )
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_resolves_and_initially_fences_bare_helpers(self) -> None:
        cases = (
            (
                "completion",
                "HOLDFAST_RECOVERY_COMPLETION_ATTESTATION_BIN",
                "completion attestation",
            ),
            ("public", "HOLDFAST_PUBLIC_VERIFY_BIN", "public verification"),
            ("runtime", "HOLDFAST_RUNTIME_VERIFY_BIN", "runtime verification"),
        )
        for index, (kind, override, label) in enumerate(cases):
            with self.subTest(kind=kind):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                before = self.completed_estate_manifest()
                wrapper_name = f"bare-{kind}-helper"
                drift_marker = self.root / f"{kind}-helper-drift.marker"
                decoy_marker = self.root / f"{kind}-helper-decoy.marker"
                decoy_dir = self.root / f"{kind}-cwd-decoy"
                decoy_dir.mkdir(mode=0o700)
                decoy = decoy_dir / wrapper_name
                decoy.write_text(
                    "#!/usr/bin/env bash\n"
                    f'touch "{decoy_marker}"\n'
                    "exit 97\n",
                    encoding="utf-8",
                )
                decoy.chmod(0o755)
                if kind == "completion":
                    real_helper = OPS_ROOT / "recovery_completion_attestation.py"
                    delegate = 'python3 "$HOLDFAST_TEST_REAL_FROZEN_HELPER" "$@"\n'
                    trigger = '"${1:-}" == "structure"'
                elif kind == "public":
                    real_helper = self.public
                    delegate = '"$HOLDFAST_TEST_REAL_FROZEN_HELPER" "$@"\n'
                    trigger = '-n "${1:-}"'
                else:
                    real_helper = self.runtime_verify
                    delegate = '"$HOLDFAST_TEST_REAL_FROZEN_HELPER" "$@"\n'
                    trigger = '-n "${1:-}"'
                self.make_fake(
                    wrapper_name,
                    delegate
                    + f'if [[ {trigger} && ! -e "$HOLDFAST_TEST_FROZEN_HELPER_DRIFT" ]]; then\n'
                    '  replacement="${BASH_SOURCE[0]}.replacement.$$"\n'
                    '  cp -- "${BASH_SOURCE[0]}" "$replacement"\n'
                    '  printf "\\n# atomic helper drift\\n" >>"$replacement"\n'
                    '  chmod 0755 -- "$replacement"\n'
                    '  mv -fT -- "$replacement" "${BASH_SOURCE[0]}"\n'
                    '  touch "$HOLDFAST_TEST_FROZEN_HELPER_DRIFT"\n'
                    "fi\n",
                )
                helper_env = self.environment(
                    PATH=f"{self.bin}:{os.environ['PATH']}",
                    HOLDFAST_TEST_REAL_FROZEN_HELPER=str(real_helper),
                    HOLDFAST_TEST_FROZEN_HELPER_DRIFT=str(drift_marker),
                    **{override: wrapper_name},
                )

                rejected = self.verify_completed(
                    private_key,
                    public_key,
                    release_root,
                    env=helper_env,
                    cwd=decoy_dir,
                )

                self.assertNotEqual(rejected.returncode, 0)
                self.assertTrue(drift_marker.exists())
                self.assertFalse(decoy_marker.exists())
                self.assertIn(
                    f"completed recovery {label} helper changed from its initial fence",
                    rejected.stderr,
                )
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_bracket_and_hash_tampering(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        current = self.state / "CURRENT.json"
        self.replace_receipt_value(
            receipt, "db_public_db_bracket", "absent-404-present"
        )
        receipt_sha = sha256(receipt)
        for path in (archive, current):
            value = json.loads(path.read_text(encoding="utf-8"))
            value["recovery_receipt_sha256"] = receipt_sha
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        before = self.completed_estate_manifest()
        rejected = self.verify_completed(private_key, public_key, release_root)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("closed-ingress evidence differs", rejected.stderr)
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertFalse(any(release_root.iterdir()))

        current_value = json.loads(current.read_text(encoding="utf-8"))
        current_value["transaction_sha256"] = "f" * 64
        current.write_text(json.dumps(current_value) + "\n", encoding="utf-8")
        frozen = current.read_bytes()
        rejected_hash = self.verify_completed(private_key, public_key, release_root)
        self.assertNotEqual(rejected_hash.returncode, 0)
        self.assertEqual(current.read_bytes(), frozen)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_converges_partial_output_and_rejects_unsafe_key_files(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        partial = release_root / "RECOVERY-COMPLETION-ATTESTATION.json"
        partial.write_text("{}\n", encoding="utf-8")
        partial.chmod(0o600)
        before = self.completed_estate_manifest()
        converged_partial = self.verify_completed(private_key, public_key, release_root)
        self.assertEqual(
            converged_partial.returncode,
            0,
            converged_partial.stdout + converged_partial.stderr,
        )
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertEqual(
            {path.name for path in release_root.iterdir()},
            {
                "RECOVERY-COMPLETION-ATTESTATION.json",
                "RECOVERY-COMPLETION-ATTESTATION.sig",
                "RECOVERY-COMPLETION-ATTESTATION.pub",
            },
        )

        for path in release_root.iterdir():
            path.unlink()
        external = self.root / "authority-copy.pub"
        external.write_bytes(public_key.read_bytes())
        external.chmod(0o600)
        public_key.unlink()
        public_key.symlink_to(external)
        rejected_symlink = self.verify_completed(private_key, public_key, release_root)
        self.assertNotEqual(rejected_symlink.returncode, 0)
        self.assertFalse(any(release_root.iterdir()))
        public_key.unlink()
        os.link(external, public_key)
        rejected_hardlink = self.verify_completed(private_key, public_key, release_root)
        self.assertNotEqual(rejected_hardlink.returncode, 0)
        self.assertIn("one link", rejected_hardlink.stderr)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_publishes_nothing_when_inputs_drift_after_issue(self) -> None:
        for index, drift_source in enumerate(("current", "predecessor")):
            with self.subTest(drift_source=drift_source):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                attestation_wrapper = self.make_fake(
                    "recovery-completion-attestation-wrapper",
                    'python3 "$HOLDFAST_TEST_REAL_ATTESTATION_TOOL" "$@"\n'
                    'if [[ "${1:-}" == "issue" ]]; then\n'
                    '  printf "post-issue-drift\\n" >>"$HOLDFAST_TEST_ATTESTATION_DRIFT"\n'
                    "fi\n",
                )
                drift_path = (
                    self.backup / "runtime/SHA256SUMS"
                    if drift_source == "current"
                    else self.root / "predecessor-backup/APPLY.receipt"
                )
                rejected = self.verify_completed(
                    private_key,
                    public_key,
                    release_root,
                    env=self.environment(
                        HOLDFAST_RECOVERY_COMPLETION_ATTESTATION_BIN=str(
                            attestation_wrapper
                        ),
                        HOLDFAST_TEST_REAL_ATTESTATION_TOOL=str(
                            OPS_ROOT / "recovery_completion_attestation.py"
                        ),
                        HOLDFAST_TEST_ATTESTATION_DRIFT=str(drift_path),
                    ),
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(
                    "completed recovery inputs changed before attestation publication",
                    rejected.stderr,
                )
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_fences_archive_before_structure_validation(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        marker = self.root / "completion-structure-drift.marker"
        attestation_wrapper = self.make_fake(
            "recovery-completion-attestation-structure-wrapper",
            'python3 "$HOLDFAST_TEST_REAL_ATTESTATION_TOOL" "$@"\n'
            'if [[ "${1:-}" == "structure" && '
            '! -e "$HOLDFAST_TEST_STRUCTURE_MARKER" ]]; then\n'
            '  printf " " >>"$HOLDFAST_TEST_STRUCTURE_DRIFT"\n'
            '  touch "$HOLDFAST_TEST_STRUCTURE_MARKER"\n'
            "fi\n",
        )

        rejected = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(
                HOLDFAST_RECOVERY_COMPLETION_ATTESTATION_BIN=str(
                    attestation_wrapper
                ),
                HOLDFAST_TEST_REAL_ATTESTATION_TOOL=str(
                    OPS_ROOT / "recovery_completion_attestation.py"
                ),
                HOLDFAST_TEST_STRUCTURE_DRIFT=str(archive),
                HOLDFAST_TEST_STRUCTURE_MARKER=str(marker),
            ),
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(
            "completed recovery candidate changed during external validation",
            rejected.stderr,
        )
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_requires_exact_activation_failure_projection(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        current = self.state / "CURRENT.json"

        current_value = json.loads(current.read_text(encoding="utf-8"))
        current_value["projection_drift"] = True
        current.write_text(json.dumps(current_value) + "\n", encoding="utf-8")
        before = self.completed_estate_manifest()
        projection_rejected = self.verify_completed(
            private_key, public_key, release_root
        )
        self.assertNotEqual(projection_rejected.returncode, 0)
        self.assertIn("CURRENT field set is not exact", projection_rejected.stderr)
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertFalse(any(release_root.iterdir()))

        current_value.pop("projection_drift")
        for path, value in (
            (current, current_value),
            (archive, json.loads(archive.read_text(encoding="utf-8"))),
        ):
            value["recovery_prior_state"] = "apply_armed"
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        prior_before = self.completed_estate_manifest()
        producer_rejected = self.verify_completed(
            private_key, public_key, release_root
        )
        self.assertNotEqual(producer_rejected.returncode, 0)
        self.assertIn("recovery retries are unsupported", producer_rejected.stderr)
        self.assertEqual(self.completed_estate_manifest(), prior_before)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_unknown_current_and_archive_keys(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        current = self.state / "CURRENT.json"
        archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        originals = {path: path.read_bytes() for path in (current, archive)}

        for targets in ((current,), (archive,), (current, archive)):
            with self.subTest(targets=tuple(path.name for path in targets)):
                for path, raw in originals.items():
                    path.write_bytes(raw)
                for path in targets:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    value["unknown_production_key"] = True
                    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                before = self.completed_estate_manifest()
                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("field set is not exact", rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

        for path, raw in originals.items():
            path.write_bytes(raw)
        archive_value = json.loads(archive.read_text(encoding="utf-8"))
        archive_value["services_activated"] = True
        archive_value["runtime_verified"] = True
        archive.write_text(json.dumps(archive_value) + "\n", encoding="utf-8")
        rejected_flags = self.verify_completed(
            private_key, public_key, release_root
        )
        self.assertNotEqual(rejected_flags.returncode, 0)
        self.assertIn("archive field set is not exact", rejected_flags.stderr)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_binds_all_historical_state_authority_fields(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        current = self.state / "CURRENT.json"
        archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        originals = {path: path.read_bytes() for path in (current, archive)}
        drift_values: dict[str, object] = {
            "apply_armed_at": "2026-08-25T00:00:01Z",
            "dry_run_receipt_sha256": "f" * 64,
            "runtime_backup_caller_armed_sha256": "f" * 64,
            "runtime_backup_stop_authority_sha256": "f" * 64,
            "legacy_empty_strad": "false",
            "restore_running_writers_manifest": "unexpected",
            "restore_running_writers_sha256": "f" * 64,
            "pre_restored_retry": "false",
            "pre_restored_source_attempt": "20260825T000001Z-1",
            "pre_restored_runtime_snapshot_sha256": "f" * 64,
            "pre_restored_estate_snapshot_sha256": "f" * 64,
            "pre_restored_superseded_attempt": "20260825T000001Z-1",
            "pre_restored_superseded_failure_receipt_sha256": "f" * 64,
            "pre_restored_superseded_state_sha256": "f" * 64,
            "pre_restored_runtime_disposition": "unexpected",
        }
        self.assertEqual(len(drift_values), 15)
        for field, drift in drift_values.items():
            with self.subTest(field=field):
                for path, raw in originals.items():
                    path.write_bytes(raw)
                    value = json.loads(path.read_text(encoding="utf-8"))
                    value[field] = drift
                    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                before = self.completed_estate_manifest()
                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(field, rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

        for path, raw in originals.items():
            path.write_bytes(raw)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["writer_set_reconciled"] = "false"
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        rejected_writer_type = self.verify_completed(
            private_key, public_key, release_root
        )
        self.assertNotEqual(rejected_writer_type.returncode, 0)
        self.assertIn("writer_set_reconciled", rejected_writer_type.stderr)
        self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_duplicate_producer_keys_before_semantics(self) -> None:
        cases = (
            "current",
            "archive",
            "predecessor-current",
            "successor-arm",
            "completion",
            "recovery-armed",
            "failure",
        )
        for index, name in enumerate(cases):
            with self.subTest(name=name):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                current = self.state / "CURRENT.json"
                archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
                if name in {"current", "archive", "predecessor-current"}:
                    if name == "current":
                        target = current
                        duplicate_key = "recovery_prior_state"
                        duplicate_value = "apply_recovery_failed"
                    elif name == "archive":
                        target = archive
                        duplicate_key = "recovery_prior_state"
                        duplicate_value = "apply_recovery_failed"
                    else:
                        target = self.backup / "PREDECESSOR-CURRENT.json"
                        duplicate_key = "release_generation"
                        duplicate_value = 2
                    target.write_text(
                        target.read_text(encoding="utf-8").replace(
                            "{",
                            json.dumps({duplicate_key: duplicate_value})[:-1] + ",",
                            1,
                        ),
                        encoding="utf-8",
                    )
                    expected_error = "duplicate JSON key"
                else:
                    if name == "successor-arm":
                        target = self.backup / "SUCCESSOR-ARMED.receipt"
                        duplicate = "release_generation=4\n"
                    elif name == "completion":
                        target = next(
                            self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")
                        )
                        duplicate = "mode=resume\n"
                    elif name == "recovery-armed":
                        target = next(
                            self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")
                        )
                        duplicate = "prior_state=apply_activation_failed\n"
                    else:
                        target = next(
                            self.state.glob("APPLY-ACTIVATION-FAILED-*.receipt")
                        )
                        duplicate = "phase=activation\n"
                    target.write_text(
                        target.read_text(encoding="utf-8") + duplicate,
                        encoding="utf-8",
                    )
                    if name == "failure":
                        current_value = json.loads(
                            current.read_text(encoding="utf-8")
                        )
                        current_value["apply_failure_receipt_sha256"] = sha256(target)
                        current.write_text(
                            json.dumps(current_value) + "\n", encoding="utf-8"
                        )
                    expected_error = "duplicate receipt key"
                before = self.completed_estate_manifest()
                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected_error, rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_requires_exact_immutable_generation_types(self) -> None:
        cases = ("predecessor-json-string", "successor-receipt-leading-zero")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                if case == "predecessor-json-string":
                    target = self.backup / "PREDECESSOR-CURRENT.json"
                    value = json.loads(target.read_text(encoding="utf-8"))
                    value["release_generation"] = "2"
                    target.write_text(json.dumps(value) + "\n", encoding="utf-8")
                    expected = "immutable predecessor generation differs"
                else:
                    target = self.backup / "SUCCESSOR-ARMED.receipt"
                    self.replace_receipt_value(target, "release_generation", "03")
                    expected = "immutable successor generation differs"
                before = self.completed_estate_manifest()

                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected, rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_prior_failure_semantic_and_time_drift(self) -> None:
        cases = (
            ("status", "0", "activation failure status differs"),
            ("status", "256", "activation failure status differs"),
            ("activation_step", "rollback", "activation failure step differs"),
            ("phase", "rollback", "prior failure claim differs: phase"),
            (
                "failed_at",
                "2026-08-24T23:59:59Z",
                "producer timestamps are out of order",
            ),
            (
                "failed_at",
                "2099-01-01T00:00:00Z",
                "producer timestamps are out of order",
            ),
        )
        for index, (key, value, expected_error) in enumerate(cases):
            with self.subTest(key=key):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                failure = next(self.state.glob("APPLY-ACTIVATION-FAILED-*.receipt"))
                self.replace_receipt_value(failure, key, value)
                failure_sha = sha256(failure)
                archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
                current = self.state / "CURRENT.json"
                for path in (archive, current):
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document["apply_failure_receipt_sha256"] = failure_sha
                    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
                before = self.completed_estate_manifest()

                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected_error, rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_rejects_output_root_overlapping_protected_storage(self) -> None:
        private_key, public_key, unused_release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        release_root = self.estate / "release-next"
        release_root.mkdir(mode=0o700)
        before = self.completed_estate_manifest()

        rejected = self.verify_completed(private_key, public_key, release_root)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("must be disjoint from protected storage", rejected.stderr)
        self.assertEqual(self.completed_estate_manifest(), before)
        self.assertFalse(any(release_root.iterdir()))
        self.assertFalse(any(unused_release_root.iterdir()))

    def test_verify_completed_ignores_tmpdir_inside_protected_storage(self) -> None:
        private_key, public_key, release_root = (
            self.install_completion_attestation_authority()
        )
        self.install_production_successor_activation_failed_state()
        completed = self.recover("resume")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        before = self.completed_estate_manifest()

        verified = self.verify_completed(
            private_key,
            public_key,
            release_root,
            env=self.environment(TMPDIR=str(self.backup)),
        )
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertEqual(self.completed_estate_manifest(), before)

    def test_verify_completed_rejects_receipt_generation_drift(self) -> None:
        cases = ("apply-armed", "recovery-armed", "completion")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                self.install_production_successor_activation_failed_state()
                if case == "apply-armed":
                    apply_armed = self.backup / "APPLY-ARMED.receipt"
                    self.replace_receipt_value(
                        apply_armed, "release_generation", "4"
                    )
                    failure = next(
                        self.state.glob("APPLY-ACTIVATION-FAILED-*.receipt")
                    )
                    self.rebind_activation_failed_state(failure)
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                current = self.state / "CURRENT.json"
                archive = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
                completion = next(
                    self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")
                )
                if case == "recovery-armed":
                    recovery_armed = next(
                        self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")
                    )
                    self.replace_receipt_value(
                        recovery_armed, "predecessor_release_generation", "1"
                    )
                    recovery_armed_sha = sha256(recovery_armed)
                    self.replace_receipt_value(
                        completion,
                        "recovery_armed_receipt_sha256",
                        recovery_armed_sha,
                    )
                    completion_sha = sha256(completion)
                    for path in (current, archive):
                        value = json.loads(path.read_text(encoding="utf-8"))
                        value["recovery_armed_receipt_sha256"] = recovery_armed_sha
                        value["recovery_receipt_sha256"] = completion_sha
                        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                elif case == "completion":
                    self.replace_receipt_value(
                        completion, "release_generation", "4"
                    )
                    completion_sha = sha256(completion)
                    for path in (current, archive):
                        value = json.loads(path.read_text(encoding="utf-8"))
                        value["recovery_receipt_sha256"] = completion_sha
                        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

                before = self.completed_estate_manifest()
                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("generation", rejected.stderr)
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_verify_completed_scope_fails_before_live_probes_or_signing(self) -> None:
        cases = (
            ("base", None, None),
            ("successor-1-to-2", 1, 2),
            ("successor-3-to-4", 3, 4),
        )
        for index, (name, predecessor, release) in enumerate(cases):
            with self.subTest(name=name):
                if index:
                    self.tearDown()
                    self.setUp()
                private_key, public_key, release_root = (
                    self.install_completion_attestation_authority()
                )
                if predecessor is None:
                    self.install_activation_failed_state()
                else:
                    self.install_successor_activation_failed_state(
                        predecessor_generation=predecessor,
                        release_generation=release,
                        historical_apply_armed_duplicates=True,
                        production_predecessor_shape=True,
                    )
                completed = self.recover("resume")
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                before = self.completed_estate_manifest()
                self.log.write_text("", encoding="utf-8")

                rejected = self.verify_completed(
                    private_key, public_key, release_root
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(
                    "requires current-production successor generation 2 -> 3",
                    rejected.stderr,
                )
                calls = self.log.read_text(encoding="utf-8").splitlines()
                self.assertFalse(
                    any(
                        line.startswith(("runtime-verify ", "public ", "psql "))
                        for line in calls
                    )
                )
                self.assertEqual(self.completed_estate_manifest(), before)
                self.assertFalse(any(release_root.iterdir()))

    def test_activation_failed_current_and_receipt_must_match_exactly(self) -> None:
        failure = self.install_activation_failed_state()
        failure.write_bytes(failure.read_bytes() + b"tampered\n")
        rejected = self.recover("resume")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("failure receipt was replaced", rejected.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))

        failure.write_text(
            failure.read_text(encoding="utf-8").removesuffix("tampered\n"), encoding="utf-8"
        )
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        current["apply_failure_receipt_sha256"] = sha256(failure)
        (self.state / "CURRENT.json").write_text(json.dumps(current) + "\n", encoding="utf-8")
        resumed = self.recover("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        final = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(final["state"], "applied_ingress_closed")

    def test_modern_restore_uses_revalidated_staged_compose_authority(self) -> None:
        dry = self.install_modern_stage_authority()
        self.install_activation_failed_state()

        restored = self.recover("restore")
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        runtime_call = next(
            line
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.startswith("runtime-restore ")
        )
        self.assertIn(f"--compose-root {dry / 'stage'}", runtime_call)
        self.assertNotIn(f"--compose-root {self.estate} ", runtime_call)

    def test_modern_stage_path_hash_and_resolved_drift_fail_before_recovery_arm(
        self,
    ) -> None:
        dry = self.install_modern_stage_authority()
        self.install_activation_failed_state()
        stage_compose = dry / "stage/deploy/docker-compose.yml"
        original_compose = stage_compose.read_bytes()

        cases = (
            (
                "path",
                lambda: dry.chmod(0o755),
                lambda: dry.chmod(0o700),
                {},
                "directories must be private",
            ),
            (
                "target-hash",
                lambda: stage_compose.write_bytes(b"name: changed-stage\n"),
                lambda: stage_compose.write_bytes(original_compose),
                {},
                "FAILED",
            ),
            (
                "resolved-config",
                lambda: None,
                lambda: None,
                {"HOLDFAST_TEST_RESOLVED_CONFIG_DRIFT": "1"},
                "staged Compose differs from the frozen runtime authority",
            ),
        )
        for name, mutate, restore, extra_env, message in cases:
            with self.subTest(name=name):
                mutate()
                rejected = self.recover("restore", env=self.environment(**extra_env))
                restore()
                self.assertNotEqual(
                    rejected.returncode, 0, rejected.stdout + rejected.stderr
                )
                self.assertIn(message, rejected.stdout + rejected.stderr)
                self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(line.startswith("runtime-restore ") for line in calls))

    def test_modern_stage_roots_must_match_both_control_bound_receipts(self) -> None:
        failure = self.install_activation_failed_state()
        (self.state / "CURRENT.json").unlink()
        failure.unlink()
        caller = self.backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        armed = self.backup / "APPLY-ARMED.receipt"
        self.replace_receipt_value(
            caller, "dry_run_dir", str(self.root / "different-dry-run")
        )
        self.replace_receipt_value(
            armed, "runtime_backup_caller_armed_sha256", sha256(caller)
        )
        self.write_control()

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("staged Compose roots differ", rejected.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(line.startswith("runtime-restore ") for line in calls))

    def test_modern_reconciled_restore_failure_retries_with_stage_authority(self) -> None:
        dry = self.install_modern_stage_authority()
        self.install_activation_failed_state()
        running = "verdict rikune-analyzer sluice sluice-internal"
        first = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES="rikune-analyzer",
            ),
        )
        self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
        first_current = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            first_current["recovery_failure_stage"], "restore_prior_running_writers"
        )
        source_attempt = first_current["recovery_attempt_id"]
        source_state = self.state / f"APPLY-RECOVERY-FAILED-{source_attempt}.json"
        source_bytes = source_state.read_bytes()

        second = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES="access-governance verdict newapi strad sluice sluice-internal",
                HOLDFAST_TEST_RESTORE_FAIL="1",
            ),
        )
        self.assertNotEqual(second.returncode, 0, second.stdout + second.stderr)
        second_current = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            second_current["recovery_failure_stage"],
            "runtime_restore_after_writer_stop",
        )
        self.assertTrue(second_current["writer_set_reconciled"])
        self.assertEqual(second_current["writer_set_source_attempt"], source_attempt)
        self.assertEqual(source_state.read_bytes(), source_bytes)
        runtime_calls = [
            line
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.startswith("runtime-restore ")
        ]
        self.assertEqual(len(runtime_calls), 2)
        self.assertTrue(
            all(f"--compose-root {dry / 'stage'}" in line for line in runtime_calls)
        )

    def test_sigkill_reentry_revalidates_stage_before_runtime_restore(self) -> None:
        dry = self.install_modern_stage_authority()
        self.install_activation_failed_state()
        killed = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_SIGKILL_RECOVERY="1")
        )
        self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
        current = self.state / "CURRENT.json"
        frozen_current = current.read_bytes()
        runtime_calls_before = sum(
            line.startswith("runtime-restore ")
            for line in self.log.read_text(encoding="utf-8").splitlines()
        )
        (dry / "stage/deploy/docker-compose.yml").write_text(
            "name: tampered-after-sigkill\n", encoding="utf-8"
        )

        rejected = self.recover("restore")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("FAILED", rejected.stdout + rejected.stderr)
        self.assertEqual(current.read_bytes(), frozen_current)
        runtime_calls_after = sum(
            line.startswith("runtime-restore ")
            for line in self.log.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(runtime_calls_after, runtime_calls_before)

    def test_control_live_and_runtime_drift_fail_before_recovery_arm(self) -> None:
        cases = (
            ("control", self.backup / "SUPPLY-CHAIN.json", b"tampered-control\n"),
            ("live", self.estate / "deploy/docker-compose.yml", b"third-party-live\n"),
            ("runtime", self.backup / "runtime/strad.dump", b"tampered-runtime\n"),
        )
        for name, path, content in cases:
            with self.subTest(name=name):
                original = path.read_bytes()
                path.write_bytes(content)
                result = self.recover("resume")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.state / "CURRENT.json").exists())
                self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
                path.write_bytes(original)

    def test_runtime_writer_contract_drift_fails_before_recovery_arm(self) -> None:
        receipt = self.backup / "runtime/BACKUP.receipt"
        receipt.write_text(
            receipt.read_text(encoding="utf-8").replace(
                "runtime_writers_stopped=passed", "runtime_writers_stopped=failed"
            ),
            encoding="utf-8",
        )
        self.write_control()
        result = self.recover("restore")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not prove stopped writers", result.stderr)
        self.assertFalse((self.state / "CURRENT.json").exists())
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))

    def test_runtime_restore_receipt_must_prove_exact_database_disposition(self) -> None:
        result = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_BAD_RESTORE_RECEIPT="1")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("database disposition differs", result.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")))

    def test_runtime_restore_receipt_must_bind_a_valid_postgres_epoch(self) -> None:
        result = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_BAD_RUNTIME_EPOCH_RECEIPT="1"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid PostgreSQL epoch proof", result.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")))

    def test_repeated_restore_failures_append_receipts_and_remain_recoverable(self) -> None:
        env = self.environment(HOLDFAST_TEST_RESTORE_FAIL="1")
        first = self.recover("restore", env=env)
        self.assertNotEqual(first.returncode, 0)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        time.sleep(0.01)
        second = self.recover("restore", env=env)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(len(list(self.state.glob("APPLY-RECOVERY-FAILED-*.receipt"))), 2)
        self.assertEqual(len(list(self.state.glob("APPLY-RECOVERY-FAILED-*.json"))), 2)

    def test_writer_failure_retry_reuses_proven_runtime_and_estate_restore(self) -> None:
        self.install_legacy_runtime()
        running = "access-governance"
        first = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES=running,
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertEqual(current["recovery_failure_stage"], "restore_prior_running_writers")
        self.assertEqual(
            (self.estate / "deploy/docker-compose.yml").read_bytes(), self.old_content
        )
        self.assertEqual(len(list(self.state.glob("RUNTIME-RESTORE-*.receipt"))), 1)
        self.assertEqual(len(list(self.state.glob("ESTATE-RESTORE-*.json"))), 1)
        (Path(str(self.log) + ".writers-stopped")).unlink()

        second = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES=running),
            legacy_empty_strad=True,
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 1)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")).read_text(
            encoding="utf-8"
        )
        self.assertIn("pre_restored_retry=true", receipt)
        self.assertRegex(
            receipt,
            r"pre_restored_source_attempt=[0-9]{8}T[0-9]{6}Z-[0-9]+",
        )
        self.assertNotIn("runtime_restore_receipt_sha256=not-required", receipt)
        self.assertNotIn("estate_restore_state_sha256=not-required", receipt)

    def test_overwritten_current_reuses_historical_completed_restore_evidence(self) -> None:
        self.install_legacy_runtime()
        running = "access-governance"
        first = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES=running,
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
        current_path = self.state / "CURRENT.json"
        first_current = json.loads(current_path.read_text(encoding="utf-8"))
        first_attempt = first_current["recovery_attempt_id"]
        self.assertEqual(first_current["recovery_failure_stage"], "restore_prior_running_writers")
        runtime_snapshot = next(
            self.state.glob(f"RUNTIME-RESTORE-{first_attempt}-*.receipt")
        )
        estate_snapshot = next(
            self.state.glob(f"ESTATE-RESTORE-{first_attempt}-*.json")
        )
        Path(str(self.log) + ".writers-stopped").unlink()

        second = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_EXISTING_VOLUMES="test_strad_uploads\n",
                HOLDFAST_TEST_RESTORE_FAIL="1",
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(second.returncode, 0, second.stdout + second.stderr)
        second_current = json.loads(current_path.read_text(encoding="utf-8"))
        second_attempt = second_current["recovery_attempt_id"]
        self.assertNotEqual(second_attempt, first_attempt)
        self.assertEqual(
            second_current["recovery_failure_stage"], "runtime_restore_after_writer_stop"
        )
        superseded_state = self.state / f"APPLY-RECOVERY-FAILED-{second_attempt}.json"
        self.assertTrue(superseded_state.is_file())

        third = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES=running),
            legacy_empty_strad=True,
        )
        self.assertEqual(third.returncode, 0, third.stdout + third.stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 2)
        receipt_path = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        receipt = dict(
            line.split("=", 1)
            for line in receipt_path.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(receipt["pre_restored_retry"], "true")
        self.assertEqual(receipt["pre_restored_source_attempt"], first_attempt)
        self.assertEqual(
            receipt["runtime_restore_receipt_sha256"], sha256(runtime_snapshot)
        )
        self.assertEqual(receipt["estate_restore_state_sha256"], sha256(estate_snapshot))
        self.assertEqual(receipt["pre_restored_superseded_attempt"], second_attempt)
        self.assertEqual(
            receipt["pre_restored_superseded_failure_receipt_sha256"],
            second_current["apply_failure_receipt_sha256"],
        )
        self.assertEqual(
            receipt["pre_restored_superseded_state_sha256"], sha256(superseded_state)
        )
        self.assertFalse(current_path.exists())

    def test_pre_restored_arm_sigkill_reentry_preserves_evidence_binding(self) -> None:
        self.install_legacy_runtime()
        running = "access-governance"
        first = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES=running,
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
        Path(str(self.log) + ".writers-stopped").unlink()

        killed = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_SIGKILL_ON_STOP="1",
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
        current_path = self.state / "CURRENT.json"
        armed = json.loads(current_path.read_text(encoding="utf-8"))
        self.assertEqual(armed["state"], "apply_recovery_armed")
        self.assertTrue(armed["pre_restored_retry"])
        evidence_keys = (
            "pre_restored_source_attempt",
            "pre_restored_runtime_snapshot_sha256",
            "pre_restored_estate_snapshot_sha256",
            "pre_restored_superseded_attempt",
            "pre_restored_superseded_failure_receipt_sha256",
            "pre_restored_superseded_state_sha256",
            "pre_restored_runtime_disposition",
        )
        evidence = {key: armed[key] for key in evidence_keys}
        arm_path = self.state / armed["recovery_armed_receipt"]
        arm_sha = sha256(arm_path)
        arm_receipt = dict(
            line.split("=", 1)
            for line in arm_path.read_text(encoding="utf-8").splitlines()
        )
        for key, value in evidence.items():
            self.assertEqual(arm_receipt[key], value)

        resumed = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES=running),
            legacy_empty_strad=True,
        )
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 1)
        receipt_path = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        receipt = dict(
            line.split("=", 1)
            for line in receipt_path.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(receipt["pre_restored_retry"], "true")
        self.assertEqual(receipt["recovery_armed_receipt_sha256"], arm_sha)
        completion_evidence = {
            key: value
            for key, value in evidence.items()
            if key
            not in {
                "pre_restored_runtime_snapshot_sha256",
                "pre_restored_estate_snapshot_sha256",
            }
        }
        completion_evidence.update(
            runtime_restore_receipt_sha256=evidence[
                "pre_restored_runtime_snapshot_sha256"
            ],
            estate_restore_state_sha256=evidence[
                "pre_restored_estate_snapshot_sha256"
            ],
        )
        for key, value in completion_evidence.items():
            self.assertEqual(receipt[key], value)
        self.assertFalse(current_path.exists())

    def test_pre_restored_runtime_writer_inspect_failure_is_fail_closed(self) -> None:
        self.install_legacy_runtime()
        running = "access-governance"
        first = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES=running,
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
        current_path = self.state / "CURRENT.json"
        original_current = current_path.read_bytes()
        original_arms = list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt"))

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_CREATED_SERVICES="strad",
                HOLDFAST_TEST_DOCKER_INSPECT_FAIL_SERVICE="strad",
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn(
            "could not inspect runtime writer state before pre-restored retry: strad",
            rejected.stderr,
        )
        self.assertEqual(current_path.read_bytes(), original_current)
        self.assertEqual(
            list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")), original_arms
        )
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 1)

    def test_live_preimage_without_completed_restore_evidence_cannot_skip_restore(self) -> None:
        env = self.environment(HOLDFAST_TEST_RESTORE_FAIL="1")
        first = self.recover("restore", env=env)
        self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["recovery_failure_stage"], "runtime_restore_after_writer_stop")
        (self.estate / "deploy/docker-compose.yml").write_bytes(self.old_content)

        second = self.recover("restore", env=env)
        self.assertNotEqual(second.returncode, 0, second.stdout + second.stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 2)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")))

    def assert_reactivated_runtime_writer_forces_fresh_restore_on_retry(
        self, writer: str
    ) -> None:
        self.install_legacy_runtime()
        first = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=writer,
                HOLDFAST_TEST_UNHEALTHY_SERVICES=writer,
            ),
            legacy_empty_strad=True,
        )
        self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["recovery_failure_stage"], "restore_prior_running_writers")
        manifest = self.state / current["restore_running_writers_manifest"]
        self.assertEqual(manifest.read_text(encoding="utf-8").splitlines(), [writer])
        (Path(str(self.log) + ".writers-stopped")).unlink()

        second = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_RUNNING_AFTER_UP_SERVICES=writer),
            legacy_empty_strad=True,
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 2)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")).read_text(
            encoding="utf-8"
        )
        self.assertIn("pre_restored_retry=false", receipt)

    def test_reactivated_strad_manifest_forces_fresh_restore_on_retry(self) -> None:
        self.assert_reactivated_runtime_writer_forces_fresh_restore_on_retry("strad")

    def test_reactivated_rikune_analyzer_manifest_forces_fresh_restore_on_retry(
        self,
    ) -> None:
        self.assert_reactivated_runtime_writer_forces_fresh_restore_on_retry(
            "rikune-analyzer"
        )

    def test_restore_restarts_only_writers_that_were_running_before_mutation(self) -> None:
        running = "access-governance verdict newapi sluice sluice-internal"
        result = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_RESTARTING_SERVICES="rikune-analyzer",
                HOLDFAST_TEST_CREATED_SERVICES="strad",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifests = list(self.state.glob("RESTORE-RUNNING-WRITERS-*.txt"))
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0].read_text(encoding="utf-8").splitlines(), running.split())
        calls = self.log.read_text(encoding="utf-8").splitlines()
        up = next(line for line in calls if " up -d --no-build --wait --wait-timeout 300 " in line)
        self.assertIn(" --no-deps ", up)
        for service in running.split():
            self.assertIn(f" {service}", up)
        self.assertNotIn(" rikune-analyzer", up)
        self.assertNotIn(" strad", up)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")).read_text(
            encoding="utf-8"
        )
        self.assertIn(f"restore_running_writers_sha256={sha256(manifests[0])}", receipt)
        self.assertIn("writers_reactivated=passed", receipt)
        self.assertIn("uncaptured_writers_inactive=passed", receipt)

    def test_restore_excludes_release_only_writer_absent_from_preimage_compose(self) -> None:
        preimage_services = "access-governance verdict newapi strad sluice sluice-internal"
        running = "verdict rikune-analyzer sluice sluice-internal"
        result = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES=preimage_services,
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES="rikune-analyzer",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = next(self.state.glob("RESTORE-RUNNING-WRITERS-*.txt"))
        self.assertEqual(
            manifest.read_text(encoding="utf-8").splitlines(),
            ["verdict", "sluice", "sluice-internal"],
        )
        calls = self.log.read_text(encoding="utf-8").splitlines()
        up = next(line for line in calls if " up -d --no-build --wait --wait-timeout 300 " in line)
        self.assertNotIn(" rikune-analyzer", up)
        armed = next(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")).read_text(
            encoding="utf-8"
        )
        self.assertIn("writer_set_reconciled=false", armed)
        self.assertIn(
            f"writer_set_preimage_compose_sha256={sha256(self.backup / 'estate/tree/deploy/docker-compose.yml')}",
            armed,
        )

    def test_restore_failed_reentry_supersedes_bad_writer_set_without_overwriting_evidence(
        self,
    ) -> None:
        source = self.install_restore_failed_with_release_only_writer()
        source_attempt = str(source["recovery_attempt_id"])
        source_manifest = self.state / str(source["restore_running_writers_manifest"])
        source_failure = self.state / str(source["apply_failure_receipt"])
        source_state = self.state / f"APPLY-RECOVERY-FAILED-{source_attempt}.json"
        source_arm = self.state / str(source["recovery_armed_receipt"])
        frozen = {
            path: path.read_bytes()
            for path in (source_manifest, source_failure, source_state, source_arm)
        }

        preimage_services = "access-governance verdict newapi strad sluice sluice-internal"
        result = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES=preimage_services,
                HOLDFAST_TEST_RUNNING_SERVICES="verdict rikune-analyzer sluice sluice-internal",
                HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES="rikune-analyzer",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path, content in frozen.items():
            self.assertEqual(path.read_bytes(), content)

        manifests = list(self.state.glob("RESTORE-RUNNING-WRITERS-*.txt"))
        self.assertEqual(len(manifests), 2)
        reconciled = next(path for path in manifests if path != source_manifest)
        self.assertEqual(
            reconciled.read_text(encoding="utf-8").splitlines(),
            ["verdict", "sluice", "sluice-internal"],
        )
        receipt_path = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        receipt = dict(
            line.split("=", 1)
            for line in receipt_path.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(receipt["writer_set_reconciled"], "true")
        self.assertEqual(receipt["writer_set_source_attempt"], source_attempt)
        self.assertEqual(
            receipt["writer_set_source_failure_receipt_sha256"], sha256(source_failure)
        )
        self.assertEqual(receipt["writer_set_source_state_sha256"], sha256(source_state))
        self.assertEqual(
            receipt["writer_set_source_manifest_sha256"], sha256(source_manifest)
        )
        self.assertEqual(receipt["pre_restored_retry"], "false")
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 2)

    def test_reconciled_writer_set_arm_is_reentrant_after_sigkill(self) -> None:
        source = self.install_restore_failed_with_release_only_writer()
        source_attempt = str(source["recovery_attempt_id"])
        preimage_services = "access-governance verdict newapi strad sluice sluice-internal"
        common = {
            "HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES": preimage_services,
            "HOLDFAST_TEST_RUNNING_SERVICES": "verdict rikune-analyzer sluice sluice-internal",
            "HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES": "rikune-analyzer",
        }
        killed = self.recover(
            "restore",
            env=self.environment(**common, HOLDFAST_TEST_SIGKILL_RECOVERY="1"),
        )
        self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
        armed_current = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(armed_current["state"], "apply_recovery_armed")
        self.assertTrue(armed_current["writer_set_reconciled"])
        self.assertEqual(armed_current["writer_set_source_attempt"], source_attempt)
        reconciled_attempt = armed_current["recovery_attempt_id"]
        reconciled_manifest = self.state / str(
            armed_current["restore_running_writers_manifest"]
        )

        resumed = self.recover("restore", env=self.environment(**common))
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(
            reconciled_manifest.read_text(encoding="utf-8").splitlines(),
            ["verdict", "sluice", "sluice-internal"],
        )
        completion = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        values = dict(
            line.split("=", 1) for line in completion.read_text().splitlines()
        )
        self.assertEqual(values["attempt_id"], reconciled_attempt)
        self.assertEqual(values["writer_set_source_attempt"], source_attempt)
        self.assertEqual(len(list(self.state.glob("RESTORE-RUNNING-WRITERS-*.txt"))), 2)

    def test_reconciled_writer_set_survives_another_failed_attempt(self) -> None:
        source = self.install_restore_failed_with_release_only_writer()
        source_attempt = str(source["recovery_attempt_id"])
        common = {
            "HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES": "access-governance verdict newapi strad sluice sluice-internal",
            "HOLDFAST_TEST_RUNNING_SERVICES": "verdict rikune-analyzer sluice sluice-internal",
            "HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES": "rikune-analyzer",
        }
        failed = self.recover(
            "restore",
            env=self.environment(**common, HOLDFAST_TEST_UNHEALTHY_SERVICES="verdict"),
        )
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        failed_current = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(failed_current["state"], "restore_failed")
        self.assertTrue(failed_current["writer_set_reconciled"])
        self.assertEqual(failed_current["writer_set_source_attempt"], source_attempt)

        completed = self.recover("restore", env=self.environment(**common))
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        receipt_path = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        receipt = dict(
            line.split("=", 1)
            for line in receipt_path.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(receipt["writer_set_reconciled"], "true")
        self.assertEqual(receipt["writer_set_source_attempt"], source_attempt)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("runtime-restore ") for line in calls), 3)

    def test_completed_reconciled_restore_revalidates_source_before_crash_finalization(
        self,
    ) -> None:
        source = self.install_restore_failed_with_release_only_writer()
        source_attempt = str(source["recovery_attempt_id"])
        source_state = self.state / f"APPLY-RECOVERY-FAILED-{source_attempt}.json"
        common = {
            "HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES": "access-governance verdict newapi strad sluice sluice-internal",
            "HOLDFAST_TEST_RUNNING_SERVICES": "verdict rikune-analyzer sluice sluice-internal",
            "HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES": "rikune-analyzer",
        }
        completed = self.recover("restore", env=self.environment(**common))
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        completion = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        values = dict(
            line.split("=", 1) for line in completion.read_text().splitlines()
        )
        attempt = values["attempt_id"]
        armed_archive = self.state / f"APPLY-RECOVERY-ARMED-STATE-{attempt}.json"
        current_path = self.state / "CURRENT.json"
        armed_archive.rename(current_path)
        frozen_current = current_path.read_bytes()
        source_state.write_bytes(source_state.read_bytes() + b"tampered\n")

        rejected = self.recover("restore", env=self.environment(**common))
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("writer reconciliation source state was replaced", rejected.stderr)
        self.assertEqual(current_path.read_bytes(), frozen_current)
        self.assertFalse(
            (self.state / f"APPLY-RECOVERY-FINALIZED-STATE-{attempt}.json").exists()
        )

    def test_writer_reconciliation_source_tampering_fails_before_new_arm(self) -> None:
        source = self.install_restore_failed_with_release_only_writer()
        source_attempt = str(source["recovery_attempt_id"])
        source_state = self.state / f"APPLY-RECOVERY-FAILED-{source_attempt}.json"
        source_state.write_bytes(source_state.read_bytes() + b"tampered\n")
        arms_before = list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt"))
        runtime_calls_before = sum(
            line.startswith("runtime-restore ")
            for line in self.log.read_text(encoding="utf-8").splitlines()
        )

        rejected = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_PREIMAGE_COMPOSE_SERVICES="access-governance verdict newapi strad sluice sluice-internal",
                HOLDFAST_TEST_RUNNING_SERVICES="verdict rikune-analyzer sluice sluice-internal",
                HOLDFAST_TEST_REMOVED_AFTER_RESTORE_SERVICES="rikune-analyzer",
            ),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("CURRENT differs from its immutable failure state", rejected.stderr)
        self.assertEqual(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")), arms_before)
        runtime_calls_after = sum(
            line.startswith("runtime-restore ")
            for line in self.log.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(runtime_calls_after, runtime_calls_before)

    def test_preimage_compose_inventory_failure_precedes_recovery_arm(self) -> None:
        rejected = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_PREIMAGE_COMPOSE_FAIL="1"),
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("could not resolve estate preimage Compose services", rejected.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(line.startswith("runtime-restore ") for line in calls))

    def test_access_chain_quarantine_is_receipt_bound_and_removes_both_writers(
        self,
    ) -> None:
        source = self.install_activation_restore_failed_with_access_chain()
        source_attempt = str(source["recovery_attempt_id"])
        source_manifest = self.state / str(source["restore_running_writers_manifest"])
        source_failure = self.state / str(source["apply_failure_receipt"])
        source_state = self.state / f"APPLY-RECOVERY-FAILED-{source_attempt}.json"
        self.log.write_text("", encoding="utf-8")

        result = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="access-governance verdict newapi rikune-analyzer strad sluice sluice-internal",
                HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifests = list(self.state.glob("RESTORE-RUNNING-WRITERS-*.txt"))
        self.assertEqual(len(manifests), 2)
        quarantined_manifest = next(path for path in manifests if path != source_manifest)
        self.assertEqual(
            quarantined_manifest.read_text(encoding="utf-8").splitlines(),
            ["verdict", "rikune-analyzer", "strad", "sluice", "sluice-internal"],
        )

        arm = next(
            path
            for path in self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")
            if f"attempt_id={source_attempt}\n" not in path.read_text(encoding="utf-8")
        )
        completion = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        completed_state = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        for path in (arm, completion):
            text = path.read_text(encoding="utf-8")
            self.assertIn("writer_set_quarantined=access-governance,newapi", text)
            self.assertIn(f"writer_set_source_attempt={source_attempt}", text)
            self.assertIn(
                f"writer_set_source_failure_receipt_sha256={sha256(source_failure)}",
                text,
            )
            self.assertIn(f"writer_set_source_state_sha256={sha256(source_state)}", text)
            self.assertIn(
                f"writer_set_source_manifest_sha256={sha256(source_manifest)}", text
            )
        completion_text = completion.read_text(encoding="utf-8")
        self.assertIn("quarantined_writers_inactive=passed", completion_text)
        completed = json.loads(completed_state.read_text(encoding="utf-8"))
        self.assertEqual(
            completed["writer_set_quarantined"], "access-governance,newapi"
        )

        calls = self.log.read_text(encoding="utf-8").splitlines()
        up = next(line for line in calls if " up -d --no-build --wait " in line)
        self.assertNotIn(" access-governance", up)
        self.assertNotIn(" newapi", up)
        self.assertTrue(any(" rm -f cid-access-governance" in line for line in calls))
        self.assertTrue(any(" rm -f cid-newapi" in line for line in calls))

    def test_access_chain_quarantine_rejects_non_retry_resume_and_schema_v1(
        self,
    ) -> None:
        direct = self.recover("restore", quarantine_access_chain=True)
        self.assertNotEqual(direct.returncode, 0)
        self.assertIn("requires a restore-failed retry", direct.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))

        resume = self.recover("resume", quarantine_access_chain=True)
        self.assertEqual(resume.returncode, 2)
        self.assertIn("usage:", resume.stderr)

        self.install_legacy_runtime()
        schema_v1 = self.recover(
            "restore",
            legacy_empty_strad=True,
            quarantine_access_chain=True,
        )
        self.assertNotEqual(schema_v1.returncode, 0)
        self.assertIn("requires a schema-v2 runtime backup", schema_v1.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))

    def test_access_chain_quarantine_rejects_healthy_and_non_activation_sources(
        self,
    ) -> None:
        source = self.install_activation_restore_failed_with_access_chain()
        arms_before = list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt"))
        healthy = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="access-governance verdict newapi rikune-analyzer strad sluice sluice-internal"
            ),
        )
        self.assertNotEqual(healthy.returncode, 0)
        self.assertIn("requires failed access-governance health evidence", healthy.stderr)
        self.assertEqual(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")), arms_before)
        self.assertEqual(
            json.loads((self.state / "CURRENT.json").read_text())["recovery_attempt_id"],
            source["recovery_attempt_id"],
        )

    def test_access_chain_quarantine_rejects_missing_source_writer(
        self,
    ) -> None:
        self.install_activation_failed_state()
        running = "access-governance verdict rikune-analyzer strad sluice sluice-internal"
        failed = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
            ),
        )
        self.assertNotEqual(failed.returncode, 0)
        rejected = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
            ),
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("source lacks both bound writers", rejected.stderr)

    def test_access_chain_quarantine_rejects_non_activation_failure_source(
        self,
    ) -> None:
        self.install_restore_failed_with_release_only_writer()
        rejected = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="access-governance verdict newapi rikune-analyzer sluice sluice-internal",
                HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
            ),
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("was not an activation failure", rejected.stderr)

    def test_access_chain_quarantine_failure_is_reentrant_only_with_same_flag(
        self,
    ) -> None:
        source = self.install_activation_restore_failed_with_access_chain()
        source_attempt = str(source["recovery_attempt_id"])
        common = {
            "HOLDFAST_TEST_RUNNING_SERVICES": "access-governance verdict newapi rikune-analyzer strad sluice sluice-internal",
            "HOLDFAST_TEST_UNHEALTHY_SERVICES": "access-governance verdict",
        }
        failed = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(**common),
        )
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        failed_current = json.loads(
            (self.state / "CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            failed_current["writer_set_quarantined"], "access-governance,newapi"
        )
        self.assertEqual(failed_current["writer_set_source_attempt"], source_attempt)
        quarantine_attempt = str(failed_current["recovery_attempt_id"])
        quarantine_arm = self.state / str(failed_current["recovery_armed_receipt"])
        quarantine_arm_bytes = quarantine_arm.read_bytes()

        missing_flag = self.recover("restore", env=self.environment(**common))
        self.assertNotEqual(missing_flag.returncode, 0)
        self.assertIn("requires its explicit flag", missing_flag.stderr)
        self.assertEqual(quarantine_arm.read_bytes(), quarantine_arm_bytes)
        self.assertEqual(
            json.loads((self.state / "CURRENT.json").read_text())["recovery_attempt_id"],
            quarantine_attempt,
        )

        completed = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=common[
                    "HOLDFAST_TEST_RUNNING_SERVICES"
                ],
            ),
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        values = dict(
            line.split("=", 1) for line in receipt.read_text().splitlines()
        )
        self.assertEqual(values["writer_set_quarantined"], "access-governance,newapi")
        self.assertEqual(values["writer_set_source_attempt"], source_attempt)

    def test_access_chain_quarantine_rejects_tampered_source_state(self) -> None:
        source = self.install_activation_restore_failed_with_access_chain()
        source_state = self.state / (
            f"APPLY-RECOVERY-FAILED-{source['recovery_attempt_id']}.json"
        )
        source_state.write_bytes(source_state.read_bytes() + b"tampered\n")
        arms_before = list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt"))
        rejected = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="access-governance verdict newapi rikune-analyzer strad sluice sluice-internal",
                HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
            ),
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("CURRENT differs from immutable failure state", rejected.stderr)
        self.assertEqual(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")), arms_before)

    def test_completed_access_chain_quarantine_revalidates_bound_evidence(self) -> None:
        self.install_activation_restore_failed_with_access_chain()
        common = self.environment(
            HOLDFAST_TEST_RUNNING_SERVICES="access-governance verdict newapi rikune-analyzer strad sluice sluice-internal",
            HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
        )
        completed = self.recover(
            "restore", quarantine_access_chain=True, env=common
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        completed_state = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))
        values = dict(line.split("=", 1) for line in receipt.read_text().splitlines())
        attempt = values["attempt_id"]
        armed_archive = self.state / f"APPLY-RECOVERY-ARMED-STATE-{attempt}.json"
        current = self.state / "CURRENT.json"
        armed_archive.rename(current)
        self.replace_receipt_value(receipt, "writer_set_quarantined", "none")
        state = json.loads(completed_state.read_text(encoding="utf-8"))
        state["recovery_receipt_sha256"] = sha256(receipt)
        completed_state.write_text(json.dumps(state) + "\n", encoding="utf-8")

        rejected = self.recover(
            "restore", quarantine_access_chain=True, env=common
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("completed writer quarantine authority differs", rejected.stderr)
        self.assertTrue(current.exists())

    def test_completed_access_chain_quarantine_rejects_recreated_writer(
        self,
    ) -> None:
        self.install_activation_restore_failed_with_access_chain()
        common = self.environment(
            HOLDFAST_TEST_RUNNING_SERVICES="access-governance verdict newapi rikune-analyzer strad sluice sluice-internal",
            HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
        )
        completed = self.recover(
            "restore", quarantine_access_chain=True, env=common
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt"))
        values = dict(line.split("=", 1) for line in receipt.read_text().splitlines())
        attempt = values["attempt_id"]
        armed_archive = self.state / f"APPLY-RECOVERY-ARMED-STATE-{attempt}.json"
        current = self.state / "CURRENT.json"
        armed_archive.rename(current)
        current_bytes = current.read_bytes()
        for service in ("access-governance", "newapi"):
            (Path(f"{self.log}.removed-{service}")).unlink()

        rejected = self.recover(
            "restore",
            quarantine_access_chain=True,
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="access-governance newapi"
            ),
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(
            "quarantined writer container exists at completion: access-governance",
            rejected.stderr,
        )
        self.assertEqual(current.read_bytes(), current_bytes)
        self.assertFalse(
            (self.state / f"APPLY-RECOVERY-FINALIZED-STATE-{attempt}.json").exists()
        )

    def test_restore_reactivation_health_failure_keeps_restore_failed_state(self) -> None:
        result = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES="access-governance",
                HOLDFAST_TEST_UNHEALTHY_SERVICES="access-governance",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertEqual(current["recovery_failure_stage"], "restore_prior_running_writers")
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")))
        self.assertFalse((self.backup / "APPLY.receipt").exists())

    def test_restore_rejects_an_uncaptured_writer_that_becomes_active(self) -> None:
        result = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_CREATED_SERVICES="strad",
                HOLDFAST_TEST_STOP_LEAK_SERVICES="strad",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "restore_failed")
        self.assertEqual(current["recovery_failure_stage"], "restore_prior_running_writers")
        self.assertIn("excluded from the restore set", result.stderr)

    def test_current_route_canonical_and_lock_guards_fail_closed(self) -> None:
        (self.state / "CURRENT.json").write_text(
            json.dumps({"schema_version": 1, "state": "ingress_open"}) + "\n", encoding="utf-8"
        )
        current_guard = self.recover("resume")
        self.assertNotEqual(current_guard.returncode, 0)
        self.assertIn("refuses current state ingress_open", current_guard.stderr)
        (self.state / "CURRENT.json").unlink()

        route_guard = self.recover("resume", env=self.environment(HOLDFAST_TEST_ROUTE_OPEN="1"))
        self.assertNotEqual(route_guard.returncode, 0)
        self.assertFalse((self.state / "CURRENT.json").exists())

        symlink = self.root / "backup-link"
        symlink.symlink_to(self.backup, target_is_directory=True)
        canonical_guard = self.recover("resume", backup=symlink)
        self.assertNotEqual(canonical_guard.returncode, 0)
        self.assertIn("canonical", canonical_guard.stderr)

        lock_env = self.environment()
        holder = subprocess.Popen(
            [
                "bash",
                "-ceu",
                f'source "{OPS_ROOT / "common.sh"}"; holdfast_acquire_lock; echo acquired; sleep 5',
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=lock_env,
        )
        try:
            self.assertEqual(holder.stdout.readline().strip(), "acquired")
            locked = self.recover("resume", env=lock_env)
            self.assertNotEqual(locked.returncode, 0)
            self.assertIn("another Holdfast estate mutation", locked.stderr)
        finally:
            holder.terminate()
            holder.communicate(timeout=5)

    def test_writer_inventory_failure_cannot_be_misread_as_an_empty_set(self) -> None:
        result = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_DOCKER_PS_FAIL_SERVICE="access-governance"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not inspect application writer", result.stderr)
        self.assertFalse((self.state / "CURRENT.json").exists())
        self.assertFalse(list(self.state.glob("RESTORE-RUNNING-WRITERS-*.txt")))

    def test_sigkill_after_recovery_arm_is_reentrant(self) -> None:
        running = "access-governance"
        killed = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_SIGKILL_RECOVERY="1",
            ),
        )
        self.assertNotEqual(killed.returncode, 0)
        current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "apply_recovery_armed")
        armed_receipt = self.state / current["recovery_armed_receipt"]
        self.assertTrue(armed_receipt.is_file())

        resumed = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES=running)
        )
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertFalse((self.state / "CURRENT.json").exists())
        self.assertEqual(len(list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))), 1)

    def test_legacy_armed_reentry_without_pre_restored_fields_remains_supported(self) -> None:
        running = "access-governance"
        killed = self.recover(
            "restore",
            env=self.environment(
                HOLDFAST_TEST_RUNNING_SERVICES=running,
                HOLDFAST_TEST_SIGKILL_RECOVERY="1",
            ),
        )
        self.assertNotEqual(killed.returncode, 0)
        current_path = self.state / "CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        self.assertEqual(current["state"], "apply_recovery_armed")
        arm = self.state / current["recovery_armed_receipt"]
        arm.write_text(
            "".join(
                line
                for line in arm.read_text(encoding="utf-8").splitlines(keepends=True)
                if not line.startswith("pre_restored_")
            ),
            encoding="utf-8",
        )
        current["recovery_armed_receipt_sha256"] = sha256(arm)
        for key in (
            "pre_restored_retry",
            "pre_restored_source_attempt",
            "pre_restored_runtime_snapshot_sha256",
            "pre_restored_estate_snapshot_sha256",
        ):
            current.pop(key, None)
        current_path.write_text(json.dumps(current) + "\n", encoding="utf-8")

        resumed = self.recover(
            "restore", env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES=running)
        )
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertFalse(current_path.exists())

    def test_completed_restore_finalization_is_idempotent(self) -> None:
        first = self.recover("restore")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = self.recover("restore")
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("previously completed", second.stdout)
        self.assertEqual(len(list(self.state.glob("APPLY-RECOVERY-COMPLETE-*.json"))), 1)

    def test_prepared_and_not_started_estate_transactions_are_recoverable(self) -> None:
        (self.backup / "estate/TRANSACTION.json").write_text(
            json.dumps({"schema_version": 1, "state": "prepared"}) + "\n",
            encoding="utf-8",
        )
        self.write_control()
        prepared = self.recover("restore")
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)

        self.tearDown()
        self.setUp()
        failure = self.install_activation_failed_state()
        (self.estate / "deploy/docker-compose.yml").write_bytes(self.old_content)
        (self.estate / "deploy/.env").write_bytes(
            (self.backup / "estate/tree/deploy/.env").read_bytes()
        )
        (self.state / "CURRENT.json").unlink()
        failure.unlink()
        shutil.rmtree(self.backup / "estate")
        self.write_control()
        not_started = self.recover("restore")
        self.assertEqual(not_started.returncode, 0, not_started.stdout + not_started.stderr)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")).read_text()
        self.assertIn("original_estate_transaction_state=not_started", receipt)
        self.assertIn("runtime_restore_receipt_sha256=not-required", receipt)

    def test_rolled_back_estate_failure_only_restores_prior_service_lifecycle(self) -> None:
        self.install_estate_rollback_recovery_state()
        result = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES="access-governance"),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.estate / "deploy/docker-compose.yml").read_bytes(), self.old_content)
        calls = self.log.read_text(encoding="utf-8")
        self.assertNotIn("runtime-restore ", calls)
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")).read_text(
            encoding="utf-8"
        )
        self.assertIn("original_estate_transaction_state=rolled_back_after_failure", receipt)
        self.assertIn("runtime_restore_receipt_sha256=not-required", receipt)
        self.assertIn("estate_restore_state_sha256=not-required", receipt)

    def test_preimage_writer_recovery_does_not_require_expired_stage(self) -> None:
        self.install_estate_rollback_recovery_state()
        armed = self.backup / "APPLY-ARMED.receipt"
        dry = Path(
            next(
                line.split("=", 1)[1]
                for line in armed.read_text(encoding="utf-8").splitlines()
                if line.startswith("dry_run_dir=")
            )
        )
        shutil.rmtree(dry)

        restored = self.recover(
            "restore",
            env=self.environment(HOLDFAST_TEST_RUNNING_SERVICES="access-governance"),
        )
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(line.startswith("runtime-restore ") for line in calls))
        receipt = next(self.state.glob("APPLY-RECOVERY-COMPLETE-*.receipt")).read_text(
            encoding="utf-8"
        )
        self.assertIn("runtime_restore_receipt_sha256=not-required", receipt)
        self.assertIn("writers_reactivated=passed", receipt)

    def test_interrupted_apply_finalization_converges_at_all_receipt_boundaries(self) -> None:
        for index, shape in enumerate(
            ("pre_finalizing_pending", "finalizing_pending", "finalizing_promoted")
        ):
            with self.subTest(shape=shape):
                if index:
                    self.tearDown()
                    self.setUp()
                self.install_interrupted_finalization(shape)
                result = self.recover("resume")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.backup / "APPLY-PENDING.receipt").exists())
                final_receipt = self.backup / "APPLY.receipt"
                self.assertTrue(final_receipt.is_file())
                current = json.loads((self.state / "CURRENT.json").read_text(encoding="utf-8"))
                self.assertEqual(current["state"], "applied_ingress_closed")
                self.assertEqual(current["apply_receipt_sha256"], sha256(final_receipt))
                self.assertNotIn("pending_apply_receipt", current)
                calls = self.log.read_text(encoding="utf-8")
                self.assertIn("runtime-verify ", calls)
                repeated = self.recover("resume")
                self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
                repeated_current = json.loads(
                    (self.state / "CURRENT.json").read_text(encoding="utf-8")
                )
                self.assertEqual(repeated_current["apply_receipt_sha256"], sha256(final_receipt))

    def test_interrupted_apply_finalization_rejects_coexisting_receipts(self) -> None:
        self.install_interrupted_finalization("finalizing_pending")
        (self.backup / "APPLY.receipt").write_bytes(
            (self.backup / "APPLY-PENDING.receipt").read_bytes()
        )
        result = self.recover("resume")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coexist", result.stderr)

    def test_interrupted_finalization_binds_activation_state_to_receipt_claims(self) -> None:
        self.install_interrupted_finalization("pre_finalizing_pending")
        pending = self.backup / "APPLY-PENDING.receipt"
        pending.write_text(
            pending.read_text(encoding="utf-8")
            .replace("services_activated=true", "services_activated=false")
            .replace("runtime_verified=true", "runtime_verified=false"),
            encoding="utf-8",
        )
        result = self.recover("resume")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("activation-armed finalization", result.stderr)
        self.assertFalse((self.backup / "APPLY.receipt").exists())

    def test_estate_intermediate_directories_must_not_be_symlinks(self) -> None:
        external_deploy = self.root / "external-deploy"
        external_deploy.mkdir(mode=0o700)
        (external_deploy / "docker-compose.yml").write_bytes(self.new_content)
        shutil.rmtree(self.estate / "deploy")
        (self.estate / "deploy").symlink_to(external_deploy, target_is_directory=True)
        result = self.recover("resume")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical and non-symlink", result.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))

    def test_nested_target_parent_must_not_escape_through_a_symlink(self) -> None:
        external_catalog = self.root / "external-catalog"
        external_catalog.mkdir(mode=0o700)
        external_target = external_catalog / "permissions.snapshot.json"
        external_target.write_bytes(self.new_content)
        (self.estate / "access-governance/catalog").symlink_to(
            external_catalog, target_is_directory=True
        )
        backup_target = (
            self.backup
            / "estate/tree/access-governance/catalog/permissions.snapshot.json"
        )
        backup_target.parent.mkdir(parents=True, mode=0o700)
        backup_target.write_bytes(self.old_content)
        relative = "access-governance/catalog/permissions.snapshot.json"
        targets = self.backup / "estate/APPLIED-TARGETS.sha256"
        preimages = self.backup / "estate/PREIMAGES.sha256"
        targets.write_text(
            targets.read_text(encoding="utf-8") + f"{sha256(external_target)}  {relative}\n",
            encoding="utf-8",
        )
        preimages.write_text(
            preimages.read_text(encoding="utf-8") + f"{sha256(backup_target)}  {relative}\n",
            encoding="utf-8",
        )
        (self.backup / "estate/TRANSACTION.json").write_text(
            json.dumps({"schema_version": 1, "state": "applied", "target_count": 2}) + "\n",
            encoding="utf-8",
        )
        (self.backup / "APPLY-PREIMAGES.sha256").write_bytes(preimages.read_bytes())
        dry = self.backup / "DRY-RUN.receipt"
        values = dict(
            line.split("=", 1) for line in dry.read_text(encoding="utf-8").splitlines()
        )
        values["targets_sha256"] = sha256(targets)
        values["apply_preimages_sha256"] = sha256(
            self.backup / "APPLY-PREIMAGES.sha256"
        )
        dry.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()),
            encoding="utf-8",
        )
        self.write_control()
        result = self.recover("resume")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe recovery target parent", result.stderr)
        self.assertFalse(list(self.state.glob("APPLY-RECOVERY-ARMED-*.receipt")))


if __name__ == "__main__":
    unittest.main()
