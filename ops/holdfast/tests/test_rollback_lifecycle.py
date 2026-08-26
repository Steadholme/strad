from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
RELEASE_SERVICES = (
    "access-governance",
    "verdict",
    "newapi",
    "rikune-analyzer",
    "strad",
    "sluice",
    "sluice-internal",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
state_path = Path(os.environ["HOLDFAST_TEST_SERVICE_STATE"])
log_path = Path(os.environ["HOLDFAST_TEST_LIFECYCLE_LOG"])
services = (
    "access-governance", "verdict", "newapi", "rikune-analyzer",
    "strad", "sluice", "sluice-internal",
)


def load_state():
    return json.loads(state_path.read_text(encoding="utf-8"))


def save_state(state):
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")


with log_path.open("a", encoding="utf-8") as handle:
    handle.write("docker " + json.dumps(args) + "\n")

if args and args[0] == "compose":
    if "config" in args and "--format" in args:
        print(json.dumps({
            "name": "test",
            "services": {service: {} for service in services},
        }))
        sys.exit(0)
    if "up" in args:
        state = load_state()
        for service in services:
            if service in args:
                state[service] = "running"
        save_state(state)
        sys.exit(0)
    sys.exit(0)

if args and args[0] == "ps":
    service = ""
    for item in args:
        prefix = "label=com.docker.compose.service="
        if item.startswith(prefix):
            service = item.removeprefix(prefix)
    if service == os.environ.get("HOLDFAST_TEST_INVENTORY_FAIL_SERVICE"):
        sys.exit(44)
    if service and load_state().get(service) != "absent":
        print("cid-" + service)
    sys.exit(0)

if args and args[0] == "inspect":
    service = args[-1].removeprefix("cid-")
    template = args[args.index("-f") + 1]
    if "State.Health" in template:
        if service == os.environ.get("HOLDFAST_TEST_UNHEALTHY_SERVICE"):
            print("unhealthy")
        else:
            print("healthy")
    else:
        print(load_state().get(service, "absent"))
    sys.exit(0)

if args and args[0] == "stop":
    state = load_state()
    for item in args:
        if item.startswith("cid-"):
            state[item.removeprefix("cid-")] = "exited"
    save_state(state)
    sys.exit(0)

sys.exit(0)
'''


FAKE_RUNTIME_RESTORE = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
log = Path(os.environ["HOLDFAST_TEST_LIFECYCLE_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write("runtime-restore " + " ".join(args) + "\n")
state_path = Path(os.environ["HOLDFAST_TEST_SERVICE_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
state["strad"] = "absent"
state["rikune-analyzer"] = "absent"
state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
backup = Path(args[args.index("--backup-dir") + 1])
(backup / "RESTORE.receipt").write_text(
    "schema_version=2\n"
    "restore_mode=schema-v2\n"
    "database_identity=postgres:5432/strad\n"
    "database_restore=restored\n"
    "runtime_writers_removed=passed\n"
    "volume_mount_release=passed\n"
    "volume_count=6\n",
    encoding="utf-8",
)
(backup / "RESTORE.receipt").chmod(0o600)
'''


FAKE_ESTATE_RESTORE = r'''#!/usr/bin/env python3
import json
import os
import shutil
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["HOLDFAST_TEST_LIFECYCLE_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write("estate-restore " + " ".join(args) + "\n")
backup = Path(args[args.index("--backup-dir") + 1])
estate = Path(args[args.index("--estate-root") + 1])
for line in (backup / "PREIMAGES.sha256").read_text(encoding="utf-8").splitlines():
    _, relative = line.split("  ", 1)
    target = estate / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup / "tree" / relative, target)
for relative in (backup / "ABSENT.before").read_text(encoding="utf-8").splitlines():
    target = estate / relative
    if target.exists() or target.is_symlink():
        target.unlink()
(backup / "TRANSACTION.json").write_text(
    json.dumps({"schema_version": 1, "state": "restored"}) + "\n",
    encoding="utf-8",
)
(backup / "TRANSACTION.json").chmod(0o600)
'''


class RollbackLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-rollback-lifecycle-")
        self.root = Path(self.temp.name)
        self.estate = self.root / "estate"
        self.backup = self.root / "backup"
        self.runtime = self.backup / "runtime"
        self.estate_backup = self.backup / "estate"
        self.state_dir = self.root / "state"
        for directory in (
            self.estate / "deploy",
            self.backup,
            self.runtime,
            self.estate_backup / "tree",
            self.state_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        (self.estate / "deploy/.env").write_text("SAFE=1\n", encoding="utf-8")
        (self.estate / "deploy/docker-compose.yml").write_text(
            "name: test\nservices: {}\n", encoding="utf-8"
        )
        estate_preimage = self.estate_backup / "tree/estate-preimage.txt"
        estate_preimage.write_text("preimage\n", encoding="utf-8")
        estate_applied = self.estate / "estate-preimage.txt"
        estate_applied.write_text("applied\n", encoding="utf-8")
        (self.estate_backup / "PREIMAGES.sha256").write_text(
            f"{sha256(estate_preimage)}  estate-preimage.txt\n", encoding="utf-8"
        )
        (self.estate_backup / "APPLIED-TARGETS.sha256").write_text(
            f"{sha256(estate_applied)}  estate-preimage.txt\n", encoding="utf-8"
        )
        (self.estate_backup / "ABSENT.before").write_text("", encoding="utf-8")
        (self.estate_backup / "TRANSACTION.json").write_text(
            '{"schema_version":1,"state":"applied"}\n', encoding="utf-8"
        )

        runtime_manifest = self.runtime / "RUNNING-SERVICES.before"
        runtime_manifest.write_text("strad\n", encoding="utf-8")
        (self.runtime / "strad.dump").write_bytes(b"strad-dump\n")
        (self.runtime / "VOLUMES.tsv").write_text("", encoding="utf-8")
        (self.runtime / "compose-config.json").write_text(
            json.dumps({"name": "test", "services": {}, "volumes": {}}) + "\n",
            encoding="utf-8",
        )
        runtime_files = (
            "strad.dump",
            "VOLUMES.tsv",
            "compose-config.json",
            "RUNNING-SERVICES.before",
        )
        (self.runtime / "SHA256SUMS").write_text(
            "".join(f"{sha256(self.runtime / name)}  {name}\n" for name in runtime_files),
            encoding="utf-8",
        )
        (self.runtime / "BACKUP.receipt").write_text(
            "schema_version=2\n"
            "postgres_database=strad\n"
            "database_identity=postgres:5432/strad\n"
            "runtime_writers=strad,rikune-analyzer,rikune-volume-init\n"
            "runtime_writers_stopped=passed\n"
            "prior_running_services_manifest=RUNNING-SERVICES.before\n"
            f"prior_running_services_sha256={sha256(runtime_manifest)}\n",
            encoding="utf-8",
        )

        route_down_sha = sha256(OPS_ROOT / "assets/20260823_rikune_root_down.sql")
        (self.backup / "RELEASE-EVIDENCE.json").write_text(
            json.dumps({"schema_version": 1, "route_down_sha256": route_down_sha})
            + "\n",
            encoding="utf-8",
        )
        (self.backup / "release.env").write_text("RELEASE=1\n", encoding="utf-8")
        (self.backup / "DRY-RUN.receipt").write_text("cargo_gate=passed\n", encoding="utf-8")
        (self.backup / "TARGETS.sha256").write_bytes(
            (self.estate_backup / "APPLIED-TARGETS.sha256").read_bytes()
        )
        (self.backup / "APPLY-PREIMAGES.sha256").write_bytes(
            (self.estate_backup / "PREIMAGES.sha256").read_bytes()
        )
        (self.backup / "APPLY-ABSENT.paths").write_bytes(
            (self.estate_backup / "ABSENT.before").read_bytes()
        )
        (self.backup / "rollback.override.yml").write_text(
            "services:\n  access-governance:\n    image: rollback.invalid@sha256:"
            + "a" * 64
            + "\n",
            encoding="utf-8",
        )
        control_files = (
            "RELEASE-EVIDENCE.json",
            "release.env",
            "DRY-RUN.receipt",
            "rollback.override.yml",
            "TARGETS.sha256",
            "APPLY-PREIMAGES.sha256",
            "APPLY-ABSENT.paths",
            "runtime/SHA256SUMS",
            "runtime/BACKUP.receipt",
        )
        (self.backup / "CONTROL.sha256").write_text(
            "".join(f"{sha256(self.backup / name)}  {name}\n" for name in control_files),
            encoding="utf-8",
        )

        self.route_identity = sha256(self.backup / "CONTROL.sha256")
        self.route_receipt = (
            self.state_dir / f"ROUTE-CLOSE-{self.route_identity}.receipt"
        )
        self.route_preimage = (
            self.state_dir / f"ROUTE-CLOSE-PREIMAGE-{self.route_identity}.jsonl"
        )
        self.route_preimage.write_text("preimage\n", encoding="utf-8")
        self.route_receipt.write_text("was_public_open=false\n", encoding="utf-8")
        self.state_file = self.state_dir / "CURRENT.json"
        self.state_file.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "route_closed_awaiting_revocation",
                    "estate_root": str(self.estate),
                    "backup_dir": str(self.backup),
                    "control_sha256": sha256(self.backup / "CONTROL.sha256"),
                    "route_close_receipt": self.route_receipt.name,
                    "route_close_receipt_sha256": sha256(self.route_receipt),
                    "route_close_preimage": self.route_preimage.name,
                    "route_close_preimage_sha256": sha256(self.route_preimage),
                    "transaction_sha256": sha256(
                        self.estate_backup / "TRANSACTION.json"
                    ),
                    "applied_targets_sha256": sha256(
                        self.estate_backup / "APPLIED-TARGETS.sha256"
                    ),
                    "ingress_opened": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )

        self.open_evidence = self.root / "open.json"
        self.open_signature = self.root / "open.sig"
        self.public_key = self.root / "authority.pub"
        self.revocation_evidence = self.root / "revocation.json"
        self.revocation_signature = self.root / "revocation.sig"
        for path in (
            self.open_evidence,
            self.open_signature,
            self.public_key,
            self.revocation_evidence,
            self.revocation_signature,
        ):
            path.write_text(path.name + "\n", encoding="utf-8")
        self.open_evidence.write_text(
            json.dumps({"source_grant_id": "test-grant"}) + "\n",
            encoding="utf-8",
        )

        self.lifecycle_log = self.root / "lifecycle.log"
        self.service_state = self.root / "services.json"
        self.initial_states = {
            "access-governance": "running",
            "verdict": "exited",
            "newapi": "running",
            "rikune-analyzer": "running",
            "strad": "exited",
            "sluice": "exited",
            "sluice-internal": "exited",
        }
        self.service_state.write_text(json.dumps(self.initial_states), encoding="utf-8")
        self.fake_docker = self.make_executable("docker-fake", FAKE_DOCKER)
        self.fake_runtime = self.make_executable("runtime-restore-fake", FAKE_RUNTIME_RESTORE)
        self.fake_estate = self.make_executable("estate-restore-fake", FAKE_ESTATE_RESTORE)
        self.fake_psql = self.make_executable("psql-fake", "#!/bin/sh\nprintf 'ok\\n'\n")
        self.fake_pass = self.make_executable("pass-fake", "#!/bin/sh\nexit 0\n")
        self.fake_supply = self.make_executable(
            "supply-fake",
            "#!/bin/sh\n"
            'printf "supply-validator %s\\n" "$*" >>"$HOLDFAST_TEST_LIFECYCLE_LOG"\n',
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_executable(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def environment(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "ROUTES_DATABASE_URL": "postgresql://routes.invalid/test",
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_LOCK_PATH": str(self.root / "holdfast.lock"),
            "HOLDFAST_PSQL_BIN": str(self.fake_psql),
            "HOLDFAST_PUBLIC_VERIFY_BIN": str(self.fake_pass),
            "HOLDFAST_RELEASE_VALIDATOR_BIN": str(self.fake_pass),
            "HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN": str(self.fake_supply),
            "HOLDFAST_AUTHORITY_EVIDENCE_BIN": str(self.fake_pass),
            "HOLDFAST_EDGE_EVIDENCE_BIN": str(self.fake_pass),
            "HOLDFAST_DOCKER_BIN": str(self.fake_docker),
            "HOLDFAST_RUNTIME_RESTORE_BIN": str(self.fake_runtime),
            "HOLDFAST_ESTATE_TRANSACTION_BIN": str(self.fake_estate),
            "HOLDFAST_TEST_SERVICE_STATE": str(self.service_state),
            "HOLDFAST_TEST_LIFECYCLE_LOG": str(self.lifecycle_log),
            **extra,
        }

    def run_rollback(
        self, *, activate: bool = False, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "bash",
            str(OPS_ROOT / "rollback.sh"),
            "--execute",
            "--phase",
            "execute",
            "--estate-root",
            str(self.estate),
            "--backup-dir",
            str(self.backup),
            "--open-evidence",
            str(self.open_evidence),
            "--open-signature",
            str(self.open_signature),
            "--authority-public-key",
            str(self.public_key),
            "--revocation-evidence",
            str(self.revocation_evidence),
            "--revocation-signature",
            str(self.revocation_signature),
            "--state-dir",
            str(self.state_dir),
        ]
        if activate:
            command.append("--activate-services")
        return subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment or self.environment(),
        )

    def run_close_route(
        self,
        *,
        environment: dict[str, str] | None = None,
        backup: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        selected_backup = backup or self.backup
        return subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "rollback.sh"),
                "--execute",
                "--phase",
                "close-route",
                "--estate-root",
                str(self.estate),
                "--backup-dir",
                str(selected_backup),
                "--open-evidence",
                str(self.open_evidence),
                "--open-signature",
                str(self.open_signature),
                "--authority-public-key",
                str(self.public_key),
                "--state-dir",
                str(self.state_dir),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment or self.environment(),
        )

    def install_successor_lineage(self) -> bytes:
        predecessor = self.root / "predecessor-backup"
        predecessor_runtime = predecessor / "runtime"
        predecessor_runtime.mkdir(parents=True, mode=0o700)
        predecessor.chmod(0o700)
        for name in (
            "strad.dump",
            "VOLUMES.tsv",
            "compose-config.json",
            "RUNNING-SERVICES.before",
            "SHA256SUMS",
            "BACKUP.receipt",
        ):
            shutil.copyfile(self.runtime / name, predecessor_runtime / name)
        predecessor_backup_receipt = predecessor_runtime / "BACKUP.receipt"
        predecessor_backup_receipt.write_text(
            predecessor_backup_receipt.read_text(encoding="utf-8")
            + "isolated_restore_probe=passed\n",
            encoding="utf-8",
        )
        shutil.copyfile(
            self.backup / "RELEASE-EVIDENCE.json",
            predecessor / "RELEASE-EVIDENCE.json",
        )
        predecessor_control_names = (
            "RELEASE-EVIDENCE.json",
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
        predecessor_runtime_receipt_sha = sha256(predecessor_backup_receipt)
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
            "release_generation": 1,
            "route_database_state": "absent",
            "public_ipv4_ipv6_closed_status": 404,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
        }
        predecessor_bytes = (json.dumps(predecessor_current) + "\n").encode()
        predecessor_snapshot = self.backup / "PREDECESSOR-CURRENT.json"
        predecessor_snapshot.write_bytes(predecessor_bytes)
        predecessor_current_sha = sha256(predecessor_snapshot)

        route_down_sha = sha256(OPS_ROOT / "assets/20260823_rikune_root_down.sql")
        (self.backup / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "release_mode": "successor",
                    "route_down_sha256": route_down_sha,
                    "successor_delta_sha256": "pending",
                    "predecessor_binding": {
                        "current_state_sha256": predecessor_current_sha,
                        "control_sha256": predecessor_control_sha,
                        "apply_receipt_sha256": predecessor_apply_sha,
                        "release_evidence_sha256": predecessor_release_sha,
                        "runtime_manifest_sha256": predecessor_runtime_manifest_sha,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        successor_delta = self.backup / "SUCCESSOR-DELTA.sha256"
        successor_delta.write_text(f"{'d' * 64}  successor-overlay\n", encoding="utf-8")
        for name, content in (
            ("SUPPLY-CHAIN.json", b"{}\n"),
            ("SUPPLY-CHAIN.sig", b"signature\n"),
            ("SUPPLY-CHAIN.pub", b"public-key\n"),
        ):
            (self.backup / name).write_bytes(content)
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
        shutil.copyfile(
            OPS_ROOT.parents[1] / "Dockerfile.analyzer",
            successor_authority / "Dockerfile.analyzer",
        )
        shutil.copyfile(
            OPS_ROOT.parents[1] / "bridge/package-lock.json",
            successor_authority / "bridge-package-lock.json",
        )
        successor_evidence = json.loads(
            (self.backup / "RELEASE-EVIDENCE.json").read_text(encoding="utf-8")
        )
        successor_evidence["successor_delta_sha256"] = sha256(successor_delta)
        (self.backup / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(successor_evidence) + "\n", encoding="utf-8"
        )
        with (self.backup / "DRY-RUN.receipt").open("a", encoding="utf-8") as handle:
            handle.write(f"successor_delta_sha256={sha256(successor_delta)}\n")
        successor_arm = self.backup / "SUCCESSOR-ARMED.receipt"
        successor_arm.write_text(
            "".join(
                [
                    "schema_version=1\n",
                    f"successor_backup_dir={self.backup}\n",
                    "predecessor_current_file=PREDECESSOR-CURRENT.json\n",
                    f"predecessor_current_sha256={predecessor_current_sha}\n",
                    f"predecessor_backup_dir={predecessor}\n",
                    f"predecessor_control_sha256={predecessor_control_sha}\n",
                    f"predecessor_apply_receipt_sha256={predecessor_apply_sha}\n",
                    f"predecessor_release_evidence_sha256={predecessor_release_sha}\n",
                    f"predecessor_runtime_backup_receipt_sha256={predecessor_runtime_receipt_sha}\n",
                    f"predecessor_runtime_backup_manifest_sha256={predecessor_runtime_manifest_sha}\n",
                    "predecessor_release_generation=1\n",
                    "release_generation=2\n",
                    "route_database_state=absent\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "predecessor_runtime_verified=true\n",
                    "ingress_opened=false\n",
                ]
            ),
            encoding="utf-8",
        )
        successor_arm_sha = sha256(successor_arm)
        control_names = (
            "RELEASE-EVIDENCE.json",
            "release.env",
            "DRY-RUN.receipt",
            "rollback.override.yml",
            "TARGETS.sha256",
            "APPLY-PREIMAGES.sha256",
            "APPLY-ABSENT.paths",
            "RENDER-INPUTS.sha256",
            "runtime/SHA256SUMS",
            "runtime/BACKUP.receipt",
            "PREDECESSOR-CURRENT.json",
            "SUCCESSOR-ARMED.receipt",
            "SUCCESSOR-DELTA.sha256",
            "SUPPLY-CHAIN.json",
            "SUPPLY-CHAIN.sig",
            "SUPPLY-CHAIN.pub",
            *(f"successor-authority/{name}" for name in generation_authorities),
            "successor-authority/Dockerfile.analyzer",
            "successor-authority/bridge-package-lock.json",
            "successor-authority/assets/20260823_rikune_root_up.sql",
            "successor-authority/assets/20260823_rikune_root_down.sql",
        )
        (self.backup / "CONTROL.sha256").write_text(
            "".join(
                f"{sha256(self.backup / name)}  {name}\n" for name in control_names
            ),
            encoding="utf-8",
        )
        self.route_identity = sha256(self.backup / "CONTROL.sha256")
        successor_route_receipt = (
            self.state_dir / f"ROUTE-CLOSE-{self.route_identity}.receipt"
        )
        successor_route_preimage = (
            self.state_dir
            / f"ROUTE-CLOSE-PREIMAGE-{self.route_identity}.jsonl"
        )
        self.route_receipt.rename(successor_route_receipt)
        self.route_preimage.rename(successor_route_preimage)
        self.route_receipt = successor_route_receipt
        self.route_preimage = successor_route_preimage
        current = json.loads(self.state_file.read_text(encoding="utf-8"))
        current.update(
            {
                "control_sha256": sha256(self.backup / "CONTROL.sha256"),
                "route_close_receipt": self.route_receipt.name,
                "route_close_receipt_sha256": sha256(self.route_receipt),
                "route_close_preimage": self.route_preimage.name,
                "route_close_preimage_sha256": sha256(self.route_preimage),
                "successor": True,
                "successor_armed_receipt": successor_arm.name,
                "successor_armed_receipt_sha256": successor_arm_sha,
                "predecessor_current_file": predecessor_snapshot.name,
                "predecessor_current_sha256": predecessor_current_sha,
                "predecessor_backup_dir": str(predecessor),
                "predecessor_control_sha256": predecessor_control_sha,
                "predecessor_apply_receipt_sha256": predecessor_apply_sha,
                "predecessor_release_evidence_sha256": predecessor_release_sha,
                "predecessor_runtime_backup_receipt_sha256": predecessor_runtime_receipt_sha,
                "predecessor_runtime_backup_manifest_sha256": predecessor_runtime_manifest_sha,
                "predecessor_release_generation": 1,
                "release_generation": 2,
            }
        )
        self.state_file.write_text(json.dumps(current) + "\n", encoding="utf-8")
        return predecessor_bytes

    def test_execute_restores_exact_frozen_subset_without_activate_flag(self) -> None:
        result = self.run_rollback()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifests = list(self.state_dir.glob("ROLLBACK-RUNNING-SERVICES-*.before"))
        self.assertEqual(len(manifests), 1)
        self.assertEqual(
            manifests[0].read_text(),
            "access-governance\nnewapi\nrikune-analyzer\n",
        )
        receipt = (self.backup / "ROLLBACK.receipt").read_text()
        self.assertIn("reactivated_services=access-governance,newapi,strad", receipt)
        self.assertIn("excluded_services_inactive=passed", receipt)
        self.assertIn("activate_services_requested=false", receipt)
        calls = self.lifecycle_log.read_text()
        self.assertLess(calls.index("runtime-restore "), calls.index("estate-restore "))
        compose_up = next(
            line for line in calls.splitlines() if line.startswith("docker ") and '"up"' in line
        )
        self.assertIn(str(self.backup / "rollback.override.yml"), compose_up)
        self.assertIn('"--no-deps"', compose_up)
        self.assertIn('"--wait"', compose_up)
        self.assertIn('"access-governance"', compose_up)
        self.assertIn('"newapi"', compose_up)
        self.assertIn('"strad"', compose_up)
        self.assertNotIn('"rikune-analyzer"', compose_up)
        self.assertFalse(self.state_file.exists())
        completed = list(self.state_dir.glob("ROLLBACK-COMPLETE-*.json"))
        self.assertEqual(len(completed), 1)
        self.assertEqual(json.loads(completed[0].read_text())["state"], "rolled_back")

    def test_route_close_receipt_crash_is_adopted_without_external_evidence(self) -> None:
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        state["state"] = "applied_ingress_closed"
        state.pop("route_close_receipt", None)
        state.pop("route_close_receipt_sha256", None)
        state.pop("route_close_preimage", None)
        state.pop("route_close_preimage_sha256", None)
        self.state_file.write_text(json.dumps(state) + "\n", encoding="utf-8")
        self.route_receipt.unlink()
        self.route_preimage.unlink()
        interrupted = self.run_close_route(
            environment=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_ROUTE_CLOSE_RECEIPT="1"
            )
        )
        self.assertEqual(interrupted.returncode, -9)
        self.assertTrue(self.route_receipt.exists())
        self.assertEqual(
            json.loads(self.state_file.read_text())["state"], "applied_ingress_closed"
        )
        self.open_evidence.unlink()
        self.open_signature.unlink()
        self.public_key.unlink()

        resumed = self.run_close_route()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        adopted = json.loads(self.state_file.read_text())
        self.assertEqual(adopted["state"], "route_closed_awaiting_revocation")
        self.assertEqual(
            adopted["route_close_receipt_sha256"], sha256(self.route_receipt)
        )
        self.assertEqual(adopted["route_close_receipt"], self.route_receipt.name)
        self.assertEqual(adopted["route_close_preimage"], self.route_preimage.name)
        self.assertEqual(
            adopted["route_close_preimage_sha256"], sha256(self.route_preimage)
        )

    def test_route_close_evidence_is_scoped_per_release_generation(self) -> None:
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        state["state"] = "applied_ingress_closed"
        for key in (
            "route_close_receipt",
            "route_close_receipt_sha256",
            "route_close_preimage",
            "route_close_preimage_sha256",
        ):
            state.pop(key, None)
        self.state_file.write_text(json.dumps(state) + "\n", encoding="utf-8")
        self.route_receipt.unlink()
        self.route_preimage.unlink()

        newer = self.run_close_route()
        self.assertEqual(newer.returncode, 0, newer.stdout + newer.stderr)
        newer_state = json.loads(self.state_file.read_text(encoding="utf-8"))
        newer_receipt = self.state_dir / newer_state["route_close_receipt"]
        newer_preimage = self.state_dir / newer_state["route_close_preimage"]
        self.assertTrue(newer_receipt.is_file())
        self.assertTrue(newer_preimage.is_file())

        older_backup = self.root / "older-backup"
        shutil.copytree(self.backup, older_backup)
        (older_backup / "release.env").write_text(
            "RELEASE=older\n", encoding="utf-8"
        )
        control = older_backup / "CONTROL.sha256"
        control_lines = []
        for line in control.read_text(encoding="utf-8").splitlines():
            _, relative = line.split("  ", 1)
            control_lines.append(f"{sha256(older_backup / relative)}  {relative}\n")
        control.write_text("".join(control_lines), encoding="utf-8")
        older_identity = sha256(control)
        self.state_file.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "applied_ingress_closed",
                    "estate_root": str(self.estate),
                    "backup_dir": str(older_backup),
                    "control_sha256": older_identity,
                    "transaction_sha256": sha256(
                        older_backup / "estate/TRANSACTION.json"
                    ),
                    "applied_targets_sha256": sha256(
                        older_backup / "estate/APPLIED-TARGETS.sha256"
                    ),
                    "ingress_opened": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )

        older = self.run_close_route(backup=older_backup)
        self.assertEqual(older.returncode, 0, older.stdout + older.stderr)
        older_state = json.loads(self.state_file.read_text(encoding="utf-8"))
        older_receipt = self.state_dir / older_state["route_close_receipt"]
        older_preimage = self.state_dir / older_state["route_close_preimage"]
        self.assertNotEqual(older_receipt, newer_receipt)
        self.assertNotEqual(older_preimage, newer_preimage)
        for path in (newer_receipt, newer_preimage, older_receipt, older_preimage):
            self.assertTrue(path.is_file())
        self.assertEqual(
            older_receipt.name, f"ROUTE-CLOSE-{older_identity}.receipt"
        )
        self.assertEqual(
            older_preimage.name,
            f"ROUTE-CLOSE-PREIMAGE-{older_identity}.jsonl",
        )

    def test_successor_close_route_rejects_wrong_control_bound_sql_before_execution(
        self,
    ) -> None:
        self.install_successor_lineage()
        route = (
            self.backup
            / "successor-authority/assets/20260823_rikune_root_down.sql"
        )
        route.write_bytes(route.read_bytes() + b"\n-- wrong frozen route authority\n")

        control = self.backup / "CONTROL.sha256"
        control_lines = []
        for line in control.read_text(encoding="utf-8").splitlines():
            digest, relative = line.split("  ", 1)
            if relative == "successor-authority/assets/20260823_rikune_root_down.sql":
                digest = sha256(route)
            control_lines.append(f"{digest}  {relative}\n")
        control.write_text("".join(control_lines), encoding="utf-8")
        route_identity = sha256(control)

        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        state.update(
            {
                "state": "applied_ingress_closed",
                "control_sha256": route_identity,
                "route_database_state": "absent",
                "public_ipv4_ipv6_closed_status": 404,
                "ingress_opened": False,
            }
        )
        for key in (
            "route_close_receipt",
            "route_close_receipt_sha256",
            "route_close_preimage",
            "route_close_preimage_sha256",
        ):
            state.pop(key, None)
        self.state_file.write_text(json.dumps(state) + "\n", encoding="utf-8")

        tracing_psql = self.make_executable(
            "psql-route-trace",
            "#!/bin/sh\n"
            'printf "route-down-executed\\n" >>"$HOLDFAST_TEST_LIFECYCLE_LOG"\n'
            'printf "ok\\n"\n',
        )
        rejected = self.run_close_route(
            environment=self.environment(HOLDFAST_PSQL_BIN=str(tracing_psql))
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("route-down SQL differs from release evidence", rejected.stderr)
        calls = (
            self.lifecycle_log.read_text(encoding="utf-8")
            if self.lifecycle_log.exists()
            else ""
        )
        self.assertNotIn("route-down-executed", calls)
        self.assertFalse(
            (
                self.state_dir
                / f"ROUTE-CLOSE-PREIMAGE-{route_identity}.jsonl"
            ).exists()
        )

    def test_activate_services_remains_compatible_but_does_not_expand_the_subset(self) -> None:
        result = self.run_rollback(activate=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = (self.backup / "ROLLBACK.receipt").read_text()
        self.assertIn("activate_services_requested=true", receipt)
        self.assertIn("reactivated_services=access-governance,newapi,strad", receipt)
        self.assertNotIn("reactivated_services=access-governance,verdict", receipt)

    def test_sigkill_after_arm_reuses_manifest_without_resampling(self) -> None:
        interrupted = self.run_rollback(
            environment=self.environment(HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_ARM="1")
        )
        self.assertEqual(interrupted.returncode, -9)
        armed = json.loads(self.state_file.read_text())
        self.assertEqual(armed["state"], "rollback_execute_armed")
        manifest = self.state_dir / armed["rollback_running_services_manifest"]
        original_manifest = manifest.read_text()
        changed = dict(self.initial_states)
        changed["access-governance"] = "exited"
        changed["verdict"] = "running"
        self.service_state.write_text(json.dumps(changed), encoding="utf-8")

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(manifest.read_text(), original_manifest)
        receipt = (self.backup / "ROLLBACK.receipt").read_text()
        self.assertIn("reactivated_services=access-governance,newapi,strad", receipt)
        self.assertNotIn("reactivated_services=verdict", receipt)
        self.assertEqual(len(list(self.state_dir.glob("ROLLBACK-RUNNING-SERVICES-*.before"))), 1)

    def test_successor_sigkill_after_arm_restores_immediate_predecessor(self) -> None:
        predecessor_bytes = self.install_successor_lineage()
        interrupted = self.run_rollback(
            environment=self.environment(HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_ARM="1")
        )
        self.assertEqual(interrupted.returncode, -9)
        armed = json.loads(self.state_file.read_text(encoding="utf-8"))
        armed_receipt = self.state_dir / armed["rollback_armed_receipt"]
        self.assertIn("successor=true", armed_receipt.read_text(encoding="utf-8"))
        self.assertIn(
            f"predecessor_current_sha256={armed['predecessor_current_sha256']}",
            armed_receipt.read_text(encoding="utf-8"),
        )

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(self.state_file.read_bytes(), predecessor_bytes)
        self.assertEqual(
            self.lifecycle_log.read_text(encoding="utf-8").count("runtime-restore "),
            1,
        )
        receipt = (self.backup / "ROLLBACK.receipt").read_text(encoding="utf-8")
        self.assertIn("successor=true", receipt)
        self.assertIn(
            f"--successor-policy {self.backup}/successor-authority/successor-policy.json",
            self.lifecycle_log.read_text(encoding="utf-8"),
        )
        self.assertEqual(len(list(self.state_dir.glob("ROLLBACK-COMPLETE-*.json"))), 1)

    def test_successor_receipt_boundary_restores_immediate_predecessor(self) -> None:
        predecessor_bytes = self.install_successor_lineage()
        interrupted = self.run_rollback(
            environment=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_RECEIPT="1"
            )
        )
        self.assertEqual(interrupted.returncode, -9)
        self.assertTrue((self.backup / "ROLLBACK.receipt").exists())

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(self.state_file.read_bytes(), predecessor_bytes)
        self.assertEqual(
            self.lifecycle_log.read_text(encoding="utf-8").count("runtime-restore "),
            1,
        )

    def test_successor_predecessor_restore_sigkill_adopts_exact_terminal(self) -> None:
        predecessor_bytes = self.install_successor_lineage()
        interrupted = self.run_rollback(
            environment=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_PREDECESSOR_CURRENT_RESTORE="1"
            )
        )
        self.assertEqual(interrupted.returncode, -9)
        self.assertEqual(self.state_file.read_bytes(), predecessor_bytes)
        self.assertTrue((self.backup / "ROLLBACK.receipt").exists())
        self.assertEqual(len(list(self.state_dir.glob("ROLLBACK-COMPLETE-*.json"))), 1)
        calls_before = self.lifecycle_log.read_text(encoding="utf-8")

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertIn("completed successor rollback was verified", resumed.stdout)
        self.assertEqual(self.state_file.read_bytes(), predecessor_bytes)
        calls_after = self.lifecycle_log.read_text(encoding="utf-8")
        self.assertEqual(calls_after.count("runtime-restore "), 1)
        self.assertEqual(calls_after.count("estate-restore "), 1)
        self.assertEqual(
            sum('"up"' in line for line in calls_after.splitlines()),
            sum('"up"' in line for line in calls_before.splitlines()),
        )

    def test_successor_rejects_cross_generation_before_runtime_or_estate_mutation(
        self,
    ) -> None:
        self.install_successor_lineage()
        current = json.loads(self.state_file.read_text(encoding="utf-8"))
        current["predecessor_backup_dir"] = str(self.root / "grandparent-backup")
        self.state_file.write_text(json.dumps(current) + "\n", encoding="utf-8")

        rejected = self.run_rollback()
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("CURRENT linkage differs", rejected.stderr)
        calls = (
            self.lifecycle_log.read_text(encoding="utf-8")
            if self.lifecycle_log.exists()
            else ""
        )
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_successor_pointer_cannot_downgrade_control_bound_backup(self) -> None:
        self.install_successor_lineage()
        current = json.loads(self.state_file.read_text(encoding="utf-8"))
        current.pop("successor")
        self.state_file.write_text(json.dumps(current) + "\n", encoding="utf-8")

        rejected = self.run_rollback()
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("mode is missing or downgraded", rejected.stderr)
        calls = (
            self.lifecycle_log.read_text(encoding="utf-8")
            if self.lifecycle_log.exists()
            else ""
        )
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_successor_frozen_route_authority_tamper_fails_before_mutation(
        self,
    ) -> None:
        self.install_successor_lineage()
        route = (
            self.backup
            / "successor-authority/assets/20260823_rikune_root_down.sql"
        )
        route.write_text(route.read_text(encoding="utf-8") + "-- tampered\n")

        rejected = self.run_rollback()
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        calls = (
            self.lifecycle_log.read_text(encoding="utf-8")
            if self.lifecycle_log.exists()
            else ""
        )
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_unhealthy_reactivated_service_keeps_durable_armed_state(self) -> None:
        result = self.run_rollback(
            environment=self.environment(HOLDFAST_TEST_UNHEALTHY_SERVICE="strad")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reactivated service is not healthy: strad=unhealthy", result.stderr)
        self.assertEqual(
            json.loads(self.state_file.read_text())["state"],
            "rollback_estate_restore_done",
        )
        self.assertFalse((self.backup / "ROLLBACK.receipt").exists())

    def test_rejects_dynamic_estate_target_before_any_runtime_mutation(self) -> None:
        with (self.estate_backup / "APPLIED-TARGETS.sha256").open(
            "a", encoding="utf-8"
        ) as handle:
            handle.write(f"{'f' * 64}  unauthorized/path\n")
        result = self.run_rollback()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("estate applied-target authority differs", result.stderr)
        self.assertFalse(self.lifecycle_log.exists())
        self.assertEqual(
            json.loads(self.service_state.read_text(encoding="utf-8")),
            self.initial_states,
        )

    def test_rejects_state_transaction_hash_before_any_runtime_mutation(self) -> None:
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        state["transaction_sha256"] = "f" * 64
        self.state_file.write_text(json.dumps(state) + "\n", encoding="utf-8")
        result = self.run_rollback()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("current state transaction authority differs", result.stderr)
        calls = self.lifecycle_log.read_text() if self.lifecycle_log.exists() else ""
        self.assertNotIn("runtime-restore ", calls)
        self.assertNotIn("estate-restore ", calls)

    def test_crash_after_runtime_restore_adopts_receipt_without_replaying(self) -> None:
        interrupted = self.run_rollback(
            environment=self.environment(HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_RESTORE="1")
        )
        self.assertEqual(interrupted.returncode, -9)
        self.assertEqual(
            json.loads(self.state_file.read_text())["state"], "rollback_execute_armed"
        )
        self.assertTrue((self.runtime / "RESTORE.receipt").exists())
        for source in (
            self.open_evidence,
            self.open_signature,
            self.public_key,
            self.revocation_evidence,
            self.revocation_signature,
        ):
            source.unlink()

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        calls = self.lifecycle_log.read_text()
        self.assertEqual(calls.count("runtime-restore "), 1)
        self.assertEqual(calls.count("estate-restore "), 1)
        self.assertEqual(
            len(list(self.state_dir.glob("ROLLBACK-RUNTIME-RESTORE-DONE-*.receipt"))),
            1,
        )

    def test_crash_after_estate_restore_skips_runtime_and_estate_replay(self) -> None:
        interrupted = self.run_rollback(
            environment=self.environment(HOLDFAST_TEST_SIGKILL_AFTER_ESTATE_RESTORE="1")
        )
        self.assertEqual(interrupted.returncode, -9)
        self.assertEqual(
            json.loads(self.state_file.read_text())["state"],
            "rollback_runtime_restore_done",
        )
        self.assertEqual(
            json.loads((self.estate_backup / "TRANSACTION.json").read_text())["state"],
            "restored",
        )

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        calls = self.lifecycle_log.read_text()
        self.assertEqual(calls.count("runtime-restore "), 1)
        self.assertEqual(calls.count("estate-restore "), 1)
        self.assertEqual(
            len(list(self.state_dir.glob("ROLLBACK-ESTATE-RESTORE-DONE-*.receipt"))),
            1,
        )

    def test_crash_after_activation_retries_only_idempotent_activation(self) -> None:
        interrupted = self.run_rollback(
            environment=self.environment(
                HOLDFAST_TEST_SIGKILL_AFTER_SERVICE_REACTIVATION="1"
            )
        )
        self.assertEqual(interrupted.returncode, -9)
        self.assertEqual(
            json.loads(self.state_file.read_text())["state"],
            "rollback_estate_restore_done",
        )

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        calls = self.lifecycle_log.read_text()
        self.assertEqual(calls.count("runtime-restore "), 1)
        self.assertEqual(calls.count("estate-restore "), 1)
        self.assertEqual(sum('"up"' in line for line in calls.splitlines()), 2)

    def test_receipt_to_current_crash_finalizes_without_replaying_mutations(self) -> None:
        interrupted = self.run_rollback(
            environment=self.environment(HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_RECEIPT="1")
        )
        self.assertEqual(interrupted.returncode, -9)
        self.assertTrue((self.backup / "ROLLBACK.receipt").exists())
        self.assertEqual(
            json.loads(self.state_file.read_text())["state"],
            "rollback_services_reactivated_done",
        )
        calls_before = self.lifecycle_log.read_text()

        resumed = self.run_rollback()
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        calls_after = self.lifecycle_log.read_text()
        self.assertEqual(calls_after.count("runtime-restore "), 1)
        self.assertEqual(calls_after.count("estate-restore "), 1)
        self.assertEqual(
            sum('"up"' in line for line in calls_after.splitlines()),
            sum('"up"' in line for line in calls_before.splitlines()),
        )

    def test_completed_receipt_rejects_non_exact_reactivated_set(self) -> None:
        interrupted = self.run_rollback(
            environment=self.environment(HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_RECEIPT="1")
        )
        self.assertEqual(interrupted.returncode, -9)
        receipt = self.backup / "ROLLBACK.receipt"
        receipt.write_text(
            receipt.read_text(encoding="utf-8").replace(
                "reactivated_services=access-governance,newapi,strad",
                "reactivated_services=access-governance",
            ),
            encoding="utf-8",
        )
        resumed = self.run_rollback()
        self.assertNotEqual(resumed.returncode, 0)
        self.assertIn(
            "reactivated-services set differs from frozen recovery authority",
            resumed.stderr,
        )

    def test_contract_orders_arm_quiesce_runtime_estate_and_exact_activation(self) -> None:
        script = (OPS_ROOT / "rollback.sh").read_text(encoding="utf-8")
        arm = script.index('.state="rollback_execute_armed"')
        quiesce = script.index("quiesce_release_services", arm)
        runtime = script.index('"$runtime_restore" --execute', quiesce)
        estate = script.index('run_python_tool "$estate_transaction"', runtime)
        activation = script.index('up -d --no-build --wait --wait-timeout 300 --no-deps', estate)
        self.assertLess(arm, quiesce)
        self.assertLess(quiesce, runtime)
        self.assertLess(runtime, estate)
        self.assertLess(estate, activation)


if __name__ == "__main__":
    unittest.main()
