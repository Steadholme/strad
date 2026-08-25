from __future__ import annotations

import hashlib
import json
import os
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
            json.dumps({"route_down_sha256": route_down_sha}) + "\n", encoding="utf-8"
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

        self.route_receipt = self.state_dir / "ROUTE-CLOSE.receipt"
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
                    "route_close_receipt_sha256": sha256(self.route_receipt),
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
        self, *, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
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
                str(self.backup),
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
        state.pop("route_close_receipt_sha256", None)
        self.state_file.write_text(json.dumps(state) + "\n", encoding="utf-8")
        self.route_receipt.unlink()
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
