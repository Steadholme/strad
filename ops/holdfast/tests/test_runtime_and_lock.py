from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
POSTGRES_CONTAINER_ID = "1" * 64
REPLACEMENT_POSTGRES_CONTAINER_ID = "2" * 64


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    body_start = start + len(f"{name}() {{")
    following = re.search(r"(?m)^[a-z_][a-z0-9_]*\(\) \{", source[body_start:])
    if following is None:
        return source[start:]
    return source[start : body_start + following.start()]


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
images = json.loads(os.environ.get("FAKE_IMAGES", "{}"))
log_path = os.environ.get("FAKE_DOCKER_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(args) + "\n")

state_root = Path(os.environ.get("FAKE_DOCKER_STATE", "/tmp/holdfast-fake-docker-unused"))
stopped_file = state_root.with_suffix(".stopped")
removed_file = state_root.with_suffix(".removed")
health_inspects_file = state_root.with_suffix(".health-inspects")
postgres_ps_count_file = state_root.with_suffix(".postgres-ps-count")
default_postgres_container_id = "1" * 64
replacement_postgres_container_id = "2" * 64


def names(path):
    if not path.exists():
        return set()
    return set(path.read_text(encoding="utf-8").splitlines())


def add_names(path, values):
    current = names(path)
    current.update(values)
    path.write_text("".join(f"{item}\n" for item in sorted(current)), encoding="utf-8")


def remove_names(path, values):
    current = names(path)
    current.difference_update(values)
    path.write_text("".join(f"{item}\n" for item in sorted(current)), encoding="utf-8")


def service_state(service):
    if service in names(stopped_file) or service in names(removed_file):
        return "exited"
    states = json.loads(os.environ.get("FAKE_SERVICE_STATES", "{}"))
    return states.get(service, "running")


if args and args[0] == "compose":
    if "config" in args and "--hash" in args:
        print(
            "postgres "
            + os.environ.get("FAKE_FROZEN_POSTGRES_CONFIG_HASH", "c" * 64)
        )
        sys.exit(0)
    if "config" in args and "--format" in args:
        digest = "sha256:" + "a" * 64
        strad_dsn = os.environ.get(
            "FAKE_STRAD_DSN", "postgresql://strad:secret@postgres:5432/strad"
        )
        services = {
            "rikune-volume-init": {"image": "registry.invalid/init@" + digest},
            "postgres": {
                "image": "registry.invalid/postgres@" + digest,
                "environment": {"POSTGRES_DB": "steadholme"},
                "volumes": [
                    {
                        "type": "volume",
                        "source": "pgdata",
                        "target": "/var/lib/postgresql",
                        "read_only": False,
                    }
                ],
            },
            "strad": {"environment": {"STRAD_DATABASE_URL": strad_dsn}},
            "rikune-analyzer": {"environment": {}},
        }
        compose_pgdata = os.environ.get("FAKE_COMPOSE_PGDATA")
        if compose_pgdata is not None:
            services["postgres"]["environment"]["PGDATA"] = compose_pgdata
        if os.environ.get("FAKE_DUPLICATE_STRAD_DSN") == "1":
            services["unexpected-writer"] = {
                "environment": {"DATABASE_URL": strad_dsn}
            }
        if os.environ.get("FAKE_COMPOSE_SEMANTIC_DRIFT") == "1":
            services["semantically-drifted-but-unrelated"] = {"environment": {}}
        print(json.dumps({
            "name": "steadholme",
            "services": services,
            "volumes": {name: {} for name in [
                "pgdata",
                "strad_uploads", "rikune_workspaces", "rikune_storage",
                "rikune_state", "rikune_cache", "rikune_audit"
            ]},
        }))
        sys.exit(0)
    if "ps" in args:
        if os.environ.get("FAKE_NO_SERVICES") == "1":
            sys.exit(0)
        service = args[-1]
        existing = set(os.environ.get("FAKE_EXISTING_SERVICES", service).split())
        if service in existing and service not in names(removed_file):
            print("cid-" + service)
        sys.exit(0)
    if "stop" in args:
        index = args.index("stop")
        services = [item for item in args[index + 1:] if not item.startswith("-") and item != "120"]
        add_names(stopped_file, services)
        sys.exit(0)
    if "start" in args:
        index = args.index("start")
        services = [item for item in args[index + 1:] if not item.startswith("-")]
        remove_names(stopped_file, services)
        remove_names(removed_file, services)
        sys.exit(0)
    if "rm" in args:
        index = args.index("rm")
        services = [item for item in args[index + 1:] if not item.startswith("-")]
        add_names(removed_file, services)
        sys.exit(0)
    if "exec" in args:
        if "runtime-contract" in args:
            print(json.dumps({"newapi_context_tokens": 32768, "newapi_model": os.environ["FAKE_MODEL"]}))
        elif "pg_dump" in " ".join(args):
            sys.stdout.buffer.write(b"PGDUMP-CUSTOM\n")
        elif "psql" in " ".join(args):
            query = sys.stdin.read()
            if "pg_stat_activity" in query:
                print(os.environ.get("FAKE_STRAD_CONNECTIONS", "0"))
            elif "pg_database" in query:
                print(os.environ.get("FAKE_STRAD_DATABASE_COUNT", "1"))
            elif "pg_tables" in query:
                print(os.environ.get("FAKE_STRAD_PUBLIC_TABLES", "0"))
            elif "pg_class" in query:
                print(os.environ.get("FAKE_STRAD_USER_RELATIONS", "0"))
        sys.exit(0)
    sys.exit(0)
if args[:2] == ["image", "inspect"]:
    template = args[args.index("--format") + 1]
    if "Config.Env" in template:
        print(
            os.environ.get(
                "FAKE_POSTGRES_IMAGE_ENV",
                json.dumps(["PGDATA=/var/lib/postgresql/18/docker"]),
            )
        )
    else:
        print(os.environ.get("FAKE_POSTGRES_IMAGE_ID", "sha256:" + "f" * 64))
    sys.exit(0)
if args and args[0] == "inspect":
    template = args[args.index("-f") + 1]
    container = args[-1]
    service = (
        "postgres"
        if len(container) == 64 and all(character in "0123456789abcdef" for character in container)
        else container.removeprefix("cid-")
    )
    if "State.Status" in template:
        print(service_state(service))
    elif "State.StartedAt" in template:
        count = (
            int(postgres_ps_count_file.read_text(encoding="utf-8"))
            if postgres_ps_count_file.exists()
            else 0
        )
        change_at = int(os.environ.get("FAKE_POSTGRES_EPOCH_CHANGE_AT_PS", "-1"))
        changed = change_at >= 0 and count >= change_at
        print(
            os.environ.get(
                "FAKE_POSTGRES_CHANGED_STARTED_AT"
                if changed
                else "FAKE_POSTGRES_STARTED_AT",
                "2026-08-25T12:00:01.000000000Z"
                if changed
                else "2026-08-25T12:00:00.000000000Z",
            )
        )
    elif "RestartCount" in template:
        count = (
            int(postgres_ps_count_file.read_text(encoding="utf-8"))
            if postgres_ps_count_file.exists()
            else 0
        )
        change_at = int(os.environ.get("FAKE_POSTGRES_EPOCH_CHANGE_AT_PS", "-1"))
        changed = change_at >= 0 and count >= change_at
        print(
            os.environ.get(
                "FAKE_POSTGRES_CHANGED_RESTART_COUNT"
                if changed
                else "FAKE_POSTGRES_RESTART_COUNT",
                "1" if changed else "0",
            )
        )
    elif "com.docker.compose.config-hash" in template:
        print(os.environ.get("FAKE_POSTGRES_CONFIG_HASH", "c" * 64))
    elif "State.Health" in template:
        delayed = int(os.environ.get("FAKE_HEALTH_STARTING_INSPECTIONS", "0"))
        count = int(health_inspects_file.read_text()) if health_inspects_file.exists() else 0
        health_inspects_file.write_text(str(count + 1), encoding="utf-8")
        print("starting" if count < delayed else "healthy")
    elif "Config.Image" in template:
        print(
            images.get(
                service,
                os.environ.get(
                    "FAKE_POSTGRES_CONTAINER_REF",
                    "registry.invalid/postgres@sha256:" + "a" * 64,
                ),
            )
        )
    elif ".Image" in template:
        print(os.environ.get("FAKE_POSTGRES_CONTAINER_IMAGE_ID", "sha256:" + "f" * 64))
    elif "json .Config.Env" in template:
        print(
            os.environ.get(
                "FAKE_POSTGRES_CONTAINER_ENV",
                json.dumps(["PGDATA=/var/lib/postgresql/18/docker"]),
            )
        )
    elif "json .Mounts" in template:
        print(
            os.environ.get(
                "FAKE_POSTGRES_MOUNTS",
                json.dumps(
                    [
                        {
                            "Type": "volume",
                            "Name": "steadholme_pgdata",
                            "Source": "/fake/steadholme_pgdata/_data",
                            "Destination": "/var/lib/postgresql",
                            "RW": True,
                        }
                    ]
                ),
            )
        )
    sys.exit(0)
if args[:2] == ["volume", "inspect"]:
    sys.exit(0 if os.environ.get("FAKE_VOLUME_STUCK") == "1" else 1)
if args[:2] == ["volume", "create"]:
    print(args[-1])
    sys.exit(0)
if args[:2] == ["volume", "rm"]:
    sys.exit(0)
if args and args[0] == "ps" and "--filter" in args:
    filters = [args[index + 1] for index, value in enumerate(args[:-1]) if value == "--filter"]
    if "label=com.docker.compose.service=postgres" in filters:
        containers = os.environ.get(
            "FAKE_POSTGRES_CONTAINERS", default_postgres_container_id
        )
        count = int(postgres_ps_count_file.read_text()) if postgres_ps_count_file.exists() else 0
        postgres_ps_count_file.write_text(str(count + 1), encoding="utf-8")
        replace_after = int(os.environ.get("FAKE_POSTGRES_REPLACE_AFTER_PS", "-1"))
        if replace_after >= 0 and count >= replace_after:
            containers = os.environ.get(
                "FAKE_REPLACEMENT_POSTGRES_CONTAINERS",
                replacement_postgres_container_id,
            )
        for container in containers.split():
            print(container)
    else:
        holder = os.environ.get("FAKE_VOLUME_HOLDER")
        if holder:
            print(holder)
    sys.exit(0)
if args and args[0] == "run":
    if "-d" in args:
        print("probe-container")
    sys.exit(0)
if args and args[0] == "exec":
    if "psql" in " ".join(args):
        query = sys.stdin.read()
        if "pg_stat_activity" in query:
            print(os.environ.get("FAKE_STRAD_CONNECTIONS", "0"))
        elif "pg_database" in query:
            print(os.environ.get("FAKE_STRAD_DATABASE_COUNT", "1"))
        elif "pg_tables" in query:
            print(os.environ.get("FAKE_STRAD_PUBLIC_TABLES", "0"))
        elif "pg_class" in query:
            print(os.environ.get("FAKE_STRAD_USER_RELATIONS", "0"))
    sys.exit(0)
if args and args[0] in {"cp", "rm"}:
    sys.exit(0)
sys.exit(0)
'''


class RuntimeAndLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-runtime-test-")
        self.root = Path(self.temp.name)
        self.fake_docker = self.root / "docker-fake"
        self.fake_docker.write_text(FAKE_DOCKER, encoding="utf-8")
        self.fake_docker.chmod(0o755)
        self.docker_log = self.root / "docker.log"
        self.docker_state = self.root / "docker-state"
        self.lock = self.root / "holdfast.lock"
        self.compose_root = self.root / "compose"
        (self.compose_root / "deploy").mkdir(parents=True)
        (self.compose_root / "deploy/.env").write_text("SAFE=1\n", encoding="utf-8")
        (self.compose_root / "deploy/docker-compose.yml").write_text("name: steadholme\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def runtime_environment(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_DOCKER_BIN": str(self.fake_docker),
            "HOLDFAST_LOCK_PATH": str(self.lock),
            "FAKE_DOCKER_LOG": str(self.docker_log),
            "FAKE_DOCKER_STATE": str(self.docker_state),
            **extra,
        }

    def test_operator_entrypoints_are_executable(self) -> None:
        for name in (
            "apply-recover.sh",
            "apply.sh",
            "candidate-source.sh",
            "dry-run.sh",
            "open-ingress.sh",
            "public-origin-verify.sh",
            "rollback.sh",
            "runtime-backup.sh",
            "runtime-restore.sh",
            "runtime-verify.sh",
            "verify.sh",
        ):
            self.assertTrue((OPS_ROOT / name).stat().st_mode & 0o111, name)

    def test_apply_caller_reentry_restores_exact_runtime_subset_and_archives_state(
        self,
    ) -> None:
        apply_source = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        function_names = (
            "require_root_control_file",
            "commit_atomic_file",
            "runtime_product_was_running",
            "validate_runtime_stop_authority",
            "load_prior_running_services",
            "resume_prior_running_products",
            "validate_runtime_backup_caller_authority",
            "record_runtime_backup_cleanup",
            "archive_runtime_backup_state",
            "recover_runtime_backup_caller_arm",
        )
        functions = "\n".join(
            shell_function(apply_source, name) for name in function_names
        )
        backup_root = self.root / "apply-backups"
        backup_root.mkdir(mode=0o700)
        backup = backup_root / "holdfast-rikune-20260825T120000Z-1234"
        runtime = backup / "runtime"
        runtime.mkdir(parents=True, mode=0o700)
        state_dir = self.root / "apply-state"
        state_dir.mkdir(mode=0o700)
        dry_run = self.root / "dry-run"
        dry_run.mkdir(mode=0o700)
        estate = self.root / "estate"
        estate.mkdir(mode=0o700)

        config = runtime / "compose-config.json"
        config.write_text(
            json.dumps({"name": "steadholme", "services": {}}) + "\n",
            encoding="utf-8",
        )
        manifest = runtime / "RUNNING-SERVICES.before"
        manifest.write_text("strad\n", encoding="utf-8")
        arm = runtime / "RUNTIME-BACKUP-ARMED.receipt"
        arm.write_text(
            "schema_version=2\n"
            "armed_at=2026-08-25T12:00:00Z\n"
            f"backup_dir={runtime}\n"
            "compose_project=steadholme\n"
            f"compose_config_sha256={sha256(config)}\n"
            "database_identity=postgres:5432/strad\n"
            "prior_running_services_manifest=RUNNING-SERVICES.before\n"
            f"prior_running_services_sha256={sha256(manifest)}\n"
            "runtime_writer_count=3\n"
            "runtime_writers=strad,rikune-analyzer,rikune-volume-init\n"
            "stop_authority=armed-before-writer-stop\n"
            "volume_init_prior_state=exited\n",
            encoding="utf-8",
        )
        caller = backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
        bindings = {
            "release_env_sha256": "1" * 64,
            "release_evidence_sha256": "2" * 64,
            "dry_run_receipt_sha256": "3" * 64,
            "targets_sha256": "4" * 64,
            "apply_preimages_sha256": "5" * 64,
            "apply_absent_sha256": "6" * 64,
            "render_inputs_sha256": "7" * 64,
        }
        caller.write_text(
            "schema_version=2\n"
            "armed_at=2026-08-25T12:00:00Z\n"
            f"estate_root={estate}\n"
            f"dry_run_dir={dry_run}\n"
            f"backup_dir={backup}\n"
            f"runtime_backup_dir={runtime}\n"
            + "".join(f"{key}={value}\n" for key, value in bindings.items())
            + "runtime_backup_armed_receipt=runtime/RUNTIME-BACKUP-ARMED.receipt\n"
            "stop_authority_contract=absence-means-stop-not-started\n"
            "ingress_opened=false\n",
            encoding="utf-8",
        )
        state_file = state_dir / "CURRENT.json"
        state_file.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "state": "runtime_backup_armed",
                    "estate_root": str(estate),
                    "backup_dir": str(backup),
                    "dry_run_dir": str(dry_run),
                    "runtime_backup_dir": str(runtime),
                    "runtime_backup_caller_armed_receipt": caller.name,
                    "runtime_backup_caller_armed_receipt_sha256": sha256(caller),
                    "runtime_backup_armed_receipt": "runtime/RUNTIME-BACKUP-ARMED.receipt",
                    **bindings,
                    "stop_authority_contract": "absence-means-stop-not-started",
                    "ingress_opened": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        fake_path = self.root / "fake-path"
        fake_path.mkdir()
        (fake_path / "docker").symlink_to(self.fake_docker)
        stopped = self.docker_state.with_suffix(".stopped")
        stopped.write_text(
            "rikune-analyzer\nrikune-volume-init\nstrad\n", encoding="utf-8"
        )
        harness = self.root / "apply-caller-recover-harness.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            f'source "{OPS_ROOT / "common.sh"}"\n'
            + functions
            + "\n"
            + textwrap.dedent(
                f"""
                estate_root={estate!s}
                dry_run_dir={dry_run!s}
                backup_root={backup_root!s}
                backup={backup!s}
                state_dir={state_dir!s}
                state_file={state_file!s}
                caller_armed_receipt={caller!s}
                prior_running_manifest={manifest!s}
                recover_runtime_backup_caller_arm reentry
                """
            ),
            encoding="utf-8",
        )
        harness.chmod(0o755)
        result = subprocess.run(
            ["bash", str(harness)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **self.runtime_environment(
                    FAKE_EXISTING_SERVICES="strad rikune-analyzer rikune-volume-init",
                    FAKE_SERVICE_STATES=json.dumps(
                        {
                            "strad": "running",
                            "rikune-analyzer": "running",
                            "rikune-volume-init": "exited",
                        }
                    ),
                ),
                "PATH": f"{fake_path}:{os.environ['PATH']}",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(state_file.exists())
        self.assertEqual(len(list(state_dir.glob("RUNTIME-BACKUP-ABORTED-*.json"))), 1)
        cleanup = (backup / "RUNTIME-BACKUP-CALLER-CLEANUP.receipt").read_text()
        self.assertIn("runtime_stop_authority=present", cleanup)
        self.assertIn("prior_running_services_restored=passed", cleanup)
        stopped_services = set(stopped.read_text(encoding="utf-8").splitlines())
        self.assertNotIn("strad", stopped_services)
        self.assertIn("rikune-analyzer", stopped_services)
        self.assertIn("rikune-volume-init", stopped_services)

    def test_apply_open_and_rollback_share_one_nonblocking_lock(self) -> None:
        env = {
            **os.environ,
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_LOCK_PATH": str(self.lock),
            "HOLDFAST_DOCKER_BIN": str(self.fake_docker),
        }
        holder = subprocess.Popen(
            [
                "bash",
                "-ceu",
                f'source "{OPS_ROOT / "common.sh"}"; holdfast_acquire_lock; echo acquired; sleep 5',
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        try:
            self.assertEqual(holder.stdout.readline().strip(), "acquired")
            contender = subprocess.run(
                [
                    "bash",
                    "-ceu",
                    f'source "{OPS_ROOT / "common.sh"}"; holdfast_acquire_lock',
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
            self.assertNotEqual(contender.returncode, 0)
            self.assertIn("another Holdfast estate mutation", contender.stderr)
            for name in ("apply.sh", "apply-recover.sh", "open-ingress.sh", "rollback.sh"):
                self.assertIn("holdfast_acquire_lock", (OPS_ROOT / name).read_text(encoding="utf-8"))
            restore_contender = subprocess.run(
                [
                    "bash",
                    str(OPS_ROOT / "runtime-restore.sh"),
                    "--execute",
                    "--compose-root",
                    str(self.compose_root),
                    "--backup-dir",
                    str(self.root / "not-inspected-while-locked"),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
            self.assertNotEqual(restore_contender.returncode, 0)
            self.assertIn("another Holdfast estate mutation", restore_contender.stderr)
        finally:
            holder.terminate()
            holder.communicate(timeout=5)

    def test_runtime_verify_checks_digest_readiness_and_actual_model(self) -> None:
        images = {
            "access-governance": "registry.example/access@sha256:" + "1" * 64,
            "rikune-analyzer": "registry.example/analyzer@sha256:" + "2" * 64,
            "strad": "registry.example/strad@sha256:" + "3" * 64,
            "verdict": "registry.example/verdict@sha256:" + "4" * 64,
            "newapi": "registry.example/newapi@sha256:" + "5" * 64,
            "sluice": "registry.example/sluice@sha256:" + "6" * 64,
            "sluice-internal": "registry.example/sluice@sha256:" + "6" * 64,
        }
        release = self.root / "release.env"
        release.write_text(
            "\n".join(
                [
                    f"ACCESS_GOVERNANCE_IMAGE={images['access-governance']}",
                    f"STRAD_ANALYZER_IMAGE={images['rikune-analyzer']}",
                    f"STRAD_IMAGE={images['strad']}",
                    f"VERDICT_IMAGE={images['verdict']}",
                    f"NEWAPI_IMAGE={images['newapi']}",
                    f"SLUICE_IMAGE={images['sluice']}",
                    "STRAD_NEWAPI_MODEL=exact-release-alias",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        evidence = self.root / "RELEASE-EVIDENCE.json"
        evidence.write_text(
            json.dumps({"release_env_sha256": hashlib.sha256(release.read_bytes()).hexdigest()}),
            encoding="utf-8",
        )
        env = {
            **os.environ,
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_DOCKER_BIN": str(self.fake_docker),
            "FAKE_IMAGES": json.dumps(images),
            "FAKE_MODEL": "exact-release-alias",
        }
        override_without_test_gate = {key: value for key, value in env.items() if key != "HOLDFAST_TEST_MODE"}
        rejected_override = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-verify.sh"),
                "--estate-root",
                str(self.compose_root),
                "--release-env",
                str(release),
                "--release-evidence",
                str(evidence),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=override_without_test_gate,
        )
        self.assertNotEqual(rejected_override.returncode, 0)
        self.assertIn("test-only", rejected_override.stderr)
        result = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-verify.sh"),
                "--estate-root",
                str(self.compose_root),
                "--release-env",
                str(release),
                "--release-evidence",
                str(evidence),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        env["FAKE_MODEL"] = "wrong-alias"
        rejected = subprocess.run(result.args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("model contract differs", rejected.stderr)

    def test_runtime_backup_and_restore_cover_only_strad_db_and_six_volumes(self) -> None:
        backup = self.root / "runtime-backup"
        env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        self.assertEqual(len((backup / "VOLUMES.tsv").read_text().splitlines()), 6)
        backup_receipt = (backup / "BACKUP.receipt").read_text()
        self.assertIn("schema_version=2", backup_receipt)
        self.assertIn("postgres_database=strad", backup_receipt)
        self.assertIn("database_identity=postgres:5432/strad", backup_receipt)
        self.assertTrue((backup / "strad.dump").is_file())
        self.assertFalse((backup / "postgres.dump").exists())
        self.assertIn("runtime_writers_stopped=passed", backup_receipt)
        self.assertIn("writers_left_quiesced=passed", backup_receipt)
        self.assertIn("runtime_backup_armed_receipt=RUNTIME-BACKUP-ARMED.receipt", backup_receipt)
        runtime_arm = backup / "RUNTIME-BACKUP-ARMED.receipt"
        self.assertTrue(runtime_arm.is_file())
        self.assertIn(
            f"runtime_backup_armed_sha256={sha256(runtime_arm)}", backup_receipt
        )
        self.assertEqual((backup / "RUNNING-SERVICES.before").read_text(), "")
        self.assertIn("RUNNING-SERVICES.before", (backup / "SHA256SUMS").read_text())
        self.assertIn("isolated_restore_probe=passed", backup_receipt)
        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        restore_receipt = (backup / "RESTORE.receipt").read_text()
        self.assertIn("database_restore=restored", restore_receipt)
        self.assertIn("runtime_writers_removed=passed", restore_receipt)
        self.assertIn("postgres_container_attestation=passed", restore_receipt)
        self.assertIn("postgres_pgdata_mount=passed", restore_receipt)
        calls = self.docker_log.read_text(encoding="utf-8")
        self.assertIn('exec pg_dump -U \\"$POSTGRES_USER\\" -d strad -Fc', calls)
        self.assertIn('dropdb --if-exists --maintenance-db postgres -U \\"$POSTGRES_USER\\" strad;', calls)
        self.assertIn('exec pg_restore -U \\"$POSTGRES_USER\\" -d strad', calls)
        self.assertNotIn(
            'dropdb --if-exists --maintenance-db postgres -U \\"$POSTGRES_USER\\" \\"$POSTGRES_DB\\"',
            calls,
        )
        self.assertNotIn("-d steadholme", calls)
        self.assertIn('"rm", "-f", "-s", "strad", "rikune-analyzer", "rikune-volume-init"', calls)

        stuck_backup = self.root / "runtime-backup-stuck-test"
        made_again = subprocess.run(
            [
                "bash", str(OPS_ROOT / "runtime-backup.sh"), "--compose-root",
                str(self.compose_root), "--backup-dir", str(stuck_backup),
            ],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        self.assertEqual(made_again.returncode, 0, made_again.stdout + made_again.stderr)
        stuck_env = {**env, "FAKE_VOLUME_STUCK": "1"}
        stuck = subprocess.run(
            [
                "bash", str(OPS_ROOT / "runtime-restore.sh"), "--execute", "--compose-root",
                str(self.compose_root), "--backup-dir", str(stuck_backup),
            ],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=stuck_env,
        )
        self.assertNotEqual(stuck.returncode, 0)
        self.assertIn("could not be removed", stuck.stderr)

    def test_runtime_backup_rejects_wrong_or_duplicated_strad_database_authority(self) -> None:
        cases = (
            (
                "wrong-database",
                {"FAKE_STRAD_DSN": "postgresql://strad:secret@postgres:5432/steadholme"},
                "must resolve exactly to postgres:5432/strad",
            ),
            (
                "duplicate-authority",
                {"FAKE_DUPLICATE_STRAD_DSN": "1"},
                "database authority is not unique",
            ),
        )
        for name, extra, expected in cases:
            with self.subTest(name=name):
                backup = self.root / f"runtime-backup-{name}"
                result = subprocess.run(
                    [
                        "bash",
                        str(OPS_ROOT / "runtime-backup.sh"),
                        "--compose-root",
                        str(self.compose_root),
                        "--backup-dir",
                        str(backup),
                    ],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self.runtime_environment(FAKE_NO_SERVICES="1", **extra),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertFalse(backup.exists())

    def test_runtime_backup_rejects_an_unexpected_strad_database_connection(self) -> None:
        backup = self.root / "runtime-backup-connected"
        result = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.runtime_environment(
                FAKE_NO_SERVICES="1", FAKE_STRAD_CONNECTIONS="1"
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another client remains connected", result.stderr)
        self.assertFalse((backup / "BACKUP.receipt").exists())

    def test_runtime_backup_records_running_writers_and_requires_inactive_volume_init(self) -> None:
        active_init_backup = self.root / "runtime-backup-active-init"
        existing = "strad rikune-analyzer rikune-volume-init"
        rejected = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(active_init_backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.runtime_environment(FAKE_EXISTING_SERVICES=existing),
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("rikune-volume-init must finish", rejected.stderr)
        self.assertFalse((active_init_backup / "BACKUP.receipt").exists())

        backup = self.root / "runtime-backup-running-writers"
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.runtime_environment(
                FAKE_EXISTING_SERVICES=existing,
                FAKE_SERVICE_STATES=json.dumps({"rikune-volume-init": "exited"}),
            ),
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        manifest = backup / "RUNNING-SERVICES.before"
        self.assertEqual(manifest.read_text(), "strad\nrikune-analyzer\n")
        self.assertIn(
            f"prior_running_services_sha256={sha256(manifest)}",
            (backup / "BACKUP.receipt").read_text(),
        )
        stopped = self.docker_state.with_suffix(".stopped").read_text()
        self.assertEqual(
            set(stopped.splitlines()),
            {"strad", "rikune-analyzer", "rikune-volume-init"},
        )
        self.assertNotIn('"start"', self.docker_log.read_text())

    def test_runtime_backup_ordinary_failure_restores_only_prior_writers(self) -> None:
        backup = self.root / "runtime-backup-compensated"
        result = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.runtime_environment(
                FAKE_EXISTING_SERVICES="strad rikune-analyzer rikune-volume-init",
                FAKE_SERVICE_STATES=json.dumps({"rikune-volume-init": "exited"}),
                HOLDFAST_TEST_FAIL_AFTER_RUNTIME_STOP="1",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("injected failure after runtime writer stop", result.stderr)
        arm = backup / "RUNTIME-BACKUP-ARMED.receipt"
        self.assertTrue(arm.is_file())
        compensation = (backup / "RUNTIME-BACKUP-COMPENSATED.receipt").read_text()
        self.assertIn(f"runtime_backup_armed_sha256={sha256(arm)}", compensation)
        self.assertIn("prior_running_services_restored=passed", compensation)
        self.assertIn("excluded_runtime_services_inactive=passed", compensation)
        self.assertIn("volume_init_inactive=passed", compensation)
        stopped = self.docker_state.with_suffix(".stopped").read_text().splitlines()
        self.assertEqual(stopped, ["rikune-volume-init"])
        self.assertFalse((backup / "BACKUP.receipt").exists())

    def test_runtime_backup_compensation_waits_for_delayed_health(self) -> None:
        backup = self.root / "runtime-backup-delayed-health"
        result = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.runtime_environment(
                FAKE_EXISTING_SERVICES="strad rikune-volume-init",
                FAKE_SERVICE_STATES=json.dumps({"rikune-volume-init": "exited"}),
                FAKE_HEALTH_STARTING_INSPECTIONS="1",
                HOLDFAST_TEST_HEALTH_POLL_SECONDS="0",
                HOLDFAST_TEST_FAIL_AFTER_RUNTIME_STOP="1",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        compensation = (backup / "RUNTIME-BACKUP-COMPENSATED.receipt").read_text()
        self.assertIn("prior_running_services_restored=passed", compensation)
        self.assertGreaterEqual(
            int(self.docker_state.with_suffix(".health-inspects").read_text()), 2
        )
        self.assertFalse((backup / "RUNTIME-BACKUP-COMPENSATION-FAILED.receipt").exists())

    def test_runtime_backup_sigkill_leaves_durable_stop_authority(self) -> None:
        backup = self.root / "runtime-backup-sigkill"
        result = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.runtime_environment(
                FAKE_EXISTING_SERVICES="strad rikune-analyzer rikune-volume-init",
                FAKE_SERVICE_STATES=json.dumps({"rikune-volume-init": "exited"}),
                HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_STOP="1",
            ),
        )
        self.assertEqual(result.returncode, -9)
        arm = backup / "RUNTIME-BACKUP-ARMED.receipt"
        self.assertTrue(arm.is_file())
        self.assertIn(
            "stop_authority=armed-before-writer-stop", arm.read_text()
        )
        self.assertEqual(
            (backup / "RUNNING-SERVICES.before").read_text(),
            "strad\nrikune-analyzer\n",
        )
        self.assertFalse((backup / "RUNTIME-BACKUP-COMPENSATED.receipt").exists())
        self.assertFalse((backup / "BACKUP.receipt").exists())
        stopped = set(self.docker_state.with_suffix(".stopped").read_text().splitlines())
        self.assertEqual(stopped, {"strad", "rikune-analyzer", "rikune-volume-init"})

    def test_runtime_restore_rejects_a_retargeted_physical_volume_before_mutation(self) -> None:
        backup = self.root / "runtime-backup-retargeted-volume"
        env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        dispositions = (backup / "VOLUMES.tsv").read_text()
        dispositions = dispositions.replace(
            "steadholme_strad_uploads", "unrelated_protected_volume", 1
        )
        (backup / "VOLUMES.tsv").write_text(dispositions)
        checksum_names = [
            line.split("  ", 1)[1]
            for line in (backup / "SHA256SUMS").read_text().splitlines()
        ]
        (backup / "SHA256SUMS").write_text(
            "".join(f"{sha256(backup / name)}  {name}\n" for name in checksum_names)
        )
        self.docker_log.write_text("")

        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertNotEqual(restored.returncode, 0)
        self.assertIn("physical volume identity differs", restored.stderr)
        calls = self.docker_log.read_text()
        self.assertNotIn('"stop"', calls)
        self.assertNotIn('["volume", "rm"', calls)

    def test_runtime_restore_attests_postgres_container_before_mutation(self) -> None:
        backup = self.root / "runtime-backup-postgres-attestation"
        base_env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=base_env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)

        digest = "sha256:" + "b" * 64
        image_id = "sha256:" + "e" * 64
        correct_mount = {
            "Type": "volume",
            "Name": "steadholme_pgdata",
            "Source": "/fake/steadholme_pgdata/_data",
            "Destination": "/var/lib/postgresql",
            "RW": True,
        }
        cases = (
            ("zero-container", {"FAKE_POSTGRES_CONTAINERS": ""}, "exactly one"),
            (
                "multi-line-frozen-config-hash",
                {
                    "FAKE_FROZEN_POSTGRES_CONFIG_HASH": (
                        f"{'c' * 64}\npostgres {'c' * 64}"
                    )
                },
                "frozen PostgreSQL Compose config hash is invalid",
            ),
            (
                "unsafe-container-id",
                {"FAKE_POSTGRES_CONTAINERS": "cid-postgres"},
                "identity is unsafe",
            ),
            (
                "two-containers",
                {
                    "FAKE_POSTGRES_CONTAINERS": (
                        f"{POSTGRES_CONTAINER_ID} {REPLACEMENT_POSTGRES_CONTAINER_ID}"
                    )
                },
                "exactly one",
            ),
            (
                "not-running",
                {"FAKE_SERVICE_STATES": json.dumps({"postgres": "exited"})},
                "is not running",
            ),
            (
                "wrong-image-ref",
                {"FAKE_POSTGRES_CONTAINER_REF": f"registry.invalid/postgres@{digest}"},
                "image reference differs",
            ),
            (
                "wrong-image-id",
                {"FAKE_POSTGRES_CONTAINER_IMAGE_ID": image_id},
                "image ID differs",
            ),
            (
                "missing-config-hash",
                {"FAKE_POSTGRES_CONFIG_HASH": ""},
                "Compose config hash is missing or invalid",
            ),
            (
                "wrong-config-hash",
                {"FAKE_POSTGRES_CONFIG_HASH": "d" * 64},
                "Compose config hash differs from frozen authority",
            ),
            (
                "wrong-mount-source",
                {
                    "FAKE_POSTGRES_MOUNTS": json.dumps(
                        [{**correct_mount, "Name": "retargeted_pgdata"}]
                    )
                },
                "expected exactly one pgdata named-volume source",
            ),
            (
                "wrong-mount-target",
                {
                    "FAKE_POSTGRES_MOUNTS": json.dumps(
                        [{**correct_mount, "Destination": "/retargeted"}]
                    )
                },
                "source, target, type, or RW disposition differs",
            ),
            (
                "read-only-mount",
                {
                    "FAKE_POSTGRES_MOUNTS": json.dumps(
                        [{**correct_mount, "RW": False}]
                    )
                },
                "source, target, type, or RW disposition differs",
            ),
            (
                "image-pgdata-missing",
                {"FAKE_POSTGRES_IMAGE_ENV": "[]"},
                "immutable image environment lacks PGDATA",
            ),
            (
                "container-pgdata-missing",
                {"FAKE_POSTGRES_CONTAINER_ENV": "[]"},
                "container environment must contain exactly one PGDATA",
            ),
            (
                "pgdata-drift",
                {
                    "FAKE_POSTGRES_CONTAINER_ENV": json.dumps(
                        ["PGDATA=/retargeted/postgresql"]
                    )
                },
                "container PGDATA differs",
            ),
            (
                "pgdata-exact-shadow-mount",
                {
                    "FAKE_POSTGRES_MOUNTS": json.dumps(
                        [
                            correct_mount,
                            {
                                "Type": "volume",
                                "Name": "shadow_pgdata",
                                "Source": "/fake/shadow_pgdata/_data",
                                "Destination": "/var/lib/postgresql/18/docker",
                                "RW": True,
                            },
                        ]
                    )
                },
                "additional container mount overlaps PGDATA",
            ),
            (
                "pgdata-nested-shadow-mount",
                {
                    "FAKE_POSTGRES_MOUNTS": json.dumps(
                        [
                            correct_mount,
                            {
                                "Type": "volume",
                                "Name": "nested_pgdata",
                                "Source": "/fake/nested_pgdata/_data",
                                "Destination": "/var/lib/postgresql/18/docker/nested",
                                "RW": True,
                            },
                        ]
                    )
                },
                "additional container mount overlaps PGDATA",
            ),
        )
        command = [
            "bash",
            str(OPS_ROOT / "runtime-restore.sh"),
            "--execute",
            "--compose-root",
            str(self.compose_root),
            "--backup-dir",
            str(backup),
        ]
        for name, extra, message in cases:
            with self.subTest(name=name):
                self.docker_log.write_text("", encoding="utf-8")
                restored = subprocess.run(
                    command,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={**base_env, **extra},
                )
                self.assertNotEqual(
                    restored.returncode, 0, restored.stdout + restored.stderr
                )
                self.assertIn(message, restored.stderr)
                calls = self.docker_log.read_text(encoding="utf-8")
                self.assertNotIn('"stop"', calls)
                self.assertNotIn('["volume", "rm"', calls)
                self.assertNotIn('"dropdb', calls)

        self.docker_log.write_text("", encoding="utf-8")
        restored = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=base_env,
        )
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        calls = [
            json.loads(line)
            for line in self.docker_log.read_text(encoding="utf-8").splitlines()
        ]
        mount_attestations = [
            index
            for index, args in enumerate(calls)
            if args[:3] == ["inspect", "-f", "{{json .Mounts}}"]
        ]
        self.assertEqual(len(mount_attestations), 2)
        writer_stop = next(
            index
            for index, args in enumerate(calls)
            if args and args[0] == "compose" and "stop" in args
        )
        writer_remove = next(
            index
            for index, args in enumerate(calls)
            if args and args[0] == "compose" and "rm" in args
        )
        first_database_command = next(
            index
            for index, args in enumerate(calls)
            if args and args[0] == "exec"
        )
        first_volume_remove = next(
            index for index, args in enumerate(calls) if args[:2] == ["volume", "rm"]
        )
        self.assertLess(mount_attestations[0], writer_stop)
        self.assertLess(writer_remove, mount_attestations[1])
        self.assertLess(mount_attestations[1], first_database_command)
        self.assertLess(mount_attestations[1], first_volume_remove)
        direct_database_execs = [args for args in calls if args and args[0] == "exec"]
        self.assertTrue(direct_database_execs)
        self.assertTrue(
            all(args[2] == POSTGRES_CONTAINER_ID for args in direct_database_execs)
        )
        self.assertFalse(
            any(
                args and args[0] == "compose" and "exec" in args and "postgres" in args
                for args in calls
            )
        )
        postgres_enumerations = [
            args
            for args in calls
            if args
            and args[0] == "ps"
            and "label=com.docker.compose.service=postgres" in args
        ]
        self.assertTrue(postgres_enumerations)
        self.assertTrue(all("--no-trunc" in args for args in postgres_enumerations))

    def test_runtime_restore_accepts_explicit_pgdata_over_image_default(self) -> None:
        backup = self.root / "runtime-backup-explicit-pgdata"
        pgdata = "/var/lib/postgresql/compose-override"
        env = self.runtime_environment(
            FAKE_NO_SERVICES="1",
            FAKE_COMPOSE_PGDATA=pgdata,
            FAKE_POSTGRES_IMAGE_ENV="[]",
            FAKE_POSTGRES_CONTAINER_ENV=json.dumps([f"PGDATA={pgdata}"]),
        )
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)

        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)

    def test_runtime_restore_rejects_epoch_change_at_second_gate_before_data_mutation(
        self,
    ) -> None:
        backup = self.root / "runtime-backup-second-gate-epoch"
        base_env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=base_env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        self.docker_log.write_text("", encoding="utf-8")

        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**base_env, "FAKE_POSTGRES_EPOCH_CHANGE_AT_PS": "2"},
        )
        self.assertNotEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertIn("epoch changed between attestations", restored.stderr)
        calls = [
            json.loads(line)
            for line in self.docker_log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(any(args and args[0] == "exec" for args in calls))
        self.assertFalse(any(args[:2] == ["volume", "rm"] for args in calls))
        self.assertFalse((backup / "RESTORE.receipt").exists())

    def test_runtime_restore_rejects_epoch_change_after_destructive_exec_without_receipt(
        self,
    ) -> None:
        backup = self.root / "runtime-backup-post-exec-epoch"
        base_env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=base_env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        self.docker_log.write_text("", encoding="utf-8")

        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**base_env, "FAKE_POSTGRES_EPOCH_CHANGE_AT_PS": "6"},
        )
        self.assertNotEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertIn("attested PostgreSQL container epoch changed", restored.stderr)
        calls = [
            json.loads(line)
            for line in self.docker_log.read_text(encoding="utf-8").splitlines()
        ]
        destructive_execs = [
            args
            for args in calls
            if args and args[0] == "exec" and "pg_restore" in " ".join(args)
        ]
        self.assertEqual(len(destructive_execs), 1)
        self.assertEqual(destructive_execs[0][1:3], ["-i", POSTGRES_CONTAINER_ID])
        self.assertFalse((backup / "RESTORE.receipt").exists())
        self.assertEqual(list(backup.glob(".RESTORE.receipt.*")), [])

    def test_runtime_restore_rejects_final_resolve_drift_before_mutation(self) -> None:
        backup = self.root / "runtime-backup-final-resolve-drift"
        base_env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=base_env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        self.docker_log.write_text("", encoding="utf-8")

        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**base_env, "FAKE_COMPOSE_SEMANTIC_DRIFT": "1"},
        )
        self.assertNotEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertIn("resolved Compose differs from frozen authority", restored.stderr)
        calls = [
            json.loads(line)
            for line in self.docker_log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(any(args and args[0] == "exec" for args in calls))
        self.assertFalse(
            any(args and args[0] == "compose" and "stop" in args for args in calls)
        )
        self.assertFalse(any(args[:2] == ["volume", "rm"] for args in calls))

    def test_runtime_restore_never_follows_a_replaced_postgres_container(self) -> None:
        backup = self.root / "runtime-backup-postgres-replaced"
        base_env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=base_env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        self.docker_log.write_text("", encoding="utf-8")

        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**base_env, "FAKE_POSTGRES_REPLACE_AFTER_PS": "2"},
        )
        self.assertNotEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertIn("attested PostgreSQL container identity changed", restored.stderr)
        calls = [
            json.loads(line)
            for line in self.docker_log.read_text(encoding="utf-8").splitlines()
        ]
        direct_execs = [args for args in calls if args and args[0] == "exec"]
        self.assertFalse(direct_execs)
        self.assertFalse(any(args[:2] == ["volume", "rm"] for args in calls))

    def test_runtime_restore_adopts_the_callers_exact_lock_fd_without_deadlock(self) -> None:
        backup = self.root / "runtime-backup-inherited-lock"
        env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        command = (
            f'source "{OPS_ROOT / "common.sh"}"; '
            "holdfast_acquire_lock; "
            f'exec bash "{OPS_ROOT / "runtime-restore.sh"}" --execute '
            f'--compose-root "{self.compose_root}" --backup-dir "{backup}"'
        )
        restored = subprocess.run(
            ["bash", "-ceu", command],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)

    def test_legacy_empty_strad_is_explicit_and_never_mutates_a_database(self) -> None:
        backup = self.root / "runtime-backup-legacy-empty"
        env = self.runtime_environment(FAKE_NO_SERVICES="1")
        made = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-backup.sh"),
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        (backup / "RUNNING-SERVICES.before").unlink()
        (backup / "strad.dump").rename(backup / "postgres.dump")
        (backup / "BACKUP.receipt").write_text(
            "schema_version=1\npostgres_dump=pg_dump_custom\nvolume_count=6\n"
            "isolated_restore_probe=passed\n",
            encoding="utf-8",
        )
        checksum_names = ("postgres.dump", "VOLUMES.tsv", "compose-config.json")
        (backup / "SHA256SUMS").write_text(
            "".join(f"{sha256(backup / name)}  {name}\n" for name in checksum_names),
            encoding="utf-8",
        )

        refused = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("requires the explicit --legacy-empty-strad gate", refused.stderr)

        self.docker_log.write_text("", encoding="utf-8")
        restored = subprocess.run(
            [
                "bash",
                str(OPS_ROOT / "runtime-restore.sh"),
                "--execute",
                "--legacy-empty-strad",
                "--compose-root",
                str(self.compose_root),
                "--backup-dir",
                str(backup),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        receipt = (backup / "RESTORE.receipt").read_text(encoding="utf-8")
        self.assertIn("database_restore=skipped_proven_empty", receipt)
        self.assertIn("legacy_public_table_count=0", receipt)
        self.assertIn("legacy_user_relation_count=0", receipt)
        calls = self.docker_log.read_text(encoding="utf-8")
        self.assertNotIn("dropdb", calls)
        self.assertNotIn("pg_restore", calls)

    def test_staged_verify_reads_stage_while_live_reads_estate(self) -> None:
        estate = self.root / "estate"
        dry_run = self.root / "dry-run"
        stage = dry_run / "stage"
        for base in (estate, stage):
            (base / "access-governance/catalog").mkdir(parents=True)
            (base / "access-governance/scripts").mkdir(parents=True)
            (base / "deploy").mkdir(parents=True)
            (base / "deploy/.env").write_text("SAFE=1\n", encoding="utf-8")
            (base / "deploy/docker-compose.yml").write_text("name: test\n", encoding="utf-8")
        marker = stage / "marker.txt"
        marker.write_text("staged\n", encoding="utf-8")
        (estate / "marker.txt").write_text("live-drift\n", encoding="utf-8")
        (stage / "TARGETS.sha256").write_text(
            f"{hashlib.sha256(marker.read_bytes()).hexdigest()}  marker.txt\n", encoding="utf-8"
        )
        (stage / "RELEASE-EVIDENCE.json").write_text(
            json.dumps({"schema_version": 1, "catalog_only": True, "release": {}}),
            encoding="utf-8",
        )
        packages = {
            "requestable_package_count": 8,
            "packages": [
                {"package_id": f"filler-{index}"} for index in range(8)
            ]
            + [
                {
                    "package_id": "pkg_rikune_analyst",
                    "membership_digest": "16b3b01187d066ce7a2e3b4b8c13185cae93bc9b64ee680ccf7c62b501df4b6c",
                    "policy_digest": "6cb61051c0fdfea360a3fedc9b938a63581e4358d992bb418408eaeb024cdffa",
                }
            ],
        }
        permissions = {
            "entries": [{"key": f"rikune.permission.{index}"} for index in range(7)]
            + [{"key": "cistern.console.enter", "risk": "high"}],
            "generated_from": [
                {"source": "rikune-authz"},
                {"source": "cistern-authz"},
            ],
        }
        routes = {
            "routes": [
                {
                    "name": "cistern-dash",
                    "protected": False,
                    "auth": "sso",
                    "internal_only": False,
                    "require_group": "",
                    "require_permission": "",
                    "permission_resource": "",
                    "risk": "",
                    "require_scope": "",
                }
            ]
        }
        for base in (estate, stage):
            (base / "access-governance/catalog/packages.snapshot.json").write_text(json.dumps(packages))
            (base / "access-governance/catalog/permissions.snapshot.json").write_text(json.dumps(permissions))
            repository = base / "access-governance/src/repository/postgres.rs"
            repository.parent.mkdir(parents=True, exist_ok=True)
            repository.write_text(
                "        if snapshot.packages.len() != 9\n"
                "            || snapshot.requestable_package_count != 8\n",
                encoding="utf-8",
            )
            (base / "deploy/routes.seed.json").write_text(json.dumps(routes))
            generator = base / "access-governance/scripts/generate_permission_catalog.sh"
            generator.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
            generator.chmod(0o755)
            (base / "access-governance/scripts/validate_authz_manifests.py").write_text("pass\n")
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        (fake_bin / "docker").write_text(FAKE_DOCKER, encoding="utf-8")
        (fake_bin / "docker").chmod(0o755)
        (fake_bin / "cargo").write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
        (fake_bin / "cargo").chmod(0o755)
        env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
        command = [
            "bash",
            str(OPS_ROOT / "verify.sh"),
            "--estate-root",
            str(estate),
            "--dry-run-dir",
            str(dry_run),
        ]
        staged = subprocess.run(
            command + ["--phase", "staged"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        live = subprocess.run(
            command + ["--phase", "live"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.assertNotEqual(live.returncode, 0)
        self.assertIn("FAILED", live.stdout + live.stderr)


if __name__ == "__main__":
    unittest.main()
