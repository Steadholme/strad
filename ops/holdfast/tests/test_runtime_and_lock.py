from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
images = json.loads(os.environ.get("FAKE_IMAGES", "{}"))
if args and args[0] == "compose":
    if "config" in args and "--format" in args:
        digest = "sha256:" + "a" * 64
        print(json.dumps({
            "name": "steadholme",
            "services": {
                "rikune-volume-init": {"image": "registry.invalid/init@" + digest},
                "postgres": {"image": "registry.invalid/postgres@" + digest},
            },
            "volumes": {name: {} for name in [
                "strad_uploads", "rikune_workspaces", "rikune_storage",
                "rikune_state", "rikune_cache", "rikune_audit"
            ]},
        }))
        sys.exit(0)
    if "ps" in args:
        if os.environ.get("FAKE_NO_SERVICES") == "1":
            sys.exit(0)
        print("cid-" + args[-1])
        sys.exit(0)
    if "exec" in args:
        if "runtime-contract" in args:
            print(json.dumps({"newapi_context_tokens": 32768, "newapi_model": os.environ["FAKE_MODEL"]}))
        elif "pg_dump" in " ".join(args):
            sys.stdout.buffer.write(b"PGDUMP-CUSTOM\n")
        sys.exit(0)
    sys.exit(0)
if args and args[0] == "inspect":
    template = args[args.index("-f") + 1]
    service = args[-1].removeprefix("cid-")
    if "State.Status" in template:
        print("running")
    elif "Config.Image" in template:
        print(images[service])
    elif ".Image" in template:
        print("sha256:" + "f" * 64)
    sys.exit(0)
if args[:2] == ["volume", "inspect"]:
    sys.exit(0 if os.environ.get("FAKE_VOLUME_STUCK") == "1" else 1)
if args[:2] == ["volume", "create"]:
    print(args[-1])
    sys.exit(0)
if args[:2] == ["volume", "rm"]:
    sys.exit(0)
if args and args[0] == "run":
    if "-d" in args:
        print("probe-container")
    sys.exit(0)
if args and args[0] in {"exec", "cp", "rm"}:
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
        self.compose_root = self.root / "compose"
        (self.compose_root / "deploy").mkdir(parents=True)
        (self.compose_root / "deploy/.env").write_text("SAFE=1\n", encoding="utf-8")
        (self.compose_root / "deploy/docker-compose.yml").write_text("name: steadholme\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_operator_entrypoints_are_executable(self) -> None:
        for name in (
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

    def test_apply_open_and_rollback_share_one_nonblocking_lock(self) -> None:
        lock = self.root / "holdfast.lock"
        env = {
            **os.environ,
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_LOCK_PATH": str(lock),
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
            for name in ("apply.sh", "open-ingress.sh", "rollback.sh"):
                self.assertIn("holdfast_acquire_lock", (OPS_ROOT / name).read_text(encoding="utf-8"))
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

    def test_runtime_backup_and_restore_cover_pg_and_all_six_volume_dispositions(self) -> None:
        backup = self.root / "runtime-backup"
        env = {
            **os.environ,
            "HOLDFAST_TEST_MODE": "1",
            "HOLDFAST_DOCKER_BIN": str(self.fake_docker),
            "FAKE_NO_SERVICES": "1",
        }
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
        self.assertIn("isolated_restore_probe=passed", (backup / "BACKUP.receipt").read_text())
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
        self.assertIn("orphan_cleanup=passed", (backup / "RESTORE.receipt").read_text())

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
            "entries": [{"key": f"rikune.permission.{index}"} for index in range(7)],
            "generated_from": [{"source": "rikune-authz"}],
        }
        for base in (estate, stage):
            (base / "access-governance/catalog/packages.snapshot.json").write_text(json.dumps(packages))
            (base / "access-governance/catalog/permissions.snapshot.json").write_text(json.dumps(permissions))
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
