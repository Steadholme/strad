from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
TRANSACTION = OPS_ROOT / "estate_transaction.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EstateTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-estate-test-")
        self.root = Path(self.temp.name)
        self.estate = self.root / "estate"
        self.stage = self.root / "stage"
        for base in (self.estate, self.stage):
            (base / "deploy").mkdir(parents=True)
            (base / "access-governance/catalog").mkdir(parents=True)
        self.old = {
            "deploy/docker-compose.yml": b"old compose\n",
            "deploy/.env": b"OLD=1\n",
        }
        self.new = {
            "deploy/docker-compose.yml": b"new compose\n",
            "deploy/.env": b"NEW=1\n",
            "access-governance/catalog/rikune-authz-v1.json": b"{}\n",
        }
        for relative, content in self.old.items():
            target = self.estate / relative
            target.write_bytes(content)
            target.chmod(0o600 if relative.endswith(".env") else 0o644)
        for relative, content in self.new.items():
            target = self.stage / relative
            target.write_bytes(content)
            target.chmod(0o600 if relative.endswith(".env") else 0o644)
        self.targets = self.root / "TARGETS.sha256"
        self.preimages = self.root / "PREIMAGES.sha256"
        self.absent = self.root / "absent.paths"
        self.targets.write_text(
            "".join(f"{sha256(self.stage / path)}  {path}\n" for path in self.new),
            encoding="utf-8",
        )
        self.preimages.write_text(
            "".join(f"{sha256(self.estate / path)}  {path}\n" for path in self.old),
            encoding="utf-8",
        )
        self.absent.write_text(
            "access-governance/catalog/rikune-authz-v1.json\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def command(self, action: str, backup: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        args = ["python3", str(TRANSACTION), action, "--estate-root", str(self.estate)]
        if action in {"apply", "preflight"}:
            args += [
                "--stage-root",
                str(self.stage),
                "--targets",
                str(self.targets),
                "--preimages",
                str(self.preimages),
                "--absent",
                str(self.absent),
            ]
        if action in {"apply", "restore"}:
            args += ["--backup-dir", str(backup)]
        args += list(extra)
        return subprocess.run(
            args,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "HOLDFAST_TEST_MODE": "1"},
        )

    def assert_preimage(self) -> None:
        for relative, content in self.old.items():
            self.assertEqual((self.estate / relative).read_bytes(), content)
        self.assertFalse((self.estate / "access-governance/catalog/rikune-authz-v1.json").exists())

    def test_partial_apply_failure_automatically_restores_every_target(self) -> None:
        backup = self.root / "backup-fault"
        result = self.command("apply", backup, "--test-fault-after", "2")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("automatically rolled back", result.stderr)
        self.assert_preimage()
        state = json.loads((backup / "TRANSACTION.json").read_text(encoding="utf-8"))
        self.assertEqual(state["state"], "rolled_back_after_failure")

    def test_preflight_validates_every_input_without_creating_a_backup(self) -> None:
        backup = self.root / "backup-must-not-exist"
        result = self.command("preflight", backup)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(backup.exists())

    def test_preflight_rejects_non_exact_manifest_coverage(self) -> None:
        self.preimages.write_text(
            self.preimages.read_text(encoding="utf-8")
            + f"{'0' * 64}  deploy/unrelated.txt\n",
            encoding="utf-8",
        )
        result = self.command("preflight", self.root / "unused-backup")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not exactly cover", result.stderr)
        self.assert_preimage()

    def test_restore_accepts_mixed_old_new_and_absent_dispositions(self) -> None:
        backup = self.root / "backup-mixed"
        applied = self.command("apply", backup)
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        # Simulate a crash after some targets were manually/already restored.
        (self.estate / "deploy/docker-compose.yml").write_bytes(self.old["deploy/docker-compose.yml"])
        (self.estate / "access-governance/catalog/rikune-authz-v1.json").unlink()
        restored = self.command("restore", backup)
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assert_preimage()
        state = json.loads((backup / "TRANSACTION.json").read_text(encoding="utf-8"))
        self.assertEqual(state["state"], "restored")
        self.assertTrue(state["mixed_estate_supported"])

    def test_restore_rejects_third_party_drift(self) -> None:
        backup = self.root / "backup-drift"
        self.assertEqual(self.command("apply", backup).returncode, 0)
        (self.estate / "deploy/.env").write_text("THIRD_PARTY=1\n", encoding="utf-8")
        result = self.command("restore", backup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("third-party drift", result.stderr)

    def test_apply_rejects_symlinked_checksum_manifest(self) -> None:
        real_targets = self.root / "TARGETS.real.sha256"
        self.targets.rename(real_targets)
        self.targets.symlink_to(real_targets)
        result = self.command("apply", self.root / "backup-symlink")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe checksum manifest", result.stderr)
        self.assert_preimage()


if __name__ == "__main__":
    unittest.main()
