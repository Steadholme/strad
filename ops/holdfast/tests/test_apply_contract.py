from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS_ROOT))

import render  # noqa: E402
import render_input_binding  # noqa: E402


class ApplyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-apply-contract-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_apply_binding_fixture(self) -> tuple[Path, Path, Path, Path]:
        ops = self.root / "fixture-ops"
        stage = self.root / "fixture-stage"
        ops.mkdir()
        stage.mkdir()
        for relative in render_input_binding.FROZEN_STATIC_PATHS:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"frozen fixture: {relative}\n", encoding="utf-8")
        extra_build_input = stage / "access-governance/fixture-extra.txt"
        extra_build_input.write_text("bound build input\n", encoding="utf-8")

        assets = ops / "assets"
        assets.mkdir()
        for relative in render_input_binding.ROUTE_ASSET_PATHS.values():
            target = ops / relative
            target.write_text(f"route fixture: {relative}\n", encoding="utf-8")

        static_lines = [
            f"{render_input_binding.digest(stage / relative)}  {relative}"
            for relative in render_input_binding.FROZEN_STATIC_PATHS
        ]
        (ops / "static-targets.sha256").write_text(
            "\n".join(static_lines) + "\n", encoding="utf-8"
        )
        semantic = {
            field: render_input_binding.digest(stage / relative)
            for field, relative in render_input_binding.STAGE_SEMANTIC_PATHS.items()
        }
        semantic["access_governance_build_input_sha256"] = (
            render_input_binding.access_build_input_sha(stage)
        )
        semantic.update(
            {
                field: render_input_binding.digest(ops / relative)
                for field, relative in render_input_binding.ROUTE_ASSET_PATHS.items()
            }
        )
        frozen = {
            "schema_version": 1,
            "generator": "holdfast-rikune-estate/test",
            **semantic,
        }
        (ops / "frozen-targets.json").write_text(
            json.dumps(frozen, sort_keys=True) + "\n", encoding="utf-8"
        )
        (ops / "preimages.sha256").write_text(
            f"{'0' * 64}  fixture.txt\n", encoding="utf-8"
        )
        (ops / "absent.paths").write_text("absent.txt\n", encoding="utf-8")
        evidence = stage / "RELEASE-EVIDENCE.json"
        evidence.write_text(
            json.dumps(
                {"schema_version": 1, "generator": frozen["generator"], **semantic}
            )
            + "\n",
            encoding="utf-8",
        )
        binding = self.root / "FIXTURE-RENDER-INPUTS.sha256"
        render_input_binding.write_binding(ops, binding)
        render_input_binding.verify_apply_binding(ops, binding, stage, evidence)
        return ops, stage, evidence, binding

    def test_checked_in_manifests_generate_exact_full_apply_coverage(self) -> None:
        stage = self.root / "stage"
        stage.mkdir()
        targets = list(render.MUTATED_PATHS) + list(render.FULL_ONLY_PATHS)

        render.write_apply_manifests(stage, targets)

        apply_preimages = render.parse_checksum_manifest(
            stage / "APPLY-PREIMAGES.sha256"
        )
        apply_absent = render.parse_path_manifest(stage / "APPLY-ABSENT.paths")
        global_preimages = render.parse_checksum_manifest(OPS_ROOT / "preimages.sha256")
        global_absent = render.parse_path_manifest(OPS_ROOT / "absent.paths")
        self.assertEqual(set(targets), set(apply_preimages) | apply_absent)
        self.assertFalse(set(apply_preimages) & apply_absent)
        self.assertEqual(len(apply_preimages), 12)
        self.assertEqual(len(apply_absent), 1)
        self.assertGreater(len(global_preimages), len(apply_preimages))
        self.assertEqual(
            apply_preimages,
            {path: global_preimages[path] for path in targets if path in global_preimages},
        )
        self.assertEqual(apply_absent, set(targets) & global_absent)

    def test_render_binding_uses_real_authority_inputs_and_rejects_tampering(self) -> None:
        binding = self.root / "RENDER-INPUTS.sha256"
        render_input_binding.write_binding(OPS_ROOT, binding)
        render_input_binding.verify_binding(OPS_ROOT, binding)
        self.assertEqual(
            tuple(render_input_binding.parse_manifest(binding)),
            render_input_binding.BOUND_INPUTS,
        )

        copied_ops = self.root / "copied-ops"
        copied_ops.mkdir()
        for name in render_input_binding.BOUND_INPUTS:
            shutil.copy2(OPS_ROOT / name, copied_ops / name)
        copied_binding = self.root / "COPIED-RENDER-INPUTS.sha256"
        render_input_binding.write_binding(copied_ops, copied_binding)
        for name in ("static-targets.sha256", "frozen-targets.json"):
            path = copied_ops / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(RuntimeError, name):
                    render_input_binding.verify_binding(copied_ops, copied_binding)
                path.write_bytes(original)

    def test_apply_binding_rejects_stage_static_target_tampering(self) -> None:
        ops, stage, evidence, binding = self.make_apply_binding_fixture()
        target = stage / "deploy/docker-compose.yml"
        target.write_bytes(target.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(RuntimeError, "stage static target drift"):
            render_input_binding.verify_apply_binding(ops, binding, stage, evidence)

    def test_apply_binding_rejects_release_evidence_tampering(self) -> None:
        ops, stage, evidence, binding = self.make_apply_binding_fixture()
        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["package_catalog_sha256"] = "f" * 64
        evidence.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "frozen semantic drift"):
            render_input_binding.verify_apply_binding(ops, binding, stage, evidence)

    def test_apply_binding_rejects_access_build_input_tampering(self) -> None:
        ops, stage, evidence, binding = self.make_apply_binding_fixture()
        target = stage / "access-governance/fixture-extra.txt"
        target.write_bytes(target.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(RuntimeError, "access_governance_build_input"):
            render_input_binding.verify_apply_binding(ops, binding, stage, evidence)

    def test_apply_binding_rejects_route_asset_tampering(self) -> None:
        ops, stage, evidence, binding = self.make_apply_binding_fixture()
        route = ops / render_input_binding.ROUTE_ASSET_PATHS["route_up_sha256"]
        route.write_bytes(route.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(RuntimeError, "route_up_sha256"):
            render_input_binding.verify_apply_binding(ops, binding, stage, evidence)

    def test_apply_preflights_before_backup_and_rebinds_after_backup(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        preflight = script.index('"$script_dir/estate_transaction.py" preflight')
        runtime_backup = script.index('"$script_dir/runtime-backup.sh"')
        apply = script.index('"$script_dir/estate_transaction.py" apply')
        first_rebind = script.index("\nverify_render_bindings\n")
        second_rebind = script.index("\nverify_render_bindings\n", first_rebind + 1)
        self.assertLess(first_rebind, preflight)
        self.assertLess(preflight, runtime_backup)
        self.assertLess(runtime_backup, second_rebind)
        self.assertLess(second_rebind, apply)
        self.assertIn("render_inputs_sha256", script)
        self.assertIn('--stage-root "$stage"', script)
        self.assertIn('--release-evidence "$stage/RELEASE-EVIDENCE.json"', script)


if __name__ == "__main__":
    unittest.main()
