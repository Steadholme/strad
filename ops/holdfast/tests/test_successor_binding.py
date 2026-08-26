from __future__ import annotations

import json
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS_ROOT))

import render  # noqa: E402
import render_input_binding  # noqa: E402
import successor_binding  # noqa: E402


class SuccessorBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-successor-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_v2_build_identity_excludes_only_declared_runtime_debris(self) -> None:
        stage = self.root / "stage"
        access = stage / "access-governance"
        access.mkdir(parents=True)
        (access / "Cargo.toml").write_text("[package]\nname='fixture'\n")
        baseline = render_input_binding.access_build_input_sha_v2(stage)

        workflow = access / ".workflow/session"
        workflow.mkdir(parents=True)
        (workflow / "state.json").write_text("{}\n")
        (access / "ignored.log").write_text("runtime noise\n")
        self.assertEqual(
            render_input_binding.access_build_input_sha_v2(stage), baseline
        )

        (access / "src").mkdir()
        (access / "src/lib.rs").write_text("pub fn bound() {}\n")
        self.assertNotEqual(
            render_input_binding.access_build_input_sha_v2(stage), baseline
        )

    def test_exact_seven_file_delta_rejects_every_extra_change(self) -> None:
        predecessor = self.root / "predecessor"
        live = self.root / "live"
        predecessor.mkdir()
        live.mkdir()
        overlay = []
        for index in range(7):
            relative = f"src/overlay_{index}.rs"
            before = predecessor / relative
            after = live / relative
            after.parent.mkdir(parents=True, exist_ok=True)
            if index != 4:
                before.parent.mkdir(parents=True, exist_ok=True)
                before.write_text(f"before {index}\n")
            after.write_text(f"after {index}\n")
            overlay.append(
                {
                    "path": f"access-governance/{relative}",
                    "before_sha256": (
                        None if index == 4 else successor_binding.sha256(before)
                    ),
                    "after_sha256": successor_binding.sha256(after),
                }
            )
        shared_before = predecessor / "shared.txt"
        shared_after = live / "shared.txt"
        shared_before.write_text("same\n")
        shared_after.write_text("same\n")
        policy = {"overlay": overlay}

        successor_binding.validate_source_delta(policy, predecessor, live)
        shared_after.write_text("extra drift\n")
        with self.assertRaisesRegex(ValueError, "exact TASK-001 overlay"):
            successor_binding.validate_source_delta(policy, predecessor, live)

    def test_delta_manifest_is_exclusive_private_and_policy_exact(self) -> None:
        stage = self.root / "private-stage"
        stage.mkdir(mode=0o700)
        policy = successor_binding.validate_policy(
            OPS_ROOT / "successor-policy.json"
        )
        output = successor_binding.write_delta_manifest(stage, policy)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        expected = "".join(
            f"{item['before_sha256'] or '0' * 64}  {item['after_sha256']}  {item['path']}\n"
            for item in policy["overlay"]
        )
        self.assertEqual(output.read_text(encoding="utf-8"), expected)
        with self.assertRaisesRegex(ValueError, "already exists"):
            successor_binding.write_delta_manifest(stage, policy)

    def test_supporting_snapshot_is_exact_and_hash_bound(self) -> None:
        stage = self.root / "supporting-stage"
        verdict_file = stage / "verdict/src/lib.rs"
        relay_root = stage / "relay/upstream/new-api/router"
        verdict_file.parent.mkdir(parents=True)
        relay_root.mkdir(parents=True)
        verdict_file.write_text("pub fn frozen() {}\n")
        relay_files = [
            relay_root / "enterprise_permissions.json",
            relay_root / "newapi-authz-v1.json",
        ]
        for index, path in enumerate(relay_files):
            path.write_text(json.dumps({"fixture": index}) + "\n")
        expected = {
            path.relative_to(stage).as_posix(): successor_binding.sha256(path)
            for path in [verdict_file, *relay_files]
        }

        successor_binding.validate_supporting_snapshot(stage, expected)
        verdict_file.write_text("tampered\n")
        with self.assertRaisesRegex(ValueError, "supporting source differs"):
            successor_binding.validate_supporting_snapshot(stage, expected)
        verdict_file.write_text("pub fn frozen() {}\n")
        (stage / "verdict/unmanifested.rs").write_text("extra\n")
        with self.assertRaisesRegex(ValueError, "field set is not exact"):
            successor_binding.validate_supporting_snapshot(stage, expected)

    def test_private_env_snapshot_uses_one_safe_byte_sequence(self) -> None:
        source = self.root / "release.env"
        source.write_text("ACCESS_GOVERNANCE_IMAGE=frozen\n")
        source.chmod(0o600)
        values, observed = render.read_private_env_snapshot(source, "release")
        source.write_text("ACCESS_GOVERNANCE_IMAGE=changed\n")
        self.assertEqual(values, {"ACCESS_GOVERNANCE_IMAGE": "frozen"})
        self.assertNotEqual(observed, render.sha256_file(source))

        sibling = self.root / "linked.env"
        sibling.hardlink_to(source)
        with self.assertRaisesRegex(SystemExit, "single-link"):
            render.read_private_env_snapshot(source, "release")

    def make_successor_copy_fixture(
        self,
    ) -> tuple[
        Path,
        Path,
        Path,
        dict[str, object],
        dict[str, str],
        dict[str, str],
        dict[str, str],
    ]:
        authority = self.root / "authority"
        asset = authority / "assets/rikune-authz-v1.json"
        asset.parent.mkdir(parents=True)
        asset.write_text('{"schema_version":1,"permissions":["new"]}\n')

        predecessor = self.root / "predecessor"
        predecessor_access = predecessor / "access-governance"
        predecessor_access.mkdir(parents=True)
        estate = self.root / "estate"
        estate_access = estate / "access-governance"
        estate_access.mkdir(parents=True)
        static_relative = "access-governance/catalog/rikune-authz-v1.json"
        old_static = predecessor / static_relative
        old_static.parent.mkdir(parents=True)
        old_static.write_text('{"schema_version":1,"permissions":["old"]}\n')

        overlay: list[dict[str, object]] = []
        for index in range(7):
            relative = f"access-governance/src/overlay_{index}.rs"
            before = predecessor / relative
            after = estate / relative
            before.parent.mkdir(parents=True, exist_ok=True)
            after.parent.mkdir(parents=True, exist_ok=True)
            before.write_text(f"before {index}\n")
            after.write_text(f"after {index}\n")
            overlay.append(
                {
                    "path": relative,
                    "before_sha256": render.sha256_file(before),
                    "after_sha256": render.sha256_file(after),
                }
            )

        verdict = predecessor / "verdict/fixture.txt"
        verdict.parent.mkdir(parents=True)
        verdict.write_text("frozen verdict\n")
        relay_files = (
            predecessor
            / "relay/upstream/new-api/router/enterprise_permissions.json",
            predecessor / "relay/upstream/new-api/router/newapi-authz-v1.json",
        )
        for index, target in enumerate(relay_files):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f'{{"fixture":{index}}}\n')
        route = predecessor / "deploy/routes.seed.json"
        route.parent.mkdir(parents=True)
        route.write_text('{"routes":[]}\n')

        preimages = {relative: "a" * 64 for relative in render.FROZEN_STATIC_PATHS}
        static_targets = dict(preimages)
        preimages[static_relative] = render.sha256_file(old_static)
        static_targets[static_relative] = render.sha256_file(asset)
        route_relative = "deploy/routes.seed.json"
        preimages[route_relative] = render.sha256_file(route)
        static_targets[route_relative] = preimages[route_relative]
        for item in overlay:
            preimages[str(item["path"])] = str(item["after_sha256"])
        preimages["deploy/.env"] = "b" * 64

        expected = self.root / "expected"
        shutil.copytree(predecessor_access, expected / "access-governance")
        for item in overlay:
            relative = str(item["path"])
            shutil.copy2(estate / relative, expected / relative)
        shutil.copy2(asset, expected / static_relative)
        policy: dict[str, object] = {
            "overlay": overlay,
            "successor": {
                "access_build_input_sha256": (
                    render_input_binding.access_build_input_sha_v2(expected)
                )
            },
        }
        supporting_targets = {
            target.relative_to(predecessor).as_posix(): render.sha256_file(target)
            for target in (verdict, *relay_files)
        }
        return (
            authority,
            estate,
            predecessor,
            policy,
            preimages,
            static_targets,
            supporting_targets,
        )

    def test_successor_stage_promotes_bound_static_asset_to_final_identity(
        self,
    ) -> None:
        (
            authority,
            estate,
            predecessor,
            policy,
            preimages,
            static_targets,
            supporting_targets,
        ) = self.make_successor_copy_fixture()
        stage = self.root / "stage"
        render.copy_successor_stage(
            estate,
            predecessor,
            stage,
            True,
            policy,
            preimages,
            static_targets,
            authority,
        )
        render.validate_successor_snapshot(
            stage, policy, preimages, supporting_targets, True
        )
        static_relative = "access-governance/catalog/rikune-authz-v1.json"
        self.assertEqual(
            render.sha256_file(stage / static_relative),
            static_targets[static_relative],
        )

    def test_successor_static_asset_transition_rejects_every_drift(self) -> None:
        (
            authority,
            estate,
            predecessor,
            policy,
            preimages,
            static_targets,
            _,
        ) = self.make_successor_copy_fixture()
        asset = authority / "assets/rikune-authz-v1.json"
        asset.write_text("tampered target source\n")
        with self.assertRaisesRegex(ValueError, "static asset source differs"):
            render.copy_successor_stage(
                estate,
                predecessor,
                self.root / "source-drift-stage",
                True,
                policy,
                preimages,
                static_targets,
                authority,
            )

        asset.write_text('{"schema_version":1,"permissions":["new"]}\n')
        drifted_targets = dict(static_targets)
        static_relative = "access-governance/catalog/rikune-authz-v1.json"
        drifted_targets[static_relative] = "f" * 64
        with self.assertRaisesRegex(ValueError, "static asset source differs"):
            render.copy_successor_stage(
                estate,
                predecessor,
                self.root / "target-drift-stage",
                True,
                policy,
                preimages,
                drifted_targets,
                authority,
            )

        (predecessor / static_relative).write_text("tampered old snapshot\n")
        with self.assertRaisesRegex(SystemExit, "static asset preimage differs"):
            render.copy_successor_stage(
                estate,
                predecessor,
                self.root / "preimage-drift-stage",
                True,
                policy,
                preimages,
                static_targets,
                authority,
            )

    def make_apply_fixture(self) -> tuple[Path, Path, Path, Path, Path]:
        ops = self.root / "ops"
        stage = self.root / "apply-stage"
        source_estate = self.root / "source-estate"
        source_access = source_estate / "access-governance"
        ops.mkdir()
        stage.mkdir(mode=0o700)
        source_access.mkdir(parents=True)
        (source_access / "Cargo.toml").write_text("[package]\nname='source'\n")
        for relative in render_input_binding.FROZEN_STATIC_PATHS:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"successor static: {relative}\n")
        for index in range(7):
            target = stage / f"access-governance/tests/overlay_{index}.txt"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"successor overlay {index}\n")
        assets = ops / "assets"
        assets.mkdir()
        for relative in render_input_binding.ROUTE_ASSET_PATHS.values():
            target = ops / relative
            target.write_text(f"successor route: {relative}\n")

        static_lines = [
            f"{render_input_binding.digest(stage / relative)}  {relative}"
            for relative in render_input_binding.FROZEN_STATIC_PATHS
        ]
        (ops / "successor-static-targets.sha256").write_text(
            "\n".join(static_lines) + "\n"
        )
        semantic = {
            field: render_input_binding.digest(stage / relative)
            for field, relative in render_input_binding.STAGE_SEMANTIC_PATHS.items()
        }
        semantic["access_governance_build_input_sha256"] = (
            render_input_binding.access_build_input_sha_v2(stage)
        )
        semantic.update(
            {
                field: render_input_binding.digest(ops / relative)
                for field, relative in render_input_binding.ROUTE_ASSET_PATHS.items()
            }
        )
        predecessor = {
            "current_state_sha256": "1" * 64,
            "control_sha256": "2" * 64,
            "apply_receipt_sha256": "3" * 64,
            "release_evidence_sha256": "4" * 64,
            "runtime_manifest_sha256": "5" * 64,
            "candidate_evidence_sha256": "6" * 64,
            "candidate_targets_sha256": "7" * 64,
            "access_image": "registry.example/access@sha256:" + "8" * 64,
            "access_build_input_schema": "access-build-input/1",
            "access_build_input_sha256": "9" * 64,
            "permission_catalog_sha256": semantic[
                "permission_catalog_sha256"
            ],
            "package_catalog_sha256": semantic["package_catalog_sha256"],
        }
        overlay = []
        for index in range(7):
            relative = f"access-governance/tests/overlay_{index}.txt"
            overlay.append(
                {
                    "path": relative,
                    "before_sha256": None,
                    "after_sha256": render_input_binding.digest(stage / relative),
                }
            )
        policy = {
            "schema_version": 1,
            "ceremony": "holdfast-rikune-successor-v1",
            "predecessor": predecessor,
            "successor": {
                "generator": "holdfast-rikune-estate/test-successor",
                "access_build_input_schema": "access-build-input/2",
                "source_access_build_input_sha256": (
                    render_input_binding.access_tree_build_input_sha_v2(
                        source_access
                    )
                ),
                "access_build_input_sha256": semantic[
                    "access_governance_build_input_sha256"
                ],
                "preimages_manifest": "successor-preimages.sha256",
                "absent_manifest": "successor-absent.paths",
                "static_targets_manifest": "successor-static-targets.sha256",
                "supporting_targets_manifest": "successor-supporting-targets.sha256",
                "frozen_targets_manifest": "successor-frozen-targets.json",
            },
            "overlay": overlay,
        }
        (ops / "successor-policy.json").write_text(json.dumps(policy) + "\n")
        (ops / "successor-preimages.sha256").write_text(
            f"{'0' * 64}  fixture.txt\n"
        )
        (ops / "successor-absent.paths").write_text("")
        supporting_files = [
            stage / "verdict/fixture.txt",
            stage / "relay/upstream/new-api/router/enterprise_permissions.json",
            stage / "relay/upstream/new-api/router/newapi-authz-v1.json",
        ]
        for index, target in enumerate(supporting_files):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"supporting fixture {index}\n")
        (ops / "successor-supporting-targets.sha256").write_text(
            "".join(
                f"{render_input_binding.digest(target)}  "
                f"{target.relative_to(stage).as_posix()}\n"
                for target in supporting_files
            )
        )
        frozen = {
            "schema_version": 2,
            "generator": policy["successor"]["generator"],
            "release_epoch": 1,
            **semantic,
            "access_governance_build_input_schema": "access-build-input/2",
            "tokenizer": {
                "name": "fixture",
                "package": "fixture@1",
                "vocabulary_sha256": "c" * 64,
                "minimum_context_tokens": 1,
            },
            "required_unresolved_inputs": list(
                render_input_binding.SUCCESSOR_UNRESOLVED_INPUTS
            ),
        }
        (ops / "successor-frozen-targets.json").write_text(
            json.dumps(frozen) + "\n"
        )
        delta = stage / "SUCCESSOR-DELTA.sha256"
        delta.write_text(
            "".join(
                f"{'0' * 64}  {item['after_sha256']}  {item['path']}\n"
                for item in overlay
            )
        )
        revision = "a" * 40
        evidence_value = {
            "schema_version": 2,
            "generator": frozen["generator"],
            "catalog_only": False,
            **semantic,
            "secret_references": [],
            "release": {
                "HOLDFAST_RELEASE_TOOL_REVISION": revision,
                "ACCESS_GOVERNANCE_ROLLBACK_IMAGE": predecessor["access_image"],
            },
            "release_env_sha256": "b" * 64,
            "supply_chain_binding": {},
            "analyzer_image_binding": {},
            "release_mode": "successor",
            "access_governance_build_input_schema": "access-build-input/2",
            "holdfast_release_tool_revision": revision,
            "predecessor_binding": predecessor,
            "successor_delta_sha256": render_input_binding.digest(delta),
        }
        evidence = stage / "RELEASE-EVIDENCE.json"
        evidence.write_text(json.dumps(evidence_value) + "\n")
        binding = self.root / "SUCCESSOR-RENDER-INPUTS.sha256"
        render_input_binding.write_binding(ops, binding, successor=True)
        return ops, stage, evidence, binding, source_estate

    def test_apply_binding_requires_explicit_successor_and_rejects_downgrade(
        self,
    ) -> None:
        ops, stage, evidence, binding, source_estate = self.make_apply_fixture()
        render_input_binding.verify_apply_binding(
            ops,
            binding,
            stage,
            evidence,
            "successor",
            source_estate_root=source_estate,
        )
        (source_estate / "access-governance/Cargo.toml").write_text(
            "[package]\nname='drifted-source'\n"
        )
        with self.assertRaisesRegex(
            RuntimeError, "live successor Access source build input differs"
        ):
            render_input_binding.verify_apply_binding(
                ops,
                binding,
                stage,
                evidence,
                "successor",
                source_estate_root=source_estate,
            )
        with self.assertRaisesRegex(RuntimeError, "field set|mode"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "base"
            )

        delta = stage / "SUCCESSOR-DELTA.sha256"
        delta.write_text(delta.read_text() + "tampered\n")
        with self.assertRaisesRegex(RuntimeError, "delta"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

    def test_successor_policy_requires_a_separate_source_build_identity(self) -> None:
        policy = json.loads((OPS_ROOT / "successor-policy.json").read_text())
        source = policy["successor"]["source_access_build_input_sha256"]
        final = policy["successor"]["access_build_input_sha256"]
        self.assertRegex(source, r"^[0-9a-f]{64}$")
        self.assertRegex(final, r"^[0-9a-f]{64}$")
        self.assertNotEqual(source, final)
        preimages = successor_binding.parse_checksum_manifest(
            OPS_ROOT / policy["successor"]["preimages_manifest"]
        )
        static_targets = successor_binding.parse_checksum_manifest(
            OPS_ROOT / policy["successor"]["static_targets_manifest"]
        )
        self.assertEqual(
            successor_binding.validate_static_asset_transition(
                preimages, static_targets, OPS_ROOT
            ),
            dict(successor_binding.SUCCESSOR_STATIC_ASSET_SOURCES),
        )

        del policy["successor"]["source_access_build_input_sha256"]
        invalid = self.root / "missing-source-build-input.json"
        invalid.write_text(json.dumps(policy) + "\n")
        with self.assertRaisesRegex(ValueError, "successor policy"):
            successor_binding.validate_policy(invalid)

if __name__ == "__main__":
    unittest.main()
