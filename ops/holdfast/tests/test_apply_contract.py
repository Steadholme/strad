from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS_ROOT))

import render  # noqa: E402
import render_input_binding  # noqa: E402


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    body_start = start + len(f"{name}() {{")
    following = re.search(r"(?m)^[a-z_][a-z0-9_]*\(\) \{", source[body_start:])
    if following is None:
        return source[start:]
    return source[start : body_start + following.start()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
            "release_epoch": 1,
            **semantic,
            "tokenizer": {},
            "required_unresolved_inputs": [],
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
                {
                    "schema_version": 1,
                    "generator": frozen["generator"],
                    "catalog_only": False,
                    **semantic,
                    "secret_references": [],
                    "release": {},
                    "release_env_sha256": "0" * 64,
                    "supply_chain_binding": {},
                    "analyzer_image_binding": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        binding = self.root / "FIXTURE-RENDER-INPUTS.sha256"
        render_input_binding.write_binding(ops, binding)
        render_input_binding.verify_apply_binding(
            ops, binding, stage, evidence, "base"
        )
        return ops, stage, evidence, binding

    def make_successor_catalog_binding_fixture(
        self,
    ) -> tuple[Path, Path, Path, Path]:
        ops = self.root / "successor-catalog-ops"
        stage = self.root / "successor-catalog-stage"
        ops.mkdir()
        stage.mkdir()
        for relative in render_input_binding.CATALOG_STATIC_PATHS:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"successor catalog: {relative}\n", encoding="utf-8")
        overlay = []
        for index in range(7):
            relative = f"access-governance/tests/successor_{index}.rs"
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"successor overlay {index}\n", encoding="utf-8")
            overlay.append(
                {
                    "path": relative,
                    "before_sha256": None,
                    "after_sha256": render_input_binding.digest(target),
                }
            )
        supporting_paths = (
            "verdict/src/lib.rs",
            "relay/upstream/new-api/router/enterprise_permissions.json",
            "relay/upstream/new-api/router/newapi-authz-v1.json",
        )
        for relative in supporting_paths:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"successor supporting: {relative}\n", encoding="utf-8")

        assets = ops / "assets"
        assets.mkdir()
        for relative in render_input_binding.ROUTE_ASSET_PATHS.values():
            target = ops / relative
            target.write_text(f"successor route: {relative}\n", encoding="utf-8")
        static_lines = []
        for relative in render_input_binding.FROZEN_STATIC_PATHS:
            target = stage / relative
            target_sha = (
                render_input_binding.digest(target)
                if target.is_file()
                else "0" * 64
            )
            static_lines.append(f"{target_sha}  {relative}")
        (ops / "successor-static-targets.sha256").write_text(
            "\n".join(static_lines) + "\n", encoding="utf-8"
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
            "permission_catalog_sha256": semantic["permission_catalog_sha256"],
            "package_catalog_sha256": semantic["package_catalog_sha256"],
        }
        policy = {
            "schema_version": 1,
            "ceremony": "holdfast-rikune-successor-v1",
            "predecessor": predecessor,
            "successor": {
                "generator": "holdfast-rikune-estate/test-successor-catalog",
                "access_build_input_schema": "access-build-input/2",
                "source_access_build_input_sha256": "d" * 64,
                "access_build_input_sha256": semantic[
                    "access_governance_build_input_sha256"
                ],
                "preimages_manifest": "successor-preimages.sha256",
                "absent_manifest": "successor-absent.paths",
                "static_targets_manifest": "successor-static-targets.sha256",
                "frozen_targets_manifest": "successor-frozen-targets.json",
                "supporting_targets_manifest": "successor-supporting-targets.sha256",
            },
            "overlay": overlay,
        }
        (ops / "successor-policy.json").write_text(
            json.dumps(policy) + "\n", encoding="utf-8"
        )
        (ops / "successor-preimages.sha256").write_text(
            f"{'0' * 64}  fixture.txt\n", encoding="utf-8"
        )
        (ops / "successor-absent.paths").write_text("", encoding="utf-8")
        (ops / "successor-supporting-targets.sha256").write_text(
            "".join(
                f"{render_input_binding.digest(stage / relative)}  {relative}\n"
                for relative in supporting_paths
            ),
            encoding="utf-8",
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
                "vocabulary_sha256": "a" * 64,
                "minimum_context_tokens": 1,
            },
            "required_unresolved_inputs": list(
                render_input_binding.SUCCESSOR_UNRESOLVED_INPUTS
            ),
        }
        (ops / "successor-frozen-targets.json").write_text(
            json.dumps(frozen) + "\n", encoding="utf-8"
        )
        delta = stage / "SUCCESSOR-DELTA.sha256"
        delta.write_text(
            "".join(
                f"{'0' * 64}  {item['after_sha256']}  {item['path']}\n"
                for item in overlay
            ),
            encoding="utf-8",
        )
        revision = "b" * 40
        evidence = stage / "RELEASE-EVIDENCE.json"
        evidence.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "generator": frozen["generator"],
                    "catalog_only": True,
                    **semantic,
                    "secret_references": [],
                    "release": {},
                    "release_mode": "successor",
                    "access_governance_build_input_schema": "access-build-input/2",
                    "holdfast_release_tool_revision": revision,
                    "predecessor_binding": predecessor,
                    "successor_delta_sha256": render_input_binding.digest(delta),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        binding = self.root / "SUCCESSOR-CATALOG-RENDER-INPUTS.sha256"
        render_input_binding.write_binding(ops, binding, successor=True)
        return ops, stage, evidence, binding

    def test_access_candidate_build_requires_successor_catalog_semantics(self) -> None:
        ops, stage, evidence, binding = self.make_successor_catalog_binding_fixture()
        render_input_binding.verify_apply_binding(
            ops, binding, stage, evidence, "successor-catalog"
        )
        with self.assertRaisesRegex(RuntimeError, "field set|catalog mode"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

        permission_path = stage / render_input_binding.STAGE_SEMANTIC_PATHS[
            "permission_catalog_sha256"
        ]
        permission_path.write_text("catalog semantic drift\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "static target drift|semantic digest"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor-catalog"
            )

        script = (OPS_ROOT / "build-access-candidate.sh").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            script.index("--expected-mode successor-catalog"),
            script.index("docker buildx build"),
        )
        self.assertIn('--stage-root "$candidate_root"', script)
        self.assertIn('--release-evidence "$evidence"', script)
        self.assertIn('builder identity must be a stable HTTPS URI', script)
        self.assertIn('--provenance="mode=max,builder-id=$builder_id"', script)
        self.assertIn("observed_builder_id=$(", script)
        self.assertIn(".Provenance.SLSA.runDetails.builder.id", script)
        self.assertIn('[[ "$observed_builder_id" == "$builder_id" ]]', script)
        self.assertIn("printf 'provenance_builder_id=%s\\n'", script)
        self.assertIn('"$observed_builder_id"', script)
        snapshot_create = script.index("build_snapshot=$(mktemp -d")
        snapshot_copy = script.index('cp -a -- "$candidate_root/."')
        ignored_debris_guard = script.index("ignored_entry=$(find")
        snapshot_freeze = script.index(
            'find "$snapshot_candidate" -type f -exec chmod 0400'
        )
        recovery_refreeze = script.index(
            'RECOVERY-COMPLETION-ATTESTATION.json', snapshot_freeze
        )
        gen5_recovery_refreeze = script.index(
            ".predecessor_binding.recovery_completion", recovery_refreeze
        )
        root_refreeze = script.index(
            'chmod 0700 -- "$snapshot_candidate"', gen5_recovery_refreeze
        )
        semantic_verify = script.index("--expected-mode successor-catalog")
        docker_build = script.index("docker buildx build")
        self.assertLess(snapshot_create, snapshot_copy)
        self.assertLess(snapshot_copy, ignored_debris_guard)
        self.assertLess(ignored_debris_guard, snapshot_freeze)
        self.assertLess(snapshot_freeze, recovery_refreeze)
        self.assertLess(recovery_refreeze, gen5_recovery_refreeze)
        self.assertLess(gen5_recovery_refreeze, root_refreeze)
        self.assertLess(root_refreeze, semantic_verify)
        self.assertLess(semantic_verify, docker_build)
        self.assertIn("trap cleanup_snapshot EXIT", script)
        self.assertIn('rm -rf --one-file-system -- "$build_snapshot"', script)
        self.assertIn('require_control_file "$evidence"', script)
        self.assertIn('require_control_file "$targets"', script)
        self.assertIn('require_control_file "$render_inputs"', script)
        self.assertIn("[.archive,.receipt,.armed_receipt,.failure_receipt][]", script)
        self.assertIn('"${#recovery_completion_files[@]}" -eq 4', script)
        self.assertIn("snapshotted Gen5 recovery completion authority", script)
        for ignored_name in (
            ".git",
            ".workflow",
            "target",
            "__pycache__",
            "*.pyc",
            "*.log",
        ):
            self.assertIn(ignored_name, script)
        self.assertEqual(
            render_input_binding.SUCCESSOR_BOUND_INPUTS[-2:],
            (
                "successor-supporting-targets.sha256",
                "successor-policy.json",
            ),
        )

    def test_schema_v5_access_candidate_uses_bounded_overlay_and_current_build_tool(
        self,
    ) -> None:
        policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(policy["schema_version"], 5)
        self.assertTrue(policy["overlay"])
        self.assertLessEqual(len(policy["overlay"]), 64)
        self.assertNotEqual(
            policy["successor"]["source_access_build_input_sha256"],
            policy["predecessor"]["access_build_input_sha256"],
        )
        self.assertNotEqual(
            policy["successor"]["access_build_input_sha256"],
            policy["predecessor"]["access_build_input_sha256"],
        )
        self.assertNotIn("access_candidate_tool_revision", policy["predecessor"])

        script = (OPS_ROOT / "build-access-candidate.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("docker buildx build", script)
        self.assertIn("--push", script)
        self.assertIn("schema=holdfast-access-candidate-build/1", script)
        self.assertIn("holdfast_release_tool_revision=%s", script)
        self.assertNotIn("holdfast-access-candidate-carry-forward", script)

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
        self.assertEqual(len(apply_preimages), 13)
        self.assertEqual(len(apply_absent), 2)
        self.assertGreater(len(global_preimages), len(apply_preimages))
        self.assertEqual(
            apply_preimages,
            {path: global_preimages[path] for path in targets if path in global_preimages},
        )
        self.assertEqual(apply_absent, set(targets) & global_absent)

    def test_full_env_renderer_sets_access_bootstrap_version_7(self) -> None:
        stage = self.root / "full-env-stage"
        deploy = stage / "deploy"
        deploy.mkdir(parents=True)
        (deploy / ".env").write_text(
            "GATEWAY_HMAC_KEY=" + "g" * 32 + "\n"
            "GATEWAY_ZONE_HMAC_KEY=" + "z" * 32 + "\n"
            "VERDICT_DECISION_TOKEN=" + "v" * 32 + "\n",
            encoding="utf-8",
        )
        example = deploy / "access-governance.env.example"
        example.write_text(
            "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION=1\n", encoding="utf-8"
        )
        release = {
            key: f"fixture-{key.lower()}"
            for key in (
                "ACCESS_GOVERNANCE_IMAGE",
                "ACCESS_GOVERNANCE_ROLLBACK_IMAGE",
                "RIKUNE_ANALYZER_IMAGE",
                "STRAD_ANALYZER_IMAGE",
                "STRAD_IMAGE",
                "STRAD_VOLUME_INIT_IMAGE",
                "VERDICT_IMAGE",
                "NEWAPI_IMAGE",
                "SLUICE_IMAGE",
                "STRAD_NEWAPI_MODEL",
            )
        }
        secrets = {
            key: chr(ord("a") + index) * 32
            for index, key in enumerate(render.SECRET_KEYS)
        }

        render.render_full_env(stage, release, secrets)

        self.assertEqual(
            render.parse_env(deploy / ".env")[
                "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION"
            ],
            "7",
        )
        self.assertEqual(
            example.read_text(encoding="utf-8"),
            "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION=7\n",
        )
        self.assertEqual(
            render.parse_checksum_manifest(OPS_ROOT / "static-targets.sha256")[
                "deploy/access-governance.env.example"
            ],
            "582a5244edabaafb82fc6214a8f6cf50abc32d232697e5acedb973aa28bb0c6c",
        )

    def test_compose_renderer_sets_access_bootstrap_version_7(self) -> None:
        stage = self.root / "compose-stage"
        deploy = stage / "deploy"
        deploy.mkdir(parents=True)
        compose = deploy / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  sluice:\n"
            "    image: steadholme/sluice:share-room-assets-20260821\n"
            "    environment:\n"
            "      GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY}\n"
            "      GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY}\n"
            "  sluice-internal:\n"
            "    image: steadholme/sluice:share-room-assets-20260821\n"
            "    environment:\n"
            "      GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY}\n"
            "      GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY}\n"
            "  newapi:\n"
            "    image: steadholme/newapi@sha256:"
            "b864dc5a347c91ee60b5bab045fefc60f116bda75eb4c695d0c1305ef4981a7f\n"
            "    environment:\n"
            "      RELAY_SERVICE_KEYS: grimoire=${GRIMOIRE_RELAY_KEY},"
            "familiar=${FAMILIAR_RELAY_KEY},warden=${WARDEN_RELAY_KEY},"
            "canvas=${CANVAS_RELAY_KEY}\n"
            "  verdict:\n"
            "    image: steadholme/verdict:web-assets-20260821\n"
            "    networks:\n"
            "      - hf-cpa-mgmt\n"
            "  access-governance:\n"
            "    build:\n"
            "      context: ../access-governance\n"
            "    image: steadholme/access-governance:uiux-20260823-r2\n"
            "    environment:\n"
            "      GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY}\n"
            "      GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY}\n"
            "      ACCESS_GOVERNANCE_BOOTSTRAP_VERSION: "
            "${ACCESS_GOVERNANCE_BOOTSTRAP_VERSION:-5}\n"
            "  ark:\n"
            "    image: fixture\n"
            "networks:\n"
            "  # Access capability snapshots are shared only with managed downstream PEPs.\n"
            "  hf-iga:\n"
            "    driver: bridge\n"
            "    internal: true\n"
            "volumes:\n"
            "  pgdata:\n",
            encoding="utf-8",
        )

        render.render_compose(stage)

        rendered = compose.read_text(encoding="utf-8")
        self.assertIn(
            "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION: "
            "${ACCESS_GOVERNANCE_BOOTSTRAP_VERSION:-7}",
            rendered,
        )
        self.assertNotIn("ACCESS_GOVERNANCE_BOOTSTRAP_VERSION:-5", rendered)
        self.assertEqual(
            render.parse_checksum_manifest(OPS_ROOT / "static-targets.sha256")[
                "deploy/docker-compose.yml"
            ],
            "f95398a0f7a383e51797c67595e0097f0905b9f187fb9ed5fce3423da1f0eec0",
        )

    def test_repository_package_shape_is_part_of_the_frozen_render_contract(self) -> None:
        relative = "access-governance/src/repository/postgres.rs"
        self.assertIn(relative, render.MUTATED_PATHS)
        self.assertIn(relative, render_input_binding.FROZEN_STATIC_PATHS)
        self.assertEqual(
            render.parse_checksum_manifest(OPS_ROOT / "preimages.sha256")[relative],
            "b8f81a049777b38f2ba5911559d9123dec213e6a311e1000c8d4d40e962cb907",
        )
        self.assertEqual(
            render.parse_checksum_manifest(OPS_ROOT / "static-targets.sha256")[relative],
            "25a776e2b1ac871891861e1b4745b700199254b8d6e1b49f7e80f47737969c77",
        )

        stage = self.root / "repository-render-stage"
        target = stage / relative
        target.parent.mkdir(parents=True)
        target.write_text(
            "before\n"
            "        if snapshot.packages.len() != 8\n"
            "            || snapshot.requestable_package_count != 7\n",
            encoding="utf-8",
        )
        render.render_repository_package_shape(stage)
        self.assertEqual(
            target.read_text(encoding="utf-8"),
            "before\n"
            "        if snapshot.packages.len() != 9\n"
            "            || snapshot.requestable_package_count != 8\n",
        )

    def test_cistern_permission_is_retained_as_an_independent_catalog_source(self) -> None:
        asset_path = OPS_ROOT / "assets/cistern-authz-v1.json"
        manifest = json.loads(asset_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["manifest_id"], "cistern-authz-v1")
        self.assertEqual(manifest["service"], "cistern")
        self.assertEqual(manifest["entries"], [])
        self.assertEqual(manifest["functions"], [])
        self.assertEqual(
            manifest["permissions"],
            [
                {
                    "key": "cistern.console.enter",
                    "risk": "high",
                    "principal_class": "human",
                    "owner_sub": "user:u_admin",
                    "approval": {"minimum_approvals": 2},
                    "recertification": {"interval_days": 180},
                }
            ],
        )
        relative = "access-governance/catalog/cistern-authz-v1.json"
        self.assertIn(relative, render.MUTATED_PATHS)
        self.assertIn(relative, render_input_binding.FROZEN_STATIC_PATHS)
        self.assertIn(relative, render.parse_path_manifest(OPS_ROOT / "absent.paths"))
        self.assertEqual(
            render.parse_checksum_manifest(OPS_ROOT / "static-targets.sha256")[relative],
            render.sha256_file(asset_path),
        )

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
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "base"
            )

    def test_apply_binding_rejects_release_evidence_tampering(self) -> None:
        ops, stage, evidence, binding = self.make_apply_binding_fixture()
        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["package_catalog_sha256"] = "f" * 64
        evidence.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "frozen semantic drift"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "base"
            )

    def test_apply_binding_rejects_access_build_input_tampering(self) -> None:
        ops, stage, evidence, binding = self.make_apply_binding_fixture()
        target = stage / "access-governance/fixture-extra.txt"
        target.write_bytes(target.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(RuntimeError, "access_governance_build_input"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "base"
            )

    def test_apply_binding_rejects_route_asset_tampering(self) -> None:
        ops, stage, evidence, binding = self.make_apply_binding_fixture()
        route = ops / render_input_binding.ROUTE_ASSET_PATHS["route_up_sha256"]
        route.write_bytes(route.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(RuntimeError, "route_up_sha256"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "base"
            )

    def test_successor_route_copy_is_release_bound_before_control(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        helper = script[
            script.index("validate_successor_route_authority() {") : script.index(
                "archive_and_restore_predecessor_current() {"
            )
        ]
        self.assertIn("route_up_sha256 route_down_sha256", helper)
        self.assertIn(".[$field]", helper)
        self.assertIn(
            '[[ "$observed" == "$expected" ]]',
            helper,
        )

        persist = script[
            script.index("persist_successor_generation_authority() {") : script.index(
                "persist_successor_authority() {"
            )
        ]
        pre_copy = persist.index(
            'validate_successor_route_authority "$stage/RELEASE-EVIDENCE.json" "$script_dir"'
        )
        copy = persist.index(
            '"$script_dir/assets/$relative" "$authority_dir/assets/$relative"'
        )
        post_copy = persist.index(
            'validate_successor_route_authority "$stage/RELEASE-EVIDENCE.json" "$authority_dir"'
        )
        self.assertLess(pre_copy, copy)
        self.assertLess(copy, post_copy)

        persisted_evidence = script.index(
            'atomic_copy_authority "$stage/RELEASE-EVIDENCE.json" "$backup/RELEASE-EVIDENCE.json"'
        )
        persisted_route_check = script.index(
            'validate_successor_route_authority "$backup/RELEASE-EVIDENCE.json"',
            persisted_evidence,
        )
        control = script.index('control_file="$backup/CONTROL.sha256"')
        self.assertLess(persisted_evidence, persisted_route_check)
        self.assertLess(persisted_route_check, control)

    def test_successor_route_drift_after_precheck_is_rejected_after_copy(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        fixture_repo = self.root / "repo"
        script_dir = fixture_repo / "ops/holdfast"
        assets = script_dir / "assets"
        stage = self.root / "stage"
        backup = self.root / "backup"
        fake_bin = self.root / "bin"
        for directory in (assets, stage, backup, fake_bin, fixture_repo / "bridge"):
            directory.mkdir(parents=True, exist_ok=True)

        route_names = (
            "20260823_rikune_root_up.sql",
            "20260823_rikune_root_down.sql",
        )
        for route_name in route_names:
            (assets / route_name).write_text(
                f"-- release-bound {route_name}\n", encoding="utf-8"
            )
        (stage / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(
                {
                    "route_up_sha256": sha256(assets / route_names[0]),
                    "route_down_sha256": sha256(assets / route_names[1]),
                }
            )
            + "\n",
            encoding="utf-8",
        )

        generation_names = tuple(f"generation-{index}.json" for index in range(6))
        for name in generation_names:
            (script_dir / name).write_text(f"{name}\n", encoding="utf-8")
        render_inputs = stage / "RENDER-INPUTS.sha256"
        render_inputs.write_text(
            "".join(f"{sha256(script_dir / name)}  {name}\n" for name in generation_names),
            encoding="utf-8",
        )
        (fixture_repo / "Dockerfile.analyzer").write_text(
            "FROM scratch\n", encoding="utf-8"
        )
        (fixture_repo / "bridge/package-lock.json").write_text(
            "{}\n", encoding="utf-8"
        )

        drift_marker = self.root / "route-drifted"
        fake_install = fake_bin / "install"
        fake_install.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'source_path=${@: -2:1}\n'
            'if [[ "$source_path" == */20260823_rikune_root_down.sql && '
            '! -e "$HOLDFAST_TEST_ROUTE_DRIFT_MARKER" ]]; then\n'
            '  printf "\\n-- deterministic test-only drift\\n" >>"$source_path"\n'
            '  touch "$HOLDFAST_TEST_ROUTE_DRIFT_MARKER"\n'
            "fi\n"
            'exec /usr/bin/install "$@"\n',
            encoding="utf-8",
        )
        fake_install.chmod(0o755)

        functions = "\n".join(
            shell_function(script, name)
            for name in (
                "require_root_control_file",
                "commit_atomic_file",
                "atomic_copy_authority",
                "validate_successor_route_authority",
                "persist_successor_generation_authority",
            )
        )
        harness = self.root / "route-copy-harness.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            f'source "{OPS_ROOT / "common.sh"}"\n'
            f"{functions}\n"
            "successor_generation_authorities=()\n"
            "successor=true\n"
            f'script_dir="{script_dir}"\n'
            f'stage="{stage}"\n'
            f'backup="{backup}"\n'
            f'render_inputs="{render_inputs}"\n'
            "persist_successor_generation_authority\n",
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
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "HOLDFAST_TEST_ROUTE_DRIFT_MARKER": str(drift_marker),
            },
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(drift_marker.exists())
        self.assertIn(
            "successor route authority differs from release evidence: route_down_sha256",
            result.stderr,
        )
        self.assertFalse(
            (backup / "successor-authority/Dockerfile.analyzer").exists()
        )

    def test_apply_preflights_before_backup_and_fully_rebinds_after_backup(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        first_rebind = script.index("\nverify_release_bindings\n")
        first_preflight = script.index('"$script_dir/estate_transaction.py" preflight')
        runtime_backup = script.index('"$script_dir/runtime-backup.sh"')
        second_rebind = script.index("\nverify_release_bindings\n", runtime_backup)
        persisted_targets = script.index(
            'atomic_copy_authority "$targets" "$backup/TARGETS.sha256"',
            second_rebind,
        )
        second_preflight = script.index(
            '"$script_dir/estate_transaction.py" preflight', first_preflight + 1
        )
        apply = script.index('"$script_dir/estate_transaction.py" apply')
        self.assertLess(first_rebind, first_preflight)
        self.assertLess(first_preflight, runtime_backup)
        self.assertLess(runtime_backup, second_rebind)
        self.assertLess(second_rebind, persisted_targets)
        self.assertLess(persisted_targets, second_preflight)
        self.assertLess(second_preflight, apply)

        full_rebind = script[
            script.index("verify_release_bindings() {") : script.index(
                "commit_atomic_file() {"
            )
        ]
        for binding in (
            "bound_dry_receipt_sha",
            "targets_sha256",
            "release_evidence_sha256",
            "release_env_sha256",
            "supply_chain_${key}_sha256",
            "verify_render_bindings",
            'sha256sum --check TARGETS.sha256',
        ):
            self.assertIn(binding, full_rebind)
        render_rebind = script[
            script.index("verify_render_bindings() {") : script.index(
                "bound_dry_receipt_sha="
            )
        ]
        self.assertIn('--stage-root "$stage"', render_rebind)
        self.assertIn(
            '--release-evidence "$stage/RELEASE-EVIDENCE.json"', render_rebind
        )
        persisted_receipt = script.index(
            'atomic_copy_authority "$receipt" "$backup/DRY-RUN.receipt"'
        )
        pinned_receipt = script.index(
            '[[ "$(holdfast_sha256 "$backup/DRY-RUN.receipt")" == "$bound_dry_receipt_sha" ]]',
            persisted_receipt,
        )
        self.assertLess(persisted_receipt, pinned_receipt)

    def test_successor_apply_rechecks_full_live_source_at_every_mutation_boundary(
        self,
    ) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        render_rebind = script[
            script.index("verify_render_bindings() {") : script.index(
                "bound_dry_receipt_sha="
            )
        ]
        self.assertIn('"${source_estate_args[@]}"', render_rebind)
        self.assertIn(
            'source_estate_args=(--source-estate-root "$estate_root")', script
        )

        persisted = script[
            script.index("verify_persisted_render_bindings() {") : script.index(
                '(cd "$stage" && sha256sum --check "$backup/TARGETS.sha256")'
            )
        ]
        self.assertIn('--ops-root "$persisted_render_ops_root"', persisted)
        self.assertIn('"${source_estate_args[@]}"', persisted)
        self.assertIn(
            'persisted_render_ops_root="$backup/successor-authority"', script
        )
        self.assertEqual(script.count("\nverify_persisted_render_bindings\n"), 2)

        final_preflight = script.rindex(
            'python3 "$script_dir/estate_transaction.py" preflight'
        )
        quiesced = script.index("verify_products_quiesced", final_preflight)
        final_source_rebind = script.index(
            "\nverify_persisted_render_bindings\n", quiesced
        )
        apply = script.index(
            'python3 "$script_dir/estate_transaction.py" apply',
            final_source_rebind,
        )
        self.assertLess(final_preflight, quiesced)
        self.assertLess(quiesced, final_source_rebind)
        self.assertLess(final_source_rebind, apply)

    def test_post_backup_render_binding_uses_canonical_staged_evidence(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        persisted_start = script.index(
            '# Validate the immutable copies and their byte-identical canonical staged'
        )
        armed_start = script.index(
            '# Persist the exact recovery intent before estate_transaction.py',
            persisted_start,
        )
        persisted = script[persisted_start:armed_start]
        equality = persisted.index(
            'persisted release evidence differs from the canonical staged control file'
        )
        render_start = persisted.index(
            'python3 "$script_dir/render_input_binding.py" verify'
        )
        render_end = persisted.index('(cd "$stage"', render_start)
        render_call = persisted[render_start:render_end]

        self.assertLess(equality, render_start)
        self.assertIn('--manifest "$backup/RENDER-INPUTS.sha256"', render_call)
        self.assertIn('--stage-root "$stage"', render_call)
        self.assertIn(
            '--release-evidence "$stage/RELEASE-EVIDENCE.json"', render_call
        )
        self.assertNotIn(
            '--release-evidence "$backup/RELEASE-EVIDENCE.json"', render_call
        )

    def test_apply_uses_safe_control_directories_and_frozen_digests(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        directory_helper = script[
            script.index("require_canonical_root_directory() {") : script.index(
                "release_control_files=("
            )
        ]
        for guard in (
            '! -L "$directory"',
            'readlink -f -- "$directory"',
            "control directory must be root-owned",
            'readlink -m -- "$directory"',
            'mkdir -m 0700 -- "$directory"',
            'sync -f "$parent"',
        ):
            self.assertIn(guard, directory_helper)
        first_current_check = script.index(
            'if [[ -e "$state_file" || -L "$state_file" ]]'
        )
        first_rebind = script.index("\nverify_release_bindings\n", first_current_check)
        self.assertLess(first_current_check, first_rebind)
        self.assertLess(
            first_current_check,
            script.index('ROUTES_DATABASE_URL is required to prove closed ingress'),
        )
        self.assertLess(
            script.index('require_canonical_root_directory "$state_dir"'),
            first_current_check,
        )
        self.assertLess(
            first_rebind,
            script.index('ensure_private_control_directory "$state_dir"'),
        )

        control_pin = script.index(
            '[[ "$(holdfast_sha256 "$control_file")" == "$control_sha" ]]'
        )
        final_bracket = script.index("\nverify_closed_bracket\n", control_pin)
        self.assertLess(control_pin, final_bracket)
        finalization = script[final_bracket:]
        self.assertNotIn(
            'control_sha "$(holdfast_sha256 "$backup/CONTROL.sha256")"',
            finalization,
        )
        self.assertGreaterEqual(finalization.count('--arg control_sha "$control_sha"'), 2)
        self.assertIn("printf 'control_sha256=%s\\n' \"$control_sha\"", finalization)

    def test_apply_persists_control_authority_before_any_estate_mutation(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        copied_targets = script.index(
            'atomic_copy_authority "$targets" "$backup/TARGETS.sha256"'
        )
        armed_commit = script.index(
            'commit_atomic_file "$armed_tmp" "$armed_receipt"', copied_targets
        )
        control_start = script.index('control_file="$backup/CONTROL.sha256"')
        control_commit = script.index(
            'commit_atomic_file "$control_tmp" "$control_file"', control_start
        )
        armed_state = script.index('state:"apply_armed"', control_commit)
        estate_apply = script.index('"$script_dir/estate_transaction.py" apply')
        self.assertLess(copied_targets, armed_commit)
        self.assertLess(armed_commit, control_start)
        self.assertLess(control_start, control_commit)
        self.assertLess(control_commit, armed_state)
        self.assertLess(armed_state, estate_apply)

        armed = script[script.index('armed_receipt="$backup/APPLY-ARMED.receipt"') : control_start]
        self.assertIn(
            'targets_sha256=%s\\n\' "$(holdfast_sha256 "$backup/TARGETS.sha256")"',
            armed,
        )
        control = script[control_start:armed_state]
        for authority in (
            "RELEASE-EVIDENCE.json",
            "release.env",
            "DRY-RUN.receipt",
            "SUPPLY-CHAIN.json",
            "SUPPLY-CHAIN.sig",
            "SUPPLY-CHAIN.pub",
            "TARGETS.sha256",
            "APPLY-PREIMAGES.sha256",
            "APPLY-ABSENT.paths",
            "RENDER-INPUTS.sha256",
            "rollback.override.yml",
            "APPLY-ARMED.receipt",
            "runtime/SHA256SUMS",
            "runtime/BACKUP.receipt",
        ):
            self.assertIn(authority, control)
        self.assertNotIn("estate/APPLIED-TARGETS.sha256", control)
        transaction = script[estate_apply : script.index("estate_status=$?", estate_apply)]
        self.assertIn('--targets "$backup/TARGETS.sha256"', transaction)
        self.assertIn('--preimages "$backup/APPLY-PREIMAGES.sha256"', transaction)
        self.assertIn('--absent "$backup/APPLY-ABSENT.paths"', transaction)

    def test_apply_receipts_use_atomic_rename_and_sync(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        atomic = script[
            script.index("commit_atomic_file() {") : script.index(
                "atomic_copy_authority() {"
            )
        ]
        chmod = atomic.index('chmod 0600 -- "$temporary"')
        sync_temporary = atomic.index('sync -f "$temporary"')
        rename = atomic.index('mv -fT -- "$temporary" "$target"')
        sync_target = atomic.index('sync -f "$target"')
        sync_parent = atomic.index('sync -f "$parent"')
        self.assertLess(chmod, sync_temporary)
        self.assertLess(sync_temporary, rename)
        self.assertLess(rename, sync_target)
        self.assertLess(sync_target, sync_parent)

        for call in (
            'commit_atomic_file "$armed_tmp" "$armed_receipt"',
            'commit_atomic_file "$control_tmp" "$control_file"',
            'commit_atomic_file "$failure_tmp" "$failure_receipt"',
            'commit_atomic_file "$apply_receipt_tmp" "$pending_apply_receipt"',
            'commit_atomic_file "$pending_apply_receipt" "$apply_receipt"',
            'commit_atomic_file "$state_tmp" "$state_dir/CURRENT.json"',
        ):
            self.assertIn(call, script)
        self.assertNotIn('} >"$apply_receipt"', script)

    def test_apply_protects_every_current_candidate_before_validation(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        candidates = list(
            re.finditer(r'>"\$(?P<variable>successor_state_tmp|state_tmp)"', script)
        )
        self.assertEqual(len(candidates), 8)

        for candidate in candidates:
            variable = candidate.group("variable")
            commit = script.index(
                f'commit_atomic_file "${variable}"', candidate.end()
            )
            pending = script[candidate.end() : commit]
            references = [
                line.strip()
                for line in pending.splitlines()
                if f'"${variable}"' in line
            ]
            self.assertTrue(references)
            self.assertEqual(
                references[0],
                f'chmod 0600 -- "${variable}"',
            )
            protection = pending.index(f'chmod 0600 -- "${variable}"')
            for validation in re.finditer(
                rf'validate_[^\n]*"\${variable}"', pending
            ):
                self.assertLess(protection, validation.start())

    def test_successor_current_candidate_is_private_at_real_validator_seam(
        self,
    ) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        harness = self.root / "persist-successor-current.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + shell_function(script, "commit_atomic_file")
            + "\n"
            + shell_function(script, "persist_successor_authority")
            + "\n"
            + "holdfast_die() { printf '%s\\n' \"$1\" >&2; return 1; }\n"
            + "holdfast_sha256() { sha256sum -- \"$1\" | cut -d' ' -f1; }\n"
            + "atomic_copy_authority() {\n"
            + "  [[ ! -e \"$2\" && ! -L \"$2\" ]] || holdfast_die \"authority target exists\"\n"
            + "  cp -- \"$1\" \"$2\"\n"
            + "  chmod 0600 -- \"$2\"\n"
            + "}\n"
            + "validate_persisted_recovery_completion_authority() { :; }\n"
            + "validate_persisted_successor_authority() {\n"
            + "  local pointer=$1 expected=$2 observed\n"
            + "  observed=$(stat -c '%a' -- \"$pointer\")\n"
            + "  printf '%s:%s\\n' \"$expected\" \"$observed\" >>\"$validation_log\"\n"
            + "  [[ \"$observed\" == 600 ]] || return 91\n"
            + "  if [[ \"$mode\" == reject && ! -e \"$root/validation-rejected\" ]]; then\n"
            + "    : >\"$root/validation-rejected\"\n"
            + "    return 92\n"
            + "  fi\n"
            + "}\n"
            + "root=$1\n"
            + "mode=$2\n"
            + "state_dir=\"$root/state\"\n"
            + "state_file=\"$state_dir/CURRENT.json\"\n"
            + "backup=\"$root/backup\"\n"
            + "stage=\"$root/stage\"\n"
            + "release_env=\"$root/release.env\"\n"
            + "receipt=\"$stage/DRY-RUN.receipt\"\n"
            + "validation_log=\"$root/validation.log\"\n"
            + "estate_root=/estate\n"
            + "dry_run_dir=/dry-run\n"
            + "successor=true\n"
            + "successor_policy_schema=2\n"
            + "predecessor_current_sha=$(holdfast_sha256 \"$state_file\")\n"
            + "predecessor_backup=/predecessor\n"
            + "predecessor_control_sha=$(printf control | sha256sum | cut -d' ' -f1)\n"
            + "predecessor_apply_sha=$(printf apply | sha256sum | cut -d' ' -f1)\n"
            + "predecessor_completion_kind=\n"
            + "predecessor_completion_attestation_sha=\n"
            + "predecessor_completion_signature_sha=\n"
            + "predecessor_completion_public_key_sha=\n"
            + "predecessor_recovery_completion_json='{}'\n"
            + "predecessor_release_sha=$(printf release | sha256sum | cut -d' ' -f1)\n"
            + "predecessor_runtime_receipt_sha=$(printf runtime-receipt | sha256sum | cut -d' ' -f1)\n"
            + "predecessor_runtime_manifest_sha=$(printf runtime-manifest | sha256sum | cut -d' ' -f1)\n"
            + "predecessor_generation=3\n"
            + "release_generation=4\n"
            + "HOLDFAST_TEST_MODE=0\n"
            + "umask 0022\n"
            + ": >\"$root/caller-umask-probe\"\n"
            + "[[ $(stat -c '%a' -- \"$root/caller-umask-probe\") == 644 ]]\n"
            + "rm -- \"$root/caller-umask-probe\"\n"
            + "persist_successor_authority\n",
            encoding="utf-8",
        )
        harness.chmod(0o755)

        for mode in ("accept", "reject"):
            with self.subTest(mode=mode):
                root = self.root / mode
                state_dir = root / "state"
                backup = root / "backup"
                stage = root / "stage"
                state_dir.mkdir(parents=True)
                backup.mkdir()
                stage.mkdir()
                state = state_dir / "CURRENT.json"
                original = b'{"state":"applied_ingress_closed","release_generation":3}\n'
                state.write_bytes(original)
                state.chmod(0o600)
                original_inode = state.stat().st_ino
                (root / "release.env").write_text("SAFE=1\n", encoding="utf-8")
                (stage / "RELEASE-EVIDENCE.json").write_text("{}\n", encoding="utf-8")
                (stage / "DRY-RUN.receipt").write_text(
                    "schema_version=2\n", encoding="utf-8"
                )

                result = subprocess.run(
                    ["bash", str(harness), str(root), mode],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                validations = (root / "validation.log").read_text(
                    encoding="utf-8"
                ).splitlines()
                if mode == "accept":
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(
                        validations,
                        ["successor_armed:600", "successor_armed:600"],
                    )
                    self.assertNotEqual(state.stat().st_ino, original_inode)
                    self.assertEqual(state.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(
                        json.loads(state.read_text(encoding="utf-8"))["state"],
                        "successor_armed",
                    )
                    self.assertEqual(list(state_dir.glob(".CURRENT.json.*")), [])
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(validations, ["successor_armed:600"])
                    self.assertEqual(state.stat().st_ino, original_inode)
                    self.assertEqual(state.read_bytes(), original)
                    candidates = list(state_dir.glob(".CURRENT.json.*"))
                    self.assertEqual(len(candidates), 1)
                    self.assertEqual(candidates[0].stat().st_mode & 0o777, 0o600)

    def test_apply_proves_closed_ingress_before_success_receipt_and_state(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        closed_function = script[
            script.index("verify_closed_bracket() {") : script.index(
                "prior_running_services=()"
            )
        ]
        first_db = closed_function.index("verify_database_absent")
        active_public = closed_function.index(
            'public-origin-verify.sh" --mode closed --url https://rikune.w33d.xyz/'
        )
        legacy_public = closed_function.index(
            'public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/'
        )
        second_db = closed_function.index("verify_database_absent", first_db + 1)
        self.assertLess(first_db, active_public)
        self.assertLess(active_public, legacy_public)
        self.assertLess(legacy_public, second_db)

        final_bracket = script.index("\nverify_closed_bracket\n", script.index("activation_step="))
        apply_receipt = script.index('apply_receipt="$backup/APPLY.receipt"')
        final_state = script.index('state:"applied_ingress_closed"')
        self.assertLess(final_bracket, apply_receipt)
        self.assertLess(apply_receipt, final_state)
        self.assertIn("ROUTES_DATABASE_URL must be a PostgreSQL URI", script)
        self.assertIn("assets/verify_rikune_root_absent.sql", script)
        route_up_lines = [
            line
            for line in script.splitlines()
            if "20260823_rikune_root_up.sql" in line
        ]
        self.assertTrue(route_up_lines)
        self.assertTrue(
            all(
                "for relative in" in line
                or "successor-authority/assets/" in line
                or "route_up_sha256) relative=" in line
                for line in route_up_lines
            ),
            "apply may freeze route-up authority but must never execute it",
        )
        self.assertNotIn(
            '-f "$script_dir/assets/20260823_rikune_root_up.sql"', script
        )
        self.assertNotIn(
            '-f "$backup/successor-authority/assets/20260823_rikune_root_up.sql"',
            script,
        )
        for evidence in (
            "closed_bracket=passed",
            "route_database_state=absent",
            "public_ipv4_ipv6_closed_status=404",
            "ingress_opened=false",
        ):
            self.assertIn(evidence, script[final_bracket:final_state])

    def test_apply_finalization_has_recoverable_fault_boundaries(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        final_bracket = script.index(
            "\nverify_closed_bracket\n", script.index("activation_step=")
        )
        receipt_temp = script.index('apply_receipt_tmp="$backup/.APPLY.receipt.$$"')
        receipt_complete = script.index('} >"$apply_receipt_tmp"', receipt_temp)
        pending_commit = script.index(
            'commit_atomic_file "$apply_receipt_tmp" "$pending_apply_receipt"',
            receipt_complete,
        )
        pending_hash = script.index(
            'pending_apply_sha=$(holdfast_sha256 "$pending_apply_receipt")',
            pending_commit,
        )
        finalizing_state = script.index(
            'state:"apply_finalizing_ingress_closed"', pending_hash
        )
        finalizing_commit = script.index(
            'commit_atomic_file "$state_tmp" "$state_file"', finalizing_state
        )
        receipt_commit = script.index(
            'commit_atomic_file "$pending_apply_receipt" "$apply_receipt"',
            finalizing_commit,
        )
        final_state = script.index('state:"applied_ingress_closed"', receipt_commit)
        final_commit = script.index(
            'commit_atomic_file "$state_tmp" "$state_dir/CURRENT.json"', final_state
        )
        self.assertLess(final_bracket, receipt_temp)
        self.assertLess(receipt_complete, pending_commit)
        self.assertLess(pending_commit, pending_hash)
        self.assertLess(pending_hash, finalizing_state)
        self.assertLess(finalizing_state, finalizing_commit)
        self.assertLess(finalizing_commit, receipt_commit)
        self.assertLess(receipt_commit, final_state)
        self.assertLess(final_state, final_commit)

        receipt_body = script[receipt_temp:receipt_complete]
        self.assertIn("schema_version=2", receipt_body)
        self.assertIn("completion_state=applied_ingress_closed", receipt_body)

        finalizing = script[finalizing_state:finalizing_commit]
        self.assertIn('pending_apply_receipt:"APPLY-PENDING.receipt"', finalizing)
        self.assertIn("pending_apply_receipt_sha256:$pending_apply_sha", finalizing)
        for binding in (
            "apply_armed_receipt_sha256",
            "control_sha256",
            "release_evidence_sha256",
            "transaction_sha256",
            "applied_targets_sha256",
            'route_database_state:"absent"',
            "public_ipv4_ipv6_closed_status:404",
            "ingress_opened:false",
        ):
            self.assertIn(binding, finalizing)
        promotion = script[finalizing_commit:final_state]
        self.assertIn('[[ ! -e "$apply_receipt" && ! -L "$apply_receipt" ]]', promotion)
        self.assertIn('[[ ! -e "$pending_apply_receipt" && ! -L "$pending_apply_receipt" ]]', promotion)
        self.assertIn(
            '[[ "$(holdfast_sha256 "$apply_receipt")" == "$pending_apply_sha" ]]',
            promotion,
        )

    def test_apply_restores_only_prior_running_products_after_auto_rollback(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        loader = script[
            script.index("load_prior_running_services() {") : script.index(
                "validate_runtime_backup_authority() {"
            )
        ]
        validator = script[
            script.index("validate_runtime_backup_authority() {") : script.index(
                "verify_products_quiesced() {"
            )
        ]
        self.assertIn("RUNNING-SERVICES.before", script)
        self.assertIn("runtime/SHA256SUMS", script)
        self.assertIn("runtime_writers_stopped", validator)
        self.assertIn("strad) index=0", loader)
        self.assertIn("rikune-analyzer) index=1", loader)
        self.assertIn("unknown service", loader)
        self.assertIn("duplicated or out of order", loader)
        self.assertIn("prior_running_services_sha256", loader)

        resume_function = script[
            script.index("resume_prior_running_products() {") : script.index(
                'prearm_cleanup_active="false"'
            )
        ]
        self.assertIn('start "${prior_running_services[@]}"', resume_function)
        self.assertIn('for service in "${prior_running_services[@]}"', resume_function)
        self.assertIn('ps -aq "$service"', resume_function)
        self.assertIn("docker inspect -f '{{.State.Status}}'", resume_function)
        self.assertIn(".State.Health", resume_function)
        self.assertIn('"$health" != "none" && "$health" != "healthy"', resume_function)
        self.assertIn("excluded runtime service remains active", resume_function)
        self.assertIn("rikune-volume-init", resume_function)

        failure = script[
            script.index("if [[ $estate_status -ne 0 ]]") : script.index(
                "for file in \"$backup/estate/APPLIED-TARGETS.sha256\""
            )
        ]
        rolled_back = failure.index('transaction_state" == "rolled_back_after_failure"')
        resume = failure.index("resume_prior_running_products", rolled_back)
        failure_receipt = failure.index('failure_receipt="$state_dir/APPLY-ESTATE-FAILED-', resume)
        self.assertLess(rolled_back, resume)
        self.assertLess(resume, failure_receipt)
        self.assertIn('prior_running_restore="failed"', failure)
        for binding in (
            "transaction_sha256",
            "control_sha256",
            "targets_sha256",
            "runtime_backup_receipt_sha256",
            "runtime_backup_manifest_sha256",
            "prior_running_manifest_sha256",
            "prior_running_restore",
            "estate_transaction_state",
            "estate_transaction_sha256",
        ):
            self.assertIn(binding, failure)

    def test_apply_restores_prior_running_products_on_every_prearm_exit(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        cleanup = script[
            script.index("prearm_exit_cleanup() {") : script.index(
                "verify_release_bindings\n"
            )
        ]
        self.assertIn("recover_runtime_backup_caller_arm prearm_failure", cleanup)
        self.assertIn("trap - EXIT HUP INT TERM", cleanup)
        self.assertIn('if [[ "$prearm_cleanup_active" == "true" ]]', cleanup)
        self.assertIn("restore_status=$?", cleanup)

        caller_active = script.index('prearm_cleanup_active="true"')
        caller_receipt = script.index(
            'commit_atomic_file "$caller_armed_tmp" "$caller_armed_receipt"',
            caller_active,
        )
        caller_state = script.index('state:"runtime_backup_armed"', caller_receipt)
        caller_state_commit = script.index(
            'commit_atomic_file "$state_tmp" "$state_file"', caller_state
        )
        runtime_backup = script.index(
            '"$script_dir/runtime-backup.sh" --compose-root "$stage"'
        )
        exit_trap = script.index("trap prearm_exit_cleanup EXIT", caller_active)
        second_rebind = script.index("\nverify_release_bindings\n", runtime_backup)
        state_commit = script.index(
            'commit_atomic_file "$state_tmp" "$state_file"', caller_state_commit + 1
        )
        cleanup_inactive = script.index(
            'prearm_cleanup_active="false"', state_commit
        )
        clear_traps = script.index("trap - EXIT HUP INT TERM", cleanup_inactive)
        estate_apply = script.index('"$script_dir/estate_transaction.py" apply')
        self.assertLess(caller_active, exit_trap)
        self.assertLess(exit_trap, caller_receipt)
        self.assertLess(caller_receipt, caller_state)
        self.assertLess(caller_state, caller_state_commit)
        self.assertLess(caller_state_commit, runtime_backup)
        self.assertLess(runtime_backup, second_rebind)
        self.assertLess(second_rebind, state_commit)
        self.assertLess(state_commit, cleanup_inactive)
        self.assertLess(cleanup_inactive, clear_traps)
        self.assertLess(clear_traps, estate_apply)
        for signal_trap in (
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
        ):
            self.assertIn(signal_trap, script[caller_active:second_rebind])

    def test_apply_runtime_backup_caller_arm_is_durable_and_recoverable(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        caller = script[
            script.index('caller_armed_receipt="$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"') :
            script.index('# Runtime backup plus isolated restore probes')
        ]
        for binding in (
            "schema_version=2",
            "estate_root=%s",
            "dry_run_dir=%s",
            "backup_dir=%s",
            "runtime_backup_dir=%s",
            "release_env_sha256=%s",
            "dry_run_receipt_sha256=%s",
            "targets_sha256=%s",
            "apply_preimages_sha256=%s",
            "apply_absent_sha256=%s",
            "render_inputs_sha256=%s",
            "runtime_backup_armed_receipt=runtime/RUNTIME-BACKUP-ARMED.receipt",
            "stop_authority_contract=absence-means-stop-not-started",
            "ingress_opened=false",
        ):
            self.assertIn(binding, caller)
        receipt_commit = caller.index(
            'commit_atomic_file "$caller_armed_tmp" "$caller_armed_receipt"'
        )
        state = caller.index('state:"runtime_backup_armed"', receipt_commit)
        state_commit = caller.index(
            'commit_atomic_file "$state_tmp" "$state_file"', state
        )
        self.assertLess(receipt_commit, state)
        self.assertLess(state, state_commit)

        recovery = script[
            script.index("recover_runtime_backup_caller_arm() {") :
            script.index('prearm_cleanup_active="false"')
        ]
        self.assertIn("validate_runtime_backup_caller_authority false", recovery)
        self.assertIn('RUNTIME-BACKUP-ARMED.receipt', recovery)
        self.assertIn("validate_runtime_stop_authority", recovery)
        self.assertIn("load_prior_running_services", recovery)
        self.assertIn("resume_prior_running_products", recovery)
        self.assertIn("record_runtime_backup_cleanup", recovery)
        self.assertIn("archive_runtime_backup_state", recovery)
        self.assertIn("runtime backup succeeded without its durable stop authority", recovery)

        control = script[
            script.index('control_file="$backup/CONTROL.sha256"') :
            script.index('control_sha=$(holdfast_sha256 "$control_file")')
        ]
        for authority in (
            "RUNTIME-BACKUP-CALLER-ARMED.receipt",
            "runtime/RUNTIME-BACKUP-ARMED.receipt",
            "runtime/RUNNING-SERVICES.before",
        ):
            self.assertIn(authority, control)

    def test_schema3_shell_entrypoints_snapshot_completion_before_render(self) -> None:
        candidate = (OPS_ROOT / "candidate-source.sh").read_text(encoding="utf-8")
        dry_run = (OPS_ROOT / "dry-run.sh").read_text(encoding="utf-8")
        verify = (OPS_ROOT / "verify.sh").read_text(encoding="utf-8")

        self.assertIn("--recovery-completion-root", candidate)
        self.assertIn(
            'render_args+=(--recovery-completion-root "$recovery_completion_root")',
            candidate,
        )
        predecessor_validation = dry_run.index(
            'python3 "$script_dir/successor_binding.py"'
        )
        first_output_write = dry_run.index('mkdir -m 0700 -- "$output"')
        snapshot = dry_run.index(
            'recovery_completion_snapshot="$output/inputs/recovery-completion"'
        )
        full_render = dry_run.index('python3 "$script_dir/render.py"')
        self.assertLess(predecessor_validation, first_output_write)
        self.assertLess(first_output_write, snapshot)
        self.assertLess(snapshot, full_render)
        self.assertIn(
            'recovery_completion_root="$recovery_completion_snapshot"', dry_run
        )
        self.assertIn(
            '"$successor_policy_schema" == "3" || \\\n'
            '    "$successor_policy_schema" == "5"',
            dry_run,
        )
        for field in (
            "predecessor_completion_kind",
            "predecessor_completion_attestation_sha256",
            "predecessor_completion_signature_sha256",
            "predecessor_completion_public_key_sha256",
        ):
            self.assertIn(field, dry_run)
        self.assertIn('if [[ "$release_mode" == "successor" ]]', verify)
        self.assertIn('--expected-mode "$render_expected_mode"', verify)
        self.assertIn('--source-estate-root "$estate_root"', verify)

    def test_schema3_apply_freezes_bundle_before_state_and_revalidates_boundaries(
        self,
    ) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        generation = script.index("\npersist_successor_generation_authority\n")
        completion = script.index("\npersist_recovery_completion_authority\n")
        evidence = script.index(
            'atomic_copy_authority "$stage/RELEASE-EVIDENCE.json"', completion
        )
        partial = script.index("\n  persist_schema3_partial_recovery_authority\n", evidence)
        successor_arm = script.index("\npersist_successor_authority\n", partial)
        runtime_backup = script.index(
            '"$script_dir/runtime-backup.sh" --compose-root "$stage"'
        )
        self.assertLess(generation, completion)
        self.assertLess(completion, evidence)
        self.assertLess(evidence, partial)
        self.assertLess(partial, successor_arm)
        self.assertLess(successor_arm, runtime_backup)

        successor_arm_function = shell_function(script, "persist_successor_authority")
        self.assertIn(
            'successor_release_evidence_authority="$backup/RELEASE-EVIDENCE.json"',
            successor_arm_function,
        )
        self.assertIn(
            'successor_dry_receipt_authority="$backup/DRY-RUN.receipt"',
            successor_arm_function,
        )
        successor_validator = shell_function(
            script, "validate_persisted_successor_authority"
        )
        self.assertIn(
            ".release_evidence_sha256 == $frozen_release_evidence",
            successor_validator,
        )
        self.assertIn(
            ".dry_run_receipt_sha256 == $frozen_dry_receipt",
            successor_validator,
        )
        self.assertIn(
            '[keys[] | select(startswith("predecessor_completion_"))] | sort',
            successor_validator,
        )
        self.assertIn(
            'validate_v3_completion_receipt_namespace "$authority"',
            shell_function(script, "validate_successor_receipt_fields"),
        )
        self.assertIn(
            'validate_v3_completion_receipt_namespace "$receipt"',
            shell_function(script, "verify_release_bindings"),
        )
        caller_validator = shell_function(
            script, "validate_runtime_backup_caller_authority"
        )
        self.assertIn(
            '"$backup/DRY-RUN.receipt" "$key"', caller_validator
        )
        for field in (
            "release_env_sha256",
            "release_evidence_sha256",
            "targets_sha256",
            "apply_preimages_sha256",
            "apply_absent_sha256",
            "render_inputs_sha256",
        ):
            self.assertIn(field, caller_validator)

        before_runtime = script.rindex(
            "validate_persisted_recovery_completion_authority false",
            successor_arm,
            runtime_backup,
        )
        estate_apply = script.index('"$script_dir/estate_transaction.py" apply')
        before_estate = script.rindex(
            "validate_persisted_recovery_completion_authority true",
            runtime_backup,
            estate_apply,
        )
        apply_receipt = script.index('apply_receipt="$backup/APPLY.receipt"')
        before_receipt = script.rindex(
            "validate_persisted_recovery_completion_authority true",
            estate_apply,
            apply_receipt,
        )
        self.assertLess(before_runtime, runtime_backup)
        self.assertLess(before_estate, estate_apply)
        self.assertLess(before_receipt, apply_receipt)

        control = script[
            script.index('control_file="$backup/CONTROL.sha256"') :
            script.index('control_sha=$(holdfast_sha256 "$control_file")')
        ]
        delta = control.index("SUCCESSOR-DELTA.sha256")
        attestation = control.index("RECOVERY-COMPLETION-ATTESTATION.json")
        signature = control.index("RECOVERY-COMPLETION-ATTESTATION.sig")
        public_key = control.index("RECOVERY-COMPLETION-ATTESTATION.pub")
        generation_authority = control.index("successor-authority/Dockerfile.analyzer")
        self.assertLess(delta, attestation)
        self.assertLess(attestation, signature)
        self.assertLess(signature, public_key)
        self.assertLess(public_key, generation_authority)

        persisted_validator = shell_function(
            script, "validate_persisted_recovery_completion_authority"
        )
        self.assertEqual(
            persisted_validator.count("sha256sum --check CONTROL.sha256"), 2
        )
        self.assertGreaterEqual(
            persisted_validator.count('holdfast_sha256 "$backup/CONTROL.sha256"'),
            2,
        )
        signed_anchor = shell_function(
            script, "validate_persisted_schema3_signed_anchor"
        )
        for authority in (
            "release.env",
            "DRY-RUN.receipt",
            "SUPPLY-CHAIN.json",
            "SUPPLY-CHAIN.sig",
            "SUPPLY-CHAIN.pub",
            "RENDER-INPUTS.sha256",
            "SUCCESSOR-DELTA.sha256",
        ):
            self.assertIn(f'"$backup/{authority}"', signed_anchor)
        self.assertIn(
            '--successor-policy "$backup/successor-authority/successor-policy.json"',
            signed_anchor,
        )
        partial_persist = shell_function(
            script, "persist_schema3_partial_recovery_authority"
        )
        self.assertLess(
            partial_persist.index('atomic_copy_authority "$release_env"'),
            partial_persist.index("validate_persisted_schema3_signed_anchor"),
        )
        normal_persist = script[
            script.index("# Rebind every receipt-reviewed authority") :
            script.index("# Persist the exact recovery intent")
        ]
        for source, target in (
            ("$release_env", "$backup/release.env"),
            ("$receipt", "$backup/DRY-RUN.receipt"),
            ("$supply_evidence", "$backup/SUPPLY-CHAIN.json"),
            ("$supply_signature", "$backup/SUPPLY-CHAIN.sig"),
            ("$supply_public_key", "$backup/SUPPLY-CHAIN.pub"),
            ("$render_inputs", "$backup/RENDER-INPUTS.sha256"),
            ("$successor_delta", "$backup/SUCCESSOR-DELTA.sha256"),
        ):
            self.assertIn(
                f'atomic_copy_or_adopt_authority "{source}" "{target}"',
                normal_persist,
            )
        apply_armed = script.index('state:"apply_armed"')
        pending_state = script.index('>"$state_tmp"', apply_armed)
        precommit_validation = script.index(
            "validate_persisted_recovery_completion_authority true", pending_state
        )
        state_commit = script.index(
            'commit_atomic_file "$state_tmp" "$state_file"', pending_state
        )
        self.assertLess(precommit_validation, state_commit)
        estate_applied = script.index("estate_status=$?", estate_apply)
        docker_config = script.index("docker compose --env-file", estate_applied)
        post_estate_validation = script.index(
            "validate_persisted_recovery_completion_authority true", estate_applied
        )
        self.assertLess(post_estate_validation, docker_config)
        estate_failure = script.index("if [[ $estate_status -ne 0 ]]", estate_apply)
        estate_failure_validation = script.index(
            "validate_persisted_recovery_completion_authority true", estate_failure
        )
        estate_failure_receipt = script.index(
            'failure_receipt="$state_dir/APPLY-ESTATE-FAILED-', estate_failure
        )
        self.assertLess(estate_failure_validation, estate_failure_receipt)
        self.assertGreaterEqual(
            script[estate_failure:estate_failure_receipt].count(
                "validate_persisted_recovery_completion_authority true"
            ),
            2,
        )
        estate_failure_state_commit = script.index(
            'commit_atomic_file "$state_tmp" "$state_file"',
            estate_failure_receipt,
        )
        estate_failure_postcommit = script.index(
            "validate_persisted_recovery_completion_authority true",
            estate_failure_state_commit,
        )
        estate_failure_restore = script.index(
            "archive_and_restore_predecessor_current", estate_failure_state_commit
        )
        self.assertLess(estate_failure_postcommit, estate_failure_restore)
        activation_failure = script.index("if [[ $activation_status -ne 0 ]]")
        activation_failure_validation = script.index(
            "validate_persisted_recovery_completion_authority true",
            activation_failure,
        )
        activation_failure_receipt = script.index(
            'failure_receipt="$state_dir/APPLY-ACTIVATION-FAILED-',
            activation_failure,
        )
        self.assertLess(activation_failure_validation, activation_failure_receipt)

        runtime_state = script.index('state:"runtime_backup_armed"')
        runtime_pending_validation = script.index(
            'validate_runtime_backup_caller_authority true "$state_tmp"',
            runtime_state,
        )
        runtime_state_commit = script.index(
            'commit_atomic_file "$state_tmp" "$state_file"', runtime_state
        )
        runtime_backup = script.index(
            '"$script_dir/runtime-backup.sh" --compose-root "$stage"',
            runtime_state_commit,
        )
        self.assertLess(runtime_pending_validation, runtime_state_commit)
        self.assertLess(
            script.index("validate_schema3_stage_against_partial_authority", runtime_state_commit),
            runtime_backup,
        )

    def test_schema3_persisted_bundle_rejects_authority_tampering(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        armed_loader_start = script.index(
            "load_armed_successor_policy_authority() {"
        )
        armed_loader = script[
            armed_loader_start : script.index(
                "\nrelease_control_files=(", armed_loader_start
            )
        ]
        snapshot = shell_function(
            script, "validate_persisted_recovery_completion_snapshot"
        )
        namespace_validator = shell_function(
            script, "validate_v3_completion_receipt_namespace"
        )
        validator = shell_function(
            script, "validate_persisted_recovery_completion_authority"
        )
        harness = self.root / "validate-persisted-completion.sh"
        completion_payloads = {
            "RECOVERY-COMPLETION-ATTESTATION.json": b"attestation\n",
            "RECOVERY-COMPLETION-ATTESTATION.sig": b"signature\n",
            "RECOVERY-COMPLETION-ATTESTATION.pub": b"public-key\n",
        }
        a_digest, b_digest, c_digest = (
            hashlib.sha256(payload).hexdigest()
            for payload in completion_payloads.values()
        )
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + namespace_validator
            + "\n"
            + armed_loader
            + "\n"
            + snapshot
            + "\n"
            + validator
            + "\n"
            + "holdfast_die() { printf '%s\\n' \"$1\" >&2; exit 1; }\n"
            + "holdfast_sha256() { sha256sum -- \"$1\" | cut -d' ' -f1; }\n"
            + "holdfast_receipt_value() { sed -n \"s/^$2=//p\" \"$1\"; }\n"
            + "require_root_control_file() { [[ -f \"$1\" && ! -L \"$1\" && $(stat -c '%u:%h' -- \"$1\") == 0:1 ]]; }\n"
            + "require_private_root_control_file() { require_root_control_file \"$1\" && [[ $(stat -c '%a' -- \"$1\") == 600 ]]; }\n"
            + "require_canonical_root_directory() {\n"
            + "  [[ -d \"$1\" && ! -L \"$1\" && $(readlink -f -- \"$1\") == \"$1\" && $(stat -c '%u' -- \"$1\") == 0 ]]\n"
            + "  case \"${tamper_during_snapshot:-}\" in\n"
            + "    release-env) printf 'changed\\n' >>\"$backup/release.env\" ;;\n"
            + "    supply-signature) printf 'changed\\n' >>\"$backup/SUPPLY-CHAIN.sig\" ;;\n"
            + "    control-entry) printf 'changed\\n' >\"$backup/BOUND.txt\" ;;\n"
            + "  esac\n"
            + "  tamper_during_snapshot=\n"
            + "}\n"
            + "validate_recovery_completion_authority() { return 0; }\n"
            + "validate_persisted_schema3_signed_anchor() {\n"
            + "  validate_v3_completion_receipt_namespace \"$backup/DRY-RUN.receipt\"\n"
            + "  ! grep -q '^predecessor_apply_receipt_sha256=' \"$backup/DRY-RUN.receipt\" || holdfast_die \"schema 3 dry-run authority contains legacy APPLY lineage\"\n"
            + "  persisted_schema3_anchor_files=(\n"
            + "    \"$backup/successor-authority/successor-policy.json\"\n"
            + "    \"$backup/successor-authority/Dockerfile.analyzer\"\n"
            + "    \"$backup/successor-authority/bridge-package-lock.json\"\n"
            + "    \"$backup/successor-authority/assets/20260823_rikune_root_up.sql\"\n"
            + "    \"$backup/successor-authority/assets/20260823_rikune_root_down.sql\"\n"
            + "    \"$backup/RELEASE-EVIDENCE.json\" \"$backup/release.env\"\n"
            + "    \"$backup/DRY-RUN.receipt\" \"$backup/SUPPLY-CHAIN.json\"\n"
            + "    \"$backup/SUPPLY-CHAIN.sig\" \"$backup/SUPPLY-CHAIN.pub\"\n"
            + "    \"$backup/RENDER-INPUTS.sha256\" \"$backup/SUCCESSOR-DELTA.sha256\"\n"
            + "    \"$backup/successor-authority/render-1\" \"$backup/successor-authority/render-2\"\n"
            + "    \"$backup/successor-authority/render-3\" \"$backup/successor-authority/render-4\"\n"
            + "    \"$backup/successor-authority/render-5\" \"$backup/successor-authority/render-6\"\n"
            + "  )\n"
            + "  persisted_schema3_anchor_hashes=()\n"
            + "  for anchor in \"${persisted_schema3_anchor_files[@]}\"; do persisted_schema3_anchor_hashes[\"$anchor\"]=$(holdfast_sha256 \"$anchor\"); done\n"
            + "  persisted_schema3_anchor_snapshot_ready=true\n"
            + "  case \"${tamper_during_signed_anchor:-}\" in\n"
            + "    trio-content) printf 'changed\\n' >>\"$backup/RECOVERY-COMPLETION-ATTESTATION.json\" ;;\n"
            + "    trio-mode) chmod 0640 \"$backup/RECOVERY-COMPLETION-ATTESTATION.sig\" ;;\n"
            + "    trio-hardlink) ln \"$backup/RECOVERY-COMPLETION-ATTESTATION.pub\" \"$backup/TRIO.extra\" ;;\n"
            + "    arm-mode) chmod 0640 \"$backup/SUCCESSOR-ARMED.receipt\" ;;\n"
            + "  esac\n"
            + "  tamper_during_signed_anchor=\n"
            + "}\n"
            + "load_successor_policy_authority() {\n"
            + "  successor_policy_schema=$(jq -er '.schema_version' \"$1\")\n"
            + "  if [[ $successor_policy_schema == 3 ]]; then\n"
            + "    predecessor_completion_kind=recovery-completion-attestation-v1\n"
            + f"    predecessor_completion_attestation_sha={a_digest}\n"
            + f"    predecessor_completion_signature_sha={b_digest}\n"
            + f"    predecessor_completion_public_key_sha={c_digest}\n"
            + "  else\n"
            + "    predecessor_completion_kind=\n"
            + "    predecessor_completion_attestation_sha=\n"
            + "    predecessor_completion_signature_sha=\n"
            + "    predecessor_completion_public_key_sha=\n"
            + "  fi\n"
            + "}\n"
            + "rewrite_control() {\n"
            + "  (cd \"$backup\" && sha256sum successor-authority/successor-policy.json RELEASE-EVIDENCE.json DRY-RUN.receipt SUCCESSOR-ARMED.receipt RECOVERY-COMPLETION-ATTESTATION.json RECOVERY-COMPLETION-ATTESTATION.sig RECOVERY-COMPLETION-ATTESTATION.pub BOUND.txt >CONTROL.sha256)\n"
            + "  chmod 0600 \"$backup/CONTROL.sha256\"\n"
            + "}\n"
            + "python3() {\n"
            + "  case \"${tamper_during_validation:-}\" in\n"
            + "    policy) printf ' ' >>\"$backup/successor-authority/successor-policy.json\" ;;\n"
            + "    policy-downgrade) printf '{\"schema_version\":2}\\n' >\"$backup/successor-authority/successor-policy.json\" ;;\n"
            + "    evidence) printf ' ' >>\"$backup/RELEASE-EVIDENCE.json\" ;;\n"
            + "    control) printf 'changed\\n' >\"$backup/BOUND.txt\" ;;\n"
            + "    control-rewrite) printf 'changed\\n' >\"$backup/BOUND.txt\"; rewrite_control ;;\n"
            + "  esac\n"
            + "  tamper_during_validation=\n"
            + "  return 0\n"
            + "}\n"
            + "successor=true\n"
            + "persisted_schema3_anchor_snapshot_ready=false\n"
            + "persisted_schema3_anchor_files=()\n"
            + "declare -A persisted_schema3_anchor_hashes=()\n"
            + "backup=$1\n"
            + "script_dir=/unused\n"
            + "predecessor_current_sha=current\n"
            + "predecessor_backup=/predecessor\n"
            + "predecessor_runtime_receipt_sha=runtime\n"
            + "successor_armed_sha=$(holdfast_sha256 \"$backup/SUCCESSOR-ARMED.receipt\")\n"
            + "control_sha=$(holdfast_sha256 \"$backup/CONTROL.sha256\")\n"
            + "case \"$2\" in\n"
            + "  policy-before) printf ' ' >>\"$backup/successor-authority/successor-policy.json\" ;;\n"
            + "  policy-downgrade-before) printf '{\"schema_version\":2}\\n' >\"$backup/successor-authority/successor-policy.json\" ;;\n"
            + "  evidence-before) printf ' ' >>\"$backup/RELEASE-EVIDENCE.json\" ;;\n"
            + "  arm-before) printf '# changed\\n' >>\"$backup/SUCCESSOR-ARMED.receipt\" ;;\n"
            + "  control-before) printf 'changed\\n' >\"$backup/BOUND.txt\" ;;\n"
            + "  control-rewrite-before) printf 'changed\\n' >\"$backup/BOUND.txt\"; rewrite_control ;;\n"
            + "  policy-during) tamper_during_validation=policy ;;\n"
            + "  policy-downgrade-during) tamper_during_validation=policy-downgrade ;;\n"
            + "  evidence-during) tamper_during_validation=evidence ;;\n"
            + "  control-during) tamper_during_validation=control ;;\n"
            + "  control-rewrite-during) tamper_during_validation=control-rewrite ;;\n"
            + "  trio-content-during-anchor) tamper_during_signed_anchor=trio-content ;;\n"
            + "  trio-mode-during-anchor) tamper_during_signed_anchor=trio-mode ;;\n"
            + "  trio-hardlink-during-anchor) tamper_during_signed_anchor=trio-hardlink ;;\n"
            + "  arm-mode-during-anchor) tamper_during_signed_anchor=arm-mode ;;\n"
            + "  release-env-during-snapshot) tamper_during_snapshot=release-env ;;\n"
            + "  supply-signature-during-snapshot) tamper_during_snapshot=supply-signature ;;\n"
            + "  control-entry-during-snapshot) tamper_during_snapshot=control-entry ;;\n"
            + "  backup-mode-0500-before) chmod 0500 \"$backup\" ;;\n"
            + "  backup-mode-0600-before) chmod 0600 \"$backup\" ;;\n"
            + "  dry-fifth-self-consistent)\n"
            + "    printf 'predecessor_completion_extra_sha256=extra\\n' >>\"$backup/DRY-RUN.receipt\"\n"
            + "    sed -i \"s/^candidate_dry_run_receipt_sha256=.*/candidate_dry_run_receipt_sha256=$(holdfast_sha256 \"$backup/DRY-RUN.receipt\")/\" \"$backup/SUCCESSOR-ARMED.receipt\"\n"
            + "    successor_armed_sha=$(holdfast_sha256 \"$backup/SUCCESSOR-ARMED.receipt\")\n"
            + "    rewrite_control; control_sha=$(holdfast_sha256 \"$backup/CONTROL.sha256\")\n"
            + "    ;;\n"
            + "  arm-fifth-self-consistent)\n"
            + "    printf 'predecessor_completion_extra_sha256=extra\\n' >>\"$backup/SUCCESSOR-ARMED.receipt\"\n"
            + "    successor_armed_sha=$(holdfast_sha256 \"$backup/SUCCESSOR-ARMED.receipt\")\n"
            + "    rewrite_control; control_sha=$(holdfast_sha256 \"$backup/CONTROL.sha256\")\n"
            + "    ;;\n"
            + "  dry-partial-self-consistent)\n"
            + "    sed -i '/^predecessor_completion_public_key_sha256=/d' \"$backup/DRY-RUN.receipt\"\n"
            + "    sed -i \"s/^candidate_dry_run_receipt_sha256=.*/candidate_dry_run_receipt_sha256=$(holdfast_sha256 \"$backup/DRY-RUN.receipt\")/\" \"$backup/SUCCESSOR-ARMED.receipt\"\n"
            + "    successor_armed_sha=$(holdfast_sha256 \"$backup/SUCCESSOR-ARMED.receipt\")\n"
            + "    rewrite_control; control_sha=$(holdfast_sha256 \"$backup/CONTROL.sha256\")\n"
            + "    ;;\n"
            + "  arm-hybrid-self-consistent)\n"
            + "    printf 'predecessor_apply_receipt_sha256=legacy\\n' >>\"$backup/SUCCESSOR-ARMED.receipt\"\n"
            + "    successor_armed_sha=$(holdfast_sha256 \"$backup/SUCCESSOR-ARMED.receipt\")\n"
            + "    rewrite_control; control_sha=$(holdfast_sha256 \"$backup/CONTROL.sha256\")\n"
            + "    ;;\n"
            + "esac\n"
            + "validate_persisted_recovery_completion_authority true\n",
            encoding="utf-8",
        )
        harness.chmod(0o755)

        def make_backup(name: str) -> Path:
            backup = self.root / name
            authority = backup / "successor-authority"
            authority.mkdir(parents=True, mode=0o700)
            backup.chmod(0o700)
            (authority / "assets").mkdir(mode=0o700)
            policy = authority / "successor-policy.json"
            policy.write_text('{"schema_version":3}\n', encoding="utf-8")
            evidence = backup / "RELEASE-EVIDENCE.json"
            evidence.write_text(
                json.dumps(
                    {
                        "predecessor_binding": {
                            "completion": {
                                "kind": "recovery-completion-attestation-v1",
                                "attestation_sha256": a_digest,
                                "signature_sha256": b_digest,
                                "public_key_sha256": c_digest,
                            }
                        }
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            arm = backup / "SUCCESSOR-ARMED.receipt"
            dry_receipt = backup / "DRY-RUN.receipt"
            dry_receipt.write_text(
                "schema_version=2\n"
                "predecessor_completion_kind=recovery-completion-attestation-v1\n"
                f"predecessor_completion_attestation_sha256={a_digest}\n"
                f"predecessor_completion_signature_sha256={b_digest}\n"
                f"predecessor_completion_public_key_sha256={c_digest}\n",
                encoding="utf-8",
            )
            arm.write_text(
                f"successor_policy_sha256={sha256(policy)}\n"
                f"candidate_release_evidence_sha256={sha256(evidence)}\n",
                encoding="utf-8",
            )
            arm.write_text(
                arm.read_text(encoding="utf-8")
                + f"candidate_dry_run_receipt_sha256={sha256(dry_receipt)}\n"
                + "predecessor_completion_kind=recovery-completion-attestation-v1\n"
                + f"predecessor_completion_attestation_sha256={a_digest}\n"
                + f"predecessor_completion_signature_sha256={b_digest}\n"
                + f"predecessor_completion_public_key_sha256={c_digest}\n",
                encoding="utf-8",
            )
            for relative, payload in completion_payloads.items():
                (backup / relative).write_bytes(payload)
            signed_anchor_paths = (
                authority / "Dockerfile.analyzer",
                authority / "bridge-package-lock.json",
                authority / "assets/20260823_rikune_root_up.sql",
                authority / "assets/20260823_rikune_root_down.sql",
                backup / "release.env",
                backup / "SUPPLY-CHAIN.json",
                backup / "SUPPLY-CHAIN.sig",
                backup / "SUPPLY-CHAIN.pub",
                backup / "RENDER-INPUTS.sha256",
                backup / "SUCCESSOR-DELTA.sha256",
                *(authority / f"render-{index}" for index in range(1, 7)),
            )
            for path in signed_anchor_paths:
                path.write_text(f"authority: {path.name}\n", encoding="utf-8")
            bound = backup / "BOUND.txt"
            bound.write_text("bound\n", encoding="utf-8")
            relative_paths = (
                "successor-authority/successor-policy.json",
                "RELEASE-EVIDENCE.json",
                "DRY-RUN.receipt",
                "SUCCESSOR-ARMED.receipt",
                "RECOVERY-COMPLETION-ATTESTATION.json",
                "RECOVERY-COMPLETION-ATTESTATION.sig",
                "RECOVERY-COMPLETION-ATTESTATION.pub",
                "BOUND.txt",
            )
            (backup / "CONTROL.sha256").write_text(
                "".join(
                    f"{sha256(backup / relative)}  {relative}\n"
                    for relative in relative_paths
                ),
                encoding="utf-8",
            )
            for path in backup.rglob("*"):
                if path.is_file():
                    path.chmod(0o600)
            return backup

        valid = subprocess.run(
            ["bash", str(harness), str(make_backup("valid")), "valid"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        for mode in (
            "policy-before",
            "policy-downgrade-before",
            "evidence-before",
            "arm-before",
            "control-before",
            "control-rewrite-before",
            "policy-during",
            "policy-downgrade-during",
            "evidence-during",
            "control-during",
            "control-rewrite-during",
            "trio-content-during-anchor",
            "trio-mode-during-anchor",
            "trio-hardlink-during-anchor",
            "arm-mode-during-anchor",
            "release-env-during-snapshot",
            "supply-signature-during-snapshot",
            "control-entry-during-snapshot",
            "backup-mode-0500-before",
            "backup-mode-0600-before",
            "dry-fifth-self-consistent",
            "arm-fifth-self-consistent",
            "dry-partial-self-consistent",
            "arm-hybrid-self-consistent",
        ):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    ["bash", str(harness), str(make_backup(mode)), mode],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_successor_pointer_and_runtime_caller_close_nested_validation_tampering(
        self,
    ) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        successor_validator = shell_function(
            script, "validate_persisted_successor_authority"
        )
        namespace_validator = shell_function(
            script, "validate_v3_completion_receipt_namespace"
        )
        successor_harness = self.root / "validate-successor-pointer.sh"
        successor_harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + namespace_validator
            + "\n"
            + successor_validator
            + "\n"
            + "holdfast_die() { printf '%s\\n' \"$1\" >&2; exit 1; }\n"
            + "holdfast_sha256() { sha256sum -- \"$1\" | cut -d' ' -f1; }\n"
            + "holdfast_receipt_value() { sed -n \"s/^$2=//p\" \"$1\"; }\n"
            + "require_root_control_file() { [[ -f \"$1\" && ! -L \"$1\" && $(stat -c '%u:%h' -- \"$1\") == 0:1 ]]; }\n"
            + "require_private_root_control_file() { require_root_control_file \"$1\" && [[ $(stat -c '%a' -- \"$1\") == 600 ]]; }\n"
            + "load_armed_successor_policy_authority() {\n"
            + "  successor_policy_schema=3\n"
            + "  predecessor_completion_kind=recovery-completion-attestation-v1\n"
            + "  predecessor_completion_attestation_sha=${attestation_sha}\n"
            + "  predecessor_completion_signature_sha=${signature_sha}\n"
            + "  predecessor_completion_public_key_sha=${public_key_sha}\n"
            + "  validate_v3_completion_receipt_namespace \"$backup/SUCCESSOR-ARMED.receipt\"\n"
            + "}\n"
            + "validate_predecessor_snapshot() {\n"
            + "  predecessor_backup=/predecessor\n"
            + "  predecessor_generation=2\n"
            + "  release_generation=3\n"
            + "  predecessor_control_sha=${control_authority}\n"
            + "  predecessor_apply_sha=\n"
            + "  predecessor_release_sha=${release_authority}\n"
            + "  predecessor_runtime_receipt_sha=${runtime_receipt_authority}\n"
            + "  predecessor_runtime_manifest_sha=${runtime_manifest_authority}\n"
            + "}\n"
            + "validate_persisted_recovery_completion_authority() {\n"
            + "  case \"$tamper_mode\" in\n"
            + "    pointer-content) printf ' ' >>\"$pointer_under_test\" ;;\n"
            + "    pointer-mode) chmod 0640 \"$pointer_under_test\" ;;\n"
            + "    pointer-hardlink) ln \"$pointer_under_test\" \"$backup/POINTER.extra\" ;;\n"
            + "  esac\n"
            + "}\n"
            + "successor=true\n"
            + "predecessor_recovery_completion_json='{}'\n"
            + "backup=$1\n"
            + "pointer_under_test=$2\n"
            + "tamper_mode=$3\n"
            + "estate_root=/estate\n"
            + "attestation_sha=$(printf attestation | sha256sum | cut -d' ' -f1)\n"
            + "signature_sha=$(printf signature | sha256sum | cut -d' ' -f1)\n"
            + "public_key_sha=$(printf public-key | sha256sum | cut -d' ' -f1)\n"
            + "control_authority=$(printf control | sha256sum | cut -d' ' -f1)\n"
            + "release_authority=$(printf release | sha256sum | cut -d' ' -f1)\n"
            + "runtime_receipt_authority=$(printf runtime-receipt | sha256sum | cut -d' ' -f1)\n"
            + "runtime_manifest_authority=$(printf runtime-manifest | sha256sum | cut -d' ' -f1)\n"
            + "control_sha=$(printf successor-control | sha256sum | cut -d' ' -f1)\n"
            + "expected_state=successor_armed\n"
            + "case \"$tamper_mode\" in\n"
            + "  state-before) jq '.state=\"runtime_backup_armed\"' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  estate-before) jq '.estate_root=\"/other\"' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  backup-before) jq '.backup_dir=\"/other\"' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  successor-missing-before) jq 'del(.successor)' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  successor-false-before) jq '.successor=false' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  pointer-fifth-before) jq '.predecessor_completion_extra_sha256=\"extra\"' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  pointer-hybrid-before) jq '.predecessor_apply_receipt_sha256=\"legacy\"' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  arm-fifth-before) printf 'predecessor_completion_extra_sha256=extra\\n' >>\"$backup/SUCCESSOR-ARMED.receipt\"; jq --arg arm_sha \"$(holdfast_sha256 \"$backup/SUCCESSOR-ARMED.receipt\")\" '.successor_armed_receipt_sha256=$arm_sha' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  precontrol-with-control) jq --arg control \"$control_sha\" '.control_sha256=$control' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  post-control-missing) expected_state=apply_armed; jq '.state=\"apply_armed\"' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  post-control-wrong) expected_state=apply_armed; jq '.state=\"apply_armed\" | .control_sha256=\"wrong\"' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  post-control-valid) expected_state=apply_armed; jq --arg control \"$control_sha\" '.state=\"apply_armed\" | .control_sha256=$control' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "esac\n"
            + "if [[ -f \"$pointer_under_test.tmp\" ]]; then mv -T \"$pointer_under_test.tmp\" \"$pointer_under_test\"; chmod 0600 \"$pointer_under_test\"; fi\n"
            + "validate_persisted_successor_authority \"$pointer_under_test\" \"$expected_state\"\n",
            encoding="utf-8",
        )
        successor_harness.chmod(0o755)

        def make_successor_pointer(name: str) -> tuple[Path, Path]:
            backup = self.root / f"successor-{name}"
            authority = backup / "successor-authority"
            authority.mkdir(parents=True, mode=0o700)
            backup.chmod(0o700)
            policy = authority / "successor-policy.json"
            policy.write_text('{"schema_version":3}\n', encoding="utf-8")
            evidence = backup / "RELEASE-EVIDENCE.json"
            evidence.write_text("{}\n", encoding="utf-8")
            dry_receipt = backup / "DRY-RUN.receipt"
            dry_receipt.write_text("schema_version=2\n", encoding="utf-8")
            release_env = backup / "release.env"
            release_env.write_text("SAFE=1\n", encoding="utf-8")
            predecessor_current = backup / "PREDECESSOR-CURRENT.json"
            predecessor_current.write_text("{}\n", encoding="utf-8")
            attestation_sha = hashlib.sha256(b"attestation").hexdigest()
            signature_sha = hashlib.sha256(b"signature").hexdigest()
            public_key_sha = hashlib.sha256(b"public-key").hexdigest()
            control_authority = hashlib.sha256(b"control").hexdigest()
            release_authority = hashlib.sha256(b"release").hexdigest()
            runtime_receipt_authority = hashlib.sha256(
                b"runtime-receipt"
            ).hexdigest()
            runtime_manifest_authority = hashlib.sha256(
                b"runtime-manifest"
            ).hexdigest()
            arm = backup / "SUCCESSOR-ARMED.receipt"
            arm.write_text(
                "schema_version=1\n"
                f"successor_backup_dir={backup}\n"
                f"candidate_dry_run_receipt_sha256={sha256(dry_receipt)}\n"
                f"candidate_release_evidence_sha256={sha256(evidence)}\n"
                f"successor_policy_sha256={sha256(policy)}\n"
                "predecessor_current_file=PREDECESSOR-CURRENT.json\n"
                f"predecessor_current_sha256={sha256(predecessor_current)}\n"
                "predecessor_backup_dir=/predecessor\n"
                f"predecessor_control_sha256={control_authority}\n"
                "predecessor_completion_kind=recovery-completion-attestation-v1\n"
                f"predecessor_completion_attestation_sha256={attestation_sha}\n"
                f"predecessor_completion_signature_sha256={signature_sha}\n"
                f"predecessor_completion_public_key_sha256={public_key_sha}\n"
                f"predecessor_release_evidence_sha256={release_authority}\n"
                f"predecessor_runtime_backup_receipt_sha256={runtime_receipt_authority}\n"
                f"predecessor_runtime_backup_manifest_sha256={runtime_manifest_authority}\n"
                "predecessor_release_generation=2\n"
                "release_generation=3\n"
                "ingress_opened=false\n",
                encoding="utf-8",
            )
            pointer = backup / "PENDING-CURRENT.json"
            pointer.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "state": "successor_armed",
                        "estate_root": "/estate",
                        "backup_dir": str(backup),
                        "successor": True,
                        "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
                        "successor_armed_receipt_sha256": sha256(arm),
                        "predecessor_current_file": "PREDECESSOR-CURRENT.json",
                        "predecessor_current_sha256": sha256(predecessor_current),
                        "predecessor_backup_dir": "/predecessor",
                        "predecessor_control_sha256": control_authority,
                        "predecessor_completion_kind": "recovery-completion-attestation-v1",
                        "predecessor_completion_attestation_sha256": attestation_sha,
                        "predecessor_completion_signature_sha256": signature_sha,
                        "predecessor_completion_public_key_sha256": public_key_sha,
                        "predecessor_release_evidence_sha256": release_authority,
                        "predecessor_runtime_backup_receipt_sha256": runtime_receipt_authority,
                        "predecessor_runtime_backup_manifest_sha256": runtime_manifest_authority,
                        "predecessor_release_generation": 2,
                        "release_generation": 3,
                        "release_env_sha256": sha256(release_env),
                        "release_evidence_sha256": sha256(evidence),
                        "dry_run_receipt_sha256": sha256(dry_receipt),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            for path in backup.rglob("*"):
                if path.is_file():
                    path.chmod(0o600)
            return backup, pointer

        for mode in (
            "valid",
            "post-control-valid",
            "state-before",
            "estate-before",
            "backup-before",
            "successor-missing-before",
            "successor-false-before",
            "pointer-fifth-before",
            "pointer-hybrid-before",
            "arm-fifth-before",
            "precontrol-with-control",
            "post-control-missing",
            "post-control-wrong",
            "pointer-content",
            "pointer-mode",
            "pointer-hardlink",
        ):
            with self.subTest(validator="successor", mode=mode):
                backup, pointer = make_successor_pointer(mode)
                result = subprocess.run(
                    [
                        "bash",
                        str(successor_harness),
                        str(backup),
                        str(pointer),
                        mode,
                    ],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if mode in ("valid", "post-control-valid"):
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

        caller_validator = shell_function(
            script, "validate_runtime_backup_caller_authority"
        )
        caller_harness = self.root / "validate-runtime-caller-tail.sh"
        caller_harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + caller_validator
            + "\n"
            + "holdfast_die() { printf '%s\\n' \"$1\" >&2; exit 1; }\n"
            + "holdfast_sha256() { sha256sum -- \"$1\" | cut -d' ' -f1; }\n"
            + "holdfast_receipt_value() { sed -n \"s/^$2=//p\" \"$1\"; }\n"
            + "require_private_root_control_file() { [[ -f \"$1\" && ! -L \"$1\" && $(stat -c '%u:%h:%a' -- \"$1\") == 0:1:600 ]]; }\n"
            + "runtime_backup_caller_release_mode() { printf 'successor\\n'; }\n"
            + "validate_persisted_successor_authority() {\n"
            + "  case \"$tamper_mode\" in\n"
            + "    pointer-during) printf ' ' >>\"$pointer_under_test\" ;;\n"
            + "    pointer-mode-during) chmod 0640 \"$pointer_under_test\" ;;\n"
            + "    caller-during) printf '# changed\\n' >>\"$caller_armed_receipt\" ;;\n"
            + "    caller-hardlink-during) ln \"$caller_armed_receipt\" \"$backup/CALLER.extra\" ;;\n"
            + "  esac\n"
            + "}\n"
            + "validate_successor_receipt_fields() { return 0; }\n"
            + "successor_policy_schema=2\n"
            + "estate_root=/estate\n"
            + "dry_run_dir=/dry-run\n"
            + "backup=$1\n"
            + "pointer_under_test=$2\n"
            + "caller_armed_receipt=$3\n"
            + "state_file=$pointer_under_test\n"
            + "tamper_mode=$4\n"
            + "case \"$tamper_mode\" in\n"
            + "  successor-missing-before) jq 'del(.successor)' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "  successor-false-before) jq '.successor=false' \"$pointer_under_test\" >\"$pointer_under_test.tmp\" ;;\n"
            + "esac\n"
            + "if [[ -f \"$pointer_under_test.tmp\" ]]; then mv -T \"$pointer_under_test.tmp\" \"$pointer_under_test\"; chmod 0600 \"$pointer_under_test\"; fi\n"
            + "validate_runtime_backup_caller_authority false \"$pointer_under_test\"\n",
            encoding="utf-8",
        )
        caller_harness.chmod(0o755)

        def make_runtime_caller(name: str) -> tuple[Path, Path, Path]:
            backup = self.root / f"caller-{name}"
            backup.mkdir(mode=0o700)
            caller = backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
            caller.write_text(
                "schema_version=2\n"
                "estate_root=/estate\n"
                "dry_run_dir=/dry-run\n"
                f"backup_dir={backup}\n"
                f"runtime_backup_dir={backup}/runtime\n"
                "release_env_sha256=release\n"
                "release_evidence_sha256=evidence\n"
                "dry_run_receipt_sha256=dry\n"
                "targets_sha256=targets\n"
                "apply_preimages_sha256=preimages\n"
                "apply_absent_sha256=absent\n"
                "render_inputs_sha256=render\n"
                "runtime_backup_armed_receipt=runtime/RUNTIME-BACKUP-ARMED.receipt\n"
                "stop_authority_contract=absence-means-stop-not-started\n"
                "ingress_opened=false\n",
                encoding="utf-8",
            )
            pointer = backup / "PENDING-CURRENT.json"
            pointer.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "state": "runtime_backup_armed",
                        "estate_root": "/estate",
                        "backup_dir": str(backup),
                        "dry_run_dir": "/dry-run",
                        "runtime_backup_dir": f"{backup}/runtime",
                        "runtime_backup_caller_armed_receipt": "RUNTIME-BACKUP-CALLER-ARMED.receipt",
                        "runtime_backup_caller_armed_receipt_sha256": sha256(caller),
                        "runtime_backup_armed_receipt": "runtime/RUNTIME-BACKUP-ARMED.receipt",
                        "release_env_sha256": "release",
                        "release_evidence_sha256": "evidence",
                        "dry_run_receipt_sha256": "dry",
                        "targets_sha256": "targets",
                        "apply_preimages_sha256": "preimages",
                        "apply_absent_sha256": "absent",
                        "render_inputs_sha256": "render",
                        "stop_authority_contract": "absence-means-stop-not-started",
                        "ingress_opened": False,
                        "successor": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            caller.chmod(0o600)
            pointer.chmod(0o600)
            return backup, pointer, caller

        for mode in (
            "valid",
            "pointer-during",
            "pointer-mode-during",
            "caller-during",
            "caller-hardlink-during",
            "successor-missing-before",
            "successor-false-before",
        ):
            with self.subTest(validator="caller", mode=mode):
                backup, pointer, caller = make_runtime_caller(mode)
                result = subprocess.run(
                    [
                        "bash",
                        str(caller_harness),
                        str(backup),
                        str(pointer),
                        str(caller),
                        mode,
                    ],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if mode == "valid":
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_partial_authority_adoption_is_exact_and_never_overwrites(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        adopt = shell_function(script, "atomic_copy_or_adopt_authority")
        harness = self.root / "adopt-authority.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + adopt
            + "\n"
            + "holdfast_die() { printf '%s\\n' \"$1\" >&2; exit 1; }\n"
            + "holdfast_sha256() { sha256sum -- \"$1\" | cut -d' ' -f1; }\n"
            + "require_root_control_file() { [[ -f \"$1\" && ! -L \"$1\" ]]; }\n"
            + "atomic_copy_authority() { exit 99; }\n"
            + "atomic_copy_or_adopt_authority \"$1\" \"$2\"\n",
            encoding="utf-8",
        )
        harness.chmod(0o755)
        source = self.root / "source"
        target = self.root / "target"
        source.write_bytes(b"frozen\n")
        target.write_bytes(source.read_bytes())
        source.chmod(0o600)
        target.chmod(0o600)
        adopted = subprocess.run(
            ["bash", str(harness), str(source), str(target)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(adopted.returncode, 0, adopted.stdout + adopted.stderr)

        target.write_bytes(b"different\n")
        before = target.read_bytes()
        mismatch = subprocess.run(
            ["bash", str(harness), str(source), str(target)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertEqual(target.read_bytes(), before)

        target.write_bytes(source.read_bytes())
        target.chmod(0o640)
        unsafe_mode = subprocess.run(
            ["bash", str(harness), str(source), str(target)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(unsafe_mode.returncode, 0)

    def test_runtime_archive_decision_uses_the_validated_caller_snapshot(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        archive = shell_function(script, "archive_runtime_backup_state")
        harness = self.root / "archive-validated-caller.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + archive
            + "\n"
            + "holdfast_die() { printf '%s\\n' \"$1\" >&2; exit 1; }\n"
            + "holdfast_sha256() { sha256sum -- \"$1\" | cut -d' ' -f1; }\n"
            + "require_root_control_file() { [[ -f \"$1\" && ! -L \"$1\" ]]; }\n"
            + "require_private_root_control_file() { require_root_control_file \"$1\" && [[ $(stat -c '%a' -- \"$1\") == 600 ]]; }\n"
            + "validate_runtime_backup_caller_authority() {\n"
            + "  case \"$flip\" in\n"
            + "    successor-to-base) printf 'schema_version=2\\n' >\"$caller_armed_receipt\"; validated_runtime_backup_caller_release_mode=base ;;\n"
            + "    base-to-successor) printf 'schema_version=2\\nsuccessor=true\\n' >\"$caller_armed_receipt\"; validated_runtime_backup_caller_release_mode=successor ;;\n"
            + "  esac\n"
            + "  chmod 0600 \"$caller_armed_receipt\"\n"
            + "  validated_runtime_backup_caller_sha=$(holdfast_sha256 \"$caller_armed_receipt\")\n"
            + "}\n"
            + "archive_and_restore_predecessor_current() { printf 'restored\\n' >\"$result_file\"; }\n"
            + "backup=$1\n"
            + "state_dir=$2\n"
            + "state_file=$3\n"
            + "caller_armed_receipt=$4\n"
            + "result_file=$5\n"
            + "flip=$6\n"
            + "validated_runtime_backup_caller_release_mode=\n"
            + "validated_runtime_backup_caller_sha=\n"
            + "archive_runtime_backup_state\n",
            encoding="utf-8",
        )
        harness.chmod(0o755)
        for flip in ("successor-to-base", "base-to-successor"):
            with self.subTest(flip=flip):
                root = self.root / flip
                backup = root / "backup"
                state_dir = root / "state"
                backup.mkdir(parents=True)
                state_dir.mkdir()
                state = state_dir / "CURRENT.json"
                state.write_text("{}\n", encoding="utf-8")
                caller = backup / "RUNTIME-BACKUP-CALLER-ARMED.receipt"
                caller.write_text(
                    "schema_version=2\n"
                    + ("successor=true\n" if flip == "successor-to-base" else ""),
                    encoding="utf-8",
                )
                caller.chmod(0o600)
                result_file = root / "restored"
                result = subprocess.run(
                    [
                        "bash",
                        str(harness),
                        str(backup),
                        str(state_dir),
                        str(state),
                        str(caller),
                        str(result_file),
                        flip,
                    ],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if flip == "successor-to-base":
                    self.assertFalse(state.exists())
                    self.assertFalse(result_file.exists())
                else:
                    self.assertTrue(state.exists())
                    self.assertTrue(result_file.exists())

    def test_predecessor_current_is_revalidated_after_successor_archive(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        restore = shell_function(script, "archive_and_restore_predecessor_current")
        harness = self.root / "restore-predecessor-current.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + restore
            + "\n"
            + "holdfast_die() { printf '%s\\n' \"$1\" >&2; exit 1; }\n"
            + "holdfast_sha256() { sha256sum -- \"$1\" | cut -d' ' -f1; }\n"
            + "require_root_control_file() { [[ -f \"$1\" && ! -L \"$1\" && $(stat -c '%u:%h' -- \"$1\") == 0:1 ]]; }\n"
            + "require_private_root_control_file() { require_root_control_file \"$1\" && [[ $(stat -c '%a' -- \"$1\") == 600 ]]; }\n"
            + "atomic_copy_authority() {\n"
            + "  install -o 0 -g 0 -m 0600 -- \"$1\" \"$2\"\n"
            + "  if [[ $mode == tamper-after-archive ]]; then printf 'changed\\n' >>\"$predecessor_current_file\"; fi\n"
            + "}\n"
            + "commit_atomic_file() { mv -fT -- \"$1\" \"$2\"; }\n"
            + "state_dir=$1\n"
            + "state_file=$2\n"
            + "predecessor_current_file=$3\n"
            + "archive=$4\n"
            + "mode=$5\n"
            + "predecessor_current_sha=$(holdfast_sha256 \"$predecessor_current_file\")\n"
            + "HOLDFAST_TEST_MODE=0\n"
            + "archive_and_restore_predecessor_current \"$archive\"\n",
            encoding="utf-8",
        )
        harness.chmod(0o755)
        for mode in ("valid", "tamper-after-archive"):
            with self.subTest(mode=mode):
                root = self.root / f"predecessor-{mode}"
                state_dir = root / "state"
                backup = root / "backup"
                state_dir.mkdir(parents=True)
                backup.mkdir()
                state = state_dir / "CURRENT.json"
                predecessor = backup / "PREDECESSOR-CURRENT.json"
                archive = state_dir / "SUCCESSOR-ARCHIVED.json"
                state.write_bytes(b"successor-current\n")
                predecessor.write_bytes(b"predecessor-current\n")
                state.chmod(0o600)
                predecessor.chmod(0o600)
                original_state = state.read_bytes()
                result = subprocess.run(
                    [
                        "bash",
                        str(harness),
                        str(state_dir),
                        str(state),
                        str(predecessor),
                        str(archive),
                        mode,
                    ],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if mode == "valid":
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(state.read_bytes(), b"predecessor-current\n")
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(state.read_bytes(), original_state)

    def test_successor_receipt_lineage_selects_exact_v3_v5_or_apply_namespace(
        self,
    ) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        persist_arm = shell_function(script, "persist_successor_authority")
        evidence_line = persist_arm.index("candidate_release_evidence_sha256=%s")
        policy_line = persist_arm.index("successor_policy_sha256=%s")
        predecessor_line = persist_arm.index("predecessor_current_file=PREDECESSOR-CURRENT.json")
        self.assertLess(evidence_line, policy_line)
        self.assertLess(policy_line, predecessor_line)
        append_function = shell_function(script, "append_successor_receipt_fields")
        append_v5_function = shell_function(
            script, "append_v5_recovery_completion_receipt_fields"
        )
        harness = self.root / "append-successor-lineage.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            f"{append_v5_function}\n"
            f"{append_function}\n"
            "successor=true\n"
            "successor_armed_sha=aa\n"
            "predecessor_current_sha=bb\n"
            "predecessor_backup=/secure/backups/predecessor\n"
            "predecessor_control_sha=cc\n"
            "predecessor_apply_sha=dd\n"
            "predecessor_completion_kind=recovery-completion-attestation-v1\n"
            "predecessor_completion_attestation_sha=ee\n"
            "predecessor_completion_signature_sha=ff\n"
            "predecessor_completion_public_key_sha=11\n"
            "predecessor_recovery_completion_kind=holdfast-rikune-recovery-resume-completion-v1\n"
            "predecessor_recovery_completion_archive=APPLY-RECOVERY-COMPLETE-attempt.json\n"
            "predecessor_recovery_completion_archive_sha=55\n"
            "predecessor_recovery_completion_receipt=APPLY-RECOVERY-COMPLETE-attempt.receipt\n"
            "predecessor_recovery_completion_receipt_sha=66\n"
            "predecessor_recovery_completion_armed_receipt=APPLY-RECOVERY-ARMED-attempt.receipt\n"
            "predecessor_recovery_completion_armed_receipt_sha=77\n"
            "predecessor_recovery_completion_failure_receipt=APPLY-ACTIVATION-FAILED-attempt.receipt\n"
            "predecessor_recovery_completion_failure_receipt_sha=88\n"
            "predecessor_release_sha=22\n"
            "predecessor_runtime_receipt_sha=33\n"
            "predecessor_runtime_manifest_sha=44\n"
            "predecessor_generation=3\n"
            "release_generation=4\n"
            "successor_policy_schema=$1\n"
            "append_successor_receipt_fields\n",
            encoding="utf-8",
        )
        harness.chmod(0o755)
        legacy = subprocess.run(
            ["bash", str(harness), "2"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(
            legacy,
            "successor=true\n"
            "successor_armed_receipt=SUCCESSOR-ARMED.receipt\n"
            "successor_armed_receipt_sha256=aa\n"
            "predecessor_current_file=PREDECESSOR-CURRENT.json\n"
            "predecessor_current_sha256=bb\n"
            "predecessor_backup_dir=/secure/backups/predecessor\n"
            "predecessor_control_sha256=cc\n"
            "predecessor_apply_receipt_sha256=dd\n"
            "predecessor_release_evidence_sha256=22\n"
            "predecessor_runtime_backup_receipt_sha256=33\n"
            "predecessor_runtime_backup_manifest_sha256=44\n"
            "predecessor_release_generation=3\n"
            "release_generation=4\n",
        )
        recovered = subprocess.run(
            ["bash", str(harness), "3"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertNotIn("predecessor_apply_receipt_sha256", recovered)
        self.assertIn(
            "predecessor_completion_kind=recovery-completion-attestation-v1\n",
            recovered,
        )
        self.assertIn("predecessor_completion_attestation_sha256=ee\n", recovered)
        self.assertIn("predecessor_completion_signature_sha256=ff\n", recovered)
        self.assertIn("predecessor_completion_public_key_sha256=11\n", recovered)
        schema4 = subprocess.run(
            ["bash", str(harness), "4"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(schema4, legacy)
        self.assertNotIn("predecessor_completion_", schema4)
        schema5 = subprocess.run(
            ["bash", str(harness), "5"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertNotIn("predecessor_apply_receipt_sha256", schema5)
        self.assertNotIn("predecessor_completion_", schema5)
        self.assertIn(
            "predecessor_recovery_completion_kind="
            "holdfast-rikune-recovery-resume-completion-v1\n",
            schema5,
        )
        self.assertIn(
            "predecessor_recovery_completion_archive="
            "APPLY-RECOVERY-COMPLETE-attempt.json\n",
            schema5,
        )
        self.assertIn(
            "predecessor_recovery_completion_failure_receipt_sha256=88\n",
            schema5,
        )
        self.assertNotIn("access_candidate_tool_revision", script)

        apply_receipt_start = script.index('apply_receipt_tmp="$backup/.APPLY.receipt.$$"')
        apply_receipt_end = script.index(
            'commit_atomic_file "$apply_receipt_tmp" "$pending_apply_receipt"',
            apply_receipt_start,
        )
        apply_receipt_body = script[apply_receipt_start:apply_receipt_end]
        frozen_runtime = apply_receipt_body.index(
            '"$successor_policy_schema" == "4"'
        )
        runtime_receipt = apply_receipt_body.index(
            "runtime_backup_receipt_sha256=%s", frozen_runtime
        )
        runtime_manifest = apply_receipt_body.index(
            "runtime_backup_manifest_sha256=%s", runtime_receipt
        )
        frozen_end = apply_receipt_body.index("\n  fi", runtime_manifest)
        self.assertLess(frozen_runtime, runtime_receipt)
        self.assertLess(runtime_receipt, runtime_manifest)
        self.assertLess(runtime_manifest, frozen_end)

    def test_schema_v5_apply_consumes_recovered_gen5_without_ordinary_apply(
        self,
    ) -> None:
        apply_source = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        dry_run_source = (OPS_ROOT / "dry-run.sh").read_text(encoding="utf-8")
        self.assertIn("holdfast-rikune-recovery-resume-completion-v1", apply_source)
        self.assertIn("--validate-gen5-lineage", apply_source)
        self.assertIn("--recovery-completion-root", apply_source)
        self.assertIn("persist_v5_recovery_completion_authority", apply_source)
        self.assertIn(".predecessor_binding.recovery_completion", apply_source)
        self.assertIn('"$successor_policy_schema" == "5"', apply_source)
        self.assertIn(
            "release_generation=$((predecessor_generation + 1))", apply_source
        )
        self.assertIn("recovered predecessor must not contain APPLY.receipt", apply_source)
        for field in (
            "predecessor_recovery_completion_archive",
            "predecessor_recovery_completion_receipt",
            "predecessor_recovery_completion_armed_receipt",
            "predecessor_recovery_completion_failure_receipt",
        ):
            self.assertIn(field, apply_source)
            self.assertIn(field, dry_run_source)
        self.assertIn(
            'elif [[ "$successor_policy_schema" == "5" ]]', dry_run_source
        )

    def test_schema_v5_dry_run_passes_recovery_root_to_actual_render_call(
        self,
    ) -> None:
        source = (OPS_ROOT / "dry-run.sh").read_text(encoding="utf-8")
        start = source.index("render_args=(")
        invocation = 'python3 "$script_dir/render.py" "${render_args[@]}"'
        end = source.index(invocation, start) + len(invocation)
        render_block = source[start:end]
        harness = self.root / "dry-run-render-args.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            "python3() { printf '%s\\n' \"$@\"; }\n"
            "script_dir=/ops/holdfast\n"
            "estate_root=/estate\n"
            "output=/dry-run\n"
            "release_env=/dry-run/inputs/release.env\n"
            "secret_env=/dry-run/inputs/secret.env\n"
            "successor=true\n"
            "current_state=/state/CURRENT.json\n"
            "predecessor_candidate=/candidate\n"
            "predecessor_stage=/predecessor-stage\n"
            "recovery_completion_root=/state/recovery-completion\n"
            "successor_policy_schema=$1\n"
            f"{render_block}\n",
            encoding="utf-8",
        )
        harness.chmod(0o755)
        schema5 = subprocess.run(
            ["bash", str(harness), "5"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        self.assertEqual(schema5[0], "/ops/holdfast/render.py")
        recovery_index = schema5.index("--recovery-completion-root")
        self.assertEqual(schema5[recovery_index + 1], "/state/recovery-completion")
        schema4 = subprocess.run(
            ["bash", str(harness), "4"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        self.assertNotIn("--recovery-completion-root", schema4)


if __name__ == "__main__":
    unittest.main()
