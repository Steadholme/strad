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
        snapshot_create = script.index("build_snapshot=$(mktemp -d")
        snapshot_copy = script.index('cp -a -- "$candidate_root/."')
        ignored_debris_guard = script.index("ignored_entry=$(find")
        snapshot_freeze = script.index(
            'find "$snapshot_candidate" -type f -exec chmod 0400'
        )
        semantic_verify = script.index("--expected-mode successor-catalog")
        docker_build = script.index("docker buildx build")
        self.assertLess(snapshot_create, snapshot_copy)
        self.assertLess(snapshot_copy, ignored_debris_guard)
        self.assertLess(ignored_debris_guard, snapshot_freeze)
        self.assertLess(snapshot_freeze, semantic_verify)
        self.assertLess(semantic_verify, docker_build)
        self.assertIn("trap cleanup_snapshot EXIT", script)
        self.assertIn('rm -rf --one-file-system -- "$build_snapshot"', script)
        self.assertIn('require_control_file "$evidence"', script)
        self.assertIn('require_control_file "$targets"', script)
        self.assertIn('require_control_file "$render_inputs"', script)
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

    def test_apply_preflights_before_backup_and_fully_rebinds_after_backup(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        first_rebind = script.index("\nverify_release_bindings\n")
        first_preflight = script.index('"$script_dir/estate_transaction.py" preflight')
        runtime_backup = script.index('"$script_dir/runtime-backup.sh"')
        second_rebind = script.index("\nverify_release_bindings\n", first_rebind + 1)
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

    def test_apply_proves_closed_ingress_before_success_receipt_and_state(self) -> None:
        script = (OPS_ROOT / "apply.sh").read_text(encoding="utf-8")
        closed_function = script[
            script.index("verify_closed_bracket() {") : script.index(
                "prior_running_services=()"
            )
        ]
        first_db = closed_function.index("verify_database_absent")
        public = closed_function.index(
            'public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/'
        )
        second_db = closed_function.index("verify_database_absent", first_db + 1)
        self.assertLess(first_db, public)
        self.assertLess(public, second_db)

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
                for line in route_up_lines
            ),
            "apply may freeze route-up authority but must never execute it",
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
        second_rebind = script.index("\nverify_release_bindings\n", exit_trap)
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


if __name__ == "__main__":
    unittest.main()
