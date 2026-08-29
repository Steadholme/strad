from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


OPS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS_ROOT))

import render  # noqa: E402
import render_input_binding  # noqa: E402
import recovery_completion_attestation  # noqa: E402
import successor_binding  # noqa: E402


class SuccessorBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-successor-")
        self.root = Path(self.temp.name)
        self.completion_index = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_policy(self, policy: dict[str, object], name: str) -> Path:
        path = self.root / name
        path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        return path

    def current_policy(self) -> dict[str, object]:
        return json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )

    def legacy_policy(
        self,
        schema_version: int,
        policy: dict[str, object] | None = None,
    ) -> dict[str, object]:
        self.assertIn(schema_version, (1, 2))
        legacy = copy.deepcopy(
            self.current_policy() if policy is None else policy
        )
        legacy["schema_version"] = schema_version
        legacy["ceremony"] = f"holdfast-rikune-successor-v{schema_version}"
        predecessor = legacy["predecessor"]
        assert isinstance(predecessor, dict)
        predecessor.pop("completion", None)
        predecessor["apply_receipt_sha256"] = hashlib.sha256(
            b"holdfast-test-legacy-apply-receipt"
        ).hexdigest()
        if schema_version == 1:
            predecessor["access_build_input_schema"] = (
                successor_binding.BUILD_INPUT_V1
            )
        return legacy

    def synthetic_access_overlay(
        self, count: int = 7
    ) -> list[dict[str, object]]:
        return [
            {
                "path": f"access-governance/src/legacy_overlay_{index:02d}.rs",
                "before_sha256": None,
                "after_sha256": f"{index + 1:064x}",
            }
            for index in range(count)
        ]

    def copy_successor_authority(self, name: str) -> Path:
        authority = self.root / name
        authority.mkdir()
        for relative in render_input_binding.SUCCESSOR_BOUND_INPUTS:
            shutil.copyfile(OPS_ROOT / relative, authority / relative)
        for _, relative in successor_binding.SUCCESSOR_STATIC_ASSET_SOURCES:
            destination = authority / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(OPS_ROOT / relative, destination)
        return authority

    def invoke_render_authority_seam(
        self, name: str, mutation: str | None
    ) -> tuple[int | SystemExit, list[object]]:
        authority = self.copy_successor_authority(f"{name}-authority")
        policy_path = authority / "successor-policy.json"
        original_policy = policy_path.read_bytes()
        policy = json.loads(original_policy)
        reordered_policy = (
            json.dumps(
                {key: policy[key] for key in reversed(tuple(policy))},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        self.assertEqual(json.loads(original_policy), json.loads(reordered_policy))
        self.assertNotEqual(original_policy, reordered_policy)
        replacement_authority = (
            self.copy_successor_authority(f"{name}-replacement-authority")
            if mutation == "replace-authority"
            else None
        )

        estate = self.root / f"{name}-estate"
        (estate / "access-governance").mkdir(parents=True)
        stage_parent = self.root / f"{name}-output"
        stage_parent.mkdir()
        stage = stage_parent / "stage"
        current_state = self.root / f"{name}-CURRENT.json"
        predecessor_candidate = self.root / f"{name}-candidate"
        predecessor_stage = self.root / f"{name}-predecessor-stage"
        context = {
            "policy": policy,
            "predecessor_candidate": predecessor_candidate,
            "successor_preimages": {},
            "successor_static_targets": {},
            "successor_supporting_targets": {},
        }
        full_render = mutation == "full-stable"
        argv = [
            "render.py",
            "--estate-root",
            str(estate),
            "--stage-root",
            str(stage),
            "--successor",
            "--current-state",
            str(current_state),
            "--predecessor-candidate",
            str(predecessor_candidate),
            "--predecessor-stage",
            str(predecessor_stage),
        ]
        if full_render:
            argv.extend(
                (
                    "--release-env",
                    str(self.root / f"{name}-release.env"),
                    "--secret-env",
                    str(self.root / f"{name}-secret.env"),
                )
            )
        else:
            argv.extend(("--catalog-only", "--release-tool-revision", "a" * 40))

        def copy_stage(*args: object, **_kwargs: object) -> None:
            rendered_stage = args[2]
            assert isinstance(rendered_stage, Path)
            rendered_stage.mkdir(mode=0o700)

        def validate_predecessor(**_kwargs: object) -> dict[str, object]:
            if mutation == "validator-transient-reorder":
                pinned_policy = _kwargs["policy_path"]
                assert isinstance(pinned_policy, Path)
                self.assertNotEqual(pinned_policy, policy_path)
                self.assertEqual(pinned_policy.read_bytes(), original_policy)
                policy_path.write_bytes(reordered_policy)
                self.assertEqual(json.loads(policy_path.read_bytes()), policy)
                self.assertEqual(pinned_policy.read_bytes(), original_policy)
                policy_path.write_bytes(original_policy)
            return context

        def read_private_env_snapshot(
            _path: Path,
            label: str,
            _allow_empty: bool = False,
        ) -> tuple[dict[str, str], str]:
            if label == "release":
                return {"HOLDFAST_RELEASE_TOOL_REVISION": "a" * 40}, "b" * 64
            return {}, "c" * 64

        def validate_render(*args: object, **_kwargs: object) -> None:
            if mutation != "validator-replace-stage":
                return
            rendered_stage = args[0]
            assert isinstance(rendered_stage, Path)
            rendered_stage.rename(self.root / f"{name}-validated-stage")
            rendered_stage.mkdir(mode=0o700)

        def write_evidence(*args: object, **_kwargs: object) -> None:
            rendered_stage = args[0]
            assert isinstance(rendered_stage, Path)
            if mutation == "transient-reorder":
                policy_path.write_bytes(reordered_policy)
            render_input_binding.write_binding(
                authority,
                rendered_stage / "RENDER-INPUTS.sha256",
                successor=True,
            )
            if mutation == "transient-reorder":
                policy_path.write_bytes(original_policy)
            elif mutation == "whitespace":
                policy_path.write_bytes(original_policy.rstrip() + b" \n")
            elif mutation == "replace-authority":
                assert replacement_authority is not None
                authority.rename(self.root / f"{name}-original-authority")
                replacement_authority.rename(authority)
            elif mutation == "replace-stage":
                original_stage = self.root / f"{name}-original-stage"
                rendered_stage.rename(original_stage)
                rendered_stage.mkdir(mode=0o700)
                shutil.copyfile(
                    original_stage / "RENDER-INPUTS.sha256",
                    rendered_stage / "RENDER-INPUTS.sha256",
                )

        snapshot_validator = mock.Mock()
        full_renderer = mock.Mock()

        with mock.patch.object(render, "OPS_ROOT", authority), mock.patch.object(
            sys, "argv", argv
        ), mock.patch.object(
            render, "validate_predecessor", side_effect=validate_predecessor
        ), mock.patch.object(
            render, "validate_release"
        ), mock.patch.object(
            render, "validate_successor_release"
        ), mock.patch.object(
            render, "validate_tool_revision"
        ), mock.patch.object(
            render, "copy_successor_stage", side_effect=copy_stage
        ), mock.patch.object(
            render,
            "validate_successor_snapshot",
            snapshot_validator,
        ), mock.patch.object(
            render,
            "read_private_env_snapshot",
            side_effect=read_private_env_snapshot,
        ), mock.patch.object(
            render,
            "render_full_env",
            full_renderer,
        ), mock.patch.object(
            render, "validate_render", side_effect=validate_render
        ), mock.patch.object(
            render, "write_evidence", side_effect=write_evidence
        ), mock.patch.object(
            render, "run_checked"
        ), mock.patch(
            "builtins.print"
        ) as printer:
            try:
                outcome: int | SystemExit = render.main()
            except SystemExit as error:
                outcome = error
            calls = list(printer.call_args_list)
        if full_render:
            self.assertEqual(snapshot_validator.call_count, 1)
            self.assertEqual(full_renderer.call_count, 1)
        return outcome, calls

    def v3_policy(
        self, completion: dict[str, object] | None = None
    ) -> dict[str, object]:
        policy = self.current_policy()
        policy["schema_version"] = 3
        policy["ceremony"] = "holdfast-rikune-successor-v3"
        predecessor = policy["predecessor"]
        assert isinstance(predecessor, dict)
        predecessor.pop("apply_receipt_sha256", None)
        predecessor["access_build_input_schema"] = successor_binding.BUILD_INPUT_V2
        predecessor["completion"] = completion or {
            "kind": recovery_completion_attestation.KIND,
            "attestation_sha256": "a" * 64,
            "signature_sha256": "b" * 64,
            "public_key_sha256": "c" * 64,
        }
        return policy

    def issue_recovery_completion(
        self,
        predecessor: dict[str, object],
        estate_root: Path,
        backup_dir: Path,
        name: str,
        artifact_hashes: dict[str, str] | None = None,
    ) -> tuple[Path, dict[str, object], dict[str, object]]:
        artifact_hashes = artifact_hashes or {}
        release = self.root / name
        release.mkdir(mode=0o700)
        private_key = self.root / f"{name}.key"
        public_key = self.root / f"{name}.pub"
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
        public_key_sha256 = hashlib.sha256(public_key.read_bytes()).hexdigest()
        args = argparse.Namespace(
            release_root=release,
            private_key=private_key,
            source_public_key=public_key,
            public_key_sha256=public_key_sha256,
            recovery_attempt_id="20260828T120000Z-4242",
            prior_failure_receipt=(
                "APPLY-ACTIVATION-FAILED-20260828T115900Z-123.receipt"
            ),
            prior_failure_receipt_sha256="1" * 64,
            apply_armed_at="2026-08-28T11:58:00Z",
            recovery_armed_at="2026-08-28T12:00:00Z",
            recovery_completed_at="2026-08-28T12:00:30Z",
            estate_root=estate_root,
            backup_dir=backup_dir,
            current_sha256=predecessor["current_state_sha256"],
            completion_receipt=(
                "APPLY-RECOVERY-COMPLETE-20260828T120000Z-4242.receipt"
            ),
            completion_receipt_sha256="2" * 64,
            completion_archive=(
                "APPLY-RECOVERY-COMPLETE-20260828T120000Z-4242.json"
            ),
            completion_archive_sha256="3" * 64,
            recovery_armed_receipt=(
                "APPLY-RECOVERY-ARMED-20260828T120000Z-4242.receipt"
            ),
            recovery_armed_receipt_sha256="4" * 64,
            control_sha256=predecessor["control_sha256"],
            release_env_sha256=artifact_hashes.get(
                "release_env_sha256", "5" * 64
            ),
            release_evidence_sha256=predecessor["release_evidence_sha256"],
            transaction_sha256=artifact_hashes.get(
                "transaction_sha256", "6" * 64
            ),
            applied_targets_sha256=artifact_hashes.get(
                "applied_targets_sha256", "7" * 64
            ),
            runtime_receipt_sha256=artifact_hashes.get(
                "runtime_receipt_sha256", "8" * 64
            ),
            runtime_manifest_sha256=predecessor["runtime_manifest_sha256"],
            predecessor_release_generation=2,
            release_generation=3,
        )
        artifact = recovery_completion_attestation.issue(args)
        completion: dict[str, object] = {
            "kind": recovery_completion_attestation.KIND,
            "attestation_sha256": artifact["attestation_sha256"],
            "signature_sha256": artifact["signature_sha256"],
            "public_key_sha256": artifact["public_key_sha256"],
        }
        document = json.loads(
            (release / recovery_completion_attestation.ATTESTATION_NAME).read_text(
                encoding="utf-8"
            )
        )
        return release, completion, document

    def make_recovered_predecessor_fixture(
        self,
    ) -> tuple[
        Path,
        Path,
        Path,
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]:
        self.completion_index += 1
        suffix = str(self.completion_index)
        estate = self.root / f"recovered-estate-{suffix}"
        backup = self.root / f"recovered-backup-{suffix}"
        state_root = self.root / f"recovered-state-{suffix}"
        estate.mkdir(mode=0o700)
        (backup / "runtime").mkdir(parents=True, mode=0o700)
        (backup / "estate").mkdir(mode=0o700)
        state_root.mkdir(mode=0o700)
        artifacts = {
            "control_sha256": backup / "CONTROL.sha256",
            "release_env_sha256": backup / "release.env",
            "release_evidence_sha256": backup / "RELEASE-EVIDENCE.json",
            "transaction_sha256": backup / "estate/TRANSACTION.json",
            "applied_targets_sha256": backup / "estate/APPLIED-TARGETS.sha256",
            "runtime_receipt_sha256": backup / "runtime/BACKUP.receipt",
            "runtime_manifest_sha256": backup / "runtime/SHA256SUMS",
        }
        for index, path in enumerate(artifacts.values(), 1):
            path.write_text(f"recovered artifact {index}\n", encoding="utf-8")
            path.chmod(0o600)
        predecessor = copy.deepcopy(self.current_policy()["predecessor"])
        assert isinstance(predecessor, dict)
        predecessor.pop("apply_receipt_sha256", None)
        predecessor["access_build_input_schema"] = successor_binding.BUILD_INPUT_V2
        for field in (
            "control_sha256",
            "release_evidence_sha256",
            "runtime_manifest_sha256",
        ):
            predecessor[field] = successor_binding.sha256(artifacts[field])
        state = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "successor": True,
            "predecessor_release_generation": 2,
            "release_generation": 3,
            "estate_root": str(estate),
            "backup_dir": str(backup),
            "control_sha256": predecessor["control_sha256"],
            "release_evidence_sha256": predecessor["release_evidence_sha256"],
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
        }
        state_path = state_root / "CURRENT.json"
        state_path.write_text(json.dumps(state, sort_keys=True) + "\n")
        predecessor["current_state_sha256"] = successor_binding.sha256(state_path)
        artifact_hashes = {
            field: successor_binding.sha256(path)
            for field, path in artifacts.items()
        }
        completion_root, completion, document = self.issue_recovery_completion(
            predecessor,
            estate,
            backup,
            f"recovery-completion-{suffix}",
            artifact_hashes,
        )
        predecessor["completion"] = completion
        return state_path, estate, backup, state, predecessor, {
            "root": completion_root,
            "document": document,
            "artifacts": artifacts,
        }

    def test_schema_v3_policy_uses_exact_nested_recovery_completion(self) -> None:
        policy = self.v3_policy()
        validated = successor_binding.validate_policy(
            self.write_policy(policy, "successor-v3.json")
        )
        self.assertEqual(validated["schema_version"], 3)
        self.assertNotIn("apply_receipt_sha256", validated["predecessor"])
        self.assertEqual(
            set(validated["predecessor"]["completion"]),
            successor_binding.RECOVERY_COMPLETION_FIELDS,
        )

        cases: list[tuple[str, dict[str, object], str]] = []
        missing = self.v3_policy()
        del missing["predecessor"]["completion"]["signature_sha256"]
        cases.append(("missing", missing, "field set"))
        extra = self.v3_policy()
        extra["predecessor"]["completion"]["extra"] = True
        cases.append(("extra", extra, "field set"))
        null_hash = self.v3_policy()
        null_hash["predecessor"]["completion"]["attestation_sha256"] = None
        cases.append(("null", null_hash, "lowercase SHA-256"))
        wrong_kind = self.v3_policy()
        wrong_kind["predecessor"]["completion"]["kind"] = "recovery-v2"
        cases.append(("kind", wrong_kind, "kind differs"))
        malformed_hash = self.v3_policy()
        malformed_hash["predecessor"]["completion"]["public_key_sha256"] = (
            "F" * 64
        )
        cases.append(("hash", malformed_hash, "lowercase SHA-256"))
        hybrid = self.v3_policy()
        hybrid["predecessor"]["apply_receipt_sha256"] = "d" * 64
        cases.append(("hybrid", hybrid, "predecessor policy field set"))
        unknown = self.v3_policy()
        unknown["schema_version"] = 4
        unknown["ceremony"] = "holdfast-rikune-successor-v4"
        cases.append(("unknown-v4", unknown, "version or ceremony"))
        for name, candidate, error in cases:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, error):
                successor_binding.validate_policy(
                    self.write_policy(candidate, f"v3-{name}.json")
                )

    def test_recovery_completion_rejects_signature_and_key_tamper(self) -> None:
        _, _, _, _, predecessor, recovery = (
            self.make_recovered_predecessor_fixture()
        )
        completion = predecessor["completion"]
        root = recovery["root"]
        successor_binding.read_recovery_completion_bundle(root, completion)

        signature_path = root / recovery_completion_attestation.SIGNATURE_NAME
        tampered_signature = bytearray(signature_path.read_bytes())
        tampered_signature[0] ^= 0x01
        signature_path.write_bytes(tampered_signature)
        signature_path.chmod(0o600)
        signature_binding = copy.deepcopy(completion)
        signature_binding["signature_sha256"] = hashlib.sha256(
            signature_path.read_bytes()
        ).hexdigest()
        with self.assertRaisesRegex(
            ValueError, "OpenSSL ceremony failed|signature verification failed"
        ):
            successor_binding.read_recovery_completion_bundle(
                root, signature_binding
            )

        _, _, _, _, predecessor, recovery = (
            self.make_recovered_predecessor_fixture()
        )
        root = recovery["root"]
        completion = predecessor["completion"]
        alternate_private = self.root / "alternate.key"
        alternate_public = self.root / "alternate.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(alternate_private),
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
                str(alternate_private),
                "-pubout",
                "-out",
                str(alternate_public),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_path = root / recovery_completion_attestation.PUBLIC_KEY_NAME
        public_path.write_bytes(alternate_public.read_bytes())
        public_path.chmod(0o600)
        key_binding = copy.deepcopy(completion)
        key_binding["public_key_sha256"] = hashlib.sha256(
            public_path.read_bytes()
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "attestation public key pin differs"):
            successor_binding.read_recovery_completion_bundle(root, key_binding)

    def test_recovered_predecessor_cross_checks_current_backup_and_generation(
        self,
    ) -> None:
        state_path, estate, backup, state, predecessor, recovery = (
            self.make_recovered_predecessor_fixture()
        )
        successor_binding.validate_recovered_predecessor(
            completion_root=recovery["root"],
            predecessor=predecessor,
            state_path=state_path,
            state=state,
            estate=estate,
            backup=backup,
        )

        original_current = state_path.read_bytes()
        state_path.write_bytes(original_current + b" ")
        with self.assertRaisesRegex(ValueError, "CURRENT bytes differ"):
            successor_binding.validate_recovered_predecessor(
                completion_root=recovery["root"],
                predecessor=predecessor,
                state_path=state_path,
                state=state,
                estate=estate,
                backup=backup,
            )
        state_path.write_bytes(original_current)

        release_env = recovery["artifacts"]["release_env_sha256"]
        release_env.write_text("tampered release env\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "backup artifact differs"):
            successor_binding.validate_recovered_predecessor(
                completion_root=recovery["root"],
                predecessor=predecessor,
                state_path=state_path,
                state=state,
                estate=estate,
                backup=backup,
            )
        release_env.write_text("recovered artifact 2\n", encoding="utf-8")

        wrong_generation = dict(state)
        wrong_generation["release_generation"] = 4
        state_path.write_text(
            json.dumps(wrong_generation, sort_keys=True) + "\n", encoding="utf-8"
        )
        wrong_predecessor = copy.deepcopy(predecessor)
        wrong_predecessor["current_state_sha256"] = successor_binding.sha256(
            state_path
        )
        artifact_hashes = {
            field: successor_binding.sha256(path)
            for field, path in recovery["artifacts"].items()
        }
        wrong_root, wrong_completion, _ = self.issue_recovery_completion(
            wrong_predecessor,
            estate,
            backup,
            "wrong-generation-completion",
            artifact_hashes,
        )
        wrong_predecessor["completion"] = wrong_completion
        with self.assertRaisesRegex(ValueError, "exactly 2 -> 3"):
            successor_binding.validate_recovered_predecessor(
                completion_root=wrong_root,
                predecessor=wrong_predecessor,
                state_path=state_path,
                state=wrong_generation,
                estate=estate,
                backup=backup,
            )

        state_path.write_bytes(original_current)

        (backup / "APPLY.receipt").write_text("legacy\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must not contain APPLY.receipt"):
            successor_binding.validate_recovered_predecessor(
                completion_root=recovery["root"],
                predecessor=predecessor,
                state_path=state_path,
                state=state,
                estate=estate,
                backup=backup,
            )

    def test_recovery_completion_copies_identical_bytes_and_is_not_render_bound(
        self,
    ) -> None:
        _, estate, backup, _, predecessor, recovery = (
            self.make_recovered_predecessor_fixture()
        )
        completion = predecessor["completion"]
        source = successor_binding.read_recovery_completion_bundle(
            recovery["root"], completion
        )
        recovery["root"].chmod(0o500)
        with self.assertRaisesRegex(ValueError, "mode 0700"):
            successor_binding.read_recovery_completion_bundle(
                recovery["root"], completion
            )
        recovery["root"].chmod(0o700)
        candidate = self.root / "candidate-stage"
        full = self.root / "full-stage"
        candidate.mkdir(mode=0o700)
        full.mkdir(mode=0o700)
        successor_binding.write_recovery_completion_bundle(
            candidate, completion, source
        )
        successor_binding.write_recovery_completion_bundle(full, completion, source)
        render.validate_final_recovery_completion(
            full, completion, source, copy.deepcopy(source)
        )
        for name in successor_binding.RECOVERY_COMPLETION_NAMES:
            self.assertEqual((candidate / name).read_bytes(), (full / name).read_bytes())
            self.assertEqual(stat.S_IMODE((candidate / name).stat().st_mode), 0o600)

        inputs = self.root / "render-inputs.sha256"
        render_input_binding.write_binding(OPS_ROOT, inputs, successor=True)
        bound_names = {
            line.split("  ", 1)[1]
            for line in inputs.read_text(encoding="utf-8").splitlines()
        }
        self.assertTrue(
            set(successor_binding.RECOVERY_COMPLETION_NAMES).isdisjoint(bound_names)
        )
        self.assertEqual(recovery["document"]["estate_root"], str(estate))
        self.assertEqual(recovery["document"]["backup_dir"], str(backup))

        signature = full / recovery_completion_attestation.SIGNATURE_NAME
        signature.write_bytes(b"tampered after initial stage validation")
        signature.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "artifact differs"):
            render.validate_final_recovery_completion(
                full, completion, source, copy.deepcopy(source)
            )

    def test_render_rejects_invalid_completion_before_creating_stage(self) -> None:
        estate = self.root / "render-order-estate"
        (estate / "access-governance").mkdir(parents=True)
        stage = self.root / "render-order-stage"
        argv = [
            "render.py",
            "--estate-root",
            str(estate),
            "--stage-root",
            str(stage),
            "--catalog-only",
            "--successor",
            "--current-state",
            str(self.root / "CURRENT.json"),
            "--predecessor-candidate",
            str(self.root / "candidate"),
            "--predecessor-stage",
            str(self.root / "predecessor-stage"),
            "--recovery-completion-root",
            str(self.root / "invalid-completion"),
        ]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            render,
            "validate_predecessor",
            side_effect=ValueError("invalid recovery completion"),
        ), mock.patch.object(render, "copy_successor_stage") as copier:
            with self.assertRaisesRegex(ValueError, "invalid recovery completion"):
                render.main()
        copier.assert_not_called()
        self.assertFalse(stage.exists())

    def test_render_final_authority_gate_accepts_stable_bytes(self) -> None:
        outcome, prints = self.invoke_render_authority_seam("stable", None)
        self.assertEqual(outcome, 0)
        self.assertEqual(len(prints), 2)

    def test_render_final_authority_gate_preserves_full_render_contract(
        self,
    ) -> None:
        outcome, prints = self.invoke_render_authority_seam(
            "full-stable",
            "full-stable",
        )
        self.assertEqual(outcome, 0)
        self.assertEqual(len(prints), 2)

    def test_render_final_authority_gate_rejects_policy_whitespace_drift(
        self,
    ) -> None:
        outcome, prints = self.invoke_render_authority_seam(
            "whitespace-drift", "whitespace"
        )
        self.assertIsInstance(outcome, SystemExit)
        self.assertIn(
            "successor authority raw bytes changed during render: "
            "successor-policy.json",
            str(outcome),
        )
        self.assertEqual(prints, [])

    def test_render_final_authority_gate_rejects_transient_policy_reorder(
        self,
    ) -> None:
        outcome, prints = self.invoke_render_authority_seam(
            "transient-reorder", "transient-reorder"
        )
        self.assertIsInstance(outcome, SystemExit)
        self.assertIn(
            "RENDER-INPUTS differs from initial successor authority: "
            "successor-policy.json",
            str(outcome),
        )
        self.assertEqual(prints, [])

    def test_render_final_authority_gate_rejects_authority_root_replacement(
        self,
    ) -> None:
        outcome, prints = self.invoke_render_authority_seam(
            "replace-authority", "replace-authority"
        )
        self.assertIsInstance(outcome, SystemExit)
        self.assertIn(
            "successor authority root identity changed during render",
            str(outcome),
        )
        self.assertEqual(prints, [])

    def test_render_final_authority_gate_rejects_stage_root_replacement(
        self,
    ) -> None:
        outcome, prints = self.invoke_render_authority_seam(
            "replace-stage", "replace-stage"
        )
        self.assertIsInstance(outcome, SystemExit)
        self.assertIn(
            "successor stage root identity changed during render",
            str(outcome),
        )
        self.assertEqual(prints, [])

    def test_render_validator_uses_pinned_authority_during_transient_reorder(
        self,
    ) -> None:
        outcome, prints = self.invoke_render_authority_seam(
            "validator-transient-reorder",
            "validator-transient-reorder",
        )
        self.assertEqual(outcome, 0)
        self.assertEqual(len(prints), 2)

    def test_render_rejects_stage_replacement_at_validator_return(
        self,
    ) -> None:
        outcome, prints = self.invoke_render_authority_seam(
            "validator-replace-stage",
            "validator-replace-stage",
        )
        self.assertIsInstance(outcome, SystemExit)
        self.assertIn(
            "successor stage root identity changed during render",
            str(outcome),
        )
        self.assertEqual(prints, [])

    def test_authority_snapshot_rejects_directory_replacement_mid_read(
        self,
    ) -> None:
        authority = self.copy_successor_authority("mid-read-authority")
        replacement = self.copy_successor_authority("mid-read-replacement")
        displaced = self.root / "mid-read-displaced"
        identity = render.stable_directory_path_identity(
            authority,
            "successor authority",
        )
        real_reader = render.read_successor_authority_bytes
        replaced = False

        def replacing_reader(
            directory: int,
            name: str,
            label: str = "successor authority",
        ) -> bytes:
            nonlocal replaced
            raw = real_reader(directory, name, label)
            if not replaced:
                authority.rename(displaced)
                replacement.rename(authority)
                replaced = True
            return raw

        with mock.patch.object(
            render,
            "read_successor_authority_bytes",
            side_effect=replacing_reader,
        ), self.assertRaisesRegex(
            SystemExit,
            "root (changed during snapshot|path mapping changed)",
        ):
            render.snapshot_successor_authority(authority, identity)
        self.assertTrue(replaced)

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
        os.mkfifo(access / "ignored-runtime.log")
        self.assertEqual(
            render_input_binding.access_build_input_sha_v2(stage), baseline
        )

        (access / "src").mkdir()
        (access / "src/lib.rs").write_text("pub fn bound() {}\n")
        self.assertNotEqual(
            render_input_binding.access_build_input_sha_v2(stage), baseline
        )

    def test_v2_secure_build_identity_preserves_exact_digest_framing(self) -> None:
        access = self.root / "secure-access"
        nested = access / "a"
        nested.mkdir(parents=True)
        files = {
            "a/z.txt": b"nested\n",
            "b.txt": b"root\n",
        }
        for relative, content in files.items():
            (access / relative).write_bytes(content)
        expected = hashlib.sha256()
        for relative in sorted(files):
            expected.update(relative.encode("utf-8"))
            expected.update(b"\0")
            expected.update(
                hashlib.sha256(files[relative]).hexdigest().encode("ascii")
            )
            expected.update(b"\n")

        self.assertEqual(
            render_input_binding.access_tree_build_input_sha_v2(access),
            expected.hexdigest(),
        )
        self.assertEqual(
            render_input_binding.access_tree_build_input_sha_v2(
                access, require_root_owner=True
            ),
            expected.hexdigest(),
        )

    def test_v2_secure_build_identity_rejects_writable_and_aliased_entries(
        self,
    ) -> None:
        writable_file_root = self.root / "writable-file"
        writable_file_root.mkdir()
        writable_file = writable_file_root / "Cargo.toml"
        writable_file.write_text("[package]\n")
        writable_file.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "group/world-writable"):
            render_input_binding.access_tree_build_input_sha_v2(
                writable_file_root, require_root_owner=True
            )

        writable_directory_root = self.root / "writable-directory"
        writable_directory = writable_directory_root / "src"
        writable_directory.mkdir(parents=True)
        (writable_directory / "lib.rs").write_text("pub fn fixture() {}\n")
        writable_directory.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, "group/world-writable"):
            render_input_binding.access_tree_build_input_sha_v2(
                writable_directory_root, require_root_owner=True
            )

        writable_root = self.root / "writable-root"
        writable_root.mkdir(mode=0o777)
        writable_root.chmod(0o777)
        (writable_root / "Cargo.toml").write_text("[package]\n")
        with self.assertRaisesRegex(RuntimeError, "group/world-writable"):
            render_input_binding.access_tree_build_input_sha_v2(
                writable_root, require_root_owner=True
            )

        non_root_owner_root = self.root / "non-root-owner"
        non_root_owner_root.mkdir()
        non_root_owner_file = non_root_owner_root / "Cargo.toml"
        non_root_owner_file.write_text("[package]\n")
        os.chown(non_root_owner_file, 65534, -1)
        with self.assertRaisesRegex(RuntimeError, "root-owned"):
            render_input_binding.access_tree_build_input_sha_v2(
                non_root_owner_root, require_root_owner=True
            )

        non_root_directory_root = self.root / "non-root-directory"
        non_root_directory = non_root_directory_root / "src"
        non_root_directory.mkdir(parents=True)
        (non_root_directory / "lib.rs").write_text("pub fn fixture() {}\n")
        os.chown(non_root_directory, 65534, -1)
        with self.assertRaisesRegex(RuntimeError, "root-owned"):
            render_input_binding.access_tree_build_input_sha_v2(
                non_root_directory_root, require_root_owner=True
            )

        hardlink_root = self.root / "hardlink"
        hardlink_root.mkdir()
        hardlink_target = hardlink_root / "Cargo.toml"
        hardlink_target.write_text("[package]\n")
        (hardlink_root / "Cargo-copy.toml").hardlink_to(hardlink_target)
        with self.assertRaisesRegex(RuntimeError, "single-link regular file"):
            render_input_binding.access_tree_build_input_sha_v2(hardlink_root)

        symlink_root = self.root / "symlink"
        symlink_root.mkdir()
        symlink_target = symlink_root / "Cargo.toml"
        symlink_target.write_text("[package]\n")
        (symlink_root / "Cargo-link.toml").symlink_to(symlink_target)
        with self.assertRaisesRegex(RuntimeError, "contains a symlink"):
            render_input_binding.access_tree_build_input_sha_v2(symlink_root)

        writer_root = self.root / "existing-writer"
        writer_root.mkdir()
        writer_target = writer_root / "Cargo.toml"
        writer_target.write_text("[package]\n")
        writer = os.open(writer_target, os.O_WRONLY)
        try:
            with self.assertRaisesRegex(RuntimeError, "read lease"):
                render_input_binding.access_tree_build_input_sha_v2(
                    writer_root, require_root_owner=True
                )
        finally:
            os.close(writer)

    def test_v2_secure_build_identity_rejects_inode_swap_between_stat_and_open(
        self,
    ) -> None:
        access = self.root / "racing-access"
        access.mkdir()
        target = access / "Cargo.toml"
        target.write_text("[package]\nname='before'\n")
        replacement = self.root / "replacement-Cargo.toml"
        replacement.write_text("[package]\nname='after'\n")
        real_open = os.open
        swapped = False

        def racing_open(
            path: str,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if (
                path == "Cargo.toml"
                and dir_fd is not None
                and not flags & os.O_DIRECTORY
                and not swapped
            ):
                replacement.replace(target)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(
            render_input_binding.os, "open", side_effect=racing_open
        ), self.assertRaisesRegex(RuntimeError, "changed while opening"):
            render_input_binding.access_tree_build_input_sha_v2(access)
        self.assertTrue(swapped)

    def test_v2_secure_build_identity_rejects_prior_file_change_during_scan(
        self,
    ) -> None:
        access = self.root / "post-read-race"
        access.mkdir()
        first = access / "a.txt"
        first.write_text("before\n")
        (access / "b.txt").write_text("trigger\n")
        real_reader = render_input_binding.read_descriptor_sha256
        real_snapshot = render_input_binding.stable_stat_snapshot
        mutated = False

        def coarse_snapshot(metadata: os.stat_result) -> tuple[int, ...]:
            snapshot = real_snapshot(metadata)
            return (*snapshot[:-2], 0, 0)

        def racing_reader(descriptor: int) -> str:
            nonlocal mutated
            opened = os.readlink(f"/proc/self/fd/{descriptor}")
            if opened.endswith("/b.txt") and not mutated:
                first.write_text("after!\n")
                mutated = True
            return real_reader(descriptor)

        with mock.patch.object(
            render_input_binding,
            "stable_stat_snapshot",
            side_effect=coarse_snapshot,
        ), mock.patch.object(
            render_input_binding,
            "read_descriptor_sha256",
            side_effect=racing_reader,
        ), self.assertRaisesRegex(RuntimeError, "digest changed"):
            render_input_binding.access_tree_build_input_sha_v2(access)
        self.assertTrue(mutated)

    def test_v2_secure_build_identity_rejects_same_tick_in_read_change(
        self,
    ) -> None:
        access = self.root / "in-read-race"
        access.mkdir()
        target = access / "large.bin"
        target.write_bytes(b"a" * (2 * 1024 * 1024))
        real_read = os.read
        real_snapshot = render_input_binding.stable_stat_snapshot
        mutated = False

        def coarse_snapshot(metadata: os.stat_result) -> tuple[int, ...]:
            snapshot = real_snapshot(metadata)
            return (*snapshot[:-2], 0, 0)

        def racing_read(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            block = real_read(descriptor, size)
            opened = os.readlink(f"/proc/self/fd/{descriptor}")
            if (
                opened.endswith("/large.bin")
                and len(block) == 1024 * 1024
                and not mutated
            ):
                target.write_bytes(b"b" * (2 * 1024 * 1024))
                mutated = True
            return block

        with mock.patch.object(
            render_input_binding,
            "stable_stat_snapshot",
            side_effect=coarse_snapshot,
        ), mock.patch.object(
            render_input_binding.os,
            "read",
            side_effect=racing_read,
        ), self.assertRaisesRegex(RuntimeError, "digest changed"):
            render_input_binding.access_tree_build_input_sha_v2(access)
        self.assertTrue(mutated)

    def test_v2_secure_build_identity_rejects_directory_entry_race(self) -> None:
        access = self.root / "directory-race"
        access.mkdir()
        (access / "Cargo.toml").write_text("[package]\n")
        extra = access / "late.txt"
        real_listdir = os.listdir
        injected = False

        def racing_listdir(path: int | str | bytes | os.PathLike[str]) -> list[str]:
            nonlocal injected
            names = real_listdir(path)
            if isinstance(path, int) and not injected:
                opened = os.readlink(f"/proc/self/fd/{path}")
                if opened.rstrip("/") == str(access):
                    extra.write_text("late\n")
                    injected = True
            return names

        with mock.patch.object(
            render_input_binding.os, "listdir", side_effect=racing_listdir
        ), self.assertRaisesRegex(RuntimeError, "directory entries changed"):
            render_input_binding.access_tree_build_input_sha_v2(access)
        self.assertTrue(injected)

    def test_v2_secure_build_identity_rejects_root_alias_without_fd_leak(
        self,
    ) -> None:
        descriptors = Path("/proc/self/fd")
        before = len(list(descriptors.iterdir()))
        for _ in range(4):
            with self.assertRaisesRegex(RuntimeError, "unsafe binding root"):
                render_input_binding.access_tree_build_input_sha_v2(Path("//"))
        self.assertEqual(len(list(descriptors.iterdir())), before)

    def test_build_identity_dispatches_v1_and_v2_and_rejects_unknown_schema(
        self,
    ) -> None:
        stage = self.root / "schema-stage"
        access = stage / "access-governance"
        access.mkdir(parents=True)
        (access / "Cargo.toml").write_text("[package]\nname='fixture'\n")
        workflow = access / ".workflow/session"
        workflow.mkdir(parents=True)
        (workflow / "state.json").write_text("{}\n")

        self.assertEqual(
            render_input_binding.access_build_input_sha_for_schema(
                stage, successor_binding.BUILD_INPUT_V1
            ),
            render_input_binding.access_build_input_sha(stage),
        )
        self.assertEqual(
            render_input_binding.access_build_input_sha_for_schema(
                stage, successor_binding.BUILD_INPUT_V2
            ),
            render_input_binding.access_build_input_sha_v2(stage),
        )
        self.assertNotEqual(
            render_input_binding.access_build_input_sha(stage),
            render_input_binding.access_build_input_sha_v2(stage),
        )
        with self.assertRaisesRegex(RuntimeError, "unsupported"):
            render_input_binding.access_build_input_sha_for_schema(
                stage, "access-build-input/3"
            )

    def test_exact_policy_delta_rejects_every_extra_change(self) -> None:
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
        original_before = overlay[0]["before_sha256"]
        overlay[0]["before_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "predecessor hash differs"):
            successor_binding.validate_source_delta(policy, predecessor, live)
        overlay[0]["before_sha256"] = original_before
        original_after = overlay[0]["after_sha256"]
        overlay[0]["after_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "successor hash differs"):
            successor_binding.validate_source_delta(policy, predecessor, live)
        overlay[0]["after_sha256"] = original_after
        shared_after.write_text("extra drift\n")
        with self.assertRaisesRegex(ValueError, "exact policy overlay"):
            successor_binding.validate_source_delta(policy, predecessor, live)

    def test_legacy_seven_path_policy_remains_valid(self) -> None:
        legacy = self.legacy_policy(1)
        legacy["overlay"] = self.synthetic_access_overlay()
        validated = successor_binding.validate_policy(
            self.write_policy(legacy, "legacy-seven-path.json")
        )
        self.assertEqual(len(validated["overlay"]), 7)
        legacy["overlay"].reverse()
        successor_binding.validate_policy(
            self.write_policy(legacy, "legacy-unsorted.json")
        )

    def test_policy_overlay_is_nonempty_sorted_unique_bounded_and_scoped(
        self,
    ) -> None:
        original = list(self.legacy_policy(2)["overlay"])

        cases: list[tuple[str, list[dict[str, object]], str]] = [
            ("empty", [], "size differs"),
            ("unsorted", list(reversed(original)), "must be sorted"),
            ("duplicate", [original[0], original[0]], "duplicate"),
        ]
        over_limit = [
            {
                "path": f"access-governance/src/generated_{index:02d}.rs",
                "before_sha256": None,
                "after_sha256": f"{index + 1:064x}",
            }
            for index in range(successor_binding.MAX_SUCCESSOR_OVERLAY_PATHS + 1)
        ]
        cases.append(("over-limit", over_limit, "size differs"))
        outside = [dict(original[0])]
        outside[0]["path"] = "rikune/src/main.rs"
        cases.append(("outside-access", outside, "outside Access"))
        traversal = [dict(original[0])]
        traversal[0]["path"] = "access-governance/../rikune/main.rs"
        cases.append(("path-traversal", traversal, "safe relative path"))
        alias = [dict(original[0])]
        alias[0]["path"] = "access-governance/src/./main.rs"
        cases.append(("path-alias", alias, "safe relative path"))

        for name, overlay, message in cases:
            with self.subTest(name=name):
                policy = self.legacy_policy(2)
                policy["overlay"] = overlay
                path = self.write_policy(policy, f"{name}.json")
                with self.assertRaisesRegex(ValueError, message):
                    successor_binding.validate_policy(path)

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

    def test_generation_three_accepts_v2_predecessor_with_new_and_modified_overlay(
        self,
    ) -> None:
        candidate = self.root / "generation-2-candidate"
        candidate_access = candidate / "access-governance"
        candidate_access.mkdir(parents=True)
        modified_before = candidate_access / "src/modified.rs"
        modified_before.parent.mkdir(parents=True)
        modified_before.write_text("before\n")
        (candidate_access / "Cargo.toml").write_text("[package]\nname='candidate'\n")

        live_access = self.root / "generation-3-live-access"
        shutil.copytree(candidate_access, live_access)
        modified_after = live_access / "src/modified.rs"
        modified_after.write_text("after\n")
        new_after = live_access / "src/new.rs"
        new_after.write_text("new\n")

        build_input = render_input_binding.access_build_input_sha_for_schema(
            candidate, successor_binding.BUILD_INPUT_V2
        )
        evidence = {
            "schema_version": 2,
            "access_governance_build_input_schema": successor_binding.BUILD_INPUT_V2,
            "access_governance_build_input_sha256": build_input,
            "release": {
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": build_input,
            },
        }
        (candidate / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(evidence) + "\n"
        )
        stage = self.root / "generation-2-stage"
        stage.mkdir(mode=0o700)
        (stage / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(evidence) + "\n"
        )

        overlay = [
            {
                "path": "access-governance/src/modified.rs",
                "before_sha256": successor_binding.sha256(modified_before),
                "after_sha256": successor_binding.sha256(modified_after),
            },
            {
                "path": "access-governance/src/new.rs",
                "before_sha256": None,
                "after_sha256": successor_binding.sha256(new_after),
            },
        ]
        policy = self.legacy_policy(2)
        predecessor = policy["predecessor"]
        predecessor["access_build_input_schema"] = successor_binding.BUILD_INPUT_V2
        predecessor["access_build_input_sha256"] = build_input
        policy["overlay"] = overlay
        policy_path = self.write_policy(policy, "generation-3-policy.json")

        validated = successor_binding.validate_policy(policy_path)
        successor_binding.validate_predecessor_access_identity(
            candidate, stage, validated["predecessor"]
        )
        successor_binding.validate_source_delta(
            validated, candidate_access, live_access
        )

        wrong_hash = dict(validated["predecessor"])
        wrong_hash["access_build_input_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "build input differs"):
            successor_binding.validate_predecessor_access_identity(
                candidate, stage, wrong_hash
            )

        wrong_evidence = dict(evidence)
        wrong_evidence["access_governance_build_input_schema"] = (
            successor_binding.BUILD_INPUT_V1
        )
        (candidate / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(wrong_evidence) + "\n"
        )
        with self.assertRaisesRegex(ValueError, "schema evidence differs"):
            successor_binding.validate_predecessor_access_identity(
                candidate, stage, validated["predecessor"]
            )

        downgrade = self.legacy_policy(1)
        downgrade["predecessor"]["access_build_input_schema"] = (
            successor_binding.BUILD_INPUT_V2
        )
        downgrade["overlay"] = self.synthetic_access_overlay()
        downgrade_path = self.write_policy(
            downgrade, "legacy-policy-v2-predecessor.json"
        )
        with self.assertRaisesRegex(ValueError, "cannot bind a v2 predecessor"):
            successor_binding.validate_policy(downgrade_path)

        policy = self.current_policy()
        policy["predecessor"]["access_build_input_schema"] = "access-build-input/3"
        unsupported = self.write_policy(policy, "unsupported-schema.json")
        with self.assertRaisesRegex(ValueError, "predecessor build-input schema"):
            successor_binding.validate_policy(unsupported)

    def test_historical_v1_predecessor_evidence_remains_valid(self) -> None:
        candidate = self.root / "generation-1-candidate"
        access = candidate / "access-governance"
        access.mkdir(parents=True)
        (access / "Cargo.toml").write_text("[package]\nname='legacy'\n")
        build_input = render_input_binding.access_build_input_sha_for_schema(
            candidate, successor_binding.BUILD_INPUT_V1
        )
        evidence = {
            "schema_version": 1,
            "access_governance_build_input_sha256": build_input,
            "release": {
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": build_input,
            },
        }
        (candidate / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(evidence) + "\n"
        )
        stage = self.root / "generation-1-stage"
        stage.mkdir(mode=0o700)
        (stage / "RELEASE-EVIDENCE.json").write_text(
            json.dumps(evidence) + "\n"
        )
        predecessor = {
            "access_build_input_schema": successor_binding.BUILD_INPUT_V1,
            "access_build_input_sha256": build_input,
        }
        successor_binding.validate_predecessor_access_identity(
            candidate, stage, predecessor
        )

    def test_v2_predecessor_generation_is_explicit_and_cannot_skip(self) -> None:
        self.assertEqual(
            successor_binding.validate_predecessor_generation(
                {
                    "successor": True,
                    "predecessor_release_generation": 1,
                    "release_generation": 2,
                },
                successor_binding.BUILD_INPUT_V2,
            ),
            2,
        )
        self.assertEqual(
            successor_binding.validate_predecessor_generation(
                {}, successor_binding.BUILD_INPUT_V1
            ),
            1,
        )
        invalid_states = (
            {},
            {"successor": True, "release_generation": 2},
            {
                "successor": True,
                "predecessor_release_generation": 1,
                "release_generation": 3,
            },
            {
                "successor": False,
                "predecessor_release_generation": 1,
                "release_generation": 2,
            },
        )
        for state in invalid_states:
            with self.subTest(state=state), self.assertRaisesRegex(
                ValueError, "generation authority differs"
            ):
                successor_binding.validate_predecessor_generation(
                    state, successor_binding.BUILD_INPUT_V2
                )

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
        *,
        overlay_count: int = 7,
        promote_static_asset: bool = True,
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
        asset.write_text(
            '{"schema_version":1,"permissions":["new"]}\n'
            if promote_static_asset
            else '{"schema_version":1,"permissions":["old"]}\n'
        )

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
        for index in range(overlay_count):
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
        policy_version = 1 if overlay_count == 7 else 2
        policy: dict[str, object] = {
            "schema_version": policy_version,
            "ceremony": f"holdfast-rikune-successor-v{policy_version}",
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

    def test_generation_three_stage_accepts_variable_overlay_and_unchanged_static(
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
        ) = self.make_successor_copy_fixture(
            overlay_count=2, promote_static_asset=False
        )
        stage = self.root / "generation-3-stage"
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
        self.assertEqual(
            successor_binding.validate_static_asset_transition(
                preimages,
                static_targets,
                authority,
                policy["schema_version"],
            ),
            {},
        )

    def test_schema_v3_successor_stage_copies_verified_completion_bytes(self) -> None:
        (
            authority,
            estate,
            predecessor_candidate,
            policy,
            preimages,
            static_targets,
            supporting_targets,
        ) = self.make_successor_copy_fixture(
            overlay_count=2, promote_static_asset=False
        )
        policy["schema_version"] = 3
        policy["ceremony"] = "holdfast-rikune-successor-v3"
        predecessor = copy.deepcopy(self.current_policy()["predecessor"])
        predecessor.pop("apply_receipt_sha256", None)
        predecessor["access_build_input_schema"] = successor_binding.BUILD_INPUT_V2
        completion_root, completion, _ = self.issue_recovery_completion(
            predecessor,
            estate,
            self.root / "stage-v3-backup",
            "stage-v3-completion",
        )
        predecessor["completion"] = completion
        policy["predecessor"] = predecessor
        source = successor_binding.read_recovery_completion_bundle(
            completion_root, completion
        )
        stage = self.root / "stage-v3"
        render.copy_successor_stage(
            estate,
            predecessor_candidate,
            stage,
            True,
            policy,
            preimages,
            static_targets,
            authority,
            source,
        )
        render.validate_successor_snapshot(
            stage, policy, preimages, supporting_targets, True
        )
        for name in successor_binding.RECOVERY_COMPLETION_NAMES:
            self.assertEqual(stage.joinpath(name).read_bytes(), source["bytes"][name])

    def test_schema_v1_static_transition_requires_the_exact_legacy_change(
        self,
    ) -> None:
        (
            authority,
            _,
            _,
            _,
            preimages,
            static_targets,
            _,
        ) = self.make_successor_copy_fixture()
        self.assertEqual(
            successor_binding.validate_static_asset_transition(
                preimages, static_targets, authority, 1
            ),
            dict(successor_binding.SUCCESSOR_STATIC_ASSET_SOURCES),
        )
        unchanged_targets = {
            relative: preimages[relative]
            for relative in render.FROZEN_STATIC_PATHS
        }
        self.assertEqual(
            successor_binding.validate_static_asset_transition(
                preimages, unchanged_targets, authority, 2
            ),
            {},
        )
        with self.assertRaisesRegex(ValueError, "path set is not exact"):
            successor_binding.validate_static_asset_transition(
                preimages, unchanged_targets, authority, 1
            )

    def test_overlay_cannot_overlap_a_changed_static_target(self) -> None:
        static_relative = "access-governance/catalog/rikune-authz-v1.json"
        preimages = {
            relative: "a" * 64 for relative in render.FROZEN_STATIC_PATHS
        }
        static_targets = dict(preimages)
        static_targets[static_relative] = "b" * 64
        policy = {
            "overlay": [
                {
                    "path": static_relative,
                    "before_sha256": "c" * 64,
                    "after_sha256": "a" * 64,
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "overlaps a changed static"):
            successor_binding.validate_overlay_static_separation(
                policy, preimages, static_targets
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

    def make_apply_fixture(
        self, *, overlay_count: int = 7
    ) -> tuple[Path, Path, Path, Path, Path]:
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
        for index in range(overlay_count):
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
        for index in range(overlay_count):
            relative = f"access-governance/tests/overlay_{index}.txt"
            overlay.append(
                {
                    "path": relative,
                    "before_sha256": None,
                    "after_sha256": render_input_binding.digest(stage / relative),
                }
            )
        policy_version = 1 if overlay_count == 7 else 2
        policy = {
            "schema_version": policy_version,
            "ceremony": f"holdfast-rikune-successor-v{policy_version}",
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
            require_root_owner=True,
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
                require_root_owner=True,
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

    def test_apply_binding_v3_requires_and_verifies_adjacent_completion_trio(
        self,
    ) -> None:
        ops, stage, evidence, binding, source_estate = self.make_apply_fixture()
        policy_path = ops / "successor-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["schema_version"] = 3
        policy["ceremony"] = "holdfast-rikune-successor-v3"
        predecessor = policy["predecessor"]
        predecessor.pop("apply_receipt_sha256")
        predecessor["access_build_input_schema"] = successor_binding.BUILD_INPUT_V2
        backup = self.root / "apply-v3-backup"
        completion_root, completion, _ = self.issue_recovery_completion(
            predecessor, source_estate, backup, "apply-v3-completion"
        )
        predecessor["completion"] = completion
        policy_path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        evidence_value = json.loads(evidence.read_text(encoding="utf-8"))
        evidence_value["predecessor_binding"] = copy.deepcopy(predecessor)
        evidence.write_text(json.dumps(evidence_value) + "\n", encoding="utf-8")
        binding.unlink()
        render_input_binding.write_binding(ops, binding, successor=True)

        with self.assertRaisesRegex(RuntimeError, "lacks the exact"):
            render_input_binding.verify_apply_binding(
                ops,
                binding,
                stage,
                evidence,
                "successor",
                source_estate_root=source_estate,
            )
        source = successor_binding.read_recovery_completion_bundle(
            completion_root, completion
        )
        successor_binding.write_recovery_completion_bundle(stage, completion, source)
        render_input_binding.verify_apply_binding(
            ops,
            binding,
            stage,
            evidence,
            "successor",
            source_estate_root=source_estate,
        )

        (stage / recovery_completion_attestation.SIGNATURE_NAME).write_bytes(
            b"tampered"
        )
        with self.assertRaisesRegex(RuntimeError, "differs: signature_sha256"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )
        policy["predecessor"]["completion"]["signature_sha256"] = hashlib.sha256(
            (stage / recovery_completion_attestation.SIGNATURE_NAME).read_bytes()
        ).hexdigest()
        policy_path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        evidence_value["predecessor_binding"] = copy.deepcopy(
            policy["predecessor"]
        )
        evidence.write_text(json.dumps(evidence_value) + "\n", encoding="utf-8")
        binding.unlink()
        render_input_binding.write_binding(ops, binding, successor=True)
        with self.assertRaisesRegex(ValueError, "OpenSSL ceremony failed"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

    def test_apply_binding_v2_forbids_recovery_completion_trio(self) -> None:
        ops, stage, evidence, binding, source_estate = self.make_apply_fixture(
            overlay_count=2
        )
        policy = json.loads(
            (ops / "successor-policy.json").read_text(encoding="utf-8")
        )
        predecessor = policy["predecessor"]
        completion_root, completion, _ = self.issue_recovery_completion(
            predecessor,
            source_estate,
            self.root / "legacy-backup",
            "legacy-extra-completion",
        )
        source = successor_binding.read_recovery_completion_bundle(
            completion_root, completion
        )
        successor_binding.write_recovery_completion_bundle(stage, completion, source)
        with self.assertRaisesRegex(RuntimeError, "legacy successor stage"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

    def test_apply_binding_v1_forbids_recovery_completion_trio(self) -> None:
        ops, stage, evidence, binding, source_estate = self.make_apply_fixture(
            overlay_count=7
        )
        predecessor = json.loads(
            (ops / "successor-policy.json").read_text(encoding="utf-8")
        )["predecessor"]
        completion_root, completion, _ = self.issue_recovery_completion(
            predecessor,
            source_estate,
            self.root / "legacy-v1-backup",
            "legacy-v1-extra-completion",
        )
        source = successor_binding.read_recovery_completion_bundle(
            completion_root, completion
        )
        successor_binding.write_recovery_completion_bundle(stage, completion, source)
        with self.assertRaisesRegex(RuntimeError, "legacy successor stage"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

    def test_apply_binding_accepts_non_legacy_exact_overlay_size(self) -> None:
        ops, stage, evidence, binding, source_estate = self.make_apply_fixture(
            overlay_count=2
        )
        render_input_binding.verify_apply_binding(
            ops,
            binding,
            stage,
            evidence,
            "successor",
            require_root_owner=True,
            source_estate_root=source_estate,
        )

    def test_legacy_apply_binding_preserves_non_root_offline_stage_semantics(
        self,
    ) -> None:
        ops, stage, evidence, binding, _ = self.make_apply_fixture(
            overlay_count=2
        )
        stage.chmod(0o500)
        render_input_binding.verify_apply_binding(
            ops, binding, stage, evidence, "successor", require_root_owner=False
        )
        stage.chmod(0o700)
        os.chown(stage, 65534, -1)
        render_input_binding.verify_apply_binding(
            ops, binding, stage, evidence, "successor", require_root_owner=False
        )

    def test_apply_binding_rejects_writable_live_source_tree(self) -> None:
        ops, stage, evidence, binding, source_estate = self.make_apply_fixture()
        (source_estate / "access-governance/Cargo.toml").chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "group/world-writable"):
            render_input_binding.verify_apply_binding(
                ops,
                binding,
                stage,
                evidence,
                "successor",
                require_root_owner=True,
                source_estate_root=source_estate,
            )

    def test_apply_binding_rejects_unsorted_overlay_after_exact_rebinding(
        self,
    ) -> None:
        ops, stage, evidence, binding, _ = self.make_apply_fixture(
            overlay_count=2
        )
        policy_path = ops / "successor-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["overlay"].reverse()
        policy_path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        delta = stage / "SUCCESSOR-DELTA.sha256"
        delta.write_text(
            "".join(
                f"{'0' * 64}  {item['after_sha256']}  {item['path']}\n"
                for item in policy["overlay"]
            ),
            encoding="utf-8",
        )
        evidence_value = json.loads(evidence.read_text(encoding="utf-8"))
        evidence_value["successor_delta_sha256"] = render_input_binding.digest(
            delta
        )
        evidence.write_text(json.dumps(evidence_value) + "\n", encoding="utf-8")
        binding.unlink()
        render_input_binding.write_binding(ops, binding, successor=True)

        with self.assertRaisesRegex(RuntimeError, "overlay path order differs"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

    def test_apply_binding_rejects_overlay_hash_that_differs_from_stage(
        self,
    ) -> None:
        ops, stage, evidence, binding, _ = self.make_apply_fixture(
            overlay_count=2
        )
        policy_path = ops / "successor-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["overlay"][0]["after_sha256"] = "f" * 64
        policy_path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        delta = stage / "SUCCESSOR-DELTA.sha256"
        delta.write_text(
            "".join(
                f"{'0' * 64}  {item['after_sha256']}  {item['path']}\n"
                for item in policy["overlay"]
            ),
            encoding="utf-8",
        )
        evidence_value = json.loads(evidence.read_text(encoding="utf-8"))
        evidence_value["successor_delta_sha256"] = render_input_binding.digest(
            delta
        )
        evidence.write_text(json.dumps(evidence_value) + "\n", encoding="utf-8")
        binding.unlink()
        render_input_binding.write_binding(ops, binding, successor=True)

        with self.assertRaisesRegex(RuntimeError, "stage successor overlay differs"):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

    def test_apply_binding_rejects_v2_predecessor_under_legacy_policy(
        self,
    ) -> None:
        ops, stage, evidence, binding, _ = self.make_apply_fixture()
        policy_path = ops / "successor-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["predecessor"]["access_build_input_schema"] = (
            successor_binding.BUILD_INPUT_V2
        )
        policy_path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
        evidence_value = json.loads(evidence.read_text(encoding="utf-8"))
        evidence_value["predecessor_binding"] = policy["predecessor"]
        evidence.write_text(json.dumps(evidence_value) + "\n", encoding="utf-8")
        binding.unlink()
        render_input_binding.write_binding(ops, binding, successor=True)

        with self.assertRaisesRegex(
            RuntimeError, "policy, frozen target and evidence bindings differ"
        ):
            render_input_binding.verify_apply_binding(
                ops, binding, stage, evidence, "successor"
            )

    def test_successor_policy_requires_a_bound_source_build_identity(self) -> None:
        policy = successor_binding.validate_policy(
            OPS_ROOT / "successor-policy.json"
        )
        source = policy["successor"]["source_access_build_input_sha256"]
        final = policy["successor"]["access_build_input_sha256"]
        self.assertRegex(source, r"^[0-9a-f]{64}$")
        self.assertRegex(final, r"^[0-9a-f]{64}$")
        preimages = successor_binding.parse_checksum_manifest(
            OPS_ROOT / policy["successor"]["preimages_manifest"]
        )
        static_targets = successor_binding.parse_checksum_manifest(
            OPS_ROOT / policy["successor"]["static_targets_manifest"]
        )
        self.assertEqual(
            successor_binding.validate_static_asset_transition(
                preimages,
                static_targets,
                OPS_ROOT,
                policy["schema_version"],
            ),
            {
                relative: source_relative
                for relative, source_relative in (
                    successor_binding.SUCCESSOR_STATIC_ASSET_SOURCES
                )
                if preimages[relative] != static_targets[relative]
            },
        )

        del policy["successor"]["source_access_build_input_sha256"]
        invalid = self.root / "missing-source-build-input.json"
        invalid.write_text(json.dumps(policy) + "\n")
        with self.assertRaisesRegex(ValueError, "successor policy"):
            successor_binding.validate_policy(invalid)

if __name__ == "__main__":
    unittest.main()
