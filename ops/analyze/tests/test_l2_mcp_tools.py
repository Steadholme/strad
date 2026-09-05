"""Unit checks for the live harness; these fixtures are not L2 evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("l2_mcp_runtime", Path(__file__).resolve().parents[1] / "l2_runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def created(sample):
    upload_id = str(uuid.uuid4())
    prefix = "https://analyze.w33d.xyz/v1/uploads/" + upload_id
    return {"analysis_id": str(uuid.uuid4()), "upload_id": upload_id,
            "finalize_operation_id": str(uuid.uuid4()), "chunk_size": 8388608, "chunk_count": 1,
            "chunk_url_template": prefix + "/chunks/{chunk_index}", "finalize_url": prefix + "/finalize"}


class FourToolHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = object.__new__(runtime.ClosedRun)
        self.run.work = Path(self.temp.name)
        self.sample = b"\x7fELFunit-fixture-not-a-real-analysis"
        (self.run.work / "sample.elf").write_bytes(self.sample)
        self.run.analysis_created = created(self.sample)
        self.run.analyzer_image = "example/analyzer@sha256:" + "f" * 64
        self.run.env = {"L2_BRIDGE_TOKEN": "unit-test-only-bridge-credential", "L2_NEWAPI_MODEL": "glm-5.2"}
        self.run.observations = {}
        self.content = json.dumps({"function_count": 1, "functions": [{"name": "example"}]}, indent=2)
        self.artifact = {"artifact_type": "ghidra_functions", "upstream_artifact_id": "function-one",
                         "artifact_ref": "ref:function-one", "sha256": hashlib.sha256(self.content.encode()).hexdigest()}
        self.calls = []
        self.http_calls = []
        self.read_count = 0
        self.creates = 0
        self.turn = {"id": str(uuid.uuid4()), "state": "completed", "provider_attempt": 1, "model_alias": "glm-5.2"}
        self.quota = {"code": -32008, "message": 'MCP error -32008: {"error":{"code":"quota_exceeded","retryable":true}}'}
        self.run.tool = self.tool
        self.run.application_http = self.http
        self.run.request = self.artifact_read
        self.run.sql = lambda query, database: "0"

    def tool(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "analysis.read":
            if "turn_id" in arguments:
                result = {"turn": self.turn, "assistant": {"content": "Example [ref:function-one]."},
                          "citations": [["ref:function-one", True]]}
            else:
                self.read_count += 1
                result = {"analysis": {"state": "analyzing" if self.read_count == 1 else "analyzed",
                                      "sample_id": "sha256:" + hashlib.sha256(self.sample).hexdigest()},
                          "artifacts": [self.artifact]}
        elif name == "analysis.conversation":
            result = {"turn": {"id": self.turn["id"]}} if "conversation_id" in arguments else {"conversation": {"id": str(uuid.uuid4())}}
        elif name == "analysis.create":
            self.creates += 1
            if self.creates == 3:
                raise runtime.McpFailure(self.quota)
            result = created(self.sample)
        elif name == "analysis.upload.cancel":
            result = {"upload_id": arguments["upload_id"], "state": "cancelled"}
        else:
            self.fail("unexpected tool: " + name)
        self.run.last_tool_text = json.dumps(result)
        return result

    def http(self, path, **kwargs):
        self.http_calls.append((path, kwargs))
        if "/chunks/" in path:
            self.assertEqual(kwargs["body"], self.sample)
            self.assertEqual(kwargs["headers"]["X-Chunk-Sha256"], hashlib.sha256(self.sample).hexdigest())
            self.assertEqual(kwargs["headers"]["Content-Range"], f"bytes 0-{len(self.sample)-1}/{len(self.sample)}")
            return 204, {}, b""
        if path.endswith("/finalize"):
            self.assertEqual(kwargs["body"], b"")
            self.assertEqual(kwargs["headers"]["Idempotency-Key"], self.run.analysis_created["finalize_operation_id"])
            return 202, {}, json.dumps({"analysis_id": self.run.analysis_created["analysis_id"], "state": "uploaded"}).encode()
        self.assertTrue(path.endswith("/cancel"))
        return 404, {}, b""

    def artifact_read(self, service, port, path, **kwargs):
        self.assertEqual((service, port, path), ("analyzer", 18090, "/internal/v1/artifacts/read"))
        args = json.loads(kwargs["body"])
        self.assertEqual(args["artifact_id"], "function-one")
        self.assertEqual(args["read_mode"], "content")
        return 200, {}, json.dumps({"data": {"content": self.content, "truncated": False,
            "bytes_read": len(self.content.encode()), "total_size": len(self.content.encode())}}).encode()

    def execute(self):
        with patch.object(runtime.time, "sleep"):
            self.run.mcp_four_tools()

    def test_complete_scenario_has_one_turn_and_fresh_read_operations(self):
        self.execute()
        self.assertEqual(self.run.observations["mcp_four_tools"]["status"], "pass")
        turns = [args for name, args in self.calls if name == "analysis.conversation" and "message" in args]
        self.assertEqual(len(turns), 1)
        reads = [args["operation_id"] for name, args in self.calls if name == "analysis.read"]
        self.assertEqual(len(reads), len(set(reads)))
        self.assertEqual(len([path for path, _ in self.http_calls if "/chunks/" in path]), 2)

    def test_cross_origin_upload_url_is_rejected_before_dispatch(self):
        self.run.analysis_created["finalize_url"] = "https://outside.invalid/finalize"
        with self.assertRaisesRegex(RuntimeError, "upload URLs"):
            self.execute()
        self.assertEqual(self.http_calls, [])

    def test_incorrect_artifact_hash_cannot_be_pass_evidence(self):
        self.artifact["sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "actual bytes"):
            self.execute()
        self.assertNotIn("mcp_four_tools", self.run.observations)

    def test_multiple_provider_attempts_cannot_be_counted_as_one(self):
        self.turn["provider_attempt"] = 2
        with self.assertRaisesRegex(RuntimeError, "single model attempt"):
            self.execute()

    def test_truncated_artifact_cannot_be_accepted_as_hash_verified(self):
        self.run.request = lambda *args, **kwargs: (200, {}, json.dumps({"data": {
            "content": self.content, "truncated": True, "bytes_read": 20, "total_size": 40}}).encode())
        with self.assertRaisesRegex(RuntimeError, "was truncated"):
            self.execute()
        self.assertFalse(any(name == 'analysis.conversation' for name, _ in self.calls))
        self.assertNotIn("mcp_four_tools", self.run.observations)

    def test_dependency_failure_is_not_misclassified_as_quota(self):
        self.quota = {"code": -32012, "message": 'MCP error -32012: {"error":{"code":"dependency_unavailable","retryable":true}}'}
        with self.assertRaises(runtime.McpFailure):
            self.execute()
        self.assertNotIn("mcp_four_tools", self.run.observations)
        self.assertFalse(any(name == 'analysis.conversation' for name, _ in self.calls))

    def test_digest_only_analyzer_selection_is_required(self):
        for value in ["example/analyzer:latest", "sha256:not-a-digest"]:
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "immutable digest"):
                runtime.ClosedRun(value)


if __name__ == "__main__":
    unittest.main()
