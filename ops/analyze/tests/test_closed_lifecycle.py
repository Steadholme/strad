import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import unittest

from .test_l2_runtime import runtime


class ClosedLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.name = "closed-lifecycle-" + secrets.token_hex(8)
        cls.keys = {name: secrets.token_hex(32) for name in ["L2_CENSUS_TOKEN",
                    "L2_LIFECYCLE_SLUICE_TOKEN", "L2_LIFECYCLE_NEWAPI_TOKEN", "L2_LIFECYCLE_KEYSTONE_TOKEN"]}
        cls.command(["docker", "network", "create", "--internal", cls.name])
        cls.addClassCleanup(cls.command, ["docker", "network", "rm", cls.name])
        cls.addClassCleanup(cls.command, ["docker", "rm", "-f", cls.name])
        cls.command(["docker", "run", "-d", "--pull=never", "--name", cls.name,
                     "--network", cls.name, "--read-only", "--cap-drop=ALL", "--user=65532:65532",
                     "--security-opt=no-new-privileges", "-v",
                     str(Path(__file__).resolve().parents[1] / "closed-lifecycle.mjs") + ":/app/fixture.mjs:ro",
                     "-e", 'L2_REGISTRATION_SUBJECTS_JSON=["user:u_admin","user:w33d"]',
                     *[arg for key in cls.keys for arg in ["-e", key]], runtime.NODE, "node", "/app/fixture.mjs"],
                    env={**os.environ, **cls.keys})
        cls.ip = json.loads(cls.command(["docker", "inspect", cls.name]))[0]["NetworkSettings"]["Networks"][cls.name]["IPAddress"]
        for _ in range(30):
            try:
                cls.request("GET", "/missing", None, "bad")
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("closed lifecycle fixture did not start")

    @staticmethod
    def command(args, **kwargs):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30, **kwargs).stdout.strip()

    @classmethod
    def request(cls, method, path, data, token):
        conn = http.client.HTTPConnection(cls.ip, 9081, timeout=3)
        try:
            conn.request(method, path, body=json.dumps(data) if data is not None else None,
                         headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                  "x-correlation-id": data.get("correlation_id", "") if isinstance(data, dict) else ""})
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_empty_workforce_is_a_real_authenticated_bounded_feed(self):
        self.assertEqual(self.request("GET", "/internal/v1/workforce/changes?after=0&limit=100", None,
                                      self.keys["L2_CENSUS_TOKEN"]),
                         (200, {"items": [], "next_cursor": 0, "has_more": False}))
        self.assertEqual(self.request("GET", "/internal/v1/workforce/changes?after=1&limit=100", None,
                                      self.keys["L2_CENSUS_TOKEN"])[0], 400)

    def test_lifecycle_replay_conflict_and_identity_are_checked_before_ack(self):
        for target in ["sluice", "newapi", "keystone"]:
            token = self.keys["L2_LIFECYCLE_" + target.upper() + "_TOKEN"]
            data = {"subject": "w33d", "state": "active", "source_version": 2,
                    "source_event_id": "effective:2:2:" + "a" * 64, "correlation_id": "effective:user:w33d:2"}
            self.assertEqual(self.request("POST", "/" + target, data, "wrong")[0], 401)
            self.assertEqual(self.request("POST", "/" + target, {**data, "subject": "production-user"}, token)[0], 400)
            self.assertEqual(self.request("POST", "/" + target, data, token),
                             (200, {"subject": "w33d", "state": "active", "source_version": 2, "replayed": False}))
            self.assertTrue(self.request("POST", "/" + target, data, token)[1]["replayed"])
            self.assertEqual(self.request("POST", "/" + target, {**data, "state": "frozen"}, token)[0], 409)
            self.assertEqual(self.request("POST", "/" + target, {**data, "extra": True}, token)[0], 400)

    def test_no_host_ports_no_anonymous_health_and_no_request_logging(self):
        details = json.loads(self.command(["docker", "inspect", self.name]))[0]
        self.assertFalse(details["HostConfig"]["PortBindings"])
        self.assertTrue(json.loads(self.command(["docker", "network", "inspect", self.name]))[0]["Internal"])
        self.assertEqual(self.request("GET", "/healthz", None, "bad")[0], 404)
        self.assertEqual(self.command(["docker", "logs", self.name]), "")
