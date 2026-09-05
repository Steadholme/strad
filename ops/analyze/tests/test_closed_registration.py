import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "closed-registration.mjs"
NODE = "node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436"
BASE = "/internal/v1/identity/registration"
SIGNATURE = "X-Keystone-RegSig"
VERSION = "X-Keystone-Registration-Feed-Version"
CONSUMER = "access-governance-registration-v1"
SUBJECTS = ["user:closed-charlie", "user:closed-alice", "user:closed-bob"]


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def signature(method, target, body, key, kid, timestamp, nonce,
              service="access-governance", audience="keystone-registration"):
    path, _, query = target.partition("?")
    canonical = "\n".join([
        "regfeed-v1", service, audience, method, path,
        "&".join(sorted(query.split("&"))) if query else "",
        sha256(body), kid, str(timestamp), nonce,
    ])
    mac = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return f"kid={kid},ts={timestamp},nonce={nonce},mac={mac}"


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)
    if result.returncode:
        # 不把命令、环境变量或子进程 stderr 中的凭据带入失败日志。
        raise AssertionError(f"{args[0]} exited with status {result.returncode}")
    return result.stdout.strip()


class ClosedRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise AssertionError("closed-registration.mjs has not been implemented")
        cls.work = tempfile.TemporaryDirectory(prefix="closed-registration-")
        cls.addClassCleanup(cls.work.cleanup)
        cls.directory = Path(cls.work.name)
        cls.containers = []
        cls.network = "closed-registration-" + secrets.token_hex(8)
        cls.network_created = False
        cls.addClassCleanup(cls.cleanup_docker)
        cls.make_certificates()
        cls.key = secrets.token_hex(32)
        cls.kid = "closed-current"
        cls.env = {
            "L2_REGISTRATION_SUBJECTS_JSON": json.dumps(SUBJECTS),
            "L2_REGISTRATION_MAC_KID": cls.kid,
            "L2_REGISTRATION_MAC_KEY": cls.key,
            "L2_REGISTRATION_TLS_CA": "/run/tls/ca.crt",
            "L2_REGISTRATION_TLS_CERT": "/run/tls/server.crt",
            "L2_REGISTRATION_TLS_KEY": "/run/tls/server.key",
        }
        command(["docker", "image", "inspect", NODE])
        command(["docker", "network", "create", "--internal", cls.network])
        cls.network_created = True
        cls.container = cls.start_container(cls.env)
        cls.ip = command([
            "docker", "inspect", "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cls.container,
        ])
        cls.context = cls.tls_context("client")
        for _ in range(40):
            if command(["docker", "inspect", "--format", "{{.State.Running}}", cls.container]) != "true":
                raise AssertionError("registration fixture exited before readiness")
            try:
                with socket.create_connection((cls.ip, 9443), timeout=0.3):
                    return
            except (ConnectionRefusedError, TimeoutError):
                time.sleep(0.1)
        raise AssertionError("registration fixture did not listen on 9443")

    @classmethod
    def cleanup_docker(cls):
        # 清理仅针对本测试记录的精确 ID；网络失败也不能跳过容器清理。
        errors = []
        try:
            for container in reversed(cls.containers):
                try:
                    command(["docker", "rm", "-f", container])
                except (AssertionError, subprocess.TimeoutExpired) as error:
                    errors.append(error)
        finally:
            if cls.network_created:
                command(["docker", "network", "rm", cls.network])
        if errors:
            raise AssertionError("owned registration containers could not all be removed") from errors[0]

    @classmethod
    def make_certificates(cls):
        def openssl(*args):
            command(["openssl", *args], cwd=cls.directory)

        for ca in ("ca", "wrong-ca"):
            openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "1", "-subj", f"/CN={ca}", "-keyout", f"{ca}.key",
                    "-out", f"{ca}.crt", "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for name, issuer, purpose in [
            ("server", "ca", "serverAuth"), ("client", "ca", "clientAuth"),
            ("wrong-client", "wrong-ca", "clientAuth"),
        ]:
            extension = cls.directory / f"{name}.ext"
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage={purpose}\nsubjectAltName=DNS:closed-registration\n"
            )
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-subj", f"/CN={name}", "-keyout", f"{name}.key",
                    "-out", f"{name}.csr")
            openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{issuer}.crt",
                    "-CAkey", f"{issuer}.key", "-set_serial", str({"server": 1, "client": 2,
                    "wrong-client": 3}[name]), "-days", "1", "-extfile", str(extension),
                    "-out", f"{name}.crt")
        # 非特权容器只挂载服务端三份文件；CA 签名密钥不进入容器。
        for name in ("ca.crt", "server.crt", "server.key"):
            (cls.directory / name).chmod(0o644)

    @classmethod
    def start_container(cls, env):
        name = "closed-registration-" + secrets.token_hex(8)
        args = [
            "docker", "run", "-d", "--pull=never", "--name", name,
            "--network", cls.network, "--user", "65532:65532", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "64",
            "--memory", "128m", "--cpus", "1",
            "--mount", f"type=bind,src={SOURCE},dst=/app/closed-registration.mjs,readonly",
        ]
        for filename in ("ca.crt", "server.crt", "server.key"):
            args += ["--mount", f"type=bind,src={cls.directory / filename},dst=/run/tls/{filename},readonly"]
        for key in env:
            args += ["-e", key]
        # 预登记精确名称，使启动中断时也有清理目标。
        cls.containers.append(name)
        command(args + [NODE, "node", "/app/closed-registration.mjs"],
                env={**os.environ, **env})
        return name

    @classmethod
    def tls_context(cls, identity=None, ca="ca"):
        context = ssl.create_default_context(cafile=str(cls.directory / f"{ca}.crt"))
        if identity:
            context.load_cert_chain(str(cls.directory / f"{identity}.crt"),
                                    str(cls.directory / f"{identity}.key"))
        return context

    def request(self, method, target, body=b"", headers=None, context=None):
        context = self.context if context is None else context
        connection = http.client.HTTPSConnection("closed-registration", 9443, timeout=3, context=context)
        raw_socket = socket.create_connection((self.ip, 9443), timeout=3)
        try:
            connection.sock = context.wrap_socket(raw_socket, server_hostname="closed-registration")
            connection.putrequest(method, target)
            connection.putheader("Connection", "close")
            connection.putheader("Content-Length", str(len(body)))
            for key, value in headers or []:
                connection.putheader(key, value)
            connection.endheaders(body)
            response = connection.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), json.loads(data) if data else None
        finally:
            connection.close()
            raw_socket.close()

    def signed(self, method, target, body=b"", *, nonce=None, timestamp=None,
               key=None, kid=None, service="access-governance", audience="keystone-registration",
               extra=(), version="2", context=None, sent_body=None):
        nonce = nonce or secrets.token_hex(16)
        header = signature(method, target, body, key or self.key, kid or self.kid,
                           int(time.time()) if timestamp is None else timestamp, nonce, service, audience)
        headers = [(SIGNATURE, header), ("Accept", "application/json")]
        if version is not None:
            headers.append((VERSION, version))
        if body:
            headers.append(("Content-Type", "application/json"))
        headers.extend(extra)
        result = self.request(method, target, body if sent_body is None else sent_body, headers, context)
        return (*result, nonce)

    def success(self, method, target, body=b"", status=200, **kwargs):
        actual, headers, data, nonce = self.signed(method, target, body, **kwargs)
        self.assertEqual(actual, status)
        self.assertEqual(data["acked_nonce"], nonce)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Cache-Control"], "private, no-store")
        self.assertEqual(headers["Vary"], f"{SIGNATURE}, {VERSION}")
        return data

    def test_canonical_mac_known_access_vector(self):
        header = signature("GET", BASE + "/changes?limit=2&after=1", b"", "a" * 32,
                           "k1", 7, "0" * 32)
        canonical = ("regfeed-v1\naccess-governance\nkeystone-registration\nGET\n"
                     "/internal/v1/identity/registration/changes\nafter=1&limit=2\n"
                     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
                     "k1\n7\n00000000000000000000000000000000")
        expected = hmac.new(b"a" * 32, canonical.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(header, f"kid=k1,ts=7,nonce={'0' * 32},mac={expected}")
        self.success("GET", BASE + "/changes?limit=2&after=1")

    def test_snapshot_pages_changes_and_real_ack(self):
        manifest = self.success("POST", BASE + "/snapshot", status=201)
        self.assertEqual(set(manifest), {"snapshot_id", "generation", "high_watermark",
                         "high_watermark_event_id", "high_watermark_payload_hash", "count",
                         "digest", "acked_nonce"})
        self.assertRegex(manifest["snapshot_id"], r"^irs_[0-9a-f]{32}$")
        self.assertEqual((manifest["generation"], manifest["high_watermark"], manifest["count"]), (1, 3, 3))
        page_path = BASE + "/snapshot/" + manifest["snapshot_id"]
        rows = []
        after = 0
        while True:
            page = self.success("GET", f"{page_path}?after_ordinal={after}&limit=2")
            self.assertEqual(set(page), set(manifest) - {"count"} |
                             {"rows", "next_after_ordinal", "done"})
            for field in ("snapshot_id", "generation", "high_watermark", "high_watermark_event_id",
                          "high_watermark_payload_hash", "digest"):
                self.assertEqual(page[field], manifest[field])
            rows.extend(page["rows"])
            after = page["next_after_ordinal"]
            self.assertEqual(after, len(rows))
            self.assertEqual(page["done"], after == 3)
            if page["done"]:
                break
        self.assertEqual([row["subject"] for row in rows], sorted(SUBJECTS))
        canonical = "registration-snapshot-v1\n3"
        for ordinal, row in enumerate(rows, 1):
            self.assertEqual(set(row), {"ordinal", "subject", "account_version", "registration_state",
                                       "email_verified", "enabled", "payload_hash"})
            self.assertEqual(row["ordinal"], ordinal)
            self.assertEqual(row["account_version"], 1)
            self.assertEqual(row["registration_state"], "registered")
            self.assertIs(row["email_verified"], True)
            self.assertIs(row["enabled"], True)
            payload = f"registration-payload-v1\n{row['subject']}\n1\nregistered\n1\n1"
            self.assertEqual(row["payload_hash"], sha256(payload.encode()))
            canonical += f"\nR\t{ordinal}\t{row['subject']}\t1\tregistered\t1\t1\t{row['payload_hash']}"
        self.assertEqual(manifest["digest"], sha256(canonical.encode()))
        end = self.success("GET", f"{page_path}?after_ordinal=3&limit=1000")
        self.assertEqual((end["rows"], end["next_after_ordinal"], end["done"]), ([], 3, True))
        again = self.success("POST", BASE + "/snapshot", status=201)
        self.assertNotEqual(again["snapshot_id"], manifest["snapshot_id"])
        self.assertEqual(again["digest"], manifest["digest"])

        events = []
        for cursor in (0, 2):
            page = self.success("GET", f"{BASE}/changes?after={cursor}&limit=2")
            self.assertEqual(set(page), {"generation", "events", "head_cursor",
                                        "retention_floor_cursor", "acked_nonce"})
            self.assertEqual((page["generation"], page["head_cursor"], page["retention_floor_cursor"]), (1, 3, 0))
            events.extend(page["events"])
        for cursor, (event, row) in enumerate(zip(events, rows, strict=True), 1):
            self.assertEqual(set(event), set(row) - {"ordinal"} | {"cursor", "event_id", "occurred_at"})
            for field in set(row) - {"ordinal"}:
                self.assertEqual(event[field], row[field])
            self.assertEqual(event["cursor"], cursor)
            self.assertEqual(event["event_id"], f"ire_{cursor:016x}_{row['payload_hash'][:16]}")
            self.assertGreater(event["occurred_at"], 0)
        event = events[-1]
        self.assertEqual(manifest["high_watermark_event_id"], event["event_id"])
        self.assertEqual(manifest["high_watermark_payload_hash"], event["payload_hash"])
        ack = {"consumer": CONSUMER, "generation": 1, "cursor": 3,
               "event_id": event["event_id"], "payload_hash": event["payload_hash"]}
        for _ in range(2):
            response = self.success("POST", BASE + "/ack", json.dumps(ack).encode())
            self.assertEqual(set(response), {"consumer", "generation", "stored_cursor", "acked_nonce"})
            self.assertEqual((response["consumer"], response["generation"], response["stored_cursor"]),
                             (CONSUMER, 1, 3))
            caught_up = self.success("GET", BASE + "/changes?after=3&limit=500")
            self.assertEqual(caught_up["events"], [])
            self.assertEqual(caught_up["head_cursor"], 3)
        replay = self.success("GET", BASE + "/changes?after=0&limit=500")
        self.assertEqual(replay["events"], events)
        for changes, code in [({"generation": 2}, "ack_generation_conflict"),
                              ({"cursor": 4}, "ack_ahead"),
                              ({"payload_hash": "0" * 64}, "ack_event_mismatch"),
                              ({"cursor": 2, "event_id": events[1]["event_id"],
                                "payload_hash": events[1]["payload_hash"]}, "ack_regression")]:
            with self.subTest(ack_error=code):
                status, _, data, nonce = self.signed("POST", BASE + "/ack", json.dumps({**ack, **changes}).encode())
                self.assertEqual((status, data), (409, {"error": code, "acked_nonce": nonce}))

    def test_mtls_and_server_trust_fail_closed(self):
        for context in (self.tls_context(), self.tls_context("wrong-client"),
                        self.tls_context("client", ca="wrong-ca")):
            with self.subTest(tls_context=context), self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                self.signed("GET", BASE + "/changes?after=0&limit=1", context=context)
        self.success("GET", BASE + "/changes?after=0&limit=1")

    def test_mac_identity_time_body_and_replay(self):
        target = BASE + "/changes?after=0&limit=1"
        for kwargs, code in [({"key": "x" * 32}, "bad_mac"), ({"kid": "old"}, "unknown_kid"),
                             ({"service": "wrong-service"}, "bad_mac"),
                             ({"audience": "wrong-audience"}, "bad_mac"),
                             ({"timestamp": int(time.time()) - 120}, "stale"),
                             ({"timestamp": int(time.time()) + 120}, "stale"),
                             ({"nonce": "F" * 32}, "invalid_signature"),
                             ({"nonce": "a" * 31}, "invalid_signature"),
                             ({"timestamp": "01"}, "invalid_signature"),
                             ({"sent_body": b"unexpected"}, "bad_mac")]:
            with self.subTest(error=code, variant=list(kwargs)):
                status, _, data, _ = self.signed("GET", target, **kwargs)
                self.assertEqual((status, data), (401, {"error": code}))
        nonce = secrets.token_hex(16)
        self.success("GET", target, nonce=nonce)
        for replay_target in (target, BASE + "/changes?after=1&limit=1"):
            status, _, data, _ = self.signed("GET", replay_target, nonce=nonce)
            self.assertEqual((status, data), (401, {"error": "replay", "acked_nonce": nonce}))

    def test_missing_duplicate_and_malformed_authorization(self):
        target = BASE + "/changes?after=0&limit=1"
        valid = signature("GET", target, b"", self.key, self.kid, int(time.time()), secrets.token_hex(16))
        for headers in [[], [(SIGNATURE, "bad")], [(SIGNATURE, valid), (SIGNATURE.lower(), valid)],
                        [(SIGNATURE, valid + ",kid=second")], [(SIGNATURE, valid.replace(",ts=", ", ts="))],
                        [(SIGNATURE, valid + ",extra=field")], [(SIGNATURE, valid), ("Authorization", "Bearer closed")],
                        [(SIGNATURE, valid), ("Authorization", "x"), ("authorization", "y")]]:
            with self.subTest(header_count=len(headers)):
                status, _, data = self.request("GET", target, headers=[(VERSION, "2"), *headers])
                self.assertEqual((status, data), (401, {"error": "invalid_signature"}))

    def test_routes_queries_versions_and_bounded_bodies(self):
        manifest = self.success("POST", BASE + "/snapshot", status=201)
        page = BASE + "/snapshot/" + manifest["snapshot_id"]
        cases = [
            ("GET", BASE + "/head", b"", 404), ("PUT", BASE + "/snapshot", b"", 405),
            ("GET", BASE + "/snapshot/irs_" + "0" * 32 + "?after_ordinal=0&limit=1", b"", 410),
            ("GET", BASE + "/snapshot/bad?after_ordinal=0&limit=1", b"", 400),
            ("GET", page + "?after_ordinal=4&limit=1", b"", 400),
            ("GET", page + "?after_ordinal=0&limit=1001", b"", 400),
            ("POST", BASE + "/snapshot?after=0", b"", 400),
            ("POST", BASE + "/snapshot", b"{}", 400),
            ("POST", BASE + "/ack", b"{", 400),
            ("POST", BASE + "/ack", b"{}", 400),
            ("POST", BASE + "/ack", b"x" * 4097, 413),
        ]
        for query in ("after=0&limit=0", "after=0&limit=501", "after=4&limit=1", "after=01&limit=1",
                      "after=-1&limit=1", "after=9007199254740992&limit=1", "after=0&limit=1&after=0",
                      "after=0&limit=1&extra=1", "after=0&limit=1&", "after=%30&limit=1", "limit=1", ""):
            cases.append(("GET", BASE + "/changes?" + query, b"", 400))
        for method, target, body, expected in cases:
            with self.subTest(method=method, target=target, size=len(body)):
                status, _, data, nonce = self.signed(method, target, body)
                self.assertEqual(status, expected)
                if expected != 413:
                    self.assertEqual(data["acked_nonce"], nonce)
        for version, extra in [(None, ()), ("1", ()), ("2", ((VERSION, "2"),))]:
            status, _, data, nonce = self.signed("POST", BASE + "/snapshot", version=version, extra=extra)
            self.assertEqual((status, data), (400, {"error": "invalid_version", "acked_nonce": nonce}))

    def test_ack_rejects_ambiguous_json_and_content_type(self):
        event = self.success("GET", BASE + "/changes?after=0&limit=1")["events"][0]
        ack = {"consumer": CONSUMER, "generation": 1, "cursor": 1,
               "event_id": event["event_id"], "payload_hash": event["payload_hash"]}
        body = json.dumps(ack).encode()
        cases = [
            body[:-1] + b',"cursor":1}',
            body[:-1] + b',"\\u0063ursor":1}',
            body.replace(b'"generation": 1', b'"generation": 1.0'),
            body.replace(b'"cursor": 1', b'"cursor": 1e0'),
            body.replace(b'"cursor": 1', b'"cursor": 0'),
            body.replace(CONSUMER.encode(), b"wrong-consumer"),
            body[:-1] + b',"unknown":1}',
            body.replace(CONSUMER.encode(), b"\xff"),
        ]
        for malformed in cases:
            status, _, data, nonce = self.signed("POST", BASE + "/ack", malformed)
            self.assertEqual((status, data), (400, {"error": "invalid_request", "acked_nonce": nonce}))
        for media_type in ("application/json", "text/plain"):
            status, _, data, nonce = self.signed("POST", BASE + "/ack", body,
                                               extra=(("Content-Type", media_type),))
            self.assertEqual((status, data), (400, {"error": "invalid_request", "acked_nonce": nonce}))

    def test_invalid_configuration_exits_without_secrets(self):
        invalid = [{key: None} for key in self.env]
        invalid += [{"L2_REGISTRATION_SUBJECTS_JSON": value} for value in
                    ("{}", "[", "[]", '["raw-subject"]', '["user:x","user:x"]', '["user:x\\n"]',
                     json.dumps([f"user:{index}" for index in range(1025)]))]
        invalid += [{"L2_REGISTRATION_MAC_KEY": "short"}, {"L2_REGISTRATION_MAC_KID": "bad,kid"},
                    {"L2_REGISTRATION_TLS_CA": "/run/tls/server.crt"},
                    {"L2_REGISTRATION_TLS_CERT": "/run/tls/ca.crt"},
                    {"L2_REGISTRATION_TLS_KEY": "/missing.key"}]
        for overrides in invalid:
            with self.subTest(config=list(overrides)):
                env = {key: overrides.get(key, value) for key, value in self.env.items()
                       if overrides.get(key, value) is not None}
                container = self.start_container(env)
                try:
                    code = command(["docker", "wait", container])
                    self.assertEqual(code, "1")
                    logs = command(["docker", "logs", container])
                    self.assertEqual(logs, "")
                    result = subprocess.run(["docker", "logs", container], capture_output=True,
                                            text=True, timeout=10, check=True)
                    self.assertEqual(result.stderr.strip(), "closed registration fixture configuration error")
                    self.assertNotIn(self.key, result.stderr)
                finally:
                    command(["docker", "rm", "-f", container])
                    self.containers.remove(container)

    def test_z_container_is_internal_unpublished_and_logs_no_requests(self):
        details = json.loads(command(["docker", "inspect", self.container]))[0]
        network = json.loads(command(["docker", "network", "inspect", self.network]))[0]
        self.assertTrue(network["Internal"])
        self.assertFalse(details["HostConfig"]["PortBindings"])
        self.assertEqual(details["Config"]["Image"], NODE)
        result = subprocess.run(["docker", "logs", self.container], capture_output=True,
                                text=True, timeout=10, check=True)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
