#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
STRAD = ROOT.parents[1]
INFRA = STRAD.parent
CHECKOUTS = {
    "access": INFRA / "access-governance",
    "strad": STRAD,
    "verdict": INFRA / ".worktrees/analyze-gen7/verdict",
    "sluice": INFRA / ".worktrees/analyze-gen7/sluice",
}
NODE = "node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436"
RUNTIME = "debian:trixie@sha256:fac46bff2e02f51425b6e33b0e1169f55dfb053d83511ca28aa50c09fd5ed7a4"
ANALYZER = "localhost/strad-analyzer@sha256:98282ccd4b3b3d49134dd991d3a471a24c6e540bcc0cf4963c074367c2cd201b"
TLS_BUNDLE = Path("/var/lib/docker/volumes/steadholme_sluice_acme/_data/access.w33d.xyz")
QUORUM_RECEIPT_SCHEMA = "w33d.access.approval-quorum-bootstrap-receipt.v1"
QUORUM_GRANT_TTL_SECONDS = 691200
QUORUM_ROLE_ID = "rol_approval_quorum_genesis_v1"
QUORUM_ROLE_NAME = "approval-quorum-genesis-v1"
REQUIRED_SCENARIOS = (
    "closed_topology", "application_approval", "oidc_browser", "mcp_four_tools",
    "authorization_negatives", "credential_rotation", "online_revocation",
    "final_fence_barrier", "fault_recovery",
)


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def scopes_digest(scopes: list[str]) -> str:
    canonical = "analyze-application-scopes-v1\n" + "\n".join(scopes) + "\n"
    return hashlib.sha256(canonical.encode()).hexdigest()


def write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".l2-receipt-", delete=False) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(value, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # 同目录 hard link 原子发布，并在目标已存在时失败，避免覆盖先前证据。
        os.link(temporary, path)
        temporary.unlink()
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink()


def source_digest(checkout: Path) -> str:
    result = hashlib.sha256()
    roots = ["Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "src", "cmd", "internal",
             "crates", "migrations", "templates", "static", "catalog", "facade"]
    for name in roots:
        path = checkout / name
        files = [path] if path.is_file() else sorted(path.rglob("*")) if path.is_dir() else []
        for file in files:
            relative = file.relative_to(checkout)
            if {"node_modules", "dist", "target", ".git"}.intersection(relative.parts):
                continue
            if file.is_file():
                if file.is_symlink():
                    raise RuntimeError(f"symlink in build input: {relative}")
                result.update(str(relative).encode() + b"\0" + bytes.fromhex(digest(file)))
    return result.hexdigest()


def verify_shared_public_contract(access_checkout: Path) -> None:
    # Access must compile independently of a sibling checkout, while composed
    # acceptance still checks that both repositories carry the exact contract.
    frozen = access_checkout / 'tests/fixtures/analyze_public_v1.json'
    if frozen.is_symlink() or not frozen.is_file() or frozen.read_bytes() != (ROOT / 'analyze-public-v1.json').read_bytes():
        raise RuntimeError('Access and Strad public Analyze contracts differ')


def require_complete(observations: dict) -> None:
    missing = [name for name in REQUIRED_SCENARIOS if observations.get(name, {}).get("status") != "pass"]
    if missing:
        raise RuntimeError("L2 release evidence incomplete: " + ", ".join(missing))
    for name in REQUIRED_SCENARIOS:
        value = observations[name]
        if not value.get("checks") or value.get("finished_at", 0) < value.get("started_at", 1):
            raise RuntimeError(f"L2 scenario has no observed checks: {name}")


def deployment_values() -> dict[str, str]:
    wanted = {"STRAD_NEWAPI_KEY", "STRAD_NEWAPI_MODEL", "STRAD_NEWAPI_CONTEXT_TOKENS"}
    result = {}
    for line in (INFRA / "deploy/.env").read_text().splitlines():
        name, separator, value = line.partition("=")
        if separator and name in wanted:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            result[name] = value
    if set(result) != wanted or len(result["STRAD_NEWAPI_KEY"]) < 32:
        raise RuntimeError("NewAPI configuration is incomplete")
    return result


class McpFailure(RuntimeError):
    def __init__(self, error):
        self.error = error
        message = error.get("message", "")
        message = re.sub(r"^MCP error -?\d+: ", "", message)
        try:
            self.contract = json.loads(message).get("error", {})
        except (ValueError, AttributeError):
            self.contract = {}
        super().__init__(f"L2 MCP returned JSON-RPC error {error.get('code')}")


def upload_contract(created, sample):
    expected = {"analysis_id", "upload_id", "finalize_operation_id", "chunk_size", "chunk_count",
                "chunk_url_template", "finalize_url"}
    if set(created) != expected:
        raise RuntimeError("create response differs from the seven-field upload contract")
    for field in ["analysis_id", "upload_id", "finalize_operation_id"]:
        if str(uuid.UUID(created[field])) != created[field]:
            raise RuntimeError("create response has a noncanonical identifier")
    prefix = "https://analyze.w33d.xyz/v1/uploads/" + created["upload_id"]
    if (created["chunk_size"] != 8388608
            or created["chunk_count"] != (len(sample) + 8388607) // 8388608
            or created["chunk_url_template"] != prefix + "/chunks/{chunk_index}"
            or created["finalize_url"] != prefix + "/finalize"):
        raise RuntimeError("upload URLs or chunk geometry violate the public contract")
    return "/v1/uploads/" + created["upload_id"]


class ClosedRun:
    def __init__(self, analyzer_image=ANALYZER):
        if not re.fullmatch(r"(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[a-f0-9]{64}", analyzer_image):
            raise RuntimeError("closed analyzer image must use an immutable digest")
        self.analyzer_image = analyzer_image
        self.run_id = secrets.token_hex(12)
        self.project = "analyze-l2-" + self.run_id
        runtime_root = INFRA / ".runtime"
        runtime_root.mkdir(mode=0o700, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="analyze-l2-", dir=runtime_root))
        self.env_file = self.work / "compose.env"
        self.env: dict[str, str] = {}
        self.sources: dict = {}
        self.observations: dict = {}
        self.images: list[str] = []
        self.container_ids: dict[str, str] = {}
        self.cookies = SimpleCookie()
        self.csrf = None
        self.browser_fixture = json.loads((ROOT / "fixtures/oidc-browser-v1.json").read_text())

    def command(self, args, *, cwd=None, env=None, timeout=900, stdin=None) -> str:
        completed = subprocess.run(args, cwd=cwd, env=env, input=stdin, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if completed.returncode:
            detail = "\n".join(stream[-2500:] for stream in (completed.stdout, completed.stderr) if stream)
            for value in self.env.values():
                if len(value) >= 24:
                    detail = detail.replace(value, "[redacted]")
            detail = re.sub(r"postgres(?:ql)?://\S+|app_v1_[A-Za-z0-9_-]{43}", "[redacted]", detail)
            raise RuntimeError(f"{Path(args[0]).name} failed ({completed.returncode}): {detail}")
        return completed.stdout.strip()

    def compose(self, *args, **kwargs) -> str:
        return self.command(["docker", "compose", "--env-file", str(self.env_file),
                             "-p", self.project, "-f", str(ROOT / "compose.closed.yml"), *args], **kwargs)

    def initialize(self):
        (self.work / 'decision-fault.json').write_text('{"mode":"pass"}\n')
        (self.work / 'decision-fault.json').chmod(0o644)
        for executable in ["docker", "cargo", "go", "node", "openssl", "git", "npm"]:
            if not shutil.which(executable):
                raise RuntimeError(f"required executable missing: {executable}")
        self.command(["docker", "compose", "version"])
        manifest = json.loads((INFRA / ".worktrees/analyze-gen7/task-003-commit-manifest.json").read_text())
        for name, checkout in CHECKOUTS.items():
            revision = self.command(["git", "rev-parse", "HEAD"], cwd=checkout)
            if name in {"sluice", "verdict"}:
                if revision != manifest["repositories"][name]["final_commit_sha"]:
                    raise RuntimeError(f"{name} manifest revision drift")
                if self.command(["git", "status", "--porcelain"], cwd=checkout):
                    raise RuntimeError(f"{name} manifest worktree is dirty")
            self.sources[name] = {"revision": revision, "source_sha256": source_digest(checkout)}
        verify_shared_public_contract(CHECKOUTS['access'])
        for image in [NODE, RUNTIME, self.analyzer_image]:
            self.command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
        if not TLS_BUNDLE.is_file() or TLS_BUNDLE.is_symlink():
            raise RuntimeError("existing Access TLS bundle is unavailable")
        self.command(["openssl", "x509", "-in", str(TLS_BUNDLE), "-noout", "-checkend", "3600"])
        self.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                      "-subj", "/CN=Analyze closed acceptance",
                      "-addext", "subjectAltName=DNS:analyze.w33d.xyz,DNS:id.w33d.xyz",
                      "-keyout", str(self.work / "test.key"), "-out", str(self.work / "test.crt")])
        (self.work / "test.crt").chmod(0o644)
        os.chown(self.work / "test.key", 65532, 65532)
        secret_names = ["POSTGRES_PASSWORD", "ACCESS_GATEWAY_KEY", "ACCESS_ZONE_KEY", "STRAD_GATEWAY_KEY",
                        "STRAD_ZONE_KEY", "VERDICT_DECISION_TOKEN", "VERDICT_PROJECTION_TOKEN",
                        "VERDICT_LIFECYCLE_TOKEN", "APPLICATION_CREDENTIAL_PEPPER", "ACCESS_INTROSPECTION_TOKEN",
                        "EXECUTION_FENCE_TOKEN", "FACADE_REVOCATION_TOKEN", "GOVERNANCE_REPORTING_TOKEN",
                        "STRAD_FACADE_TOKEN", "SLUICE_SESSION_SECRET", "BRIDGE_TOKEN", "FILE_SERVER_KEY",
                        "MFA_ASSERTION_HMAC_KEY", "ASSURANCE_TOKEN", "OIDC_CLIENT_SECRET",
                        "REGISTRATION_MAC_KEY", "CONSEQUENCE_KEY", "CENSUS_TOKEN",
                        "LIFECYCLE_SLUICE_TOKEN", "LIFECYCLE_NEWAPI_TOKEN", "LIFECYCLE_KEYSTONE_TOKEN",
                        "CLI_SERVICE_TOKEN", "CLI_DELTA_TOKEN"]
        self.env = {"L2_" + name: secrets.token_hex(32) for name in secret_names}
        subject = "usr_" + secrets.token_urlsafe(32)
        self.env.update({"L2_TEST_SUBJECT": subject, "L2_TEST_OWNER_SUBJECT": "user:" + subject})
        self.env.update({"L2_REGISTRATION_MAC_KID": "registration-l2",
                         "L2_REGISTRATION_SUBJECTS_JSON": json.dumps(
                             ["user:" + subject, "user:u_admin", "user:w33d"], separators=(",", ":"))})
        self.registration_tls()
        for prefix, kid in [("APPLICATION", "application-l2"), ("APPROVAL", "approval-l2")]:
            seed = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
            public = self.command(["node", "-e", """
const c=require('node:crypto');const fs=require('node:fs');
const k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(fs.readFileSync(0,'utf8'),'base64url')]),format:'der',type:'pkcs8'});
process.stdout.write(c.createPublicKey(k).export({format:'jwk'}).x);
"""], stdin=seed)
            self.env[f"L2_{prefix}_SIGNING_KEYRING"] = json.dumps({kid: seed}, separators=(",", ":"))
            if prefix == "APPLICATION":
                self.env["L2_APPLICATION_VERIFICATION_KEYRING"] = json.dumps({kid: {"public_key": public, "retired_at": None}}, separators=(",", ":"))
                self.env["L2_SPONSOR_PUBLIC_KEYRING"] = json.dumps({kid: public}, separators=(",", ":"))
        for name, value in deployment_values().items():
            self.env["L2_" + name.removeprefix("STRAD_")] = value
        self.env.update({"L2_ANALYZER_IMAGE": self.analyzer_image, "L2_NODE_IMAGE": NODE,
                         "L2_WORK_ROOT": str(self.work), "L2_ACCESS_TLS_BUNDLE": str(TLS_BUNDLE),
                         "L2_NEWAPI_URL": "http://newapi:9080/v1/chat/completions",
                         "L2_NEWAPI_NETWORK": "steadholme_hf-ai"})
        for relative in ["uploads", *["analyzer/" + name for name in ["workspaces", "storage", "state", "cache", "audit"]]]:
            path = self.work / relative
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
            os.chown(path, 1000, 1000)
        routes = [
            {"name": "analyze-mcp", "match": {"host": "analyze.w33d.xyz", "path_prefix": "/mcp"}, "auth": "application", "upstream": "http://facade:18120"},
            {"name": "analyze-uploads", "match": {"host": "analyze.w33d.xyz", "path_prefix": "/v1/uploads"}, "auth": "application", "upstream": "http://facade:18120"},
            {"name": "analyze-access", "match": {"host": "analyze.w33d.xyz", "path_prefix": "/"}, "auth": "sso", "upstream": "http://access:9390", "step_up_resume_path": "/applications/"},
        ]
        (self.work / "sluice.json").write_text(json.dumps({"keystone_issuer": "https://id.w33d.xyz", "routes": routes}))
        (self.work / "sluice.json").chmod(0o644)

    def registration_tls(self):
        root = self.work / "registration"
        root.mkdir(mode=0o700)
        self.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                      "-subj", "/CN=Closed registration authority", "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                      "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")])
        for index, (name, uid, purpose) in enumerate([
                ("server", 65532, "serverAuth"), ("client", 1000, "clientAuth")], 1):
            extension = root / f"{name}.ext"
            extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                                 f"extendedKeyUsage={purpose}\n" +
                                 ("subjectAltName=DNS:closed-registration\n" if name == "server" else ""))
            self.command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                          "-subj", f"/CN=closed-registration-{name}", "-keyout", str(root / f"{name}.key"),
                          "-out", str(root / f"{name}.csr")])
            self.command(["openssl", "x509", "-req", "-in", str(root / f"{name}.csr"),
                          "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"),
                          "-set_serial", str(index), "-days", "2", "-extfile", str(extension),
                          "-out", str(root / f"{name}.crt")])
            (root / f"{name}.key").chmod(0o600)
            os.chown(root / f"{name}.key", uid, uid)
            (root / f"{name}.crt").chmod(0o644)
            (root / f"{name}.csr").unlink()
            extension.unlink()
        (root / "ca.crt").chmod(0o644)
        (root / "ca.key").unlink()

    def registration_snapshot(self, timeout=60):
        deadline = time.monotonic() + timeout
        expected = sorted(json.loads(self.env["L2_REGISTRATION_SUBJECTS_JSON"]))
        while time.monotonic() < deadline:
            raw = self.sql("""SELECT json_build_object(
 'snapshot_id',s.snapshot_id,'digest',s.digest,'count',s.row_count,
 'cursor',c.acked_cursor,'subjects',(SELECT json_agg(subject_sub ORDER BY subject_sub)
   FROM subject_registration_state WHERE registration_state='registered'))
FROM registration_snapshot_state s JOIN keystone_registration_consumer_cursor c
 ON c.source_generation=s.source_generation
WHERE s.active AND s.complete AND s.digest_verified_at IS NOT NULL
 AND s.staged_count=s.row_count AND s.imported_count=s.row_count AND s.imported_at IS NOT NULL
 AND NOT c.snapshot_required AND NOT c.quarantined AND c.last_error IS NULL
 AND c.acked_cursor=c.after_cursor AND c.after_cursor=c.head_cursor
 AND s.high_watermark<=c.acked_cursor
 AND EXISTS(SELECT 1 FROM worker_heartbeat h WHERE h.worker_name='keystone-registration-consumer'
   AND h.last_success_at>=extract(epoch FROM clock_timestamp())::bigint-8 AND h.last_error IS NULL);""")
            if raw:
                value = json.loads(raw)
                if value["subjects"] != expected or value["count"] != len(expected) or value["cursor"] != len(expected):
                    raise RuntimeError("registration worker subject snapshot differs from the explicit closed identities")
                return value
            time.sleep(1)
        raise RuntimeError("registration worker did not import, ACK and catch up to the closed snapshot")

    def access_cli(self, command, settings=None, *, production=False):
        overrides = dict(settings or {})
        if production:
            # 正式 cutover/promotion CLI 只使用 DB，不启动 registration client。
            # prod origin 仅供配置校验；dev worker 始终访问 closed-registration:9443。
            overrides.update({"STEADHOLME_PROFILE": "prod", "KEYSTONE_REGISTRATION_URL": "https://keystone:8443",
                              "ACCESS_GOVERNANCE_SERVICE_TOKEN": self.env["L2_CLI_SERVICE_TOKEN"],
                              "DELTA_URL": "http://closed-lifecycle:9081",
                              "DELTA_SERVICE_TOKEN": self.env["L2_CLI_DELTA_TOKEN"]})
        args = ["run", "--rm", "--no-deps"]
        for name, value in overrides.items():
            args += ["-e", f"{name}={value}"]
        return self.compose(*args, "access", command, timeout=120)

    def configure_access(self, **settings):
        self.env.update(settings)
        self.env_file.write_text("".join(f"{name}='{value}'\n" for name, value in self.env.items()))
        self.env_file.chmod(0o600)
        self.compose("up", "-d", "--no-deps", "access", timeout=120)
        self.container_ids["access"] = self.compose("ps", "-q", "access")

    def wait_legacy_writer_drain(self, timeout=35):
        # 旧 worker 的租约为 30 秒；停进程不等于租约失效，清理由正式 cutover 做 CAS 和审计。
        deadline = time.monotonic() + timeout
        while True:
            raw = self.sql("""SELECT json_build_object(
 'pending_events',(SELECT count(*) FROM jml_event WHERE state='received'),
 'has_error',last_error IS NOT NULL,
 'lease_active',lease_owner IS NOT NULL AND
   (lease_expires_at IS NULL OR lease_expires_at>extract(epoch FROM clock_timestamp())::bigint))
FROM workforce_consumer_cursor WHERE consumer='census-workforce';""")
            if not raw:
                raise RuntimeError("legacy workforce cursor is missing")
            state = json.loads(raw)
            if state["pending_events"] or state["has_error"]:
                raise RuntimeError("legacy Census has undrained events or worker errors")
            if not state["lease_active"]:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("legacy Census lease did not expire after worker stop")
            time.sleep(1)

    def wait_birthright_projection(self, expected_count, timeout=30):
        # lifecycle ACK 不代表 grant projection 已完成；这里只等待状态，完整一致性仍由正式 CLI 校验。
        deadline = time.monotonic() + timeout
        while True:
            state = json.loads(self.sql("""SELECT json_build_object(
 'subjects',count(*),
 'active',count(*) FILTER(WHERE a.state='active' AND g.state IN ('active','expiring')
   AND a.desired_grant_version=g.version AND p.state='projected'
   AND p.desired_version=g.version AND p.policy_epoch>0
   AND a.projection_ack_version=p.desired_version AND a.projection_ack_epoch=p.policy_epoch
   AND a.projection_ack_digest=p.projection_ack_digest),
 'failed',count(*) FILTER(WHERE a.last_error IS NOT NULL OR p.last_error IS NOT NULL
   OR a.state='dead' OR p.state='dead'))
FROM subject_effective_access_state e JOIN effective_writer_epoch w
 ON w.id=1 AND w.writer_mode='effective' AND e.writer_epoch=w.epoch AND e.writer_generation=w.generation
LEFT JOIN birthright_assignment a ON a.subject_sub=e.subject_sub AND a.package_id='pkg_registered_user_baseline'
LEFT JOIN "grant" g ON g.id=a.grant_id
LEFT JOIN grant_projection p ON p.grant_id=a.grant_id
WHERE e.effective_state='active';"""))
            if state["failed"]:
                raise RuntimeError("Birthright worker or projection failed")
            if state["subjects"] > expected_count:
                raise RuntimeError("Birthright subject count drift")
            if state["subjects"] == expected_count and state["active"] == expected_count:
                return state
            if time.monotonic() >= deadline:
                raise RuntimeError("Birthright projection did not finish: " + json.dumps(state, sort_keys=True))
            time.sleep(1)

    def catalog_prerequisites(self):
        started = time.time()
        snapshot = self.registration_snapshot()
        print(f"L2 registration: imported={snapshot['count']} ACK={snapshot['cursor']} caught up", flush=True)
        maxima = json.loads(self.sql("""SELECT json_build_object(
 'CENSUS',GREATEST(COALESCE((SELECT max(source_version) FROM subject_access_state),0),
                  COALESCE((SELECT max(source_version) FROM jml_event),0)),
 'VERDICT',COALESCE(max(source_version) FILTER(WHERE verdict_applied_at IS NOT NULL),0),
 'SLUICE',COALESCE(max(source_version) FILTER(WHERE sluice_applied_at IS NOT NULL),0),
 'NEWAPI',COALESCE(max(source_version) FILTER(WHERE newapi_applied_at IS NOT NULL),0),
 'KEYSTONE',COALESCE(max(source_version) FILTER(WHERE keystone_applied_at IS NOT NULL),0)) FROM jml_event;"""))
        verdict_max = int(self.sql("SELECT COALESCE(max(source_version),0) FROM policy_subject_status;", "verdict_l2"))
        if any(maxima.values()) or verdict_max:
            raise RuntimeError("closed genesis cutover requires observed empty workforce and lifecycle stores")
        self.compose("stop", "access", timeout=60)
        self.wait_legacy_writer_drain()
        settings = {"ACCESS_EFFECTIVE_CUTOVER_CONFIRMATION": "CONFIRM_EFFECTIVE_WRITER_CUTOVER_IS_IRREVERSIBLE",
                    "ACCESS_EFFECTIVE_CUTOVER_SNAPSHOT_ID": snapshot["snapshot_id"],
                    "ACCESS_EFFECTIVE_CUTOVER_SNAPSHOT_DIGEST": snapshot["digest"],
                    "ACCESS_EFFECTIVE_CUTOVER_CORRELATION_ID": "closed-cutover:" + self.run_id}
        settings.update({f"ACCESS_EFFECTIVE_CUTOVER_{name}_MAX_SOURCE_VERSION": str(value) for name, value in maxima.items()})
        cutover = self.access_cli("activate-effective-writer", settings, production=True)
        print("L2 cutover: " + cutover, flush=True)
        self.configure_access(L2_EFFECTIVE_WORKER="true")
        self.registration_snapshot()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            pending = self.sql("""SELECT count(*) FROM effective_lifecycle_delivery d
JOIN subject_effective_access_state e ON e.subject_sub=d.subject_sub AND e.effective_version=d.effective_version
WHERE d.state='acked' AND d.ack_version=e.effective_version AND d.ack_state=e.effective_state;""")
            if int(pending) == snapshot["count"] * 4:
                break
            time.sleep(1)
        else:
            raise RuntimeError("effective lifecycle worker did not acknowledge every registered subject")
        birthright = self.wait_birthright_projection(snapshot["count"])
        parity = self.access_cli("check-effective-parity")
        print("L2 parity: " + parity, flush=True)
        self.observations["catalog_prerequisites"] = {"status": "pass", "started_at": started,
            "finished_at": time.time(), "checks": ["real registration snapshot/changes/ACK",
                "official effective writer activation", "real lifecycle delivery and effective parity"],
            "snapshot": snapshot, "cutover": cutover, "birthright": birthright, "parity": parity,
            "identity_domain": "closed synthetic humans", "production_user_used": False}

    def promote_catalog(self):
        quorum = json.loads(self.sql("""SELECT COALESCE(json_agg(subject ORDER BY subject),'[]'::json) FROM (
SELECT DISTINCT g.beneficiary_sub AS subject FROM "grant" g
 JOIN grant_entitlement ge ON ge.grant_id=g.id AND ge.grant_version=g.version
 JOIN entitlement e ON e.id=ge.entitlement_id AND e.active AND e.key='access.approval.decide'
 JOIN grant_projection p ON p.grant_id=g.id AND p.desired_version=g.version AND p.state='projected' AND p.policy_epoch>0
 JOIN subject_effective_access_state s ON s.subject_sub=g.beneficiary_sub AND s.effective_state='active'
 WHERE g.beneficiary_sub IN ('user:u_admin','user:w33d') AND g.state IN ('active','expiring')
 AND (g.expires_at IS NULL OR g.expires_at>extract(epoch FROM clock_timestamp())::bigint+604800)) q;"""))
        if quorum != ["user:u_admin", "user:w33d"]:
            raise RuntimeError("catalog promotion blocked: real approval grants/projections required for closed user:u_admin and user:w33d")
        self.compose("stop", "access", timeout=60)
        self.configure_access(L2_BIRTHRIGHT_ENFORCED="true")
        self.registration_snapshot()
        self.access_cli("check-effective-parity")
        promoted = self.access_cli("promote-package-catalog", {
            "ACCESS_PACKAGE_CATALOG_PROMOTION_ENABLED": "true",
            "ACCESS_PACKAGE_PROMOTION_CONFIRMATION": "CONFIRM_PACKAGE_CATALOG_PROMOTION",
            "ACCESS_PACKAGE_PROMOTION_CORRELATION_ID": "closed-promotion:" + self.run_id}, production=True)
        counts = json.loads(self.sql("""SELECT json_build_array(count(*),count(*) FILTER(WHERE requestable))
FROM access_package WHERE package_catalog_frozen;"""))
        if counts != [10, 9]:
            raise RuntimeError("promoted catalog differs from 10 frozen / 9 requestable packages")
        self.configure_access(L2_CATALOG_PROMOTED="true")
        before = json.loads(self.command(["docker", "inspect", self.container_ids["access"]]))[0]["State"]["StartedAt"]
        self.compose("restart", "access", timeout=60)
        self.registration_snapshot()
        readiness = self.ready()
        after = json.loads(self.command(["docker", "inspect", self.container_ids["access"]]))[0]["State"]["StartedAt"]
        if before == after:
            raise RuntimeError("Access restart did not change the actual process start time")
        self.access_cli("check-effective-parity")
        self.observations["catalog_promotion_restart"] = {"status": "pass", "started_at": time.time(),
            "finished_at": time.time(), "checks": ["official catalog promotion", "10 frozen / 9 requestable",
                "Access restarted", "post-restart worker ACK, parity and readiness"],
            "promotion": promoted, "before": before, "after": after, "readiness": readiness}
        print("L2 catalog: promoted 9/10 packages; Access restart and readiness verified", flush=True)

    def build(self):
        for name, checkout in CHECKOUTS.items():
            print(f"L2 build: {name}", flush=True)
            context = self.work / "build" / name
            app = context / "app"
            app.mkdir(parents=True)
            if name == "sluice":
                git_dir = self.command(["git", "rev-parse", "--absolute-git-dir"], cwd=checkout)
                self.command(["go", "build", "-trimpath", "-o", str(app / "service"), "./cmd/sluice"],
                             cwd=checkout, env={**os.environ, "CGO_ENABLED": "0", "GOMAXPROCS": "2",
                                                "GIT_DIR": git_dir, "GIT_WORK_TREE": str(checkout)})
                build_info = self.command(["go", "version", "-m", str(app / "service")])
                if "vcs.revision=" + self.sources[name]["revision"] not in build_info:
                    raise RuntimeError("Sluice binary is missing its manifest VCS revision")
            else:
                binary = "access-governance" if name == "access" else name
                self.command(["cargo", "build", "--locked", "--bin", binary], cwd=checkout,
                             env={**os.environ, "CARGO_BUILD_JOBS": "1"})
                shutil.copy2(checkout / "target/debug" / binary, app / "service")
                self.command(["strip", str(app / "service")])
            if name == "strad":
                for directory in ["templates", "static"]:
                    shutil.copytree(checkout / directory, app / directory)
            if source_digest(checkout) != self.sources[name]["source_sha256"]:
                raise RuntimeError(f"{name} source changed during build")
            tag = f"{self.project}-{name}"
            self.command(["docker", "build", "--quiet", "--build-arg", f"L2_RUNTIME_IMAGE={RUNTIME}",
                          "--build-arg", f"L2_SOURCE_SHA256={self.sources[name]['source_sha256']}",
                          "-f", str(ROOT / "Dockerfile.native"), "-t", tag, str(context)], timeout=1200)
            self.images.append(tag)
            image = self.command(["docker", "image", "inspect", tag, "--format", "{{.Id}}"])
            self.sources[name]["image"] = image
            self.env["L2_" + name.upper() + "_IMAGE"] = image
        print("L2 build: facade", flush=True)
        tag = f"{self.project}-facade"
        self.command(["docker", "build", "--quiet", "--build-arg", f"STRAD_NODE_BUILDER_IMAGE={NODE}",
                      "-f", "Dockerfile.facade", "-t", tag, "."], cwd=STRAD, timeout=1200)
        self.images.append(tag)
        self.env["L2_FACADE_IMAGE"] = self.command(["docker", "image", "inspect", tag, "--format", "{{.Id}}"])
        self.env_file.write_text("".join(f"{name}='{value}'\n" for name, value in self.env.items()))
        self.env_file.chmod(0o600)
        configuration = json.loads(self.compose("config", "--format", "json"))
        if not configuration["networks"]["closed"].get("internal"):
            raise RuntimeError("L2 network is not internal")
        if any(service.get("ports") for service in configuration["services"].values()):
            raise RuntimeError("L2 must not publish host ports")

    def start(self):
        print("L2 runtime: migrate and start real services", flush=True)
        try:
            self.compose("up", "-d", "--wait", "postgres", "acceptance", "closed-registration", "closed-lifecycle", timeout=120)
        except RuntimeError as error:
            logs = self.compose("logs", "--no-color", "--tail", "18", "acceptance", "postgres")
            for value in self.env.values():
                if len(value) >= 24:
                    logs = logs.replace(value, "[redacted]")
            raise RuntimeError(str(error) + "\n" + logs) from error
        self.compose("run", "--rm", "--no-deps", "access", "migrate", timeout=180)
        self.compose("up", "-d", "access", "verdict", "analyzer", "strad", "facade", "sluice", timeout=240)
        services = json.loads(self.compose("config", "--format", "json"))["services"]
        for name in services:
            identifier = self.compose("ps", "-q", name)
            if not identifier:
                raise RuntimeError(f"L2 service absent: {name}")
            inspect = json.loads(self.command(["docker", "inspect", identifier]))[0]
            if inspect["HostConfig"].get("PortBindings"):
                raise RuntimeError(f"L2 host port binding: {name}")
            self.container_ids[name] = identifier
        self.observations["closed_topology"] = {"status": "pass", "started_at": time.time(),
            "finished_at": time.time(), "checks": [f"all {len(services)} actual containers exist", "no host port bindings", "internal closed network"],
            "container_ids": self.container_ids}

    def address(self, name):
        data = json.loads(self.command(["docker", "inspect", self.container_ids[name]]))[0]
        if not data["State"]["Running"]:
            log = self.command(["docker", "logs", "--tail", "12", self.container_ids[name]])
            for value in self.env.values():
                if len(value) >= 24:
                    log = log.replace(value, "[redacted]")
            raise RuntimeError(f"L2 service stopped: {name}: {log}")
        return data["NetworkSettings"]["Networks"][self.project + "_closed"]["IPAddress"]

    def request(self, service, port, path, *, host=None, tls=False, method="GET", body=None, headers=None, timeout=5):
        ip = self.address(service)
        if tls:
            context = ssl.create_default_context()
            context.load_verify_locations(self.work / "test.crt")
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
            connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection((ip, port), timeout)
        else:
            connection = http.client.HTTPConnection(ip, port, timeout=timeout)
        try:
            connection.request(method, path, body=body, headers={"Host": host or f"{service}:{port}", **(headers or {})})
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise RuntimeError("L2 probe response exceeded bound")
            response_headers = {name.lower(): value for name, value in response.getheaders()}
            response_headers["set-cookie"] = response.headers.get_all("Set-Cookie", [])
            return response.status, response_headers, raw
        finally:
            connection.close()

    def ready(self):
        checks = [("access", 9390, "/readyz"), ("verdict", 9140, "/healthz"),
                  ("analyzer", 18090, "/readyz"), ("strad", 9360, "/readyz"),
                  ("facade", 18120, "/readyz"), ("sluice", 9090, "/healthz")]
        observations = []
        for name, port, path in checks:
            deadline = time.monotonic() + 90
            last = "no response"
            while time.monotonic() < deadline:
                try:
                    status, _, raw = self.request(name, port, path)
                    if status == 200:
                        observations.append({"service": name, "path": path, "status": status,
                                             "response_sha256": hashlib.sha256(raw).hexdigest(), "observed_at": time.time()})
                        print(f"L2 ready: {name}", flush=True)
                        break
                    last = f"HTTP {status}: {raw[:800].decode(errors='replace')}"
                except (OSError, http.client.HTTPException) as error:
                    last = type(error).__name__
                time.sleep(1)
            else:
                raise RuntimeError(f"L2 readiness failed: {name}: {last}")
        return observations

    def cleanup(self):
        if self.env_file.exists():
            try:
                self.compose("down", "--volumes", "--remove-orphans", timeout=120)
            except (RuntimeError, subprocess.TimeoutExpired):
                print(f"L2 cleanup requires attention: project={self.project}", flush=True)
                return
        for image in self.images:
            subprocess.run(["docker", "image", "rm", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(self.work)

    def browser_request(self, url, *, method="GET", body=None, headers=None):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc not in {"analyze.w33d.xyz", "id.w33d.xyz"}:
            raise RuntimeError("closed browser attempted to leave allowed origins")
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        cookie = "; ".join(f"{value.key}={value.value}" for value in self.cookies.values()
                           if not value["domain"] or parsed.hostname.endswith(value["domain"].lstrip(".")))
        response = self.request("acceptance", 443, path, host=parsed.hostname, tls=True,
                                method=method, body=body, headers={"Cookie": cookie, **(headers or {})})
        for raw_cookie in response[1]["set-cookie"]:
            self.cookies.load(raw_cookie)
        return response

    def browser(self):
        started = time.time()
        url = self.browser_fixture["origin"] + self.browser_fixture["resume_path"]
        status, headers, _ = self.browser_request(url)
        if status != 302 or not headers.get("location", "").startswith("https://id.w33d.xyz/authorize?"):
            raise RuntimeError(f"anonymous Analyze request did not redirect to the closed issuer: HTTP {status}")
        status, headers, _ = self.browser_request(headers["location"])
        if status != 302 or not headers.get("location", "").startswith(self.browser_fixture["oidc"]["callback"] + "?"):
            raise RuntimeError("closed issuer did not return the bound callback")
        status, headers, body = self.browser_request(headers["location"])
        if status != 302:
            raise RuntimeError(f"Sluice callback failed: HTTP {status}: {body[:120].decode(errors='replace')}")
        cookie = self.cookies.get("__Secure-gw")
        if not cookie or not cookie["secure"] or not cookie["httponly"] or cookie["samesite"].lower() != "lax":
            raise RuntimeError("gateway cookie flags differ from the browser contract")
        location = headers.get("location", "")
        if location not in {url, "/applications/"}:
            raise RuntimeError("callback resume path differs from /applications/")
        status, headers, body = self.browser_request(url)
        if status != 200:
            raise RuntimeError(f"authenticated applications page failed: HTTP {status}")
        html = body.decode()
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', html)
        if not csrf:
            raise RuntimeError("applications page did not provide form CSRF")
        self.csrf = csrf[1]
        self.observations["oidc_browser_core"] = {"status": "pass", "started_at": started, "finished_at": time.time(),
            "checks": ["anonymous issuer redirect", "state/nonce/PKCE callback", "secure gateway cookie",
                       "applications resume", "authenticated applications DOM with CSRF"],
            "dom_sha256": hashlib.sha256(html.replace(self.csrf, "[csrf]").encode()).hexdigest(),
            "issuer_fixture": "closed-test-issuer", "production_user_used": False}
        print("L2 browser: real Sluice callback and Access applications page verified", flush=True)

    def sql(self, query, database="access_l2"):
        if database not in {"access_l2", "sluice_l2", "verdict_l2", "facade_l2", "strad_l2"}:
            raise RuntimeError("unknown closed database")
        return self.command(["docker", "exec", "-i", self.container_ids["postgres"],
                             "psql", "-U", "l2", "-d", database, "-qAt", "-v", "ON_ERROR_STOP=1"], stdin=query)

    def signed_bootstrap(self, command, authority, idempotency, *, environment=None):
        prefixes = {"system-bootstrap-analyze-approver": "ACCESS_ANALYZE_APPROVER_BOOTSTRAP_",
                    "system-bootstrap-approval-quorum": "ACCESS_APPROVAL_QUORUM_BOOTSTRAP_"}
        if command not in prefixes:
            raise RuntimeError("unknown closed bootstrap ceremony")
        prefix = prefixes[command]
        release_parent = Path("/secure/release")
        if not release_parent.is_dir() or release_parent.is_symlink():
            raise RuntimeError("signed bootstrap requires the existing /secure/release root")
        ceremony_root = Path(tempfile.mkdtemp(prefix="analyze-l2-", dir=release_parent))
        try:
            self.command(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                          "-out", str(ceremony_root / "private.pem")])
            self.command(["openssl", "pkey", "-in", str(ceremony_root / "private.pem"), "-pubout",
                          "-out", str(ceremony_root / "public.pem")])
            key_digest = digest(ceremony_root / "public.pem")
            authority = {**authority, "mode": "commit",
                         "idempotency_key_sha256": hashlib.sha256(idempotency.encode()).hexdigest(),
                         "signing_key_sha256": key_digest}
            (ceremony_root / "authority.json").write_text(json.dumps(authority, separators=(",", ":")))
            self.command(["openssl", "dgst", "-sha256", "-sign", str(ceremony_root / "private.pem"),
                          "-out", str(ceremony_root / "authority.sig"), str(ceremony_root / "authority.json")])
            for file in ceremony_root.iterdir():
                file.chmod(0o600)
            environment = {**(environment or {}),
                "DATABASE_URL": f"postgresql://l2:{self.env['L2_POSTGRES_PASSWORD']}@{self.address('postgres')}:5432/access_l2",
                prefix + "MODE": "commit", prefix + "IDEMPOTENCY_KEY": idempotency,
                prefix + "RELEASE_ROOT": str(ceremony_root),
                prefix + "AUTHORITY_FILE": str(ceremony_root / "authority.json"),
                prefix + "AUTHORITY_SIGNATURE_FILE": str(ceremony_root / "authority.sig"),
                prefix + "AUTHORITY_PUBLIC_KEY_FILE": str(ceremony_root / "public.pem"),
                prefix + "AUTHORITY_PUBLIC_KEY_SHA256": key_digest}
            receipts = [json.loads(self.command([str(self.work / "build/access/app/service"),
                        command], env=environment)) for _ in range(2)]
            receipt_schema = QUORUM_RECEIPT_SCHEMA if command == "system-bootstrap-approval-quorum" else authority["schema"]
            expected = {"schema": receipt_schema, "mode": "commit",
                        "authority_payload_sha256": digest(ceremony_root / "authority.json"),
                        "signature_sha256": digest(ceremony_root / "authority.sig"),
                        "signing_key_sha256": key_digest,
                        "idempotency_key_sha256": authority["idempotency_key_sha256"]}
            if any(any(receipt.get(key) != value for key, value in expected.items()) for receipt in receipts):
                raise RuntimeError("signed bootstrap receipt does not match its exact authority bundle")
            return receipts
        finally:
            shutil.rmtree(ceremony_root)

    def bootstrap_quorum(self):
        if self.observations.get("catalog_prerequisites", {}).get("status") != "pass":
            raise RuntimeError("catalog prerequisites must pass before quorum genesis")
        started = time.time()
        snapshot = self.registration_snapshot()
        writer = json.loads(self.sql("""SELECT json_build_object('epoch',epoch,'generation',generation)
FROM effective_writer_epoch WHERE id=1 AND writer_mode='effective';"""))
        now = int(time.time())
        subjects = ["user:u_admin", "user:w33d"]
        permissions = ["access.approval.decide"]
        principal = "service:access-governance-approval-quorum-bootstrap"
        authority = {"schema": "w33d.access.approval-quorum-bootstrap-authority.v1",
            "ceremony": "release-root-rsa-pkcs1v15-sha256", "trust_domain": "service:system",
            "environment": "closed-acceptance", "principal": principal,
            "operation": "access.approval-quorum.bootstrap", "subjects": subjects, "permissions": permissions,
            "catalog_digest": digest(CHECKOUTS["access"] / "catalog/permissions.snapshot.json"),
            "registration_snapshot_id": snapshot["snapshot_id"], "registration_snapshot_digest": snapshot["digest"],
            "writer_epoch": writer["epoch"], "writer_generation": writer["generation"],
            "grant_expires_at": now + QUORUM_GRANT_TTL_SECONDS, "issued_at": now, "expires_at": now + 300}
        counts_query = """SELECT json_build_object(
 'requests',(SELECT count(*) FROM access_request),'approval_decisions',(SELECT count(*) FROM approval_decision),
 'application_requests',(SELECT count(*) FROM application_request),
 'application_decisions',(SELECT count(*) FROM application_system_policy_decision),
 'application_principals',(SELECT count(*) FROM application_principal),
 'application_credentials',(SELECT count(*) FROM application_credential),
 'grants',(SELECT count(*) FROM "grant"),'roles',(SELECT count(*) FROM "role"),
 'requestable',(SELECT count(*) FROM access_package WHERE requestable));"""
        before = json.loads(self.sql(counts_query))
        if before["requestable"]:
            raise RuntimeError("quorum genesis cannot run after catalog promotion")
        receipts = self.signed_bootstrap("system-bootstrap-approval-quorum", authority,
            "analyze-l2-quorum-" + self.run_id, environment={"STEADHOLME_PROFILE": "dev",
            "ACCESS_APPROVAL_QUORUM_BOOTSTRAP_ENVIRONMENT": "closed-acceptance"})
        first, replay = receipts
        fields = {"schema_version", "schema", "mode", "created", "subjects", "permissions", "grant_ids",
                  "grant_expires_at", "authority_payload_sha256", "signature_sha256", "signing_key_sha256",
                  "idempotency_key_sha256", "requests_consumed", "human_approvals_created"}
        if (any(set(receipt) != fields for receipt in receipts)
                or first["schema_version"] != 1 or first["schema"] != QUORUM_RECEIPT_SCHEMA
                or first["mode"] != "commit" or first["created"] is not True or replay["created"] is not False
                or replay != {**first, "created": False} or first["subjects"] != subjects
                or first["permissions"] != permissions or first["grant_expires_at"] != now + QUORUM_GRANT_TTL_SECONDS
                or first["requests_consumed"] != 0 or first["human_approvals_created"] != 0):
            raise RuntimeError("quorum genesis receipt exceeded the authorized closed scope")
        grant_ids = first["grant_ids"]
        if (not isinstance(grant_ids, list) or len(grant_ids) != 2
                or any(not isinstance(value, str) or not re.fullmatch(r"grt_[A-Za-z0-9_-]{1,120}", value)
                       for value in grant_ids) or len(set(grant_ids)) != 2):
            raise RuntimeError("quorum genesis returned invalid grant identifiers")
        after = json.loads(self.sql(counts_query))
        if after != {**before, "grants": before["grants"] + 2, "roles": before["roles"] + 1}:
            raise RuntimeError("quorum genesis changed requests, votes, credentials or catalog outside its scope")
        deadline = time.monotonic() + 30
        while True:
            state = json.loads(self.sql(f"""SELECT json_build_object(
 'grants',count(*),
 'exact',count(*) FILTER(WHERE g.grant_source='role' AND g.role_id='{QUORUM_ROLE_ID}'
   AND g.granted_by='{principal}' AND g.entitlement_id IS NULL AND g.package_id IS NULL
   AND g.request_id IS NULL AND g.version=1 AND g.catalog_version=1 AND g.state='active'
   AND g.expires_at={now + QUORUM_GRANT_TTL_SECONDS}
   AND g.beneficiary_sub=CASE g.id WHEN '{grant_ids[0]}' THEN 'user:u_admin' ELSE 'user:w33d' END
   AND EXISTS(SELECT 1 FROM "role" r WHERE r.id=g.role_id AND r.name='{QUORUM_ROLE_NAME}'
       AND r.owner_sub='{principal}' AND r.active AND r.version=1 AND r.created_at=g.granted_at
       AND (SELECT count(*) FROM role_entitlement m WHERE m.role_id=r.id)=1
       AND (SELECT count(*) FROM role_entitlement m JOIN entitlement e ON e.id=m.entitlement_id
            WHERE m.role_id=r.id AND e.active AND e.key='access.approval.decide')=1)
   AND (SELECT count(*) FROM grant_entitlement m WHERE m.grant_id=g.id)=1
   AND (SELECT count(*) FROM grant_entitlement m JOIN entitlement e ON e.id=m.entitlement_id
        WHERE m.grant_id=g.id AND m.grant_version=g.version AND e.active AND e.key='access.approval.decide')=1
   AND (SELECT count(*) FROM grant_binding b WHERE b.grant_id=g.id)=1
   AND (SELECT count(*) FROM grant_binding b WHERE b.grant_id=g.id AND b.grant_version=g.version
        AND b.grant_source='role' AND b.permission='access.approval.decide')=1),
 'projected',count(*) FILTER(WHERE p.state='projected' AND p.desired_version=g.version
   AND p.policy_epoch>0 AND p.projected_edge_count=1 AND p.projection_ack_digest ~ '^[0-9a-f]{{64}}$'),
 'failed',count(*) FILTER(WHERE p.last_error IS NOT NULL OR p.state='dead'))
FROM "grant" g LEFT JOIN grant_projection p ON p.grant_id=g.id
WHERE g.id IN ('{grant_ids[0]}','{grant_ids[1]}');"""))
            if state["grants"] != 2 or state["exact"] != 2 or state["failed"]:
                raise RuntimeError("quorum genesis grants or real projection differ from authorized scope")
            if state["projected"] == 2:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("quorum genesis grants were not projected by the real worker")
            time.sleep(1)
        self.observations["quorum_genesis"] = {"status": "pass", "started_at": started,
            "finished_at": time.time(), "checks": ["release-root signed closed genesis",
                "two finite decide-only grants", "no requests or human votes", "exact idempotent replay",
                "real Verdict projection for both grants"], "receipt": first, "projection": state,
            "production_user_used": False}
        print("L2 quorum: signed system genesis and both real grant projections verified", flush=True)

    def bootstrap_approver(self):
        # 目录开放必须由正式 promotion 完成；bootstrap 只创建限定范围的审批身份。
        promoted_revision = self.sql("""
SELECT json_build_object('id',r.id,'digest',r.revision_digest)
FROM access_package p JOIN access_package_revision r ON r.id=p.active_revision_id AND r.package_id=p.id
WHERE p.id='pkg_analyze_mcp_client' AND p.requestable=TRUE AND p.package_catalog_frozen=TRUE;
""")
        if not promoted_revision:
            raise RuntimeError("closed package catalog must be promoted before approver bootstrap")
        revision = json.loads(promoted_revision)
        counts_query = """SELECT json_build_array(
 (SELECT count(*) FROM application_request), (SELECT count(*) FROM application_system_policy_decision),
 (SELECT count(*) FROM application_principal), (SELECT count(*) FROM application_credential),
 (SELECT count(*) FROM \"grant\"));"""
        before = self.sql(counts_query)
        now = int(time.time())
        authority = {"schema": "w33d.access.analyze-approver-bootstrap-authority.v1",
            "ceremony": "release-root-rsa-pkcs1v15-sha256", "trust_domain": "service:system",
            "principal": "service:access-governance-analyze-approval", "package_id": "pkg_analyze_mcp_client",
            "package_revision_id": revision["id"], "package_revision_digest": revision["digest"],
            "scopes_digest": scopes_digest(
                ["analysis.create", "analysis.read", "analysis.conversation", "analysis.upload.cancel"]),
            "quota_tier": "mvp-default-v1", "issued_at": now, "expires_at": now + 300}
        receipts = self.signed_bootstrap("system-bootstrap-analyze-approver", authority, "analyze-l2-" + self.run_id)
        if ([item["created"] for item in receipts] != [True, False]
                or any(item["requests_consumed"] != 0 for item in receipts)
                or before != self.sql(counts_query)):
            raise RuntimeError("bootstrap created request authority outside its exact scope")
        self.bootstrap_receipt = receipts[0]
        print("L2 approval: signed non-login approver bootstrap verified", flush=True)

    def api(self, path, *, method="GET", value=None, expected=200):
        body = None if value is None else json.dumps(value, separators=(",", ":")).encode()
        status, _, raw = self.browser_request("https://analyze.w33d.xyz" + path,
            method=method, body=body, headers={"Content-Type": "application/json", "X-CSRF-Token": self.csrf})
        if status != expected:
            raise RuntimeError(f"L2 control-plane {method} {path} failed: HTTP {status}")
        return json.loads(raw)["data"] if raw else None

    def application_approval(self):
        started = time.time()
        request = self.api("/api/v1/application-requests", method="POST", expected=201, value={
            "name": "Closed L2 client", "purpose": "Real composed Analyze acceptance",
            "package_id": "pkg_analyze_mcp_client",
            "scopes": ["analysis.create", "analysis.read", "analysis.conversation", "analysis.upload.cancel"],
            "credential_ttl_seconds": 86400, "quota_tier": "mvp-default-v1",
            "justification": "Verify the approved public application lifecycle"})
        if request["state"] != "draft" or request["expires_at"] - request["created_at"] != 604800:
            raise RuntimeError("application creation violated the draft/7-day contract")
        request_id = request["id"]
        if not re.fullmatch(r"arq_[A-Za-z0-9_-]+", request_id):
            raise RuntimeError("invalid request identifier")
        path = "/api/v1/application-requests/" + request_id
        pending = self.api(path + "/submit", method="POST", value={"expected_version": request["version"]})
        if pending["state"] != "pending_approval":
            raise RuntimeError("Sponsor submit did not enter pending approval")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            approved = self.api(path)
            if approved["state"] == "approved":
                break
            if approved["state"] != "pending_approval":
                raise RuntimeError("approval worker returned terminal state: " + approved["state"])
            time.sleep(.5)
        else:
            raise RuntimeError("real approval worker did not fulfill the request")
        proof = json.loads(self.sql(f"""SELECT json_build_object(
 'decisions',(SELECT count(*) FROM application_system_policy_decision WHERE request_id='{request_id}' AND consumed_at IS NOT NULL),
 'grants',(SELECT count(*) FROM \"grant\" WHERE request_id='{request_id}'),
 'principals',(SELECT count(*) FROM application_principal WHERE request_id='{request_id}'),
 'version',(SELECT version FROM application_principal WHERE request_id='{request_id}'));"""))
        if any(proof[name] != 1 for name in ["decisions", "grants", "principals"]):
            raise RuntimeError("approval consumption/grant/principal cardinality differs from one")
        credential = self.api("/api/v1/applications/" + request_id + "/credentials", method="POST",
                              expected=201, value={"expected_version": proof["version"]})
        if not re.fullmatch(r"app_v1_[A-Za-z0-9_-]{43}", credential["token"]):
            raise RuntimeError("credential did not use the exact opaque 32-byte format")
        self.application_request = approved
        self.credential = credential
        self.mcp_session = None
        self.observations["application_approval_core"] = {"status": "pass", "started_at": started,
            "finished_at": time.time(), "request_id": request_id, "application_sub": approved["application_sub"],
            "checks": ["signed bootstrap creates no requests", "idempotent bootstrap replay",
                "public create draft", "7-day request TTL", "live Sluice Sponsor submit", "real Access worker approval",
                "single consumed system decision", "one grant and principal", "strong-MFA credential issue"],
            "bootstrap": self.bootstrap_receipt, "counts": proof,
            "credential_id": credential["credential_id"], "credential_fingerprint": credential["fingerprint"]}
        print("L2 approval: public Sponsor submission, worker approval and credential issue verified", flush=True)

    def application_http(self, path, *, body=None, headers=None, method="POST", timeout=5):
        request_headers = {"Authorization": "Bearer " + self.credential["token"],
            "MCP-Protocol-Version": "2025-11-25", "Accept": "application/json, text/event-stream"}
        if getattr(self, "mcp_session", None):
            request_headers["Mcp-Session-Id"] = self.mcp_session
        return self.request("acceptance", 443, path, host="analyze.w33d.xyz", tls=True,
            method=method, body=body, headers={**request_headers, **(headers or {})}, timeout=timeout)

    def mcp(self, method, params=None):
        self.rpc_id = getattr(self, "rpc_id", 0) + 1
        value = {"jsonrpc": "2.0", "id": self.rpc_id, "method": method}
        if params is not None:
            value["params"] = params
        status, headers, raw = self.application_http("/mcp", body=json.dumps(value).encode(),
            headers={"Content-Type": "application/json"})
        if status != 200:
            raise RuntimeError(f"L2 MCP {method} failed: HTTP {status}")
        result = json.loads(raw)
        if result.get("id") != self.rpc_id:
            raise RuntimeError("MCP response identifier mismatch")
        if "error" in result:
            raise McpFailure(result["error"])
        if method == "initialize":
            self.mcp_session = headers.get("mcp-session-id")
            if not self.mcp_session:
                raise RuntimeError("MCP initialize omitted its session identifier")
        return result["result"]

    def tool(self, name, arguments):
        result = self.mcp("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content")
        if result.get("isError") or not isinstance(content, list) or len(content) != 1 or content[0].get("type") != "text":
            raise RuntimeError("MCP tool did not return the exact result envelope")
        self.last_tool_text = content[0]["text"]
        return json.loads(self.last_tool_text)

    def wait_application_projection(self, timeout=30):
        subject = self.application_request["application_sub"]
        if not re.fullmatch(r"application:[A-Za-z0-9_-]{16,128}", subject):
            raise RuntimeError("invalid application subject in acceptance response")
        deadline = time.monotonic() + timeout
        last = {}
        while time.monotonic() < deadline:
            authority = json.loads(self.sql(f"""SELECT json_build_object(
 'state',p.state,'subject_version',p.version,'policy_epoch',p.policy_epoch,
 'revocation_epoch',p.revocation_epoch,'grant_state',g.state,
 'projection_state',gp.state,'projection_error',gp.last_error,
 'projected_edges',gp.projected_edge_count)
 FROM application_principal p JOIN \"grant\" g ON g.id=p.grant_id
 LEFT JOIN grant_projection gp ON gp.grant_id=g.id WHERE p.subject='{subject}';"""))
            raw = self.sql(f"""SELECT json_build_object('state',state,
 'subject_version',subject_version,'policy_epoch',policy_epoch,'revocation_epoch',revocation_epoch)
 FROM policy_application_subject_status WHERE application_sub='{subject}';""", "verdict_l2")
            projected = json.loads(raw) if raw else None
            last = {"authority": authority, "verdict": projected}
            if (authority["state"] == "active" and authority["grant_state"] in {"active", "expiring"}
                    and authority["projection_state"] == "projected" and authority["projected_edges"] == 4
                    and projected == {field: authority[field] for field in
                                      ["state", "subject_version", "policy_epoch", "revocation_epoch"]}):
                print("L2 projection: real Verdict application state and four grant edges caught up", flush=True)
                return last
            time.sleep(1)
        raise RuntimeError("application projection did not converge: " + json.dumps(last))

    def mcp_transport(self):
        started = time.time()
        projection = self.wait_application_projection()
        initialized = self.mcp("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "closed-analyze-acceptance", "version": "1.0.0"}})
        if initialized["protocolVersion"] != "2025-11-25" or set(initialized["capabilities"]) != {"tools"}:
            raise RuntimeError("MCP negotiated capabilities differ from the frozen contract")
        names = [tool["name"] for tool in self.mcp("tools/list")["tools"]]
        if names != ["analysis.create", "analysis.read", "analysis.conversation", "analysis.upload.cancel"]:
            raise RuntimeError("MCP exposed an unexpected tool list")
        self.command(["docker", "cp", self.container_ids["analyzer"] + ":/usr/bin/true", str(self.work / "sample.elf")])
        sample = (self.work / "sample.elf").read_bytes()
        arguments = {"operation_id": str(uuid.uuid4()), "filename": "sample.elf", "total_bytes": len(sample)}
        try:
            created = self.tool("analysis.create", arguments)
        except RuntimeError:
            reason = self.sql("SELECT json_build_object('reason',reason,'decision',decision) "
                              "FROM policy_application_decisions_v2 ORDER BY issued_at DESC LIMIT 1;", "verdict_l2")
            print("L2 MCP decision diagnosis: " + reason, flush=True)
            raise
        self.analysis_created = created
        created_text = self.last_tool_text
        replay = self.tool("analysis.create", arguments)
        if created != replay or created_text != self.last_tool_text:
            raise RuntimeError("MCP create idempotency replay differs")
        print("L2 MCP: initialize, exact tool discovery and idempotent application create verified", flush=True)
        self.observations["mcp_transport"] = {"status": "pass", "started_at": started, "finished_at": time.time(),
            "checks": ["real public bearer authentication", "MCP 2025-11-25 initialize", "exact four tools",
                "Verdict-authorized application create", "idempotent create replay"],
            "projection": projection, "created": created}

    def mcp_upload_cancellation_and_quota(self, sample):
        reserved = self.tool("analysis.create", {"operation_id": str(uuid.uuid4()), "filename": "cancel.elf",
            "total_bytes": len(sample)})
        cancel_prefix = upload_contract(reserved, sample)
        upload_id = reserved["upload_id"]
        cleanup_query = f"SELECT count(*) FROM cleanup_jobs WHERE upload_id='{upload_id}';"
        before = self.sql(cleanup_query, "strad_l2")
        rest_status, _, _ = self.application_http(cancel_prefix + "/cancel", body=b"")
        if rest_status not in {404, 405} or before != "0" or self.sql(cleanup_query, "strad_l2") != before:
            raise RuntimeError("unsupported REST cancel dispatched compensation")
        cancel_args = {"operation_id": str(uuid.uuid4()), "upload_id": upload_id}
        cancelled = self.tool("analysis.upload.cancel", cancel_args)
        cancelled_text = self.last_tool_text
        if cancelled != {"upload_id": upload_id, "state": "cancelled"}:
            raise RuntimeError("MCP upload cancellation did not reach cancelled")
        if self.tool("analysis.upload.cancel", cancel_args) != cancelled or self.last_tool_text != cancelled_text:
            raise RuntimeError("MCP cancellation replay differs")
        # Initial create/finalize already consume two create slots. Five bounded
        # attempts also handle one UTC hourly quota boundary during this run.
        for _ in range(5):
            try:
                extra = self.tool("analysis.create", {"operation_id": str(uuid.uuid4()),
                    "filename": "quota.elf", "total_bytes": len(sample)})
            except McpFailure as error:
                if (error.error.get("code") != -32008 or error.contract.get("code") != "quota_exceeded"
                        or error.contract.get("retryable") is not True):
                    raise
                return rest_status
            self.tool("analysis.upload.cancel", {"operation_id": str(uuid.uuid4()), "upload_id": extra["upload_id"]})
        raise RuntimeError("bounded create quota was not enforced")

    def diagnostic_checkpoint(self, stage, **details):
        if not getattr(self, "keep_for_diagnosis", False):
            return
        # Synthetic closed-environment credentials only. Keep this mode-0600
        # state inside the mode-0700 run directory, never in a release receipt.
        write_private_json(self.work / (stage + ".private.json"), {
            "project": self.project, "container_ids": self.container_ids,
            "mcp_session": self.mcp_session, "credential": self.credential,
            "application_request": self.application_request, "analysis_created": self.analysis_created,
            "rpc_id": self.rpc_id, "observations": self.observations, **details})

    def mcp_four_tools(self):
        started = time.time()
        self.diagnostic_checkpoint("mcp-client")
        created = self.analysis_created
        sample = (self.work / "sample.elf").read_bytes()
        if not sample.startswith(b"\x7fELF"):
            raise RuntimeError("acceptance sample is not the real ELF binary")
        prefix = upload_contract(created, sample)
        for index in range(created["chunk_count"]):
            start = index * created["chunk_size"]
            chunk = sample[start:start + created["chunk_size"]]
            headers = {"Content-Type": "application/octet-stream",
                       "Content-Range": f"bytes {start}-{start + len(chunk) - 1}/{len(sample)}",
                       "X-Chunk-Sha256": hashlib.sha256(chunk).hexdigest()}
            for _ in range(2):
                status, _, body = self.application_http(prefix + f"/chunks/{index}", body=chunk, headers=headers)
                if status != 204 or body:
                    raise RuntimeError(f"chunk upload/replay did not return empty 204: {status}")
        status, _, body = self.application_http(prefix + "/finalize", body=b"",
            headers={"Idempotency-Key": created["finalize_operation_id"]}, timeout=35)
        if status != 202 or json.loads(body).get("analysis_id") != created["analysis_id"]:
            raise RuntimeError(f"public finalize did not accept the analysis: HTTP {status}")

        analysis_id = created["analysis_id"]
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            read = self.tool("analysis.read", {"operation_id": str(uuid.uuid4()), "analysis_id": analysis_id})
            state = read["analysis"]["state"]
            if state == "analyzed":
                break
            if state in {"failed", "degraded", "deleted", "cancelled"}:
                raise RuntimeError("real analysis entered a non-success state: " + state)
            time.sleep(2)
        else:
            raise RuntimeError("real analysis did not reach analyzed before its deadline")
        sample_id = "sha256:" + hashlib.sha256(sample).hexdigest()
        if read["analysis"]["sample_id"] != sample_id:
            raise RuntimeError("analysis result is not bound to the uploaded sample")
        functions = [artifact for artifact in read["artifacts"] if artifact["artifact_type"] == "ghidra_functions"]
        if not functions:
            raise RuntimeError("terminal analysis omitted its real Ghidra function artifact")
        artifact = functions[0]
        status, _, raw = self.request("analyzer", 18090, "/internal/v1/artifacts/read", method="POST",
            body=json.dumps({"sample_id": sample_id, "artifact_id": artifact["upstream_artifact_id"],
                             "read_mode": "content"}).encode(),
            headers={"Authorization": "Bearer " + self.env["L2_BRIDGE_TOKEN"], "Content-Type": "application/json"},
            timeout=35)
        if status != 200:
            try:
                error_code = json.loads(raw).get("error", {}).get("code")
            except (ValueError, AttributeError):
                error_code = "non-json-response"
            raise RuntimeError(f"persisted Ghidra artifact read failed: HTTP {status}, code={error_code}")
        artifact_read = json.loads(raw)["data"]
        if artifact_read.get("truncated") or artifact_read.get("bytes_read") != artifact_read.get("total_size"):
            raise RuntimeError("Ghidra artifact read was truncated; full SHA256 cannot be verified")
        content = artifact_read["content"]
        if hashlib.sha256(content.encode()).hexdigest() != artifact["sha256"]:
            raise RuntimeError("Ghidra artifact SHA256 differs from its actual bytes")
        payload = json.loads(content)
        if not payload.get("functions") or payload.get("function_count") != len(payload["functions"]):
            raise RuntimeError("Ghidra artifact has no verified function index")
        print("L2 MCP: public upload, terminal analysis and raw Ghidra artifact digest verified", flush=True)

        # Finish non-model checks first; a failed quota/cancellation check must
        # not consume a NewAPI generation just to be repeated on the next run.
        rest_status = self.mcp_upload_cancellation_and_quota(sample)
        conversation = self.tool("analysis.conversation", {"operation_id": str(uuid.uuid4()),
            "analysis_id": analysis_id, "title": "Closed Analyze acceptance"})["conversation"]
        submitted = self.tool("analysis.conversation", {"operation_id": str(uuid.uuid4()),
            "analysis_id": analysis_id, "conversation_id": conversation["id"], "client_seq": 1,
            "model": self.env["L2_NEWAPI_MODEL"],
            "message": "仅依据上下文，用一句话指出样本的一个函数，并引用 [" + artifact["artifact_ref"] +
                       "]。若上下文不足，请明确说明，不要推断。"})["turn"]
        self.diagnostic_checkpoint("mcp-turn", conversation=conversation, submitted=submitted)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            turn_read = self.tool("analysis.read", {"operation_id": str(uuid.uuid4()), "analysis_id": analysis_id,
                "conversation_id": conversation["id"], "turn_id": submitted["id"]})
            turn = turn_read["turn"]
            if turn["state"] == "completed":
                break
            if turn["state"] in {"failed", "partial", "cancelled"}:
                raise RuntimeError("NewAPI acceptance turn did not complete: " + str(turn.get("error_code")))
            time.sleep(2)
        else:
            raise RuntimeError("NewAPI acceptance turn exceeded its deadline")
        if (turn["provider_attempt"] != 1 or turn["model_alias"] != self.env["L2_NEWAPI_MODEL"]
                or not turn_read["assistant"]["content"]
                or [artifact["artifact_ref"], True] not in turn_read["citations"]):
            raise RuntimeError("conversation lacks a single model attempt and a verified artifact citation")

        self.observations["mcp_four_tools"] = {"status": "pass", "started_at": started,
            "finished_at": time.time(), "checks": ["real ELF upload and identical chunk replay", "public finalize",
                "terminal Ghidra analysis.read", "raw artifact SHA256", "one NewAPI conversation with verified citation",
                "REST cancel rejected without compensation", "MCP cancel and byte-identical replay", "create quota enforced"],
            "analysis_id": analysis_id, "sample_sha256": hashlib.sha256(sample).hexdigest(),
            "function_artifact_sha256": artifact["sha256"], "function_count": payload["function_count"],
            "turn_id": turn["id"], "newapi_model": turn["model_alias"], "newapi_conversation_calls": turn["provider_attempt"],
            "rest_cancel_status": rest_status, "analyzer_image": self.analyzer_image}
        print("L2 MCP: all four tools, one cited NewAPI turn, cancellation and quota verified", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    parser.add_argument("--analyzer-image", default=ANALYZER, help="immutable analyzer image for this isolated run")
    parser.add_argument("--four-tools", action="store_true", help="exercise the complete four-tool scenario in runtime-only mode")
    parser.add_argument("--keep-on-failure", action="store_true", help="retain this isolated runtime for diagnosis after failure")
    parser.add_argument("--catalog-only", action="store_true", help="verify registration, promotion and restart; stdout only, never full L2")
    parser.add_argument("--runtime-only", action="store_true", help="check live topology only; never emits an L2 pass receipt")
    args = parser.parse_args()
    if args.four_tools and not args.runtime_only:
        parser.error("--four-tools requires --runtime-only; full L2 always includes all four tools")
    if args.catalog_only and (args.output or args.runtime_only or args.four_tools):
        parser.error("--catalog-only produces stdout observations only")
    if not args.catalog_only and not args.output:
        parser.error("--output is required unless --catalog-only is selected")
    output = Path(args.output).resolve() if args.output else None
    canonical = ROOT / "evidence/l2-acceptance-v1.json"
    if args.runtime_only and output == canonical:
        parser.error("runtime observations cannot replace the L2 acceptance receipt")
    if not args.catalog_only and not args.runtime_only and output != canonical:
        parser.error("L2 acceptance must use its canonical evidence path")
    if output and output.exists():
        parser.error("output exists; select a fresh runtime path or explicitly archive the old acceptance receipt")
    os.umask(0o077)
    run = ClosedRun(args.analyzer_image)
    run.keep_for_diagnosis = args.keep_on_failure
    completed = False
    try:
        run.initialize()
        run.build()
        run.start()
        readiness = run.ready()
        run.catalog_prerequisites()
        run.bootstrap_quorum()
        run.promote_catalog()
        if args.catalog_only:
            print(json.dumps({"status": "catalog_restart_verified", "release_eligible": False,
                              "sources": run.sources, "observations": run.observations}), flush=True)
            completed = True
            return
        run.browser()
        run.bootstrap_approver()
        run.application_approval()
        run.mcp_transport()
        if args.four_tools or not args.runtime_only:
            run.mcp_four_tools()
        if not args.runtime_only:
            require_complete(run.observations)
        result = {"status": "runtime_verified", "release_eligible": False, "run_id": run.run_id,
                  "sources": run.sources, "readiness": readiness, "observations": run.observations}
        write_private_json(output, result)
        completed = True
        print("L2 live runtime verified; full scenario acceptance remains required", flush=True)
    except Exception as error:
        print(f"L2 scenario failed ({type(error).__name__})", flush=True)
        raise
    finally:
        if args.keep_on_failure and not completed and run.env_file.exists():
            print(f"L2 isolated diagnosis retained: project={run.project} work={run.work}", flush=True)
        else:
            run.cleanup()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
