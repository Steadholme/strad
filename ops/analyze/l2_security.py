#!/usr/bin/env python3
"""Live security checks against an existing, private Analyze acceptance run.

All authority mutations use the public Access API. Database queries only observe
versions, dispatch counters, and durable results; they never manufacture grants.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

import l2_runtime as runtime


DEFAULT = object()
INITIALIZE = {"protocolVersion": "2025-11-25", "capabilities": {},
              "clientInfo": {"name": "closed-security-acceptance", "version": "1.0.0"}}


def restore(work: Path, checkpoint_name: str):
    expected_parent = runtime.INFRA / ".runtime"
    if (work.parent != expected_parent or not work.name.startswith("analyze-l2-")
            or work.is_symlink() or not work.is_dir()):
        raise RuntimeError("security checks require an existing closed run directory")
    if Path(checkpoint_name).name != checkpoint_name or not checkpoint_name.endswith(".private.json"):
        raise RuntimeError("invalid private checkpoint name")
    checkpoint_path = work / checkpoint_name
    if checkpoint_path.is_symlink() or checkpoint_path.stat().st_mode & 0o077:
        raise RuntimeError("private checkpoint permissions are unsafe")
    checkpoint = json.loads(checkpoint_path.read_text())
    run = object.__new__(runtime.ClosedRun)
    run.work = work
    run.env_file = work / "compose.env"
    run.env = {}
    for line in run.env_file.read_text().splitlines():
        name, separator, value = line.partition("=")
        if (not separator or not re.fullmatch(r"L2_[A-Z0-9_]+", name)
                or not value.startswith("'") or not value.endswith("'")):
            raise RuntimeError("closed environment file has unexpected syntax")
        run.env[name] = value[1:-1]
    if run.env.get("L2_WORK_ROOT") != str(work):
        raise RuntimeError("closed environment directory binding differs")
    run.project = checkpoint["project"]
    if not re.fullmatch(r"analyze-l2-[0-9a-f]{24}(?:[0-9a-f]{8})?", run.project):
        raise RuntimeError("invalid closed project name")
    run.run_id = run.project.removeprefix("analyze-l2-")
    run.container_ids = {}
    for service in checkpoint["container_ids"]:
        identifier = run.compose("ps", "-q", service)
        if not re.fullmatch(r"[a-f0-9]{64}", identifier):
            raise RuntimeError(f"closed service handle missing: {service}")
        observed = json.loads(run.command(["docker", "inspect", identifier]))[0]
        if (not observed["State"]["Running"]
                or observed["Config"]["Labels"].get("com.docker.compose.project") != run.project
                or any(observed["NetworkSettings"]["Ports"].values())):
            raise RuntimeError("service is not running inside the unpublished closed project")
        run.container_ids[service] = identifier
    network = json.loads(run.command(["docker", "network", "inspect", run.project + "_closed"]))[0]
    if network["Internal"] is not True:
        raise RuntimeError("acceptance network is no longer internal")
    run.analyzer_image = run.env["L2_ANALYZER_IMAGE"]
    run.credential = checkpoint["credential"]
    run.application_request = checkpoint["application_request"]
    run.analysis_created = checkpoint["analysis_created"]
    run.mcp_session = checkpoint["mcp_session"]
    run.rpc_id = 100000
    run.observations = checkpoint["observations"]
    run.bootstrap_receipt = run.observations["application_approval_core"]["bootstrap"]
    run.cookies = runtime.SimpleCookie()
    run.csrf = None
    run.browser_fixture = json.loads((runtime.ROOT / "fixtures/oidc-browser-v1.json").read_text())
    run.keep_for_diagnosis = True
    return run


class SecurityChecks:
    def __init__(self, run):
        self.run = run
        self.cases = {}
        self.rotated = None
        self.rotation = None

    def fresh_browser(self):
        self.run.cookies = runtime.SimpleCookie()
        self.run.csrf = None
        self.run.browser()

    def principal(self):
        subject = self.run.application_request["application_sub"]
        if not re.fullmatch(r"application:[A-Za-z0-9_-]{16,128}", subject):
            raise RuntimeError("invalid application subject")
        return json.loads(self.run.sql(f"""SELECT json_build_object('version',version,
 'policy_epoch',policy_epoch,'revocation_epoch',revocation_epoch,'state',state,'grant_id',grant_id)
 FROM application_principal WHERE subject='{subject}';"""))

    def dispatches(self, operation_id):
        operation_id = str(uuid.UUID(operation_id))
        return int(self.run.sql(f"SELECT COALESCE(sum(dispatch_count),0) FROM application_operations WHERE operation_id='{operation_id}';", "strad_l2"))

    def rpc_probe(self, method, params, *, token=DEFAULT, session=DEFAULT, allow_transport_error=False):
        self.run.rpc_id += 1
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": "2025-11-25"}
        if token is DEFAULT:
            token = self.run.credential["token"]
        if session is DEFAULT:
            session = self.run.mcp_session
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if session is not None:
            headers["Mcp-Session-Id"] = session
        body = json.dumps({"jsonrpc": "2.0", "id": self.run.rpc_id, "method": method, "params": params}).encode()
        status, response_headers, raw = self.run.request("acceptance", 443, "/mcp", host="analyze.w33d.xyz",
            tls=True, method="POST", body=body, headers=headers, timeout=35)
        try:
            value = json.loads(raw)
        except ValueError:
            if allow_transport_error and status in {502, 503}:
                value = {'transport_error': True}
            else:
                raise RuntimeError(f"security probe received non-JSON HTTP {status}") from None
        return status, response_headers, value, hashlib.sha256(raw).hexdigest()

    def read_probe(self, **kwargs):
        operation_id = str(uuid.uuid4())
        result = self.rpc_probe("tools/call", {"name": "analysis.read", "arguments": {
            "operation_id": operation_id, "analysis_id": self.run.analysis_created["analysis_id"]}}, **kwargs)
        return operation_id, result

    def expect_denied(self, name, operation_id, response, *, http=None, rpc=None):
        if rpc is None and (http is None or http < 400):
            raise RuntimeError("an explicit denial response contract is required")
        status, _, value, response_sha = response
        if http is not None and status != http:
            raise RuntimeError(f"{name}: expected HTTP {http}, observed {status}")
        if rpc is not None and (status != 200 or value.get("error", {}).get("code") != rpc):
            actual = value.get("error", {}).get("code")
            raise RuntimeError(f"{name}: expected JSON-RPC {rpc}, observed HTTP {status}, JSON-RPC {actual}")
        count = self.dispatches(operation_id)
        if count != 0:
            raise RuntimeError(f"{name}: unauthorized dispatch count is {count}")
        self.cases[name] = {"status": "pass", "http_status": status, "json_rpc_code": rpc,
            "dispatch_count": count, "operation_id": operation_id, "response_sha256": response_sha,
            "observed_at": int(time.time())}
        print(f"L2 security: {name} rejected; dispatch=0", flush=True)

    def basic(self, expired_credential=None, expired_session=None):
        # Establish positive evidence before treating any denial as meaningful.
        self.run.tool("analysis.read", {"operation_id": str(uuid.uuid4()),
            "analysis_id": self.run.analysis_created["analysis_id"]})
        for name, token in [("no_token", None), ("fake_credential", "app_v1_" + "A" * 43)]:
            operation, response = self.read_probe(token=token)
            self.expect_denied(name, operation, response, http=401)
        if expired_credential is not None:
            if not expired_session:
                raise RuntimeError("expiry validation requires the credential's original session")
            operation, response = self.read_probe(token=expired_credential["token"], session=expired_session)
            self.expect_denied("expired_credential", operation, response, http=401)
        operation = str(uuid.uuid4())
        response = self.rpc_probe("tools/call", {"name": "analysis_read", "arguments": {
            "operation_id": operation, "analysis_id": self.run.analysis_created["analysis_id"]}})
        self.expect_denied("alias", operation, response, rpc=-32010)

    def rotate(self):
        self.fresh_browser()
        old = self.run.credential.copy()
        old_session = self.run.mcp_session
        principal = self.principal()
        new = self.run.api("/api/v1/applications/" + self.run.application_request["id"] + "/credentials/rotate",
            method="POST", value={"expected_version": principal["version"]})
        self.run.credential = new
        self.run.mcp_session = None
        self.run.diagnostic_checkpoint("rotation-unbound-" + new["credential_id"])
        self.run.wait_application_projection()
        # An overlap credential may keep its original session, but cannot initialize.
        operation, (status, _, value, _) = self.read_probe(token=old["token"], session=old_session)
        if status != 200 or "error" in value:
            raise RuntimeError("rotated credential lost its authorized original-session overlap")
        denied = self.rpc_probe("initialize", INITIALIZE, token=old["token"], session=None)
        if denied[0] != 401:
            raise RuntimeError(f"overlap credential initialized a new session or returned unexpected HTTP {denied[0]}")
        self.run.mcp("initialize", INITIALIZE)
        if self.run.mcp_session == old_session:
            raise RuntimeError("rotated credential reused the old session identifier")
        self.run.diagnostic_checkpoint("rotation-bound-" + new["credential_id"])
        operation, denied = self.read_probe(token=old["token"])
        self.expect_denied("overlap_cross_session", operation, denied, http=404)
        _, (status, _, value, _) = self.read_probe(token=old["token"], session=old_session)
        if status != 200 or "error" in value:
            raise RuntimeError("new credential initialization invalidated the legitimate overlap session")
        old_id = old["credential_id"]
        new_id = new["credential_id"]
        if not all(re.fullmatch(r"acr_[A-Za-z0-9_]+", item) for item in [old_id, new_id]):
            raise RuntimeError("invalid credential identifiers")
        lineage = json.loads(self.run.sql(f"""SELECT json_build_object(
 'old_state',old.credential_state,'overlap_until',old.overlap_until,'rotated_at',new.issued_at,
 'old_last_used',old.last_used_at,'old_root_id',old.root_credential_id,'parent_id',new.parent_credential_id,
 'root_id',new.root_credential_id,'generation',new.generation,'new_expires',new.expires_at,
 'principal_expires',p.expires_at) FROM application_credential old
 JOIN application_credential new ON new.id='{new_id}'
 JOIN application_principal p ON p.subject=new.application_sub WHERE old.id='{old_id}';"""))
        if (lineage["old_state"] != "overlap" or lineage["parent_id"] != old_id
                or lineage["root_id"] != lineage["old_root_id"] or lineage["generation"] != old["generation"] + 1
                or lineage["overlap_until"] - lineage["rotated_at"] != 300
                or lineage["new_expires"] > lineage["principal_expires"] or lineage["old_last_used"] is None):
            raise RuntimeError("rotation lineage/expiry/overlap contract differs")
        self.rotated = {"old": old, "old_session": old_session, "new": new}
        self.rotation = lineage
        print("L2 security: real rotation, original-session overlap and new-session binding verified", flush=True)

    def expire_overlap(self):
        if self.rotated is None or self.rotation is None:
            raise RuntimeError("rotation must be observed before overlap expiry")
        deadline = self.rotation["overlap_until"]
        print(f"L2 security: waiting for the real 300-second overlap deadline {deadline}", flush=True)
        while int(time.time()) <= deadline:
            time.sleep(min(2, deadline + 1 - int(time.time())))
        operation, response = self.read_probe(token=self.rotated["old"]["token"], session=self.rotated["old_session"])
        self.expect_denied("old_overlap_expired", operation, response, http=401)
        self.run.tool("analysis.read", {"operation_id": str(uuid.uuid4()),
            "analysis_id": self.run.analysis_created["analysis_id"]})

    def introspection_outage(self):
        self.run.tool("analysis.read", {"operation_id": str(uuid.uuid4()),
            "analysis_id": self.run.analysis_created["analysis_id"]})
        try:
            self.run.compose("stop", "--timeout", "5", "access", timeout=30)
            operation, response = self.read_probe()
            self.expect_denied("introspection_outage", operation, response, http=503)
        finally:
            self.run.compose("start", "access", timeout=30)
            self.run.ready()
        self.run.tool("analysis.read", {"operation_id": str(uuid.uuid4()),
            "analysis_id": self.run.analysis_created["analysis_id"]})
        print("L2 security: Access outage fails closed and normal access recovers", flush=True)

    def postgres_outage(self):
        self.run.tool("analysis.read", {"operation_id": str(uuid.uuid4()),
            "analysis_id": self.run.analysis_created["analysis_id"]})
        try:
            self.run.command(['docker', 'pause', self.run.container_ids['postgres']])
            operation, response = self.read_probe(allow_transport_error=True)
        finally:
            self.run.command(['docker', 'unpause', self.run.container_ids['postgres']])
            self.run.ready()
        # Observe durable dispatch state only after PostgreSQL has resumed.
        if response[0] not in {502, 503}:
            raise RuntimeError('database outage did not fail at the authentication/transport boundary')
        self.expect_denied('postgresql_outage', operation, response, http=response[0])
        self.run.tool("analysis.read", {"operation_id": str(uuid.uuid4()),
            "analysis_id": self.run.analysis_created["analysis_id"]})
        print('L2 dependency: PostgreSQL outage fails closed and recovers', flush=True)

    def revoke(self):
        self.fresh_browser()
        principal = self.principal()
        credential_id = self.run.credential["credential_id"]
        started = time.time()
        self.run.api("/api/v1/applications/" + self.run.application_request["id"] +
                     "/credentials/" + credential_id + "/revoke", method="POST", expected=204,
                     value={"expected_version": principal["version"]})
        operation, response = self.read_probe()
        self.expect_denied("revoked_credential", operation, response, http=401)
        elapsed = time.time() - started
        if elapsed > 30:
            raise RuntimeError("revoked credential remained usable beyond the enforcement deadline")
        current = self.principal()
        if current["revocation_epoch"] <= principal["revocation_epoch"]:
            raise RuntimeError("revocation did not advance its authoritative epoch")
        self.cases["revoked_credential"]["enforced_within_seconds"] = elapsed
        self.cases["revoked_credential"]["revocation_epoch"] = current["revocation_epoch"]
        self.run.diagnostic_checkpoint("revoked-" + credential_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--rotate-and-revoke", action="store_true")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists() or output.parent != runtime.INFRA / ".runtime":
        parser.error("select a new diagnostic output path inside the private runtime directory")
    os.umask(0o077)
    run = restore(Path(args.work), args.checkpoint)
    checks = SecurityChecks(run)
    failure = None
    try:
        # A resumed diagnostic client must authenticate a fresh MCP session;
        # previous sessions may have reached their real idle deadline.
        run.mcp_session = None
        run.mcp("initialize", INITIALIZE)
        run.diagnostic_checkpoint("security-client-" + uuid.uuid4().hex)
        expired_client = json.loads((run.work / "mcp-client.private.json").read_text())
        expired = expired_client["credential"]
        checks.basic(expired if expired["expires_at"] <= time.time() else None, expired_client["mcp_session"])
        if args.rotate_and_revoke:
            checks.rotate()
            checks.expire_overlap()
            checks.revoke()
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
        raise
    finally:
        runtime.write_private_json(output, {"schema_version": 1, "scope": "partial_live_security_acceptance",
            "release_eligible": False, "project": run.project, "cases": checks.cases,
            "rotation": checks.rotation, "failure": failure})


if __name__ == "__main__":
    main()
