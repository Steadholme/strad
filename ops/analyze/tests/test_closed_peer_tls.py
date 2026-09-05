import importlib.util
from pathlib import Path
import time
import unittest
import os


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("l2_runtime", ROOT / "l2_runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class ClosedPeerTlsTests(unittest.TestCase):
    def test_real_peer_selects_each_domain_certificate(self):
        run = runtime.ClosedRun()
        network = run.project + "_closed"
        container = None
        created_network = False
        try:
            run.initialize()
            run.command(["docker", "network", "create", "--internal", network])
            created_network = True
            container = run.command([
                "docker", "run", "-d", "--network", network, "--user", "65532:65532",
                "--cap-drop", "ALL", "--read-only",
                "-v", str(ROOT / "closed-peer.mjs") + ":/app/closed-peer.mjs:ro",
                "-v", str(ROOT / "decision-faults.mjs") + ":/app/decision-faults.mjs:ro",
                "-v", str(run.work / "test.crt") + ":/run/l2/test.crt:ro",
                "-v", str(run.work / "test.key") + ":/run/l2/test.key:ro",
                "-v", str(runtime.TLS_BUNDLE) + ":/run/l2/access.pem:ro",
                "-e", "L2_TEST_SUBJECT", "-e", "L2_OIDC_CLIENT_SECRET", "-e", "L2_ASSURANCE_TOKEN",
                runtime.NODE, "node", "/app/closed-peer.mjs"], env={**os.environ, **run.env})
            run.container_ids["acceptance"] = container
            for attempt in range(30):
                try:
                    if run.request("acceptance", 18130, "/healthz")[0] == 200:
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                self.fail("closed peer did not become ready")
            for host, path, status in [
                ("analyze.w33d.xyz", "/internal/not-public", 404),
                ("id.w33d.xyz", "/jwks", 200),
                ("access.w33d.xyz", "/not-found", 404),
            ]:
                with self.subTest(host=host):
                    self.assertEqual(run.request("acceptance", 443, path, host=host, tls=True)[0], status)
        finally:
            if container:
                run.command(["docker", "rm", "-f", container])
            if created_network:
                run.command(["docker", "network", "rm", network])
            run.cleanup()


if __name__ == "__main__":
    unittest.main()
