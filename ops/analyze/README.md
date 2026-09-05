# Analyze MCP rollout

Target: `https://analyze.w33d.xyz` serves approved application API/MCP access;
`https://rikune.w33d.xyz` remains the human workbench. The application owner uses
SSO and sponsor confirmation, then the non-login system approver applies the
package policy. Opaque credentials do not bypass scope, ownership, quota, live
authorization, or revocation checks. The public contract is
[`analyze-public-v1.json`](analyze-public-v1.json).

## Current release status — 2026-09-05

**Not promoted to production.** The retained private acceptance project has
verified real approval/credential issuance, Ghidra upload and artifact integrity,
credential rotation/revocation, cross-application isolation, the final execution
fence, and three failure/recovery paths. Boundary fault injection is labelled
separately from actual public-path behavior in the private evidence files.

The upload timeout exposed a real recovery defect: a disconnected finalize
request could leave `forwarding` behind, and expired leases were only reclaimed
at startup. `UploadService::reconcile_uncertain` now reclaims expired leases on
each worker sweep. It does not steal an unexpired lease or resend the upload.
The retained original operation was recovered from the real analyzer journal,
audited once, and replayed through the public endpoint with one dispatch and no
remaining operation reservation. The no-restart behavior is additionally covered
by a PostgreSQL contract test; the retained live recovery involved a service image
replacement and is not evidence of a no-restart rollout.

Current checks: 27 Strad contracts, 24 Access application/worker contracts, 54
acceptance-harness unit tests, and both Rust all-target Clippy checks passed.
The full 462-test Holdfast deployment-tool regression also passed.
These are scoped results, not a complete release receipt. The harness unit tests
use doubles and do not prove a successful real model conversation.

Remaining work:

1. Resolve the existing GLM-5.2 upstream 500 through NewAPI, then perform one
   purposeful conversation acceptance with a verified artifact citation. Catalog
   availability and a healthy NewAPI service do not prove generation works.
   Do not add completion-based health probes or silently switch model/provider.
2. Finish the complete composed acceptance runner and receipt. The current
   `l2_runtime.py` exercises runtime/approval/MCP subsets; its normal full-run
   branch is not yet a complete nine-scenario release-receipt producer.
3. Integrate and verify the new production overlay and staged route operations
   described below with immutable images, migration/bootstrap, and rollback.
   The legacy `ops/holdfast` public-open ceremony is still Rikune-only and retains
   an Analyze tombstone. Do not use it as an Analyze public rollout.
4. Review and commit the integration changes, synchronize Loom and GitHub,
   publish immutable release images, then execute and verify the controlled
   production rollout. The Rikune Loom remote was not found at the previously
   tested `w33d/rikune.git` address; its correct remote is still needed. The
   updated Strad release workflow now includes facade publication, but has not
   been executed. It requires a published static-image digest for the corrected
   Rikune source revision; that upstream image is not published yet.

## Closed diagnostics

`compose.closed.yml` has no host-published ports. Its synthetic browser identities
and issuer keys belong only to this isolated environment, never production.
Private checkpoints contain credentials and sessions and must remain in their
mode-0700 runtime directory as mode-0600 files. Never commit or print them.

Use `l2_runtime.py --runtime-only --keep-on-failure --output <private-output>`
for a fresh runtime-only run. `--four-tools` includes a real model generation and
must be used deliberately, not as a recurring probe. Select the intended
immutable analyzer explicitly with `--analyzer-image`.

`l2_security.py`, `l2_fence.py`, `l2_decisions.py`, `l2_context.py`,
`l2_commit_fault.py`, `l2_cleanup_fault.py`, and `l2_missing_dependencies.py`
exercise bounded scenarios against a retained closed run. Inspect their CLI
arguments before use. They do not replace full release acceptance.

For an already uncertain timeout operation, use:

```sh
python3 ops/analyze/l2_timeout.py \
  --work <retained-private-run> --checkpoint <original-private-checkpoint> \
  --resume --output <new-private-runtime-receipt>
```

Resume reads the original backend journal and uses the private audited
reconciliation endpoint; it does not create a new application or resend an
upload. A new timeout test pauses the real analyzer, keeps the 900-second HTTP
deadline and 30-minute upload lease unchanged, and may therefore take over 30
minutes. An unresolved backend result must retain its reservation.

The latest retained-run evidence is indexed in
`/root/w33d_infra/.runtime/analyze-upload-recovery-progress-20260905.json`.
Runtime evidence remains `release_eligible: false`; no full canonical passing
receipt has been produced.

## OCI publication workflow (not yet executed)

`.github/workflows/release.yml` builds Strad, analyzer, and the Analyze facade
from the same checked-out main revision. Before publishing it requires all 27
current CI check names, exact source SHA, and successful (not skipped) outcomes.
The facade receives the same digest signing, provenance, SBOM, and verification
steps as the other two images. Its offline runtime check verifies four tools,
the non-root user, compiled entrypoint/healthcheck, and migration directory.

Dispatch requires `rikune_analyzer_image`, an already published immutable static
image under `ghcr.io/last-emo-boy/rikune-analyzer-static`. The workflow verifies
both its source label and attested source commit against
`RIKUNE_EXPECTED_SOURCE_REVISION`; it no longer silently uses the old static base.
Source-commit and signer-workflow constraints use the
[GitHub CLI attestation verification options](https://cli.github.com/manual/gh_attestation_verify).

The legacy signed `release-images.json` retains its exact two-image shape for
existing Holdfast consumers. The separately signed `analyze-images.json` binds
the three Strad-owned Analyze components and the legacy manifest digest. It is
not a full-stack deployment receipt: Access, Sluice, Verdict, secret provisioning,
closed acceptance, and actual rollout still require their own verified inputs.

## Production wiring (not yet applied)

`compose.production.yml` merges into the existing estate Compose file. It keeps
the original Access origin and enables the separately signed `analyze-access`
entry. It adds no published ports and uses the existing `hf-mgmt` network and
certificate-valid `sso.w33d.xyz` alias of **internal** Sluice. Facade does not
receive application signing private keys. Existing service credentials still
authenticate the internal backend handlers; `auth: public` on these internal-only
gateway routes means no interactive SSO, not unauthenticated backend execution.

The internal `/readyz` route reaches Strad's composite check, which includes
Verdict, Access execution fencing, the analyzer, and NewAPI service readiness.
It is not the gateway's `/healthz` and makes no model completion call.

`production_routes.py` prints SQL only; it does not connect to or change a live
database. Use `--phase internal|public --direction up|down` to render the exact
transaction. Public apply requires private routes first; private removal requires
public routes to have been closed. Repeated exact operations are idempotent;
drift and conflicting host/path ownership abort rather than overwrite. Real
PostgreSQL contract evidence is in
`/root/w33d_infra/.runtime/analyze-production-route-contract-20260905.json`.

Before any production execution, bind the overlay to published digest-pinned
images and protected provisioned secrets, create the dedicated facade database
and restricted role, complete the application migration and system-approver
bootstrap, and verify closed readiness and rollback. Route SQL alone does not
prove release eligibility. Existing estate snapshots and other services must be
preserved. Neither the overlay nor route SQL has been applied to production.

The dual-origin closed check completed real SSO, Sponsor submission, system
approval, credential issuance, and MCP create/cancel. See
`/root/w33d_infra/.runtime/analyze-dual-origin-20260905.json`.

## Long-running bridge probe issue

The retained analyzer's bridge PID 1 exhausted its approximately 4 GiB V8 heap
after over eight hours. The crash is recorded in
`/root/w33d_infra/.runtime/analyze-analyzer-heap-exit-20260905.json`.
Repeated SDK `listTools()` calls recompile anonymous output schemas into AJV's
retained cache: 101 local catalogs retained 607 schemas instead of seven.
`verifyFrozenToolCatalog` now compiles the boot catalog once and validates later
live catalog responses without recompiling; schema/tool-set drift still fails
closed. A 1,000-probe regression test verifies a constant six compilations. The
updated image also completed 100 real readiness probes in 139 seconds and a
public MCP read without restarting; bridge RSS was about 127–128 MiB during
probes 40–100. Evidence is in
`/root/w33d_infra/.runtime/analyze-bounded-live-probes-20260905.json`.
This short observation does not prove the absence of every possible long-running
memory leak; extended runtime observation remains necessary.
