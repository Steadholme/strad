# Analyze MCP rollout

Target: `https://analyze.w33d.xyz` serves approved application API/MCP access;
`https://rikune.w33d.xyz` remains the human workbench. The application owner uses
SSO and sponsor confirmation, then the non-login system approver applies the
package policy. Opaque credentials do not bypass scope, ownership, quota, live
authorization, or revocation checks. The public contract is
[`analyze-public-v1.json`](analyze-public-v1.json).

## Current release status — 2026-09-06

**Deployed to production using operator-authorized, digest-pinned on-host images.**
The operator explicitly waived creation of Rikune's missing Loom repository and
a successful GLM conversation as launch prerequisites. This is a model-free
production rollout, not a passing receipt from the model-required full L2 suite.
`/applications/` and the root require SSO; `/mcp` and `/v1/uploads` require an
approved application credential. Internal routes remain hidden from the public
gateway. The original Rikune workbench and its permission checks remain intact.

Access was migrated through its official CLI to v18, the existing catalog
promotion was reused idempotently, and the Analyze-only non-login system
approver was bootstrapped with the existing on-host RSA release authority.
No human request, business grant, or application credential was injected for
production acceptance. The existing production analysis recovered to `analyzed`
and produced 17 artifacts; the production conversation table remained empty.
Six successive checks over 106 seconds found all nine services healthy with no
additional restarts. Public SSO, missing/invalid credential, untrusted Origin,
and private-route denial checks passed. The stored Ghidra functions file also
matched its persisted SHA256. Exact pins, evidence hash and rollback entry point
are recorded in [`production-release-20260906.json`](production-release-20260906.json).

The retained private acceptance project has
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

Current checks: 27 Strad contracts, 24 Access application/worker contracts, 63
acceptance-harness unit tests, and both Rust all-target Clippy checks passed.
The full 462-test Holdfast deployment-tool regression also passed.
These are scoped results, not a complete release receipt. The harness unit tests
use doubles and do not prove a successful real model conversation.

Non-blocking follow-ups, not acceptance claims:

1. GLM-5.2 generation was not retried during launch. Its last purposeful test
   failed upstream. NewAPI service readiness does not prove model generation;
   health probes must not call completions or silently change the model.
2. The complete model-required L2 receipt and registry publication/attestation
   remain separate future work. Do not describe the on-host rollout as either.
3. Access, Strad, Sluice and Verdict sources are synchronized to Loom and GitHub.
   Rikune's main was pushed to GitHub; its absent Loom repository was waived.

Use `/root/w33d_infra/deploy/analyze-compose.sh` for later Compose operations;
it loads the production overlay and protected `analyze.env`. Running only the
legacy base Compose file would omit the application-auth configuration.
Protected database/config/volume backups and launch tooling are retained at
`/root/w33d_infra/.runtime/analyze-production-20260906-bPZq1N`.
To close only the new public Analyze ingress, run that directory's
`launch.py routes public down`. Do not downgrade Access to v17 without a
coordinated database recovery; preserve post-launch writes.

The legacy `ops/holdfast` public-open ceremony remains Rikune-only and retains
an Analyze tombstone. Do not use it to reconcile this Analyze deployment.

## Closed diagnostics

`compose.closed.yml` has no host-published ports. Its synthetic browser identities
and issuer keys belong only to this isolated environment, never production.
Private checkpoints contain credentials and sessions and must remain in their
mode-0700 runtime directory as mode-0600 files. Never commit or print them.

The full entry point is:

```sh
./ops/analyze/run-l2-acceptance.sh \
  --analyzer-image <named-immutable-analyzer-reference> \
  --output ops/analyze/evidence/l2-acceptance-v1.json
```

Full mode requires clean, revision-bound source checkouts. Native tests use
separate databases and exported source snapshots; their fixtures never enter
the application-approval databases. The suite checks all refusal, rotation,
revocation, dependency, and fault-recovery scenarios before its one model
conversation. The real 900-second request timeout, 30-minute upload lease, and
300-second rotation overlap remain unchanged. Allow roughly an hour for a full
run; no shortened test clock is used for those live guarantees.

On success the JSON Schema and semantic validator both run before the passing
receipt is published. The sibling `l2-evidence-<run-id>/` directory preserves
the explicit non-secret proof files, whose byte hashes are in the receipt.
Diagnostic `*.private.json` checkpoints are never included in that bundle.
On failure full mode retains the closed project and private diagnostics, and
does not write a passing marker. Archive a prior receipt and its evidence bundle
explicitly before asking for a new run at the same canonical output path.

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

For future production executions, bind the overlay to verified digest-pinned
images and protected provisioned secrets, create the dedicated facade database
and restricted role, complete the application migration and system-approver
bootstrap, and verify closed readiness and rollback. Route SQL alone does not
prove release eligibility. Existing estate snapshots and other services must be
preserved. The overlay and both route phases were applied on 2026-09-06 under
the explicit on-host, model-free launch authorization above.

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

Production also exposed a late-response race: an SDK request could time out
while a busy child had already sent its response. That late frame was reported
as an unknown ID and caused a fatal bridge restart. `LateTimeoutTransport` now
discards only the first late response for an actually sent request with the
SDK's exact timeout cancellation. Unknown IDs, duplicates and transport/parse
errors still fail closed; the tracking cache is bounded. All 38 bridge tests
pass, including a real SDK timeout/late-response regression. Production now
uses both this fix and the bounded catalog probes.
