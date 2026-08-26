# Holdfast Rikune release package

This package renders, verifies, applies, opens, and rolls back the Rikune estate with checksum,
signature, and state-machine gates. Rendering is isolated. Nothing here mutates the live estate or
route database without a separate explicit `--execute` ceremony. The existing W33D wildcard edge
and DNS are observed but never changed by this package. No production secret value belongs here or
in Git.

## Immutable release inputs

Create a mode-`0600` release env outside the repository from `release.env.example`. Every image,
including Access Governance, Verdict, NewAPI, both Sluice services, Strad, analyzer overlay, the
official analyzer base, volume-init, and build/runtime images, must be an exact
`repo@sha256:<64 lowercase hex>` reference. Tags, equal candidate/rollback images, and equal
Rikune base/Strad overlay images fail closed.

The release env also pins:

- the exact Access build-input, permission catalog, and package catalog hashes;
- the independent acceptance account's exact canonical `user:usr_*` subject in
  `RIKUNE_ACCEPTANCE_SUBJECT`;
- the 40-character Strad source revision and the real NewAPI default alias (`glm-5.2` for the
  current release); the Web selector may expose other aliases returned for the same service key,
  but retries never change a turn's recorded model; Strad readiness checks only NewAPI's own
  `/readyz` endpoint and never creates a completion;
- the authority and supply-chain public-key hashes;
- detached supply-chain evidence/signature hashes.

The signed supply-chain JSON must prove registry manifest identity, `linux/amd64`, SBOM,
provenance, attestation, signer/issuer/transparency-log identity for every image, the official
base-to-overlay relationship, the frozen static lock, Dockerfile and bridge lock, and the exact
Access candidate build inputs. `supply_chain_evidence.py` cross-checks those claims against the
local Dockerfile/lock, release env, and rendered `RELEASE-EVIDENCE.json`; operator-authored claims
without a valid pinned signature are rejected.

Schema v2 permits only five narrowly scoped, short-lived provenance waivers when historical build
metadata cannot be recreated honestly: full provenance for the pinned Distroless runtime, and only
an absent `builder_id` for the pinned Access rollback, Verdict, NewAPI, and Sluice images. Every
waiver is bound to the exact image ref, a fixed reason code, an HTTPS ticket and digest, an approver,
a maximum 30-day UTC interval, and a signed compensating attestation with Rekor identity. SBOM,
signature, subject/digest, platform, and transparency-log evidence are never waivable. The Access
candidate and both final Strad images are never waivable. Schema v1 remains accepted unchanged.

Schema v3 is the successor-release form. It keeps the analyzer overlay bound to `STRAD_REVISION`,
but binds the Access candidate to `access-build-input/2` and the independent
`HOLDFAST_RELEASE_TOOL_REVISION`. It embeds the exact immediate predecessor authority and requires
`ACCESS_GOVERNANCE_ROLLBACK_IMAGE` to be that predecessor image. A schema-v3 document requires the
canonical `successor-policy.json`; it cannot be verified as schema v1/v2 or skip a generation.

Keep `STRAD_DATABASE_URL`, bridge/file-server/NewAPI tokens, and all existing gateway/Verdict
secrets in a separate mode-`0600` secret env. Evidence files contain only identities and hashes.

## Candidate and dry-run

The first-apply renderer remains available for a new estate. An estate with an active
`applied_ingress_closed` `CURRENT.json` must use the successor ceremony. Create a new root-owned,
mode-`0700`, versioned release directory; never overwrite or reuse an earlier candidate, dry-run,
release env, or predecessor backup.

Render from the sealed immediate predecessor plus the exact seven-file TASK-001 overlay, then
build and push from that immutable tree:

```sh
./candidate-source.sh \
  --successor \
  --estate-root /root/w33d_infra \
  --current-state /var/lib/holdfast-rikune/CURRENT.json \
  --predecessor-candidate /secure/release/<sealed-predecessor>/rikune-candidate-source \
  --predecessor-stage /secure/release/<sealed-predecessor>/rikune-dry-run/stage \
  --release-tool-revision <clean-strad-head-commit> \
  --output /secure/release/holdfast-successor-<release-id>/rikune-candidate-source

./build-access-candidate.sh \
  --candidate-root /secure/release/holdfast-successor-<release-id>/rikune-candidate-source \
  --image-tag registry.w33d.xyz/steadholme/access-governance:<release-id> \
  --release-tool-revision <clean-strad-head-commit> \
  --metadata-file /secure/release/holdfast-successor-<release-id>/access-build.metadata.json \
  --receipt /secure/release/holdfast-successor-<release-id>/ACCESS-BUILD.receipt
```

The build always pushes `linux/amd64` with BuildKit `mode=max` provenance and SBOM, then records
the immutable digest. Real registry attestation, image-signature, signer/issuer, and
transparency-log evidence must be collected into schema-v3 `SUPPLY-CHAIN.json` and detached-signed
off host before the full dry-run. The script does not invent or locally sign that evidence.

Then run the full gate. There is no `--skip-cargo` option; every production receipt records
`cargo_gate=passed`, and `apply.sh` rejects a missing or altered gate.

```sh
TMPDIR=/secure/tmp CARGO_TARGET_DIR=/secure/build/access \
./dry-run.sh \
  --successor \
  --estate-root /root/w33d_infra \
  --current-state /var/lib/holdfast-rikune/CURRENT.json \
  --predecessor-candidate /secure/release/<sealed-predecessor>/rikune-candidate-source \
  --predecessor-stage /secure/release/<sealed-predecessor>/rikune-dry-run/stage \
  --release-env /secure/release/holdfast-successor-<release-id>/rikune.release.env \
  --secret-env /secure/release/holdfast-successor-<release-id>/rikune.secrets.env \
  --supply-chain-evidence /secure/release/holdfast-successor-<release-id>/SUPPLY-CHAIN.json \
  --supply-chain-signature /secure/release/holdfast-successor-<release-id>/SUPPLY-CHAIN.sig \
  --supply-chain-public-key /secure/release/holdfast-successor-<release-id>/release-authority.pub \
  --output /secure/release/holdfast-successor-<release-id>/rikune-dry-run

./verify.sh \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/holdfast-successor-<release-id>/rikune-dry-run \
  --phase staged --deep
```

`verify --phase staged` checks only `dry-run/stage`; it never substitutes the live estate.
`DRY-RUN.receipt`, `TARGETS.sha256`, `RELEASE-EVIDENCE.json`, release-env identity, signed supply
chain, patches, catalog tests, Compose expansion, shell/Python tests, and Rust tests form one
immutable review unit.

The dry-run reads the release env, secret env, and all three supply-chain files once through a
root-owned, non-symlink, single-link boundary, snapshots those exact bytes into its private
attempt directory, and uses only the snapshots afterward. A successor stage also freezes the six
generation policy inputs, Dockerfile, bridge lock, and both route assets; apply, recovery, and
rollback validate those generation-local copies rather than the later live checkout.

## Apply while ingress remains closed

`apply.sh` acquires `/run/lock/holdfast-rikune.lock` before checking any preimage. The same lock is
used by open, apply recovery, and rollback. It dumps only the dedicated literal `strad` PostgreSQL
database; the shared SSO/IAM/routes/audit database is never a backup or restore target. It also
snapshots `strad_uploads` and all five analyzer volumes and restores every snapshot into an
isolated probe. `strad`, `rikune-analyzer`, and `rikune-volume-init` are stopped before capture;
the exact pre-capture running subset is checksum-bound and remains quiesced for apply. The caller
durably records `apply_armed` before applying files through `estate_transaction.py`. A failure
after any target automatically restores every old/absent disposition. Service activation is
followed by the exact runtime verifier; an activation/readiness failure records
`apply_activation_failed` and an immutable failure receipt without creating `APPLY.receipt`. The
durable backup supports a later mixed old/new/absent estate after a crash and rejects any
third-party checksum.

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./apply.sh --execute \
  --successor \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/holdfast-successor-<release-id>/rikune-dry-run \
  --release-env /secure/release/holdfast-successor-<release-id>/rikune.release.env \
  --backup-root /secure/backups \
  --activate-services
```

Ingress is still closed. Preserve the printed backup directory and `/var/lib/holdfast-rikune`
state receipts.

Each successor is exactly generation `n + 1` of the checksum-bound immediate predecessor. Its
backup contains the predecessor `CURRENT.json`, lineage receipt, delta, and frozen generation
authority. Successful successor recovery or rollback restores that exact predecessor pointer;
terminal reruns adopt the existing completion evidence and do not replay runtime, estate, or
Compose mutations.

### Recover an interrupted, activation-failed, or legacy orphan apply

`apply-recover.sh` is the only supported recovery path when apply did not reach its ordinary final
state. It accepts an armed/activation-failed apply, a durable prepared or applied estate
transaction, a new apply whose estate transaction never started, and the legacy orphan shape where
`CURRENT.json`, `APPLY-ARMED.receipt`, and `APPLY.receipt` are all absent. Legacy adoption
additionally requires an explicit estate root. Both modes validate the canonical root-owned
backup, `CONTROL.sha256`, release/dry-run bindings, exact transaction state, and an
`absent -> dual-stack 404 -> absent` database/public/database bracket before recording a durable
recovery arm. A crash after that arm reuses the same attempt, service manifest, and immutable
receipt; a crash after completion but before the active pointer update only finalizes the existing
completion.

There is one earlier crash boundary: `CURRENT.json` may still be
`runtime_backup_armed` because `runtime-backup.sh` stopped the Strad writers before apply could
persist the full CONTROL package. In that state, restore mode consumes only the durable caller
arm and, when present, the runtime stop arm with its frozen Compose snapshot and prior-running
manifest. Absence of the runtime stop arm proves that stop never began. Otherwise recovery
restarts exactly the prior `strad`/`rikune-analyzer` subset, keeps the excluded product and
`rikune-volume-init` inactive, archives `CURRENT.json`, and requires a fresh apply ceremony. It
does not restore a database, volume, or estate and remains usable if the original dry-run inputs
have disappeared.

Restore mode stops and confirms all seven application writers, restores PostgreSQL and six volume
dispositions, then restores a mixed applied/preimage/absent estate from an attempt-local copy.
Before mutation it freezes the exact subset whose container state is `running`; `Created` and
`restarting` services are excluded. After restoring the old Compose estate it starts only that
frozen subset with Compose `--no-deps --wait`, verifies each is running and each declared
healthcheck is healthy, then proves every excluded writer remains non-running. The service-set
hash is bound into the immutable recovery receipt/state. It does not
leave an active `CURRENT.json`:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./apply-recover.sh --execute --mode restore \
  --backup-dir /secure/backups/holdfast-rikune-TIMESTAMP-PID \
  --estate-root /root/w33d_infra
```

If an earlier restore reached `restore_prior_running_writers` but the Access database has already
advanced beyond the estate preimage, a retry may add `--quarantine-access-chain`. This is a narrow,
fail-closed exception: it requires a schema-v2 activation-failure receipt, closed ingress, an
unhealthy or non-running `access-governance` container, and both `access-governance` and `newapi`
in the signed source writer set and preimage Compose. The retry restores every other prior writer,
removes both quarantined containers, and binds the exclusion and inactive proof into the recovery
arm, failure, completion, and state records. The same flag is mandatory after a crash. This mode
does not roll back the shared Access database or start either quarantined service; follow it
immediately with a separately verified release apply while ingress remains closed.

The one historical schema-v1 backup may be adopted only with `--legacy-empty-strad`. That path
first proves the literal `strad` database has zero connections, public tables, and non-system user
relations, restores only the six absent volume dispositions, and deliberately ignores the old
shared `postgres.dump`. No command in this package restores that shared dump.

If estate apply already rolled itself back, restore mode first proves every live target is exactly
at its preimage and performs only the frozen service-lifecycle recovery; it does not restore the
Strad dump, any volume, or the estate a second time. If apply crashed while promoting
`APPLY-PENDING.receipt` or before committing the final `CURRENT.json`, resume mode validates the
exact receipt and applied transaction, repeats runtime and closed-ingress verification, then
idempotently promotes the receipt and finalizes `applied_ingress_closed`.

Resume mode is narrower: every live target must still equal the applied target manifest. It starts
the seven exact release services, verifies their configured digests, readiness, and NewAPI model,
then records an independent recovery receipt and returns `CURRENT.json` to
`applied_ingress_closed`. It never manufactures the ordinary `APPLY.receipt`:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./apply-recover.sh --execute --mode resume \
  --backup-dir /secure/backups/holdfast-rikune-TIMESTAMP-PID
```

## Authority and route-only opening

The acceptance user must first self-register at `https://sso.w33d.xyz/register`, verify the email,
sign in to `https://sso.w33d.xyz/account`, enroll a passkey or TOTP factor, and copy the exact
Account `Subject`. Replace the `RIKUNE_ACCEPTANCE_SUBJECT` placeholder in the protected release env
with that canonical `user:usr_*` value before generating and signing release evidence. Provision
the finite 30-day `pkg_rikune_analyst` request for exactly that release-pinned subject, through the
acceptance user's own step-up and normal 2-of-2 approval. Record the same pinned beneficiary, exact
source grant, and all seven positive epochs/ack timestamps using `authority-open.example.json`,
then detached-sign the JSON with the release-pinned authority key.

`analyze.w33d.xyz` already reaches the existing W33D Sluice ingress through the managed wildcard
Cloudflare/DNS estate. With no `rikune-root` row, both public IPv4 and IPv6 must return exact
`404` responses carrying the expected W33D safety headers. Opening and rollback are route-only:
they never change GitHub Pages, Cloudflare, DNS, wildcard ownership, or caches.

Prepare validates the release/runtime and authority, then brackets the public closed probe with two
independent route-database absence checks. It does not insert a route:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./open-ingress.sh --execute --phase prepare \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/rikune-dry-run \
  --release-env /secure/release/rikune.release.env \
  --authority-evidence /secure/release/authority-open.json \
  --authority-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub
```

A successful prepare atomically records `OPEN-PREPARE.receipt` and
`edge_prepared_route_closed`. It proves `absent -> dual-stack 404 -> absent`, the
`analyze.w33d.xyz` host, and `existing-w33d-sluice`, with
`external_edge_mutation=none`.

After prepare, copy `edge-preopen.example.json` to a protected operator directory. Record exactly
one post-prepare IPv4 probe and one post-prepare IPv6 probe. Each probe must target
`https://analyze.w33d.xyz/`, return `404`, identify the existing W33D Sluice edge and
route-absent state, and include a SHA-256 of the complete response headers. Keep
`external_edge_mutations` as the exact empty list, fill the receipt/evidence hashes and same
`source_grant_id`, then detached-sign the v2 JSON with the same authority key.

Finalize validates that signed v2 pre-open evidence before any exposure change, repeats runtime and
the database/public/database closed bracket, validates the pinned up/down SQL, and atomically writes
`finalizing_route_armed`. Only then is the `rikune-root` row inserted as the final exposure
mutation. Verification accepts only a same-round IPv4+IPv6 anonymous `302` to
`https://sso.w33d.xyz/authorize...` where every `Cache-Control` field is exactly the
`private,no-store` directive set. Both closed and open checks retry for at least 70 seconds to
cover Sluice's reload window, and the open probe is bracketed by exact database route checks.

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./open-ingress.sh --execute --phase finalize \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/rikune-dry-run \
  --release-env /secure/release/rikune.release.env \
  --authority-evidence /secure/release/authority-open.json \
  --authority-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub \
  --edge-evidence /secure/release/edge-preopen.json \
  --edge-signature /secure/release/edge-preopen.sig
```

Every ordinary failure after arming runs the exact down path plus the closed
database/public/database bracket. It writes an immutable interrupted receipt and restores
`edge_prepared_route_closed`. A `SIGKILL` leaves `finalizing_route_armed`; the next invocation
closes and verifies the route before release revalidation, records the interruption, restores the
prepared state, and refuses that invocation. If any compensation check cannot be proven, the state
is atomically changed to `ingress_compensation_unverified`; further finalize attempts are
prohibited until the rollback close ceremony resolves the route.

For direct diagnostics, the public verifier requires an explicit mode:

```sh
./public-origin-verify.sh --mode closed --url https://analyze.w33d.xyz/
./public-origin-verify.sh --mode open --url https://analyze.w33d.xyz/
```

Closed mode requires same-round dual-stack `404`, HSTS, `nosniff`, `SAMEORIGIN`,
`strict-origin-when-cross-origin`, safe handling of every Cache-Control field, and no
Pages/Fastly markers. Open mode requires the exact trusted SSO redirect and private/no-store
contract above.

## Rollback ceremony

Do **not** pre-create revocation evidence. Rollback ordering is enforced:

1. snapshot every route row with name `rikune-root` or the `analyze.w33d.xyz` root match;
2. delete both the same-name row and any conflicting analyze-root owner under the route advisory
   lock, then prove `absent -> dual-stack 404 -> absent`;
3. write the immutable route-close receipt and revoke the exact `source_grant_id`;
4. wait for and acknowledge all seven tombstones/epochs;
5. if the route may have been public, sign v2 rollback evidence proving only the same dual-stack
   route-absent `404` state; no Pages, Cloudflare, or DNS restore exists;
6. durably arm the exact seven-service running snapshot, quiesce all seven release services,
   restore the dedicated Strad database, six volume dispositions, and the mixed-state estate,
   then reactivate only the frozen shared-service subset plus the runtime pre-apply Strad/analyzer
   subset while continuing to verify the public route remains closed.

Create the route-close receipt first:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./rollback.sh --execute --phase close-route \
  --estate-root /root/w33d_infra \
  --backup-dir /secure/backups/holdfast-rikune-TIMESTAMP-PID \
  --open-evidence /secure/release/authority-open.json \
  --open-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub
```

The close phase is valid from `ingress_open`, `finalizing_route_armed`,
`ingress_compensation_unverified`, `edge_prepared_route_closed`, or
`applied_ingress_closed`. The route-close receipt and
`ROUTE-CLOSE-PREIMAGE-<CONTROL-SHA256>.jsonl` are scoped to the exact release generation and
preserve the complete pre-delete rows, including drift, before the fail-closed conflict cleanup.
Older generation artifacts remain immutable so a completed successor terminal can still be
revalidated while the restored predecessor begins a separate rollback ceremony.

Populate and sign `authority-rollback.example.json` only after route close. If
`was_public_open=true`, also populate and sign `edge-rollback.example.json`; it binds the v2
pre-open evidence, route-close receipt, revocation evidence, same source grant, exact host/edge,
empty external-mutation list, and two post-revocation `404` probes.

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./rollback.sh --execute --phase execute \
  --estate-root /root/w33d_infra \
  --backup-dir /secure/backups/holdfast-rikune-TIMESTAMP-PID \
  --open-evidence /secure/release/authority-open.json \
  --open-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub \
  --revocation-evidence /secure/release/authority-rollback.json \
  --revocation-signature /secure/release/authority-rollback.sig \
  --open-edge-evidence /secure/release/edge-preopen.json \
  --edge-rollback-evidence /secure/release/edge-rollback.json \
  --edge-rollback-signature /secure/release/edge-rollback.sig \
  --activate-services
```

Before the first runtime or estate mutation, execute atomically records
`rollback_execute_armed`, the exact running-service manifest, and its immutable receipt. A crash
reuses that attempt and never resamples service state. Runtime restore explicitly removes
Strad/analyzer/volume-init containers before restoring the literal `strad` database and six
volumes. The restored Compose estate is started with the rollback Access override and
`--no-deps --wait`; every included service must be running/healthy and every excluded service must
remain inactive. `--activate-services` remains accepted for command compatibility but cannot
expand or shrink this frozen set. Physical sample deletion performed after release is not
logically reversible without separately authorized backup recovery; this package never claims
otherwise.
