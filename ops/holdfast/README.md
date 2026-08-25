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
- the 40-character Strad source revision and real NewAPI alias;
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

Keep `STRAD_DATABASE_URL`, bridge/file-server/NewAPI tokens, and all existing gateway/Verdict
secrets in a separate mode-`0600` secret env. Evidence files contain only identities and hashes.

## Candidate and dry-run

Render the Access candidate source first and build/push it from exactly that tree:

```sh
./candidate-source.sh \
  --estate-root /root/w33d_infra \
  --output /secure/release/rikune-candidate-source
```

Then run the full gate. There is no `--skip-cargo` option; every production receipt records
`cargo_gate=passed`, and `apply.sh` rejects a missing or altered gate.

```sh
TMPDIR=/secure/tmp CARGO_TARGET_DIR=/secure/build/access \
./dry-run.sh \
  --estate-root /root/w33d_infra \
  --release-env /secure/release/rikune.release.env \
  --secret-env /secure/release/rikune.secrets.env \
  --supply-chain-evidence /secure/release/SUPPLY-CHAIN.json \
  --supply-chain-signature /secure/release/SUPPLY-CHAIN.sig \
  --supply-chain-public-key /secure/release/release-authority.pub \
  --output /secure/release/rikune-dry-run

./verify.sh \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/rikune-dry-run \
  --phase staged --deep
```

`verify --phase staged` checks only `dry-run/stage`; it never substitutes the live estate.
`DRY-RUN.receipt`, `TARGETS.sha256`, `RELEASE-EVIDENCE.json`, release-env identity, signed supply
chain, patches, catalog tests, Compose expansion, shell/Python tests, and Rust tests form one
immutable review unit.

## Apply while ingress remains closed

`apply.sh` acquires `/run/lock/holdfast-rikune.lock` before checking any preimage. The same lock is
used by open and rollback. It takes a PostgreSQL custom dump, snapshots `strad_uploads` and all five
analyzer volumes, restores each into isolated probes, then applies files through
`estate_transaction.py`. A failure after any target automatically restores every old/absent
disposition. The durable backup supports a later mixed old/new/absent estate after a crash and
rejects any third-party checksum.

```sh
./apply.sh --execute \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/rikune-dry-run \
  --release-env /secure/release/rikune.release.env \
  --backup-root /secure/backups \
  --activate-services
```

Ingress is still closed. Preserve the printed backup directory and `/var/lib/holdfast-rikune`
state receipts.

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
6. restore PostgreSQL, six volume dispositions, and the mixed-state estate while continuing to
   verify the public route remains closed.

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
`applied_ingress_closed`. `ROUTE-CLOSE-PREIMAGE.jsonl` preserves the complete pre-delete rows,
including drift, before the fail-closed conflict cleanup.

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

Runtime restore explicitly stops and removes orphan Strad/analyzer containers before restoring
volumes. Restored services remain stopped unless `--activate-services` is requested. Physical
sample deletion performed after release is not logically reversible without separately authorized
backup recovery; this package never claims otherwise.
