# Holdfast Rikune release package

This package renders, verifies, applies, opens, and rolls back the Rikune estate with checksum,
signature, and state-machine gates. Rendering is isolated. Nothing here mutates the live estate,
route database, GitHub Pages, Cloudflare, or DNS without a separate explicit `--execute` ceremony.
No production secret value belongs in this directory or in Git.

## Immutable release inputs

Create a mode-`0600` release env outside the repository from `release.env.example`. Every image,
including Access Governance, Verdict, NewAPI, both Sluice services, Strad, analyzer overlay, the
official analyzer base, volume-init, and build/runtime images, must be an exact
`repo@sha256:<64 lowercase hex>` reference. Tags, equal candidate/rollback images, and equal
Rikune base/Strad overlay images fail closed.

The release env also pins:

- the exact Access build-input, permission catalog, and package catalog hashes;
- the 40-character Strad source revision and real NewAPI alias;
- the authority and supply-chain public-key hashes;
- detached supply-chain evidence/signature hashes.

The signed supply-chain JSON must prove registry manifest identity, `linux/amd64`, SBOM,
provenance, attestation, signer/issuer/transparency-log identity for every image, the official
base-to-overlay relationship, the frozen static lock, Dockerfile and bridge lock, and the exact
Access candidate build inputs. `supply_chain_evidence.py` cross-checks those claims against the
local Dockerfile/lock, release env, and rendered `RELEASE-EVIDENCE.json`; operator-authored claims
without a valid pinned signature are rejected.

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

## Authority and public-domain cutover

Provision the finite 30-day `pkg_rikune_analyst` request for exactly
`user:rikune-acceptance`, through normal step-up and 2-of-2 approval. Record the exact source grant
and all seven positive epochs/ack timestamps using `authority-open.example.json`, then detached-sign
the JSON with the release-pinned authority key.

Public `rikune.w33d.xyz` is currently owned by GitHub Pages (`Last-emo-boy/rikune`, `main:/docs`,
`cname=rikune.w33d.xyz`, status `built`) behind Cloudflare/Fastly. A Sluice SQL row alone does not
take over that domain. Opening is therefore deliberately two-phase.

First prepare the W33D route and prove exact runtime digests/readiness and the real NewAPI alias:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./open-ingress.sh --execute --phase prepare \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/rikune-dry-run \
  --release-env /secure/release/rikune.release.env \
  --authority-evidence /secure/release/authority-open.json \
  --authority-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub
```

Only after `OPEN-PREPARE.receipt` exists may the external-domain authority perform the last-step
cutover:

1. Snapshot and hash `GET /repos/Last-emo-boy/rikune/pages` and the Cloudflare DNS record.
2. Detach only the custom domain with GitHub REST API version `2026-03-10`:
   `PUT /repos/Last-emo-boy/rikune/pages` with
   `{"cname":null,"source":{"branch":"main","path":"/docs"}}`; require HTTP `204`, then hash a
   post-`GET` proving `cname=null`.
3. Read a Cloudflare token only from an external absolute secret path. Its exact scopes are
   `DNS Write` and `Cache Purge`. Never print or embed it in evidence. Use
   `PATCH /zones/{zone_id}/dns_records/{record_id}` to point the record at the W33D Sluice origin;
   record the exact pre-record, request, response, and post-`GET` record hashes. Record both old
   and new TTLs, wait at least their maximum, and timestamp TTL convergence.
4. Call `POST /zones/{zone_id}/purge_cache` with `{"hosts":["rikune.w33d.xyz"]}`; record the
   response id/hash. This is mandatory because the old Pages response advertises
   `cache-control:max-age=600`, `x-proxy-cache`, and `x-github-request-id`.
5. Only after both purge and TTL convergence, from public IPv4 and IPv6, prove the response no
   longer has GitHub/Fastly markers and has
   `Cache-Control: private, no-store`. Record header hashes and timestamps.

Use `edge-cutover.example.json` as the exact operator worksheet. Use a locked-down curl config or
credential helper for the Cloudflare `Authorization` header; never place the token directly on
the command line. The signed edge JSON is validated by
`edge_evidence.py` and binds the Pages snapshot, Cloudflare record identities, open authority
grant, route prepare receipt, purge, and dual-stack probes.

Finalize only after the external evidence exists:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./open-ingress.sh --execute --phase finalize \
  --estate-root /root/w33d_infra \
  --dry-run-dir /secure/release/rikune-dry-run \
  --release-env /secure/release/rikune.release.env \
  --authority-evidence /secure/release/authority-open.json \
  --authority-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub \
  --edge-evidence /secure/release/edge-cutover.json \
  --edge-signature /secure/release/edge-cutover.sig
```

Finalize rechecks the route, all seven service containers/digests, Access/Verdict/NewAPI/Sluice,
bridge and Strad readiness, the actual model alias, and live IPv4/IPv6 origin/cache headers. The
state machine and shared flock reject concurrent or repeated opens.

## Rollback ceremony

Do **not** pre-create revocation evidence. Rollback ordering is enforced:

1. close and verify the route;
2. revoke the exact `source_grant_id` from the signed open ceremony;
3. wait for and acknowledge all seven tombstones/epochs;
4. if public cutover occurred, restore the original Pages `main:/docs` cname and original
   Cloudflare record, purge again, and prove IPv4/IPv6 Pages ownership;
5. restore PostgreSQL, six volume dispositions, and the mixed-state estate.

Create the route-close receipt first:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./rollback.sh --execute --phase close-route \
  --estate-root /root/w33d_infra \
  --backup-dir /secure/backups/holdfast-rikune-TIMESTAMP-PID \
  --open-evidence /secure/release/authority-open.json \
  --open-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub
```

This phase is also valid from `applied_ingress_closed`: the down migration and absence probe still
create the immutable first receipt before the same grant is revoked, so an operator can recover an
applied release without ever exposing the public route.

Now populate and sign `authority-rollback.example.json`. It must bind the immutable
`ROUTE-CLOSE.receipt` hash/time and open evidence hash, name the same grant, and timestamp every
tombstone after grant revocation. If the public edge was opened, separately sign Pages/Cloudflare
restore evidence using `edge-rollback.example.json`. Then execute recovery:

```sh
ROUTES_DATABASE_URL='supplied by route authority' ./rollback.sh --execute --phase execute \
  --estate-root /root/w33d_infra \
  --backup-dir /secure/backups/holdfast-rikune-TIMESTAMP-PID \
  --open-evidence /secure/release/authority-open.json \
  --open-signature /secure/release/authority-open.sig \
  --authority-public-key /secure/release/release-authority.pub \
  --revocation-evidence /secure/release/authority-rollback.json \
  --revocation-signature /secure/release/authority-rollback.sig \
  --open-edge-evidence /secure/release/edge-cutover.json \
  --edge-rollback-evidence /secure/release/edge-rollback.json \
  --edge-rollback-signature /secure/release/edge-rollback.sig \
  --activate-services
```

Runtime restore explicitly stops and removes orphan Strad/analyzer containers before restoring
volumes. Restored services remain stopped unless `--activate-services` is requested. Physical
sample deletion performed after release is not logically reversible without separately authorized
backup recovery; this package never claims otherwise.
