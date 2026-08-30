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
Schema v3 records keyless Cosign signatures as `identity` plus `issuer`, and key-based signatures as
`mode=key` plus `public_key_sha256`; a key-based signature must not invent a Fulcio issuer.

Schema v4 is the Gen5 form and is intentionally separate from schema v3. It binds the policy-v4
predecessor `apply_receipt_sha256`, the exact Access candidate receipt, and fresh
`ACCESS_GOVERNANCE_IMAGE`, `STRAD_IMAGE`, and `STRAD_ANALYZER_IMAGE` records. Every other image
record is copied byte-for-byte from the signed predecessor evidence. Strad and analyzer must share
the release manifest's exact `STRAD_REVISION`; Access must use the frozen Gen5 build-input digest.
`assemble_supply_chain_v4.py` verifies root-owned private `cosign save` OCI layouts with the pinned
offline Cosign image, including the image signature, GitHub provenance, BuildKit provenance, SBOM,
platform, config labels, and OCI digest graph. It only writes unsigned evidence and an unsigned env;
`finalize-env` accepts only a detached signature that passes the production validator.

Keep `STRAD_DATABASE_URL`, bridge/file-server/NewAPI tokens, and all existing gateway/Verdict
secrets in a separate mode-`0600` secret env. Evidence files contain only identities and hashes.

## Candidate and dry-run

The first-apply renderer remains available for a new estate. An estate with an active
`applied_ingress_closed` `CURRENT.json` must use the successor ceremony. Create a new root-owned,
mode-`0700`, versioned release directory; never overwrite or reuse an earlier candidate, dry-run,
release env, or predecessor backup.

Render from the sealed immediate predecessor plus the exact frozen policy-v4 overlay, then
build and push from that immutable tree:

```sh
set -euo pipefail
umask 077
release_dir=/secure/release/holdfast-successor-<release-id>
install -d -o root -g root -m 0700 "$release_dir"
./candidate-source.sh \
  --successor \
  --estate-root /root/w33d_infra \
  --current-state /var/lib/holdfast-rikune/CURRENT.json \
  --predecessor-candidate /secure/release/<sealed-predecessor>/rikune-candidate-source \
  --predecessor-stage /secure/release/<sealed-predecessor>/rikune-dry-run/stage \
  --release-tool-revision <clean-strad-head-commit> \
  --output "$release_dir/rikune-candidate-source"
```

The Access signer, release signer, registry auth config, and any password source stay outside the
release directory. The commands below pass only credential paths or environment-variable names;
never put their values in the release tree, command line, or log. Before building, create the new
release directory as root-owned mode `0700`, copy only the two public keys and pinned Sigstore
trusted root into it as mode `0600`, and verify these frozen trust anchors:

```sh
set -euo pipefail
umask 077
release_dir=/secure/release/holdfast-successor-<release-id>
previous_release=/secure/release/<sealed-predecessor>
registry_auth=/root/.docker/config.json
access_signing_key=/secure/authority/holdfast-cosign.key
release_signing_key=/secure/authority/holdfast-release-authority.key
cosign_image='ghcr.io/sigstore/cosign/cosign@sha256:6ca1127dc1e9ff19f3f2bfa214936813a86fbbf52919652eda49d393c888ad3c'

install -d -o root -g root -m 0700 "$release_dir"
install -o root -g root -m 0600 /secure/authority/holdfast-cosign.pub \
  "$release_dir/holdfast-cosign.pub"
install -o root -g root -m 0600 "$previous_release/SIGSTORE-TRUSTED-ROOT.json" \
  "$release_dir/SIGSTORE-TRUSTED-ROOT.json"
openssl pkey -in "$release_signing_key" -pubout \
  -out "$release_dir/release-authority.pub"
chmod 0600 "$release_dir/release-authority.pub"
test "$(sha256sum "$release_dir/holdfast-cosign.pub" | cut -d' ' -f1)" = \
  425becc7b2ea1ef27f6103bfb5299c99b2d4e746c448680174bcb4a6cf9a8d40
test "$(sha256sum "$release_dir/SIGSTORE-TRUSTED-ROOT.json" | cut -d' ' -f1)" = \
  844a1c6de3986c9f02070266b25e0d1a2fa99ceccc89f6b9ad90aae47b62a16e
test "$(stat -c '%a:%U:%h' "$registry_auth")" = 600:root:1
test "$(stat -c '%a:%U:%h' "$access_signing_key")" = 600:root:1
test "$(stat -c '%a:%U:%h' "$release_signing_key")" = 600:root:1
jq -e '.auths["registry.w33d.xyz"] | type == "object" and
  (has("auth") or has("identitytoken"))' "$registry_auth" >/dev/null
```

Build and push only after substituting the verified Access public-key digest in the exact canonical
builder URI:

```sh
set -euo pipefail
export DOCKER_CONFIG="$(dirname "$registry_auth")"
./build-access-candidate.sh \
  --candidate-root /secure/release/holdfast-successor-<release-id>/rikune-candidate-source \
  --image-tag registry.w33d.xyz/steadholme/access-governance:holdfast-successor-<release-id> \
  --builder-id 'https://w33d.xyz/holdfast/builders/local-root/v1?cosign-sha256=425becc7b2ea1ef27f6103bfb5299c99b2d4e746c448680174bcb4a6cf9a8d40' \
  --release-tool-revision <clean-strad-head-commit> \
  --metadata-file /secure/release/holdfast-successor-<release-id>/access-build.metadata.json \
  --receipt /secure/release/holdfast-successor-<release-id>/ACCESS-BUILD.receipt
```

The build always pushes `linux/amd64` with BuildKit `mode=max` provenance, the canonical HTTPS
builder identity containing the exact Access public-key SHA-256, and SBOM, then records the
immutable digest. Parse that digest exactly, sign it with the pinned Cosign container using the
local Access key, upload both the timestamp and transparency-log entry, and immediately verify the
same digest. `COSIGN_PASSWORD` may be injected into the shell, but its value must never be printed:

```sh
set -euo pipefail
access_ref="$(sed -n 's/^image=//p' "$release_dir/ACCESS-BUILD.receipt")"
test "$(grep -c '^image=' "$release_dir/ACCESS-BUILD.receipt")" -eq 1
printf '%s\n' "$access_ref" | grep -Eq \
  '^registry\.w33d\.xyz/steadholme/access-governance@sha256:[0-9a-f]{64}$'

docker run --rm --pull=never --platform linux/amd64 --user 0:0 \
  --env COSIGN_PASSWORD --env DOCKER_CONFIG=/cosign-auth \
  --volume "$registry_auth:/cosign-auth/config.json:ro" \
  --volume "$access_signing_key:/keys/holdfast-cosign.key:ro" \
  --volume "$release_dir:/release" \
  "$cosign_image" sign --yes --use-signing-config=true \
  --trusted-root /release/SIGSTORE-TRUSTED-ROOT.json \
  --key /keys/holdfast-cosign.key \
  --bundle /release/ACCESS-CANDIDATE.image-signature.bundle.json \
  "$access_ref"

docker run --rm --pull=never --platform linux/amd64 --user 0:0 \
  --env DOCKER_CONFIG=/cosign-auth \
  --volume "$registry_auth:/cosign-auth/config.json:ro" \
  --volume "$release_dir:/release:ro" \
  "$cosign_image" verify --key /release/holdfast-cosign.pub \
  --trusted-root /release/SIGSTORE-TRUSTED-ROOT.json \
  --use-signed-timestamps "$access_ref"
```

Snapshot the exact registry-rendered Access provenance and SBOM wrappers for that same digest:

```sh
set -euo pipefail
umask 077
set -o noclobber
export DOCKER_CONFIG="$(dirname "$registry_auth")"
docker buildx imagetools inspect "$access_ref" \
  --format '{{json .Provenance.SLSA}}' \
  > "$release_dir/ACCESS-CANDIDATE.builder-provenance.predicate.json"
docker buildx imagetools inspect "$access_ref" \
  --format '{{json .Provenance}}' \
  > "$release_dir/ACCESS-CANDIDATE.provenance.json"
docker buildx imagetools inspect "$access_ref" \
  --format '{{json .SBOM}}' \
  > "$release_dir/ACCESS-CANDIDATE.sbom.json"
chmod 0600 \
  "$release_dir/ACCESS-CANDIDATE.builder-provenance.predicate.json" \
  "$release_dir/ACCESS-CANDIDATE.provenance.json" \
  "$release_dir/ACCESS-CANDIDATE.sbom.json"
```

The assembler rejects those snapshots unless they exactly match the BuildKit attestation blobs in
the verified Access OCI layout. Obtain `release-images.json` and its Sigstore bundle from the
successful `Release OCI images` workflow run whose `headSha` is the exact Gen5 Strad revision, and
verify them against the already pinned trusted-root copy. Authenticate `gh` through its ordinary
protected environment; do not print its token:

```sh
set -euo pipefail
umask 077
set -o noclobber
gh run view <release-workflow-run-id> --repo Steadholme/strad \
  --json headSha,headBranch,event,conclusion,workflowName \
  > "$release_dir/release-workflow-run.json"
jq -e --arg revision '<clean-strad-head-commit>' \
  '.headSha == $revision and .headBranch == "main" and
   .event == "workflow_dispatch" and .conclusion == "success" and
   .workflowName == "Release OCI images"' \
  "$release_dir/release-workflow-run.json"
gh run download <release-workflow-run-id> --repo Steadholme/strad \
  --name strad-oci-release-<clean-strad-head-commit> --dir "$release_dir"
chmod 0600 "$release_dir/release-workflow-run.json" \
  "$release_dir/release-images.json" \
  "$release_dir/release-images.sha256" \
  "$release_dir/release-images.sigstore.json"

docker run --rm --pull=never --network none --platform linux/amd64 --user 0:0 \
  --volume "$release_dir:/release:ro" \
  "$cosign_image" verify-blob \
  --bundle /release/release-images.sigstore.json \
  --trusted-root /release/SIGSTORE-TRUSTED-ROOT.json \
  --certificate-identity 'https://github.com/Steadholme/strad/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha <clean-strad-head-commit> \
  --use-signed-timestamps /release/release-images.json

strad_ref="$(jq -er '.images.STRAD_IMAGE' "$release_dir/release-images.json")"
analyzer_ref="$(jq -er '.images.STRAD_ANALYZER_IMAGE' "$release_dir/release-images.json")"
printf '%s\n' "$strad_ref" | grep -Eq \
  '^ghcr\.io/steadholme/strad@sha256:[0-9a-f]{64}$'
printf '%s\n' "$analyzer_ref" | grep -Eq \
  '^ghcr\.io/steadholme/strad-analyzer@sha256:[0-9a-f]{64}$'
```

Only after those authorities pass, collect all three exact immutable references. Each `cosign save`
uses the pinned container and the same protected registry-auth file; it must not use a mutable tag:

```sh
set -euo pipefail
for layout in access.oci strad.oci strad-analyzer.oci; do
  install -d -o root -g root -m 0700 "$release_dir/$layout"
done
docker run --rm --pull=never --platform linux/amd64 --user 0:0 \
  --env DOCKER_CONFIG=/cosign-auth \
  --volume "$registry_auth:/cosign-auth/config.json:ro" \
  --volume "$release_dir/access.oci:/oci" \
  "$cosign_image" save --dir /oci "$access_ref"
docker run --rm --pull=never --platform linux/amd64 --user 0:0 \
  --env DOCKER_CONFIG=/cosign-auth \
  --volume "$registry_auth:/cosign-auth/config.json:ro" \
  --volume "$release_dir/strad.oci:/oci" \
  "$cosign_image" save --dir /oci "$strad_ref"
docker run --rm --pull=never --platform linux/amd64 --user 0:0 \
  --env DOCKER_CONFIG=/cosign-auth \
  --volume "$registry_auth:/cosign-auth/config.json:ro" \
  --volume "$release_dir/strad-analyzer.oci:/oci" \
  "$cosign_image" save --dir /oci "$analyzer_ref"

chown -R root:root "$release_dir/access.oci" "$release_dir/strad.oci" \
  "$release_dir/strad-analyzer.oci"
find "$release_dir/access.oci" "$release_dir/strad.oci" \
  "$release_dir/strad-analyzer.oci" -type d -exec chmod 0700 {} +
find "$release_dir/access.oci" "$release_dir/strad.oci" \
  "$release_dir/strad-analyzer.oci" -type f -exec chmod 0600 {} +
test -z "$(find "$release_dir/access.oci" "$release_dir/strad.oci" \
  "$release_dir/strad-analyzer.oci" \( -type l -o -type f ! -links 1 \) -print -quit)"
```

The Access image signature above is distinct from the outer `SUPPLY-CHAIN.json` signature below.
Once the three private OCI snapshots are normalized, assemble, externally sign, and finalize:

```sh
set -euo pipefail
./assemble_supply_chain_v4.py build-evidence \
  --previous-release-root /secure/release/<sealed-predecessor> \
  --previous-successor-policy /secure/backups/<predecessor-backup>/successor-authority/successor-policy.json \
  --current-state /var/lib/holdfast-rikune/CURRENT.json \
  --estate-root /root/w33d_infra \
  --release-root /secure/release/holdfast-successor-<release-id> \
  --candidate-root /secure/release/holdfast-successor-<release-id>/rikune-candidate-source \
  --successor-policy /root/w33d_infra/strad/ops/holdfast/successor-policy.json \
  --strad-revision <clean-strad-head-commit> \
  --release-tool-revision <clean-strad-head-commit> \
  --issued-at <RFC3339-UTC> \
  --access-oci-layout /secure/release/holdfast-successor-<release-id>/access.oci \
  --strad-oci-layout /secure/release/holdfast-successor-<release-id>/strad.oci \
  --strad-analyzer-oci-layout /secure/release/holdfast-successor-<release-id>/strad-analyzer.oci \
  --strad-release-manifest /secure/release/holdfast-successor-<release-id>/release-images.json \
  --strad-release-bundle /secure/release/holdfast-successor-<release-id>/release-images.sigstore.json \
  --access-cosign-public-key /secure/release/holdfast-successor-<release-id>/holdfast-cosign.pub \
  --sigstore-trusted-root /secure/release/holdfast-successor-<release-id>/SIGSTORE-TRUSTED-ROOT.json \
  --supply-chain-public-key /secure/release/holdfast-successor-<release-id>/release-authority.pub \
  --output-release-env /secure/release/holdfast-successor-<release-id>/rikune.release.env.unsigned \
  --output-evidence /secure/release/holdfast-successor-<release-id>/SUPPLY-CHAIN.json

openssl dgst -sha256 -sign "$release_signing_key" \
  -out /secure/release/holdfast-successor-<release-id>/SUPPLY-CHAIN.sig \
  /secure/release/holdfast-successor-<release-id>/SUPPLY-CHAIN.json

./assemble_supply_chain_v4.py finalize-env \
  --release-root /secure/release/holdfast-successor-<release-id> \
  --unsigned-release-env /secure/release/holdfast-successor-<release-id>/rikune.release.env.unsigned \
  --evidence /secure/release/holdfast-successor-<release-id>/SUPPLY-CHAIN.json \
  --signature /secure/release/holdfast-successor-<release-id>/SUPPLY-CHAIN.sig \
  --public-key /secure/release/holdfast-successor-<release-id>/release-authority.pub \
  --successor-policy /root/w33d_infra/strad/ops/holdfast/successor-policy.json \
  --output-release-env /secure/release/holdfast-successor-<release-id>/rikune.release.env
```

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

`rikune.w33d.xyz` reaches the existing W33D Sluice ingress through the managed wildcard
Cloudflare/DNS estate; `analyze.w33d.xyz` is its permanently closed tombstone. With no canonical
root route and no route on the tombstone host, both hosts must return exact `404` responses over
public IPv4 and IPv6 with the expected W33D safety headers. Opening and rollback are route-only:
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

If a completed successor apply finds a stale predecessor `OPEN-PREPARE.receipt`, supersede it in a
standalone invocation before preparing again. The reason must be a canonical root-owned,
single-link, mode-`0600` file. This mode requires the exact schema-v4/Gen5 successor authority,
including the frozen policy and predecessor APPLY hashes with no recovery-completion namespace. It
verifies both frozen release hash chains, archives the original bytes without overwrite, writes the
hash-bound supersede receipt, and exits; it cannot be combined with prepare or finalize. Existing
artifacts are accepted only as byte-exact replay, and any hybrid or conflicting receipt fails closed:

```sh
./open-ingress.sh --execute --abandon-prepare \
  --reason-file /secure/release/open-prepare-abandon.reason
```

A successful prepare atomically records `OPEN-PREPARE.receipt` and
`edge_prepared_route_closed`. It proves database absence around exact dual-stack `404` responses
for `rikune.w33d.xyz` and the `analyze.w33d.xyz` tombstone on `existing-w33d-sluice`, with
`external_edge_mutation=none`.

After prepare, copy `edge-preopen.example.json` to a protected operator directory. Record exactly
one post-prepare IPv4 and one post-prepare IPv6 probe for each of `https://rikune.w33d.xyz/` and
`https://analyze.w33d.xyz/` (four probes total). Every probe must return `404`, identify the
existing W33D Sluice edge and route-absent state, and include a SHA-256 of the complete response
headers. Keep `external_edge_mutations` as the exact empty list, fill the receipt/evidence hashes,
frozen `successor_policy_sha256`, and same `source_grant_id`, then detached-sign the v3 JSON with
the same authority key.

Finalize validates that signed v3 pre-open evidence before any exposure change, repeats runtime and
the database/public/database closed bracket, validates the pinned up/down SQL, and atomically writes
`finalizing_route_armed`. Only then is the `rikune-root` row inserted as the final exposure
mutation. Verification accepts only a same-round IPv4+IPv6 anonymous `302` to
`https://sso.w33d.xyz/authorize...` where every `Cache-Control` field is exactly the
`private,no-store` directive set on `rikune.w33d.xyz`, while `analyze.w33d.xyz` must remain exact
dual-stack `404`. Both closed and open checks retry for at least 70 seconds to cover Sluice's
reload window, and the public probes are bracketed by exact database route checks.

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
./public-origin-verify.sh --mode closed --url https://rikune.w33d.xyz/
./public-origin-verify.sh --mode closed --url https://analyze.w33d.xyz/
./public-origin-verify.sh --mode open --url https://rikune.w33d.xyz/
```

Closed mode requires same-round dual-stack `404`, HSTS, `nosniff`, `SAMEORIGIN`,
`strict-origin-when-cross-origin`, safe handling of every Cache-Control field, and no
Pages/Fastly markers. Open mode requires the exact trusted SSO redirect and private/no-store
contract above.

## Rollback ceremony

Do **not** pre-create revocation evidence. Rollback ordering is enforced:

1. snapshot every route row with name `rikune-root`, the `rikune.w33d.xyz` root match, or any route
   on the `analyze.w33d.xyz` tombstone;
2. delete that exact conflict set under the route advisory lock, then prove database absence around
   exact dual-stack `404` responses for both hosts;
3. write the immutable route-close receipt and revoke the exact `source_grant_id`;
4. wait for and acknowledge all seven tombstones/epochs;
5. if the route may have been public, sign v3 rollback evidence with four probes proving the same
   dual-stack route-absent `404` state for both hosts; no Pages, Cloudflare, or DNS restore exists;
6. durably arm the exact seven-service running snapshot, quiesce all seven release services,
   restore the dedicated Strad database, six volume dispositions, and the mixed-state estate,
   then reactivate only the frozen shared-service subset plus the runtime pre-apply Strad/analyzer
   subset while continuing to verify the public route remains closed.

Frozen releases before schema-v4 continue to use the exact legacy v2 analyze-only evidence and
route-close receipt contracts. The validator dispatches from the frozen release/policy; it never
accepts v2 as a substitute for the Gen5 dual-host v3 ceremony.

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
`was_public_open=true`, also populate and sign `edge-rollback.example.json`; it binds the matching
policy-versioned pre-open evidence, route-close receipt, revocation evidence, same source grant,
exact host/edge, empty external-mutation list, and four post-revocation `404` probes covering both
hosts and both address families.

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
