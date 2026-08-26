# Strad

Strad is the w33d AI binary-analysis workbench. It provides an Axum web application, a
TypeScript bridge to Rikune's locked static MCP profile, and a fail-closed Holdfast release
package for deployment and rollback.

The conversation composer discovers the models currently exposed to Strad's NewAPI service key
and records the user's explicit choice on every turn. `STRAD_NEWAPI_MODEL` remains the
release-pinned default (`glm-5.2` for the current release); retries always reuse the recorded model
and never fail over silently.

## Repository layout

- `src/`, `templates/`, and `static/`: the Rust service and server-rendered workbench.
- `bridge/`: the authenticated MCP child-process bridge.
- `migrations/`: the PostgreSQL schema.
- `tests/`: Rust and browser-contract tests.
- `ops/holdfast/`: checksum-bound release, verification, cutover, and rollback tooling.

## Development checks

Required toolchains are stable Rust, Node.js 22 or newer, Python 3, and PostgreSQL 18 for the
database contract suite.

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --lib --bins

cd bridge
npm ci
npm run typecheck
npm test
cd ..

node --test tests/frontend/*.test.js
python3 -m unittest discover -s ops/holdfast/tests -v
```

Each PostgreSQL contract test must use an empty, dedicated database. CI gives every test its own
PostgreSQL service. A local invocation is:

```sh
STRAD_TEST_DATABASE_URL=postgres://postgres:password@127.0.0.1:5432/strad_test \
  cargo test --locked --test postgres_contract TEST_NAME -- --exact
```

Never place release or runtime secrets in the repository. Holdfast consumes mode-`0600` env and
signed evidence files from absolute paths outside Git; see `ops/holdfast/README.md`.

## Git authority

Loom is authoritative and GitHub is the public mirror. Both `main` branches must resolve to the
same full commit SHA before a release revision is accepted.

- Loom: `https://git.w33d.xyz/git/w33d/strad.git`
- GitHub: `https://github.com/Steadholme/strad.git`

## License

Licensed under either Apache License 2.0 or the MIT license, at your option.
