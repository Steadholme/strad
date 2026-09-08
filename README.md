# Strad

Strad is the w33d AI binary-analysis workbench. It provides an Axum web application, a
TypeScript bridge to Rikune's locked static MCP profile, and a fail-closed Holdfast release
package for deployment and rollback.

The conversation composer discovers the models currently exposed to Strad's NewAPI service key
and records the user's explicit choice on every turn. `STRAD_NEWAPI_MODEL` remains the
release-pinned default (`glm-5.2` for the current release); retries always reuse the recorded model
and never fail over silently.

Startup and `/readyz` check only NewAPI's own `/readyz` endpoint. Health probes never request a
model catalog or create a billable chat completion. Catalog, credential, selected-model, and
provider validity are checked on demand when the corresponding user action needs them.

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

## 前端 v2（2026-09-08）

七个 SSR 模板按 Figma 文件 `KLOaplFFOVGZm5FUEgvb8F`（Strad / Rikune Workbench，oxide accent）
换到共享的 Steadholme v2 视觉系统。SSR 契约一字未动：flat `{{key}}` 全转义、未知占位符 →
500、`src/templates.rs` 里的 enrich 锚点字符串、全部 `data-wb-*` 钩子、CSP 无内联样式、
`[data-section]` 纯 CSS 分区切换、以及 upload 恢复文案。

`static/rikune.css` 现在由三层拼成（strad 直接从磁盘回源，故必须自包含）：
Odyssey canonical（原样 vendored 自 `/root/w33d_infra/odyssey/css/`）+ 共享 v2 kit（oxide）
+ Rikune 表面层。token 变更仍回 canonical Odyssey 仓修改。

模板改动只在外壳：应用栏补上主机名 / All apps / 身份，页头去掉无意义的 eyebrow，
页脚补上同产品线链接。
