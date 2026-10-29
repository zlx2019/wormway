# Contributing to zora

Thanks for your interest! zora is pre-release and maintained by a single person, so please read this page before you start.

## Before you start

- Open an issue or a discussion before working on anything larger than a small fix, so we can agree on the scope first.
- The scope is deliberately narrow: the first release has no proxy client, HTTP/3, Kubernetes controller, WAF, AI gateway or Wasm plugins. Please check this list before proposing a feature.
- Response time is best effort. Pull requests outside the current milestone may be declined or parked.

## Development setup

Requirements: Rust stable (MSRV 1.98), [cargo-nextest](https://nexte.st/), [cargo-deny](https://github.com/EmbarkStudios/cargo-deny), [typos](https://github.com/crate-ci/typos) and [pre-commit](https://pre-commit.com/).

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --workspace --doc
cargo deny check
typos
```

All of these run in CI and must pass.

Changes to the dashboard in `ui/` also need Node.js 22.22 or later and pnpm 10. After `pnpm --dir ui install`, run `pnpm --dir ui lint` (Biome: lint and formatting) and `pnpm --dir ui build` (type check and build); CI runs both.

### Git hooks

Install the hooks once with `pre-commit install`. It sets up three hooks:

- `pre-commit`: file hygiene, `cargo fmt` and `typos` on every commit.
- `commit-msg`: checks that the message follows Conventional Commits.
- `pre-push`: `cargo clippy`, `cargo nextest`, doctests, `cargo doc` and `cargo deny` before every push.

Run them by hand with `pre-commit run --all-files` (fast checks) and `pre-commit run --all-files --hook-stage pre-push` (slow checks).

## Code conventions

- Rust edition 2024. Do not break the MSRV declared as `rust-version` in `Cargo.toml`.
- Libraries use `thiserror` for error types. `anyhow` is only for binary crates.
- No `.unwrap()` outside tests and prototypes (enforced by clippy). Return errors instead.
- Use `tokio` and never block inside async code. Prefer borrowing over `Arc` and `clone` unless sharing is really needed.
- The public API must not expose types of low-level dependencies such as Pingora or quinn.
- Unit tests live in a `#[cfg(test)]` module at the end of the file, integration tests in `tests/`. Tests run with cargo-nextest.
- Comments: all comments are written in English, including doc comments in source code and comments in configuration files. Every function has a doc comment.
- `unsafe` is denied by default. If you need it, isolate it and explain why in the pull request.

## Dependencies

- Every new dependency needs a justification in the pull request: what it replaces, its maintenance state and its size.
- Licenses must be compatible with MIT. `cargo deny check` enforces the allow-list in `deny.toml`. GPL, AGPL and LGPL code cannot be added.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) in English: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `perf:`, `build:`, `ci:`, `chore:`.
- Keep a pull request to one logical change, and update tests and docs together with the code.
- Fill in the pull request template.

## License of contributions

By submitting a contribution you agree that it is licensed under the [MIT license](LICENSE) of this project.

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

---

## 中文说明

zora 处于发布前阶段，由一人维护。

- 动手前先开 issue 或 discussion 对齐范围。范围刻意收窄：首版不做代理客户端、HTTP/3、Kubernetes 控制器、WAF、AI 网关和 Wasm 插件。
- 响应时间是尽力而为，不在当前里程碑内的 PR 可能被暂缓或拒绝。
- 开发命令见上文，CI 中全部要通过。建议运行一次 `pre-commit install` 安装 Git 钩子：提交时检查文件格式、`cargo fmt` 和拼写，并校验提交信息是否符合 Conventional Commits；推送前运行 clippy、测试、文档构建和 `cargo deny`。
- 改 `ui/` 里的面板还需要 Node.js 22.22 及以上和 pnpm 10：`pnpm --dir ui install` 之后运行 `pnpm --dir ui lint`（Biome 检查代码与格式）和 `pnpm --dir ui build`（类型检查与构建），CI 也会运行这两步。
- 代码约定：edition 2024；库用 `thiserror`，二进制才用 `anyhow`；测试与原型之外禁用 `.unwrap()`；async 里不做阻塞调用；公共 API 不暴露 Pingora、quinn 等底层类型；单元测试写在模块末尾的 `#[cfg(test)]`，集成测试放 `tests/`，用 cargo-nextest 运行。
- 项目内的所有注释（源码注释、文档注释、配置文件注释）一律使用英文，且每个函数都要有文档注释。
- 新依赖要在 PR 里说明理由；许可证必须与 MIT 兼容（`cargo deny check` 会检查），不接受 GPL、AGPL、LGPL 代码。
- 提交遵循 Conventional Commits，提交信息和 PR 用英文。
- 提交的贡献按本项目的 MIT 许可证授权。
- 安全问题请勿公开提交，见 [SECURITY.md](SECURITY.md)。
