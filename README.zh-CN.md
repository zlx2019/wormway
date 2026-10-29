# zora

[English](README.md)

用 Rust 编写的可编程网络流量代理**库**，以及基于它构建的开箱即用**程序**：网关、多协议代理、反向隧道与 Web 面板。

> **状态：发布前（pre-release）。** zora 由一人维护。目前没有任何发布（没有 crates.io 版本，也没有二进制），一切都可能不经通知地变化。

## 规划范围

| 支柱 | 内容 |
|---|---|
| 网关 | 反向代理、正向代理与负载均衡（HTTP/1.1、HTTP/2、gRPC、WebSocket），TLS 与 ACME，限流，健康检查。L7 引擎基于 [Pingora](https://github.com/cloudflare/pingora)。 |
| 代理协议 | 首批：SOCKS5、HTTP CONNECT、Shadowsocks、Trojan、VLESS、Hysteria2，之后按需增加。 |
| 反向隧道 | 把位于 NAT 后的服务通过网关对外发布。 |
| 面板 | Web 界面与 Admin API，管理配置、证书、用户与流量。 |

交付物：一组可嵌入的 crate（`zora-*`），以及把它们装配起来的单一二进制 `zora`。配置文件为 TOML（`zora.toml`）。

暂不涉及：面向终端用户的代理客户端（TUN、系统代理、客户端规则分流）。

## 仓库结构

| 路径 | 内容 |
|---|---|
| `zora-*/` | 库 crate，每个一个目录：`zora-core`（配置模型）、`zora-runtime`（监听器、配置热更新与优雅关闭）、`zora-control`（SQLite 存储与配置版本、Admin API、Prometheus 指标、面板）。 |
| `apps/zora/` | `zora` 二进制：`zora run`、`zora check`（校验配置文件）和 `zora schema`。目前还没有内置任何协议，所以 `zora run` 只接受不含监听器的配置。 |
| `ui/` | 面板（React 与 TypeScript）。zora 在 Admin API 地址的 `/ui/` 下提供面板，默认是 `http://127.0.0.1:9872/ui/`，登录时输入 Admin API 的 token。 |
| `benches/` | 性能测量的方法，以及开放负载压测和记录测试环境的脚本。 |
| `zora.example.toml` | 示例配置。 |
| `zora.schema.json` | 配置文件的 JSON Schema，由 `zora schema` 生成。编辑器用它补全和校验，例如 VS Code 装上 Even Better TOML 后，示例开头的 `#:schema` 一行即可生效。 |

## 开发

依赖：Rust stable（MSRV 1.98）、[cargo-nextest](https://nexte.st/)、[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)、[typos](https://github.com/crate-ci/typos) 和 [pre-commit](https://pre-commit.com/)。

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --workspace --doc
cargo deny check
typos
pre-commit install   # 可选：把这些检查装成 Git 钩子
```

面板需要 Node.js 22.22 及以上和 pnpm 10。要先构建面板再构建 zora：release 构建会把 `ui/dist` 嵌入程序，debug 构建运行时从磁盘读取；没有构建面板时，zora 会返回一个说明构建方法的页面。

```sh
pnpm --dir ui install
pnpm --dir ui dev     # http://localhost:5173/ui/，API 请求转发给 127.0.0.1:9872 上的 zora
pnpm --dir ui lint
pnpm --dir ui build   # 输出到 ui/dist
```

## 贡献与安全

- 提交 Pull Request 前请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 请私下报告安全漏洞，见 [SECURITY.md](SECURITY.md)。
- 本项目遵循[行为准则](CODE_OF_CONDUCT.md)（英文）。

## 许可证

[MIT](LICENSE)

## 使用声明

zora 是通用的网络代理与网关工具集，面向合法用途，例如 API 网关、反向代理、安全访问自己的服务以及网络研究。使用者需自行遵守所在地区的法律法规，以及所连接的网络与服务的条款。本软件按「现状」提供，不附带任何形式的担保（见 [LICENSE](LICENSE)）。
