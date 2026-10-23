# wx-cli Agent Rules

规则以 [CLAUDE.md](CLAUDE.md) 为准，本文件不再单独维护，避免两份规则互相矛盾。

要点（详见 CLAUDE.md）：

- 改任何 `.rs` 文件后立刻 `cargo check`，不通过不提交；同时建议跑 `cargo test`
- 改跨平台代码（`#[cfg(...)]` / `Cargo.toml` dependencies）时，额外 check `x86_64-unknown-linux-gnu` 和 `x86_64-pc-windows-gnu`（本地；CI 用 msvc）
- 改 `Cargo.toml` 版本号后运行 `cargo update --workspace`
