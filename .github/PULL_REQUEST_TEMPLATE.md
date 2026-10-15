## Summary / 概要

<!-- What does this pull request change, and why? 这个 PR 改了什么，为什么改？ -->

## Related issue / 关联 issue

<!-- e.g. Closes #123 -->

## Checklist / 检查清单

- [ ] The title follows Conventional Commits, e.g. `feat: ...` / 标题符合 Conventional Commits
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo nextest run --workspace` passes, and new behavior has tests / 新行为有测试
- [ ] `cargo deny check` passes if dependencies changed / 依赖有变更时
- [ ] Docs are updated if user-facing behavior changed / 对外行为变化时更新了文档
- [ ] No Pingora, quinn or other low-level types are exposed in a public API / 公共 API 未暴露底层类型

## Breaking changes / 破坏性变更

<!-- None, or describe them. 没有，或在此说明。 -->
