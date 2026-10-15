# Security Policy

## Supported versions

zora is pre-release and nothing has been published yet. Only the latest commit on `main` is supported. This section will list the supported release lines once releases exist.

## Reporting a vulnerability

**Please do not report vulnerabilities in public issues, pull requests or discussions.**

Use GitHub's private vulnerability reporting: open this repository's **Security** tab and choose **Report a vulnerability**. Please include:

- the affected component and the commit or version;
- the impact, and if possible a minimal reproduction (configuration, request bytes or a test);
- whether you believe the issue is already public or exploited.

## What to expect

zora has a single maintainer, so all timelines are best effort:

- acknowledgement within 7 days;
- an initial assessment within 14 days;
- fix and disclosure coordinated with you, and credit for the report unless you prefer to stay anonymous.

## Scope

In scope: vulnerabilities in zora's own code, for example HTTP request smuggling or desync, authentication or access-control bypass, memory-safety issues, resource-exhaustion (DoS) amplification, mistakes in TLS or certificate handling, and information leaks through the Admin API or the dashboard.

Out of scope: vulnerabilities that live purely in third-party dependencies (please report them upstream, and tell us too so that we can bump the dependency), issues that require a malicious or already compromised administrator, and insecure configurations that are documented as such.

---

## 中文说明

- **受支持版本**：目前没有任何发布，仅支持 `main` 的最新提交。
- **报告方式**：请勿在公开 issue、PR 或 discussion 中报告漏洞。请打开本仓库的 **Security** 标签页，选择 **Report a vulnerability** 私下提交，并附上受影响的组件与版本、影响说明和最小复现。
- **响应预期**：由一人维护，一切时限都是尽力而为：7 天内确认，14 天内给出初步评估，修复与披露时间与你协商，默认会在致谢中署名。
- **范围**：zora 自身代码中的漏洞（请求走私、认证与访问控制绕过、内存安全、资源耗尽放大、TLS 与证书处理错误、Admin API 与面板的信息泄露等）。纯第三方依赖的漏洞请向上游报告，同时告知我们以便升级依赖；需要恶意或已被攻陷的管理员才能触发的问题，以及文档中已说明不安全的配置，不在范围内。
