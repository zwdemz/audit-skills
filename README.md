# Audit Skills

## 前言
只做五件事：

1、默认输出目录约定

2、组件漏洞扫描

3、Java/.NET/Python/Node.js/Go 语言参考、反编译与反混淆

4、确定漏洞有效性

5、安全边界


## 安装

将本仓库根目录的 `audit-skills` 内容（`SKILL.md` / `references/` / `scripts/`）整个放置到 claude 或 codex 可识别的 `.skills/audit-skills/` 目录下；能力范围覆盖 Java、.NET、PHP、Python、Node.js 与 Go 审计：

```text
.skills/
└── audit-skills/
    ├── SKILL.md
    ├── references/
    │   ├── java.md
    │   ├── net.md
    │   ├── python.md
    │   ├── nodejs.md
    │   ├── go.md
    │   ├── java-vulnerability.yaml
    │   ├── python-vulnerability.yaml
    │   ├── node-vulnerability.yaml
    │   └── go-vulnerability.yaml
    └── scripts/
        └── run_component_vulnerability_scan.py
```

## 使用
在使用本 Skill 的时候，你必须要有强指向性，如：`是否存在SQL注入漏洞?`。

```text
使用 /audit-skills 帮我梳理当前源码的路由信息，输出 Markdown 路由报告。
```

```text
使用 /audit-skills 帮我梳理当前源码下的鉴权信息，包括认证机制、权限配置和路由鉴权映射。
```

```text
使用 /audit-skills 帮我梳理当前源码下的是否存在SQL注入漏洞。
```

```text
使用 /audit-skills 帮我梳理当前源码下的是否存在反序列化漏洞。
```

```text
使用 /audit-skills 帮我梳理当前源码下的是否存在反序列化漏洞，可以使用多Agent形式分配任务进行审计。
```

```text
使用 /audit-skills 帮我梳理当前源码下，分析中间件以及组件是否存在路径穿越漏洞。
```

多语言组件扫描（自动识别 Python/Node/Go/Java 依赖清单并合并降噪）：

```text
使用 /audit-skills 扫描当前源码的依赖组件版本风险，按严重等级输出命中报告，默认跳过 test/dev 作用域依赖。
```

```text
使用 /audit-skills 审计当前 Python 源码是否存在 pickle 反序列化 / 模板注入 / 命令执行漏洞。
```

```text
使用 /audit-skills 审计当前 Node.js 源码是否存在原型污染 / 模板注入 / SSRF 漏洞。
```

```text
使用 /audit-skills 审计当前 Go 源码是否存在 SQL 注入 / 路径穿越 / 命令执行漏洞，并核查 go.mod 组件版本风险。
```

## 使用codex配合（推荐）

通过Codex的目标持续运行：
```text
/goal
你是代码审计编排器。

任务：
1. 先完整阅读 SKILL.md，严格遵守其中对 claude CLI 的调用方式。
2. 先枚举目标仓库的语言、框架、入口、路由、权限模型、数据流、危险函数、配置与依赖。
3. 将审计拆分为多个漏洞类型，每次调用 claude CLI 只能审计一种漏洞类型。
4. 每轮审计必须要求 claude 只输出当前漏洞类型的发现，不要泛化到其他漏洞。
5. 每轮结果必须包含：漏洞类型、风险等级、文件路径、行号、可达路径、触发条件、攻击方式、影响、证据、修复建议、置信度、是否需要动态验证。
6. 主审计员需要复核 claude 的结果，去重、降噪、排除误报，并把所有单项结果合并成复合审计报告。
7. 最终报告按严重程度排序，并明确列出：确认漏洞、疑似漏洞、未发现但已覆盖的审计项、审计盲区。

源码地址：/path

权限要求：
- 默认只允许只读审计。
- 不允许 claude 修改代码、删除文件、提交 git、安装依赖、联网下载、执行破坏性命令。
- 如必须执行命令，只允许用于读取项目信息、搜索代码、运行只读测试或静态分析。
- 不使用 --dangerously-skip-permissions，除非用户明确授权且环境隔离。
```
