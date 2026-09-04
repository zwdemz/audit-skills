---
name: audit-skills
description: 当用户要求审计 Java、.NET、PHP、Python、Node.js 或 Go 源码/部署产物/反编译产物/安全发现，并需要默认脚本输出目录、报告输出目录、Java/.NET 反编译与反混淆参考、Python/Node/Go 审计参考、多语言组件 YAML 正则匹配扫描、确认漏洞判定标准、安全 Payload 和 BurpSuite 原始 HTTP 请求包证据时使用。仅用于授权代码审计和防御性安全验证。
---

# Audit Skills

## 1. 默认输出目录

未指定目录时，先创建 `<目标目录>/audit-workspace/` 作为审计工作目录；组件扫描脚本未指定 `--workspace` 时使用当前目录下的 `audit-workspace/`。

- 默认临时脚本输出目录：`<审计工作目录>/script-output/`
- 报告输出目录：`<审计工作目录>/reports/`
- 工具目录：`<审计工作目录>/tools/`
- 反编译目录：`<审计工作目录>/decompiled/`
- 反混淆目录：`<审计工作目录>/deobfuscated/`
- 证据目录：`<审计工作目录>/evidence/`

`audit-workspace/` 是总工作目录；组件扫描结果固定写入 `evidence/component-hits/`（包括 `range-risks.md`），`script-output/` 只保存命令日志和临时文件。最终可交付报告只写入 `reports/`，默认文件名为 `audit-report.md`。

## 2. 语言参考入口

按目标语言只读取对应参考文件，避免无关上下文进入审计：

- Java 审计、CFR 反编译、Java 组件 YAML 正则匹配扫描：读取 `references/java.md`
- .NET / ASP.NET 反编译与反混淆：读取 `references/net.md`
- Python 审计、`.pyc`/PyInstaller 反编译、Python 组件扫描：读取 `references/python.md`
- Node.js 审计、source map 还原、Node 组件扫描：读取 `references/nodejs.md`
- Go 审计、Go 二进制逆向、Go 组件扫描：读取 `references/go.md`
- PHP 审计：读取 `references/php.md`。

语言参考中的扫描或组件命中只能作为线索；确认漏洞必须回到本文件的有效性标准。

### 组件扫描的降噪与误报抑制

- 多语言规则聚合：`scripts/run_component_vulnerability_scan.py` 默认加载 `references/*-vulnerability.yaml` 全部规则，按目标依赖自动匹配对应语言。
- 命中合并：同一「组件+版本+规则正则」跨来源合并为一行，列出全部命中 CVE，避免同一组件重复占行。
- 作用域过滤：默认跳过 `test`/`dev` 作用域依赖（含 Gradle testRuntimeOnly、npm devDependencies、Pipfile/pyproject dev 组）；optional/peer/indirect 默认保留，因为它们可能进入运行时；需包含测试/开发依赖时加 `--include-test-scope`。
- 跳过数量写入 `evidence/component-hits/manifest.json`，不静默。
- `manifest.json` 同时记录 `range_risk_count`、`parse_error_count` 和 `parse_errors`；范围风险写入 `range-risks.md`，解析错误不得视为“无依赖”。
- 扫描状态为 `success`、`partial`、`empty` 或 `failed`；只有全部输入无法解析且没有依赖时返回失败状态。

## 3. 如何判定漏洞有效

只有同时满足以下标准，才能把发现写成“确认漏洞”：

- 可达：存在真实外部入口，例如 HTTP 路由、Servlet、Filter、Controller、RPC、WebService、上传处理入口等。
- 可控：能指出用户可控参数、参数来源、绑定方式，以及参数进入代码的准确位置。
- 可传播：存在清晰的 source-to-sink 文件/方法级调用链，且中途没有有效鉴权、校验、编码、白名单或类型约束阻断。
- 可利用：sink 的语义在当前项目上下文中能造成真实安全影响。
- 可复现：必须有构造的安全 Payload，并提供与入口匹配的最小复现证据。
- 影响成立：能说明触发后产生的越权、泄露、绕过、写入或其他安全影响。

任一标准缺失时，只能写为“高风险线索 / 待人工验证”，不得写入“确认漏洞”。

每个确认漏洞必须包含：

```text
标题:
严重等级:
受影响入口:
鉴权要求:
用户可控输入:
Source-to-sink 调用链:
Sink:
同源/相似受影响路由:
防护判断:
安全 Payload:
BurpSuite 原始请求包:
影响:
证据文件和行号:
限制说明:
```

网络协议漏洞的请求证据应匹配协议：HTTP 漏洞提供可直接粘贴进 BurpSuite Repeater 的原始请求包；RPC/消息协议提供对应协议请求；CLI、桌面程序、Go 二进制或纯配置漏洞提供最小安全复现步骤；无法安全复现时标记为“待验证”。HTTP 请求示例：

```http
POST /<授权测试路径> HTTP/1.1
Host: <授权测试主机>
Content-Type: application/x-www-form-urlencoded
Connection: close

<参数名>=<安全证明Payload>
```

## 4. 安全边界

- 不准输出破坏性 Payload。
- 不准包含删除文件、修改配置、删除/清空/截断数据库、擦除表数据、写入持久化后门、反弹 shell、窃取敏感数据或横向移动的 Payload。
- 只使用无害证明 Payload，例如只读验证、布尔差异、受控回显标记，或针对非敏感测试记录的越权证明。
- Host、Cookie、凭据、ID、敏感值默认使用占位符；除非用户明确提供授权测试值。
- 如果漏洞必须依赖破坏性操作才能证明，只能写为高风险线索，并说明缺失的非破坏性验证路径。
