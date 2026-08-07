# Go 审计参考

## 组件 YAML 正则匹配扫描

需要从 `go.mod` 或部署目录中发现 Go module 版本风险时，使用内置组件扫描资源。

- 脚本：`scripts/run_component_vulnerability_scan.py`
- 规则：`references/go-vulnerability.yaml`（默认会与 `references/*-vulnerability.yaml` 一并加载）
- 规则机制：YAML 中按严重等级维护 module 路径与版本正则；脚本解析 `go.mod` 的 `require` 与 `replace` 后，用这些正则匹配版本命中。`replace` 指令会覆盖原版本，扫描器按替换后版本匹配，避免对已被修复的旧版本误报。

扫描默认候选源：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录>
```

指定一个或多个扫描源：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源码目录|go.mod|部署目录>
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源1> --source <源2>
```

`// indirect` 标记的依赖默认保留（仍编译进二进制），如需仅看直接依赖可按 `source_type=go-mod` 的 `scope` 过滤。组件命中只能作为线索；不能仅凭 module 名、版本或 CVE 命中确认漏洞，必须继续证明入口、可控参数、传播链、可利用性、安全 Payload 和 BurpSuite 请求包。

注意：Go 标准库（`go.mod` 的 `go` 指令版本）不在依赖命中范围；需单独核查 `go 1.x` 版本对应的标准库 CVE（如 HTTP/2 Rapid Reset 影响 go1.21.2 以下、go1.20.9 以下）。

## Go 二进制逆向

只有二进制产物或缺失源码时再逆向；Go 二进制包含大量运行时元数据，可用专门工具恢复符号与函数。

### GoReSym 恢复符号

`GoReSym` 提取 Go 二进制的函数、类型、模块路径与源文件信息：

```bash
GoReSym -t -d -p <目标.elf|目标.exe> > <反编译目录>/<目标名>.json
```

### Redress 人工分析

`redress` 提供面向 Go 的二进制摘要与分类视图：

```bash
redress info <目标.elf>
redress source <目标.elf> > <反编译目录>/<目标名>.source
```

### Ghidra Golang 插件

Ghidra 配合 [golang-re](https://github.com/golang-re) 系列插件恢复字符串、函数名与类型；适合复杂二进制深度分析。

### 反汇编片段

快速定位函数反汇编：

```bash
go tool objdump -s '<函数名正则>' <目标.elf> > <反编译目录>/<目标名>.asm
```

反编译失败、部分成功或跳过都必须记录到 manifest；不要静默忽略入口程序集失败。

## Go 危险 sink 与审计重点

按漏洞类型核查用户可控数据是否进入以下 sink：

- **命令执行**：`exec.Command` 使用 `sh -c` 拼接用户输入、`os/exec` 的 `CommandContext`。
- **SQL 注入**：`database/sql` 的 `db.Query` / `db.Exec` 字符串拼接；`fmt.Sprintf` 拼 SQL；ORM（`gorm` / `sqlx` / `beego`）`Raw` / `Order(user_input)`。
- **路径穿越**：`filepath.Join(base, userInput)` 未校验 `..`、`os.Open(user_path)`、`http.ServeFile` / `http.FileServer` 未限制根目录、`archive/zip` 解压未校验目标路径（Zip Slip）。
- **模板注入**：`text/template` 渲染用户可控模板（注意：`text/template` 不做 HTML 转义，应改用 `html/template`）；模板名或内容可控。
- **SSRF**：`http.Get` / `http.Post` / `http.NewRequest` 的 URL 来自用户输入；未限制内网/协议；`client.Do` 跟随重定向。
- **反序列化**：`encoding/gob` / `encoding/json` 反序列化到接口触发方法；`yaml.Unmarshal` 到接口；第三方（`colfer`、`msgpack`）。
- **加密**：`crypto/aes` 使用 ECB、IV 复用、`math/rand` 生成密钥/Token、`crypto/sha1` / MD5 用于密码、硬编码密钥。
- **认证/会话**：JWT（`golang-jwt`）算法未校验、`gorilla/websocket` Origin 未校验、Cookie 未设 `HttpOnly`/`Secure`/`SameSite`。
- **认证绕过**：`net/http` 中间件顺序错误、`ServeMux` 路径匹配差异、`http.Dir` 未拒绝 `..`。
- **SSRF/请求走私**：`net/http` 旧版本、`x/net/http2` Rapid Reset；TLS 证书校验关闭（`InsecureSkipVerify: true`）。

框架入口识别：`net/http` Handler / `ServeMux`、`gin` / `echo` / `chi` / `fiber` / `gorilla/mux` 路由（`router.GET`、`r.POST`）、`grpc` service、WebSocket upgrader。
