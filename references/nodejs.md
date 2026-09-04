# Node.js 审计参考

## 组件 YAML 正则匹配扫描

需要从 `package.json`、`package-lock.json`、`yarn.lock` 或部署目录中发现组件版本风险时，使用内置组件扫描资源。

- 脚本：`scripts/run_component_vulnerability_scan.py`
- 规则：`references/node-vulnerability.yaml`（默认会与 `references/*-vulnerability.yaml` 一并加载）
- 规则机制：脚本解析 `package.json` / `package-lock.json` / `yarn.lock`；lockfile 的确定版本参与命中，`^`、`~`、`>=` 等 manifest 范围保留为范围风险，不作为实际版本命中。通配、URL、别名视为未解析。

扫描默认候选源：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录>
```

指定一个或多个扫描源：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源码目录|package.json|部署目录>
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源1> --source <源2>
```

默认跳过 `devDependencies` 与 lockfile 中标记为 `dev` 的依赖，如需包含加 `--include-test-scope`：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --include-test-scope
```

组件命中只能作为线索；不能仅凭包名、版本或 CVE 命中确认漏洞，必须继续证明入口、可控参数、传播链和可利用性。HTTP 漏洞提供 Burp 原始请求，其他协议或非网络漏洞提供对应的最小安全复现步骤。

## 源码还原与去混淆

Node.js 通常以源码或 minified JS 分发；无源码时按需还原。

### source map 还原

存在 `.js.map` 时还原原始源码：

```bash
# 使用 shuji / source-map-explorer / sourcemap-decoder
npx shuji -o <反编译目录> -i <目标.js.map>
```

### 压缩 JS 美化

minified JS 先美化再审计：

```bash
npx prettier --write <目标.min.js>
npx js-beautify -f <目标.min.js> -o <反编译目录>/<目标名>.js
```

### 打包产物解包

Webpack / Vite / Browserify 产物可尝试 `unpacker` / `webpack-unpack`；如存在 source map 优先走 source map 还原。

反编译失败、部分成功或跳过都必须记录到 manifest；不要静默忽略。

## Node.js 危险 sink 与审计重点

按漏洞类型核查用户可控数据是否进入以下 sink：

- **反序列化**：`node-serialize` 的 `unserialize`（直接 RCE）、`funcster`、自定义 JSON.parse 后方法调用。
- **命令执行**：`child_process.exec` / `execSync` 拼接用户输入、`spawn(cmd, args, {shell:true})`、`eval`、`new Function`、`vm.runInThisContext`。
- **原型污染**：`lodash.set` / `defaultsDeep`、`merge` / `extend` / `assign` 深合并用户对象；`qs` 解析 allowDots/数组；`ejs` / `handlebars` 渲染受污染对象。
- **模板注入/SSTI**：`ejs.render(user_input)`、`pug.compile`、`handlebars.compile`、`nunjucks` 渲染用户模板。
- **SQL 注入**：`mysql` / `pg` / `sequelize` / `knex` 字符串拼接查询；`query(util.format(...))`。
- **路径穿越**：`path.join` / `path.resolve` 拼接用户输入未规范化、`res.sendFile` / `express.static` 未限制、`fs.readFile(user_path)`。
- **SSRF**：`axios` / `node-fetch` / `got` / `request` 请求 URL 来自用户输入；跟随重定向未限制协议/内网。
- **XXE**：`libxmljs` / `xmldom` 解析用户 XML 未禁用外部实体。
- **认证/会话**：`jsonwebtoken` 旧版本算法混淆、`express-session` 弱 `secret` 或默认存储、`cookie-parser` 未签名、CORS `origin: true`。
- **正则 DoS（ReDoS）**：`semver`、用户输入进入复杂正则；关注 `validator` / 自定义正则。
- **依赖与原型**：`lodash` <4.17.21、`minimist`、`qs` 旧版本；核查 `package.json` 中是否锁定到已修复版本。

框架入口识别：Express / Koa / Fastify / NestJS 路由（`app.get`、`router.post`、`@Controller`）、中间件、WebSocket（`ws` / `socket.io`）、GraphQL resolver。
