# PHP 审计参考

## 入口与审计清单

- 入口：`public/index.php`、路由定义、控制器/action、CLI command、队列 consumer、WebSocket/RPC handler。
- sink：SQL 拼接、`include/require`、`eval`、命令执行、文件上传/解压、路径拼接、HTTP 客户端 SSRF、`unserialize`、模板渲染和反射。
- 核查认证/授权、参数绑定、路径规范化、上传 MIME 与扩展名、反序列化类白名单、SSRF 出站策略和敏感错误信息。

组件命中仅是线索；按 `SKILL.md` 要求证明入口、可控输入、传播链和影响。
