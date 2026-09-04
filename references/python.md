# Python 审计参考

## 组件 YAML 正则匹配扫描

需要从 `requirements.txt`、`Pipfile`、`Pipfile.lock`、`pyproject.toml`、`poetry.lock`、`setup.py` 或部署目录中发现组件版本风险时，使用内置组件扫描资源；锁定文件优先于 manifest 范围。

- 脚本：`scripts/run_component_vulnerability_scan.py`
- 规则：`references/python-vulnerability.yaml`（默认会与 `references/*-vulnerability.yaml` 一并加载）
- 规则机制：脚本解析 requirements / Pipfile / pyproject / poetry.lock / setup.py；lockfile 的确定版本参与命中，`>=`、`<`、`~=`、`^` 等约束保留为范围风险，不作为实际版本命中。

扫描默认候选源：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录>
```

指定一个或多个扫描源（源码目录、`requirements.txt`、`pyproject.toml`、部署目录均可）：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源码目录|requirements.txt|部署目录>
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源1> --source <源2>
```

默认跳过 `dev` 作用域依赖（Pipfile `[dev-packages]`、pyproject dev-dependencies）；PEP 621 optional-dependencies 标记为 optional 并默认保留，如需包含测试/开发依赖加 `--include-test-scope`：

```bash
python3 scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --include-test-scope
```

组件命中只能作为线索；不能仅凭包名、版本或 CVE 命中确认漏洞，必须继续证明入口、可控参数、传播链和可利用性。HTTP 漏洞提供 Burp 原始请求，其他协议或非网络漏洞提供对应的最小安全复现步骤。

## 字节码反编译与解包

默认有源码时优先审源码；只有 `.pyc`、PyInstaller/frozen 产物或缺失关键代码时再反编译。

### .pyc 反编译

按 Python 版本选择反编译器：

- Python 3.8 及以下：`uncompyle6`（`pip install uncompyle6`）
- Python 3.7-3.8：`decompyle3`（`pip install decompyle3`）
- 任意版本（含 3.9+）：`pycdc`（`Decompyle++`，需源码编译）

```bash
pip install uncompyle6
uncompyle6 <目标.pyc> > <反编译目录>/<目标名>.py
```

### PyInstaller / frozen 解包

PyInstaller 打包的 exe/elf 内含 `.pyc`，先用 `pyinstxtractor` 解包，再用上述反编译器处理：

```bash
python3 pyinstxtractor.py <目标.exe|目标.elf>
# 产物在 <目标名>_extracted/，.pyc 位于其中，再用 uncompyle6/pycdc 反编译
```

反编译失败、部分成功或跳过都必须记录到 manifest；不要静默忽略。

## Python 危险 sink 与审计重点

按漏洞类型核查用户可控数据是否进入以下 sink：

- **反序列化**：`pickle.loads` / `pickle.load` / `cPickle` / `shelve` / `yaml.load`（未指定 `Loader` 或使用 `Loader=yaml.Loader`）/ `marshal.loads`。
- **命令执行**：`subprocess`（`shell=True`）、`os.system`、`os.popen`、`commands`、`pexpect` 拼接用户输入。
- **代码执行**：`eval`、`exec`、`compile`、`pickle`、`__import__`。
- **模板注入/SSTI**：`Jinja2` / `Mako` / `Django.template` 渲染用户可控模板字符串（`Template(user_input).render()`）。
- **SQL 注入**：f-string、`%`、`str.format` 拼接 SQL；`cursor.execute` 直接带入用户可控片段；ORM `raw`、`extra`、`order_by(user_input)`。
- **路径穿越**：`open(user_path)`、`os.path.join(base, user)` 未规范化、`send_file` / `send_from_directory` 未限制、`tarfile.extractall` 无过滤。
- **SSRF**：`requests` / `urllib` / `httpx` / `aiohttp` 请求 URL 来自用户输入；`verify=False` 全局关闭证书校验（CVE-2024-35195）。
- **XXE**：`lxml` / `xml.etree` 解析用户 XML 未禁用外部实体；`defusedxml` 未使用。
- **认证/会话**：Flask `debug=True`、`SECRET_KEY` 硬编码或弱值、JWT 算法未固定（`PyJWT` 旧版本算法混淆）。
- **文件上传**：未校验扩展名/MIME/大小、保存路径可控。

框架入口识别：Flask/FastAPI/Django 路由装饰器（`@app.route`、`@router.get`、`path()`）、ASGI/WSGI、Celery 任务、管理命令。
