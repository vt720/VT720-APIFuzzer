# VT720-APITest

> 一款轻量级、高并发的 **自动化 API 安全测试与脆弱性模糊测试（Fuzzing）引擎**。

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📖 简介

`VT720-APITest` 是一款面向安全测试人员的 API 接口模糊测试工具，支持自定义 HTTP 方法、自定义 Headers、动态 Payload 注入以及多线程并发请求。

工具通过自动替换请求中的 `{FUZZ}` 标记，快速发现 API 接口中可能存在的注入漏洞、异常处理缺陷及潜在安全风险。

> ⚠️ **使用声明：** 本项目仅供**授权范围内的安全测试、学习与研究**使用。请遵守 [DISCLAIMER.md](DISCLAIMER.md)。

---

## ✨ 核心特性

- 🎯 **精准 Fuzzing**：支持在 URL 或 Body 中通过 `{FUZZ}` 与 `{FUZZ_data}` 标记进行精准的 Payload 注入。
- 🚀 **多线程并发**：基于 `ThreadPoolExecutor` 实现多线程并发探测，提高测试效率。
- 🛠️ **高度自定义**：
  - 支持 `GET`、`POST`、`PUT`、`DELETE` 等请求方法。
  - 支持自定义请求头（Headers）和 Content-Type（`json` / `data`）。
  - 支持加载外部自定义 Payload 字典。
- ⏱️ **延时控制**：支持通过 `--delay` 设置请求间歇延时，降低请求过快导致目标拒绝服务的风险。
- 📊 **JSON 结果输出**：测试结果以结构化格式输出，便于后续分析与报告生成。

---

## 📦 环境要求

- Python 3.8+
- 第三方依赖见 [`requirements.txt`](requirements.txt)。

---

## 🔧 安装

### 1. 克隆仓库

```bash
git clone https://github.com/vt720/VT720-APITest.git
cd VT720-APITest
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

---

## 🚀 使用方法

### 基本语法

```bash
python apitest.py -u <URL> -m <METHOD> -H <HEADERS> --content-type <TYPE> [options]
```

---

## ⚙️ 参数说明

| 参数 | 简写 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `--url` | `-u` | `str` | 必填 | 目标 API URL，必须包含 `{FUZZ}` 标记 |
| `--method` | `-m` | `str` | `GET` | 请求方式，支持 `GET`、`POST`、`PUT`、`DELETE` |
| `--data` | `-d` | `str` | — | POST / PUT 请求体内容，支持包含 `{FUZZ_data}` 的 JSON 或表单字符串 |
| `--content-type` | — | `str` | 必填 | 指定请求类型，可选 `json` 或 `data`（表单） |
| `--headers` | `-H` | `str` | 必填 | 自定义请求头，使用 JSON 格式字符串 |
| `--payloads` | `-p` | `str` | 内置字典 | 外部 Payload 字典文件路径；未指定时使用内置通用 SQL / 异常测试 Payload 集合 |
| `--delay` | — | `float` | `0.5` | 请求间歇休眠时间，单位为秒 |
| `--concurrency` | `-c` | `int` | `5` | 并发探测线程数 |
| `--timeout` | — | `float` | `5.0` | 单次请求超时时间，单位为秒 |
| `--output` | `-o` | `str` | — | 输出结果文件名，使用 JSON 格式 |

---

## 💻 使用示例

### 1. 基础测试：GET 参数模糊测试

对 URL 中的 `id` 参数进行 Payload 注入：

```bash
python apitest.py \
  -u 'http://example.com/api/v1/user?id={FUZZ}' \
  -m GET \
  --content-type data \
  -H '{"User-Agent": "VT720"}'
```

### 2. POST JSON 测试：请求体注入探测

针对登录接口的 `password` 字段进行测试，并将结果保存为 JSON 文件：

```bash
python apitest.py \
  -u 'http://example.com/api/v1/login' \
  -m POST \
  --content-type json \
  -d '{"username": "admin", "password": "{FUZZ_data}"}' \
  -H '{"Content-Type": "application/json"}' \
  -o result.json
```

### 3. 高并发自定义字典测试

加载自定义 Payload 字典，将并发线程数设置为 `10`，请求间隔设置为 `0.1` 秒：

```bash
python apitest.py \
  -u 'http://example.com/api/v1/search?q={FUZZ}' \
  -m GET \
  --content-type data \
  -H '{"Cookie": "session=123"}' \
  -p custom_payloads.json \
  -c 10 \
  --delay 0.1
```

> 请仅对拥有明确授权的 API 目标执行测试，并根据目标环境合理设置并发数、请求间隔与超时时间。

---

## 📄 自定义字典格式

如果通过 `-p` 指定外部 Payload 字典文件，请按照以下 JSON 结构组织数据，包含 `json`、`type` 和 `data` 三个键：

```json
{
  "json": [
    "payload1",
    "payload2"
  ],
  "type": [
    "payload1",
    "payload2"
  ],
  "data": [
    "payload1",
    "payload2"
  ]
}
```

**注意：** 以上仅展示原项目所描述的字典格式示例，具体字段用途及 Payload 加载逻辑应以程序实际实现为准。

---

## 🗂️ 目录结构

```text
VT720-APITest/
├── apitest.py           # 主程序入口
├── requirements.txt     # 依赖列表
├── README.md            # 项目说明
├── DISCLAIMER.md        # 免责声明
├── LICENSE              # MIT 开源协议
└── .gitignore           # Git 忽略规则
```

---

## 🛡️ 免责声明

本项目仅供**学习、研究及授权范围内的安全测试**使用。使用者需自行确保其行为符合当地法律法规及目标网站的服务条款。因使用本项目产生的一切后果由使用者自行承担。

详细内容请参阅 [DISCLAIMER.md](DISCLAIMER.md)。

---

## 📜 License

本项目基于 [MIT License](LICENSE) 开源。
