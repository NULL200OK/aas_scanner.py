# CVE-2026-94293 — AAS Edge Client Scanner

> **A fast, asynchronous scanner to detect exposed AAS Edge Client instances potentially vulnerable to CVE-2026-94293.**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-NULL200OK-red?style=for-the-badge&logo=github)

## 👤 Author

**Nabeel Hasan** — known as **NULL200OK**
🔗 GitHub: [https://github.com/NULL200OK](https://github.com/NULL200OK)

> *This script created by Nabeel Hasan ===> NULL200OK*

## 📖 Overview

**CVE-2026-94293** affects **AAS Edge Client** and may expose the `/api/v1/submodels` endpoint without proper authentication.
This tool is designed to **detect** such exposed instances — it does **not** exploit the vulnerability, modify data, or perform any destructive action.

It is built for **authorized security testing**, internal audits, and vulnerability assessments.

The scanner uses asynchronous I/O (`asyncio` + `aiohttp`) to achieve high performance while remaining lightweight and easy to use.

## ✨ Features

- ⚡ **Asynchronous scanning** using `asyncio` + `aiohttp` for high performance.
- 🌐 Supports **HTTP** and **HTTPS** protocols.
- 🎯 Scans multiple **ports** and **paths** in a single run.
- 📁 Accepts targets from:
  - Single IP / host
  - Text file (one target per line)
  - CIDR ranges (e.g., `192.168.1.0/24`)
- 🧠 **Smart response analysis** to reduce false positives.
- 📊 Generates reports in **TXT**, **JSON**, and **CSV** formats.
- ⏱️ Configurable **timeout**, **concurrency**, and **rate limiting**.
- 🔒 Optional SSL verification disable (`--insecure`).
- ✅ Requires explicit **`--authorized`** flag to run — ensuring ethical use.
- 🎨 Clean banner and progress logging.
- 🛡️ Safe detection only — no exploitation, no data modification.

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/NULL200OK/aas_scanner.py.git
cd aas_scanner.py
