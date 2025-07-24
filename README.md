# tzEnc2

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Build with ❤️ by TaggedZi](https://img.shields.io/badge/built%20with-%E2%9D%A4%EF%B8%8F%20by%20TaggedZi-blueviolet)](mailto:taggedzi.mpc@gmail.com)
[![Testing Release](https://img.shields.io/badge/status-testing-yellow)](https://github.com/taggedzi/tzEnc2)

> **This package is an early TEST RELEASE for community review. Please do not use for real secrets or production data.**

---

## 📦 Project Overview

**tzEnc2** is a Python-based encryption and decryption tool that demonstrates novel grid-based message encoding using modern cryptography and parallel processing.

- **CLI and Gradio Web UI** included for testing.
- Modern cryptography (`argon2id`, AES, HMAC).
- Easily installable via pip.
- **For demonstration, review, and testing purposes only.**

---

## 🚀 Quickstart

### 1. Install from PyPI

> Requires **Python 3.8+**  
> (Best practice: use a [virtual environment](https://docs.python.org/3/library/venv.html))

```bash
pip install tzEnc2
````

### 2. Usage

#### **Command-Line Interface (CLI)**

* **Encrypt a message:**

  ```bash
  tzenc encrypt -m "Your secret message" -p YOUR_PASSWORD -o output.tzenc
  ```

  Or encrypt from a file:

  ```bash
  tzenc encrypt -i input.txt -p YOUR_PASSWORD -o output.tzenc
  ```

* **Decrypt a message:**

  ```bash
  tzenc decrypt -f output.tzenc -p YOUR_PASSWORD -o message.txt
  ```

* **Optional arguments:**

  * `-d, --digest-passphrase` for integrity check
  * `-r, --redundancy` to adjust redundancy factor (default: 3)
  * `-v, --verbose` for more logging (`-v`, `-vv`, `-vvv`)

* **Help:**

  ```bash
  tzenc --help
  tzenc encrypt --help
  tzenc decrypt --help
  ```

#### **Gradio Web UI**

* Launch the web interface:

  ```bash
  tzenc-web
  ```

  This opens a local browser UI for encryption and decryption.

---

## 🔒 Security & Testing Notice

* **This is a TEST version.**
  It is provided for open review, feedback, and cryptanalysis.
  **Do not use for production or sensitive data.**
* The encryption logic is intentionally transparent for community review.
* Please report any vulnerabilities, weaknesses, or suggestions via issues or email.

---

## 🧑‍💻 Developer & Contributor Guide

* Source code: [GitHub Repo](https://github.com/taggedzi/tzEnc2)
* Issues & feedback: Use the [GitHub Issues](https://github.com/taggedzi/tzEnc2/issues) page or email [taggedzi.mpc@gmail.com](mailto:taggedzi.mpc@gmail.com)
* To run tests or build from source, see `requirements-dev.txt` and the `tasks.py` commands:

  ```bash
  pip install -r requirements-dev.txt
  invoke test     # Run tests
  invoke lint     # Code linting
  invoke format   # Auto-format
  invoke build    # Build distributable
  ```

---

## 📝 Requirements

* Python **3.8+**
* See `requirements.txt` (installed automatically via pip).
