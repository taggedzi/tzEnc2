# tzEnc2

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Build with ❤️ by TaggedZi](https://img.shields.io/badge/built%20with-%E2%9D%A4%EF%B8%8F%20by%20TaggedZi-blueviolet)](mailto:taggedzi.mpc@gmail.com)
[![Testing Release](https://img.shields.io/badge/status-testing-yellow)](https://github.com/taggedzi/tzEnc2)

> **This package is an early TEST RELEASE for community review. Please do not use for real secrets or production data.**


### What is the Grid/Time-Based Encryption Scheme in tzEnc2?

**tzEnc2** uses a novel encryption method that hides your message by converting it into a series of coordinates within a **shuffled 3D grid** of characters. Here’s how it works at a high level:

#### **The Big Idea:**

* Instead of directly storing or transmitting your message, each character is mapped to a unique position (an x, y, z coordinate) in a large, scrambled cube (the grid).
* The arrangement of this grid isn’t random: it’s generated in a **deterministic** way using a combination of your password, a random salt, and a time-like parameter (an incrementing counter).
* The process ensures that the same character can appear in many different positions, and each message, password, and time produces a totally unique mapping. Every time. The same message never encodes twice even with all the same data input.

#### **What makes this useful or different?**

* **Obfuscation through Structure:** The actual message is never stored or sent in plain text or even as a simple substitution—it’s hidden as a series of coordinates in a massive virtual space that only someone with the right password (and settings) can reconstruct.
* **Time-Variation:** Each character’s position depends not just on your password, but also on a time-like counter that changes as you move through the message. This means even repeated characters in the message are mapped differently, defeating simple pattern analysis.
* **Resistance to Frequency Analysis:** Traditional ciphers leak information if the same character always encrypts to the same symbol. Here, every instance is placed differently, making statistical attacks much harder.
* **Parameterizable Complexity:** Settings like **redundancy** and **grid size** let you trade off between speed and security, and potentially tune for different use cases or threat models.

#### **Why is this interesting?**

* It combines the ideas of **key derivation, grid-based hiding, and time-driven shuffling** to create a cipher that is hard to analyze using traditional cryptanalysis.
* It’s useful for experimenting with “location-based” or “structure-based” encryption, and for learning how combinatorial complexity can help protect secrets.
* The design encourages public review and feedback to find weaknesses or suggest improvements, making it a great candidate for open cryptanalysis.

---

**In summary:**
*tzEnc2* turns your message into a map of coordinates, where only the right password, salt, and grid logic can reveal the original message.

---

## 📦 Project Overview

**tzEnc2** is a Python-based encryption and decryption tool that demonstrates novel grid-based message encoding using modern cryptography and parallel processing.

- **CLI and Gradio Web UI** included for testing.
- Modern cryptography (`argon2id`, AES, HMAC).
- Easily installable via pip from source (not on PyPI).
- **For demonstration, review, and testing purposes only.**

---

## 🚀 Quickstart

### 1. Install from Source

> Requires **Python 3.8+**  
> (Best practice: use a [virtual environment](https://docs.python.org/3/library/venv.html))

Clone the repository:
```bash
git clone https://github.com/taggedzi/tzEnc2.git
cd tzEnc2
````

Install dependencies and the package (editable mode recommended for testing):

```bash
pip install -r requirements.txt
pip install -e .
```

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

### What Does "Redundancy" Mean in tzEnc2?

In **tzEnc2**, **redundancy** controls the number of times every character in your message is **guaranteed to appear** in the encrypted data’s underlying character grid.

#### **Why is redundancy important?**

* **Security**: Increasing redundancy ensures that each character appears multiple times in the encrypted structure, making frequency analysis and brute-force attacks more difficult for an attacker. This “adds noise” and hides the true message content.
* **Obfuscation**: With higher redundancy, the mapping between original characters and their encrypted coordinates becomes less predictable, as there are more possible positions for each character.
* **Resource usage**: Greater redundancy means a larger grid, using more memory and requiring more computation during encryption and decryption.

#### **How does it work?**

* If you set `redundancy` to `3` (the default), then **every character in your message is present at least 3 times** in the character grid that underlies the encryption process.
* You can increase this value for more security and obfuscation (at the cost of performance).

#### **Summary Table**

| Redundancy Value | Effect                                             |
| ---------------- | -------------------------------------------------- |
| 1                | Minimum size, fastest, less obfuscation            |
| 3                | Default: good balance for testing                  |
| 5+               | More “noise,” harder to analyze, slower to process |

---

**In short:**

* Higher redundancy → more copies of each character in the grid → more security and “noise,” but slower and more memory-intensive.

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
