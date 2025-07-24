# Getting Started

## **Prerequisites**

* Python 3.9+
* Recommended: Virtualenv

## **Installation**

```bash
git clone https://github.com/taggedzi/tzEnc2.git
cd tzenc2
pip install -r ./requirements.txt
pip install -e .
```

## **Quick Start Example in Code**

```python
from tzenc2 import encode_string, decode_string

ciphertext = encode_string("Hello, world!", passphrase="secret")
plaintext = decode_string(ciphertext, passphrase="secret")
assert plaintext == "Hello, world!"
```
