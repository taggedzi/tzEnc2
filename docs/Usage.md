# Usage

## **Command-Line Interface**

```bash
tzenc2 encode -i input.txt -o output.tzenc2 -p "my passphrase"
tzenc2 decode -i output.tzenc2 -o output.txt -p "my passphrase"
```

* See `tzenc2 --help` for options.

## **Python Library Usage**

> See “Getting Started” for the example.

**Configuration Options**:

* `redundance` (default: 2)
* `grid_size` (default: auto)
* `digest_algorithm` (default: sha256)
* See [config section](#) for details.
