import argparse
import json
from pathlib import Path
from tzEnc2.log_config import set_log_level, get_logger
from tzEnc2.main import encrypt, decrypt  # Replace with your actual import path
log = get_logger(__name__)


def map_verbosity_to_level(count: int) -> str:
    if count >= 3:
        return "DEBUG"
    elif count == 2:
        return "INFO"
    elif count == 1:
        return "WARNING"
    else:
        return "ERROR"

def parse_args():
    parser = argparse.ArgumentParser(description="tzEnc Encryption/Decryption CLI Tool")
    parser.add_argument("--verbose", "-v", action="count", default=0,
                        help="Increase verbosity level (-v, -vv, -vvv)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a message")
    encrypt_source = encrypt_parser.add_mutually_exclusive_group(required=True)
    encrypt_source.add_argument("-m", "--message", help="Message to encrypt")
    encrypt_source.add_argument(
        "-i", "--input", type=Path, help="Path to input text file"
    )

    encrypt_parser.add_argument(
        "-p", "--password", required=True, help="Encryption password"
    )
    encrypt_parser.add_argument(
        "-d", "--digest-passphrase", help="Optional digest passphrase for verification"
    )
    encrypt_parser.add_argument(
        "-r",
        "--redundancy",
        type=int,
        default=3,
        help="Grid redundancy factor (default: 3)",
    )
    encrypt_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="Output path for .tzenc file"
    )

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a .tzenc file")
    decrypt_parser.add_argument(
        "-f", "--file", type=Path, required=True, help="Path to .tzenc file"
    )
    decrypt_parser.add_argument(
        "-p", "--password", required=True, help="Decryption password"
    )
    decrypt_parser.add_argument(
        "-d", "--digest-passphrase", help="Optional digest passphrase for verification"
    )
    decrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Path to save decrypted plaintext",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    level = map_verbosity_to_level(args.verbose)
    set_log_level(level)
    log.debug("Debugging enabled")
    log.info("CLI started")
    
    if args.command == "encrypt":
        if args.message:
            message = args.message
        else:
            if not args.input.exists():
                print(f"Error: input file {args.input} does not exist.")
                return
            message = args.input.read_text(encoding="utf-8")

        encrypted_data = encrypt(
            password=args.password,
            redundancy=args.redundancy,
            message=message,
            digest_passphrase=args.digest_passphrase,
        )

        args.output.write_text(json.dumps(encrypted_data, indent=2), encoding="utf-8")
        print(f"[+] Encrypted message written to {args.output}")

    elif args.command == "decrypt":
        if not args.file.exists():
            print(f"Error: file {args.file} does not exist.")
            return
        try:
            json_data = json.loads(args.file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("Error: Encrypted file is not valid JSON.")
            return

        plaintext = decrypt(
            password=args.password,
            json_data=json_data,
            digest_passphrase=args.digest_passphrase,
        )

        args.output.write_text(plaintext, encoding="utf-8")
        print(f"[+] Decrypted message written to {args.output}")


if __name__ == "__main__":
    main()
