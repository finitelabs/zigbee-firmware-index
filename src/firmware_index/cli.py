"""The firmware-index command."""

import argparse
import sys
from pathlib import Path

from firmware_index import keys


def keygen(args: argparse.Namespace) -> int:
    try:
        public = keys.generate(args.path)
    except FileExistsError:
        print(f"error: {args.path} exists; a key is never written over", file=sys.stderr)
        return 1
    print(public)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firmware-index")
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser(
        "keygen",
        help="write a new Ed25519 signing key and print its public key in hex",
    )
    p.add_argument("path", type=Path, help="where to write the private key (PEM)")
    p.set_defaults(run=keygen)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
