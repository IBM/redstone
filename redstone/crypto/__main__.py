"""Command-line tool to encrypt/decrypt data using IBM KeyProtect

This is meant to be a quick way to encrypt/decrypt via the command line
with shell or other tools. It only works on data sizes up to about 2 gigabytes,
and will not be the most performant way.

It also does not support some more advanced features like reading the encrypted
message metadata header, or providing additional authentication data during encryption.
If you need these features please use the 'crypto' module directly.
"""

import argparse
import base64
import os
import sys

from redstone import crypto


key_crn_env_var = "RSCRYPTO_KEY_CRNS"


def main():
    p = argparse.ArgumentParser()

    subp = p.add_subparsers(dest="action")

    ep = subp.add_parser("encrypt")
    ep.add_argument(
        "--key-crns",
        help=(
            "Space separated list of CRNs of KMS Keys to use during encryption. "
            "At least one CRN must be specified here or by setting %s" % key_crn_env_var
        ),
    )
    ep.add_argument(
        "infile",
        type=argparse.FileType("rb"),
        help=(
            "Input file to encrypt. Output will be written to stdout. "
            "Use '-' to read from stdin."
        ),
    )

    dp = subp.add_parser("decrypt")
    dp.add_argument(
        "infile",
        type=argparse.FileType("rb"),
        help=(
            "Input file to decrypt. Output will be written to stdout. "
            "Use '-' to read from stdin."
        ),
    )

    args = p.parse_args()

    api_key = os.getenv("IBMCLOUD_API_KEY")
    if not api_key:
        print("'IBMCLOUD_API_KEY' must be set", file=sys.stderr)
        return 1

    if args.action == "encrypt":
        key_crns = args.key_crns or os.getenv(key_crn_env_var)
        if not key_crns:
            print(
                (
                    "No key CRNs specified. "
                    "Please pass the CRNs with --key-crns or set '%s'"
                )
                % key_crn_env_var,
                file=sys.stderr,
            )
            return 1
        key_crns = key_crns.split(" ")

        data = args.infile.read()
        if isinstance(data, str):
            data = data.encode("utf-8")

        message, _ = crypto.encrypt(
            data, key_crns=key_crns, aad="redstone.crypto.__main__"
        )
        print(base64.b64encode(message).decode("utf-8"), file=sys.stdout)
    elif args.action == "decrypt":
        message, _ = crypto.decrypt(base64.b64decode(args.infile.read()))
        # write raw bytes, as we don't know the encoding of the data
        sys.stdout.buffer.write(message)
    else:
        p.print_usage(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
