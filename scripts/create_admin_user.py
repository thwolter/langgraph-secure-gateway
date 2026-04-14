"""CLI compatibility shim for admin user bootstrap."""

from __future__ import annotations

import argparse
import sys

from langgraph_secure_gateway.auth_cli import create_or_update_admin_user


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username', required=True, help='Admin username')
    parser.add_argument('--password', required=True, help='Admin password')
    parser.add_argument(
        '--inactive',
        action='store_true',
        help='Create/update admin as inactive',
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    action = create_or_update_admin_user(
        username=args.username,
        password=args.password,
        inactive=args.inactive,
    )
    print(f"Admin user '{args.username}' {action}.")
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f'create_admin_user failed: {exc}\n')
        raise
