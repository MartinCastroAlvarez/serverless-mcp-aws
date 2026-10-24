"""`serverless-mcp-aws` command line."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from collections.abc import Sequence

from serverless_mcp_aws import __version__

__all__ = ["main"]


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="serverless-mcp-aws",
        description="Run an MCP server on AWS Lambda; develop it locally.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    dev = sub.add_parser(
        "dev",
        help="serve a Lambda handler (or an MCP server) locally over HTTP",
        description=(
            "Serve TARGET (module:attribute) at http://HOST:PORT/mcp through the same "
            "API Gateway event path Lambda uses. An MCPServer target runs without "
            "authentication, for localhost; a handler target keeps its own auth settings."
        ),
    )
    dev.add_argument("target", help="module:attribute, e.g. app:server or app:handler")
    dev.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    dev.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    dev.add_argument(
        "--authorizer",
        metavar="MODULE:ATTR",
        help="emulate API Gateway's Lambda authorizer with this handler",
    )
    dev.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow binding to a non-loopback address (not recommended)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    from serverless_mcp_aws.dev import DevServer
    from serverless_mcp_aws.dev import as_handler
    from serverless_mcp_aws.dev import load_target

    if not _is_loopback(args.host) and not args.allow_remote:
        print(
            f"refusing to bind to {args.host}: the dev server is for localhost "
            "(pass --allow-remote to override)",
            file=sys.stderr,
        )
        return 2
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        handler = as_handler(load_target(args.target))
        authorizer = as_handler(load_target(args.authorizer)) if args.authorizer else None
    except (ImportError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    server = DevServer(handler, host=args.host, port=args.port, authorizer=authorizer)
    print(f"serving {args.target} at {server.url}/mcp (Ctrl+C to stop)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
    return 0
