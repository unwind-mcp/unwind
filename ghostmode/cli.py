"""Ghost Mode CLI — one command, zero config.

Usage:
    ghostmode -- npx @modelcontextprotocol/server-filesystem ~/Documents
    ghostmode -v -- python my_mcp_server.py
    ghostmode --export session.json -- node my_tools.js
"""

import argparse
import asyncio
import logging
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ghostmode",
        description=(
            "\U0001f47b Ghost Mode — see what your AI agent would do, "
            "without letting it do anything."
        ),
        epilog=(
            "Example:\n"
            "  ghostmode -- npx @modelcontextprotocol/server-filesystem ~/Documents\n"
            "\n"
            "Point your agent at ghostmode instead of the MCP server.\n"
            "Reads pass through. Writes get intercepted. Nothing changes.\n"
            "\n"
            "For full security (rollback, enforcement, audit chain), upgrade to UNWIND:\n"
            "  pip install unwind-mcp\n"
            "  https://github.com/unwind-mcp/unwind"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "upstream_command",
        nargs=argparse.REMAINDER,
        help="The MCP server command (after --)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Log every intercepted and passed action to stderr",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export the session log to a JSON file on exit",
    )
    parser.add_argument(
        "--also-block",
        metavar="TOOL",
        action="append",
        default=[],
        help="Additional tool names to treat as writes (can be repeated)",
    )

    args = parser.parse_args()

    # Parse upstream command
    upstream_cmd = args.upstream_command
    if upstream_cmd and upstream_cmd[0] == "--":
        upstream_cmd = upstream_cmd[1:]

    if not upstream_cmd:
        print(
            "\n  \U0001f47b Ghost Mode — dry-run proxy for AI agents\n"
            "\n"
            "  Usage:\n"
            "    ghostmode -- <upstream MCP server command>\n"
            "\n"
            "  Examples:\n"
            "    ghostmode -- npx @modelcontextprotocol/server-filesystem ~/Documents\n"
            "    ghostmode -- python my_mcp_server.py\n"
            "    ghostmode -v -- node tools_server.js\n"
            "\n"
            "  The agent talks to ghostmode. Reads pass through to your\n"
            "  real MCP server. Writes get intercepted. Nothing changes.\n"
            "\n"
            "  When the session ends, you see everything the agent tried to do.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # Custom write tools
    custom_writes = frozenset(args.also_block) if args.also_block else None

    # Logging
    level = logging.DEBUG if args.verbose else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [ghostmode] %(message)s", datefmt="%H:%M:%S",
    ))
    logging.root.addHandler(handler)
    logging.root.setLevel(level)

    # Banner
    print(
        "\n  \U0001f47b Ghost Mode active\n"
        f"  Upstream: {' '.join(upstream_cmd)}\n"
        f"  Writes will be intercepted. Reads pass through.\n",
        file=sys.stderr,
    )

    from .proxy import run_ghost_proxy

    # Run with export on exit
    async def _run():
        from .proxy import GhostProxy
        proxy = GhostProxy(upstream_cmd, custom_writes, args.verbose)
        await proxy.run()

        # Export if requested
        if args.export:
            from pathlib import Path
            count = proxy.log.export_json(Path(args.export))
            print(f"\n  Exported {count} events to {args.export}", file=sys.stderr)

    asyncio.run(_run())


if __name__ == "__main__":
    main()
