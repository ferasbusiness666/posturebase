from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import ScanConfig
from .scanner import SecurityScanner


def create_server() -> FastMCP:
    server = FastMCP("Supabase Security Scanner", json_response=True)

    @server.tool()
    def get_security_findings() -> dict[str, Any]:
        """Run the configured local, read-only Supabase scan and return redacted structured findings.

        Credentials and source paths are read exclusively from the local process environment.
        This tool accepts no arguments, preventing an agent from requesting arbitrary filesystem paths.
        """

        return SecurityScanner().scan(ScanConfig.from_environment()).to_dict()

    return server


def main() -> None:
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
