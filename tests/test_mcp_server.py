import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def test_mcp_server_returns_a_source_only_scan(tmp_path: Path) -> None:
    (tmp_path / "client.ts").write_text("export const ready = true;\n", encoding="utf-8")

    async def call_server() -> dict:
        server = StdioServerParameters(
            command=sys.executable,
            args=["-m", "supabase_security_scanner.mcp_server"],
            cwd=Path.cwd(),
            env={
                "SUPABASE_PROJECT_REF": "",
                "SUPABASE_DATABASE_URL": "",
                "SUPABASE_ACCESS_TOKEN": "",
                "SUPABASE_SCANNER_SOURCE_DIR": str(tmp_path),
            },
        )
        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=10)
                response = await asyncio.wait_for(session.call_tool("get_security_findings", {}), timeout=10)
                assert not response.isError
                if response.structuredContent:
                    return response.structuredContent
                for item in response.content:
                    if getattr(item, "type", None) == "text":
                        return json.loads(item.text)
                raise AssertionError("MCP tool did not return structured findings.")

    payload = asyncio.run(call_server())

    assert payload["findings"] == []
    assert payload["checks_run"] == ["source"]
