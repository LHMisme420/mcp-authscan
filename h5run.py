import asyncio
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("H5_PORT", "8765"))
URL = f"http://127.0.0.1:{PORT}/mcp"


def _text(res):
    content = getattr(res, "content", res)
    if isinstance(content, list):
        return " ".join(getattr(c, "text", str(c)) for c in content)
    return str(content)


async def session(label, auth):
    print(f"SESSION {label}", flush=True)
    try:
        from fastmcp import Client
        client = Client(URL, auth=auth) if auth is not None else Client(URL)
        async with client:
            try:
                tools = await client.list_tools()
                names = " ".join(sorted(t.name for t in tools))
                print(f"RESULT tools {len(tools)} {names}", flush=True)
            except Exception as e:
                print(f"RESULT tools exception {type(e).__name__} {e}", flush=True)
            try:
                res = await client.call_tool("probe_ping", {})
                print(f"RESULT call {_text(res)}", flush=True)
            except Exception as e:
                print(f"RESULT call exception {type(e).__name__} {e}", flush=True)
    except Exception as e:
        print(f"RESULT exception {type(e).__name__} {e}", flush=True)


async def main():
    from fastmcp.client.auth import BearerAuth
    await session("noauth", None)
    await session("bearer", BearerAuth(token="synthetic-token"))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseException as e:
        print(f"RESULT exception {type(e).__name__} {e}", flush=True)
    sys.exit(0)
