#!/usr/bin/env python3

# Real MCP servers from the ecosystem
REAL_MCP_SERVERS = [
    {"name": "Filesystem", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem"},
    {"name": "Git", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/git"},
    {"name": "GitHub", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/github"},
    {"name": "Web Browser", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/web-browser"},
    {"name": "Sqlite", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite"},
    {"name": "Postgres", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/postgres"},
    {"name": "Google Drive", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/google-drive"},
    {"name": "Slack", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/slack"},
    {"name": "Linear", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/linear"},
    {"name": "Notion", "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/notion"},
]

def get_real_servers():
    return REAL_MCP_SERVERS

if __name__ == "__main__":
    servers = get_real_servers()
    print(f"✅ Using {len(servers)} real MCP servers:")
    for s in servers:
        print(f"  - {s['name']}: {s['url']}")
