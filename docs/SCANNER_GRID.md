# Three MCP scanners, one server, same authorization

Target: hosted.flowstatemcp.com/mcp (FlowState). Written authorization from the operator, window through 2026-11-18. Each tool run once, in its own environment, against the same endpoint. No tool was configured after another's results were seen.

| | mcp-authscan 1.1.20 | Ramparts 0.8.10 | Cisco mcp-scanner 4.8.7 |
|---|---|---|---|
| Reached an auth-protected server | yes | no, 401 on resources and prompts | no, 401 |
| Auth surface | 13 in scope, 10 PASS, 3 EXCLUDED | none | none |
| Tool content | surface digest only, content not graded | 16 tools read and assessed | not reached |
| Findings | 0 | 1 CRITICAL (YARA, log_work) | none |
| Evidence for findings | response body required, hash over graded content | none recorded beside the match | n/a |

## What each one can say about this server

mcp-authscan: ten properties positively demonstrated, three excluded with the prerequisite named, and the tool digest recorded as not captured with the reason (no session id on initialize). The report hash 90af13a4... reproduces across two runs from the same authorization block.

Ramparts: it read 16 tool descriptions and passed them on its own tool assessments, then its YARA pre-scan flagged log_work as CRITICAL SQL injection at HIGH confidence. log_work is a decision logger. Its description mentions no query and takes no SQL. Ramparts' own record carries the rule, the severity and the confidence, and no matched text.

Cisco: could not authenticate and did not scan.

## Where each one comes out worst

mcp-authscan: it does not grade tool content at all, so a poisoned description or a secret in a prompt is invisible to it on this server.

Ramparts: a CRITICAL with no quoted evidence, and it could not read resources or prompts on a server that requires a token.

Cisco: on this target it produced nothing. With an LLM judge key it may fare differently; the API analyzer was not run.

## The point

These answer different questions. One asks whether the surface is authenticated and proves each answer with the response. The others read what the server says it does. Run against an auth-protected server, only the first one has anything to say; run against an open one, only the others read the tools. A grid with one winner is a grid with a missing column.
