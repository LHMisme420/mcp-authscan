import http from "node:http";
import fs from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
const MCP = process.argv[2];
const STORE = process.argv[3];
const CPORT = 9301;
const CALLBACK = "http://localhost:" + CPORT + "/callback";
let st = { info: null, toks: null, verifier: null };
try { st = JSON.parse(fs.readFileSync(STORE, "utf8")); } catch (e) { }
let pending = null;
let resolveCode = null;
const codeReady = new Promise((r) => { resolveCode = r; });
const save = () => { fs.writeFileSync(STORE, JSON.stringify(st)); };
const provider = {
get redirectUrl() { return CALLBACK; },
get clientMetadata() { return { client_name: "matrix-ts", redirect_uris: [CALLBACK], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" }; },
clientInformation() { return st.info || undefined; },
saveClientInformation(ci) { st.info = ci; save(); console.log("SAVED CLIENT", JSON.stringify(ci).slice(0, 200)); },
tokens() { console.log("TOKENS CALLED", JSON.stringify(st.toks || null).slice(0, 200)); return st.toks || undefined; },
saveTokens(t) { st.toks = { access_token: t.access_token, token_type: t.token_type, expires_in: t.expires_in, refresh_token: t.refresh_token }; save(); console.log("SAVED TOKENS", JSON.stringify(t).slice(0, 300)); },
async redirectToAuthorization(u) { pending = u.toString(); console.log("AUTHORIZE", pending.slice(0, 100)); },
saveCodeVerifier(v) { st.verifier = v; save(); },
codeVerifier() { return st.verifier; }
};
const srv = http.createServer((req, res) => {
const q = new URL(req.url, "http://localhost:" + CPORT);
console.log("CALLBACK code=" + q.searchParams.get("code") + " state=" + q.searchParams.get("state"));
const c = q.searchParams.get("code"); if (c) { resolveCode(c); }
res.writeHead(200, { "content-type": "text/plain" });
res.end("ok");
});
srv.listen(CPORT, () => console.log("LISTENING", CPORT));
const deliver = async () => {
if (!pending) { return; }
const u = pending; pending = null;
try {
const r = await fetch(u, { redirect: "manual" });
const loc = r.headers.get("location");
console.log("AUTHZ", r.status, (loc || "").slice(0, 120));
if (loc) { const r2 = await fetch(loc); console.log("REDIRECT", r2.status); }
} catch (e) { console.log("DELIVER ERR", String(e).slice(0, 150)); }
};
setInterval(deliver, 1000);
const transport = new StreamableHTTPClientTransport(new URL(MCP), { authProvider: provider });
const client = new Client({ name: "matrix-ts", version: "0.0.1" });
let client2 = null;
try {
await client.connect(transport);
console.log("CONNECTED FIRST");
} catch (e) {
console.log("FIRST ERR", String(e).slice(0, 200));
const code = await codeReady;
console.log("GOT CODE", code);
await transport.finishAuth(code);
const t2 = new StreamableHTTPClientTransport(new URL(MCP), { authProvider: provider });
client2 = new Client({ name: "matrix-ts", version: "0.0.1" });
await client2.connect(t2);
}
const live = client2 || client;
try {
const tools = await live.listTools();
console.log("RESULT tools=" + tools.tools.length);
} catch (e) { console.log("CLIENT ERR", String(e).slice(0, 400)); }
save();
srv.close();
process.exit(0);
