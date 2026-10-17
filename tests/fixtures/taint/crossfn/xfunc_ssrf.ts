// Cross-FUNCTION SSRF: source in one function, sink in another. OSS taint cannot
// connect these; the Semgrep Pro engine (--pro) can. Expected to fire T1-SSRF under Pro.
function getTarget(req: any): string {
  return req.query.callback
}
export async function handler(req: any) {
  const target = getTarget(req)
  return await fetch(target)
}
