// VULN: request input flows straight into fetch(), no host allowlist. Expect T1-SSRF.
export async function handler(req: any, res: any) {
  const target = req.query.url
  const resp = await fetch(target)
  res.send(await resp.text())
}
