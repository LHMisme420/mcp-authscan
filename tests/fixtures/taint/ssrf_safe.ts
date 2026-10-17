// SAFE: input passes through a named URL validator before the sink. Expect NO finding.
import { validateUrl } from "./guards"
export async function handler(req: any, res: any) {
  const target = validateUrl(req.query.url)
  const resp = await fetch(target)
  res.send(await resp.text())
}
