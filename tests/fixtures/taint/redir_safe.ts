import { safeRedirect } from "./guards"
export function go(req: any, res: any) {
  return res.redirect(safeRedirect(req.query.next))   // sanitizer returns safe path -> silent
}
