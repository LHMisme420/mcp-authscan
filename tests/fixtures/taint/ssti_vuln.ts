import * as ejs from "ejs"
export function page(req: any) {
  const t = req.query.tpl
  return ejs.render(t, {})   // T5-SSTI
}
