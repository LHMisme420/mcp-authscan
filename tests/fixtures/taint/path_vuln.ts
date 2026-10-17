import * as fs from "fs"
export function handler(req: any) {
  const f = req.query.file
  return fs.readFileSync(f)   // T3-PATH
}
