export function make(req: any) {
  return new RegExp(req.query.pattern)   // T13-REDOS
}
