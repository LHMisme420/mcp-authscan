export function run(req: any) {
  const code = req.body.code
  return eval(code)   // T6-EVAL
}
