export function go(req: any, res: any) {
  return res.redirect(req.query.next)   // T9-REDIR
}
