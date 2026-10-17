export async function login(req: any, Users: any) {
  // req.body.user can arrive as {$ne: null} -> auth bypass. T12-NOSQLI
  return await Users.findOne({ user: req.body.user, pass: req.body.pass })
}
