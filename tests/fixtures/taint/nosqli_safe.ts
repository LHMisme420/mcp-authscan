export async function get(req: any, Users: any) {
  return await Users.findOne({ _id: String(req.params.id) })   // cast to primitive -> silent
}
