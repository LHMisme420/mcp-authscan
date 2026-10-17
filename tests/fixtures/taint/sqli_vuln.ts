export async function handler(req: any, db: any) {
  const id = req.query.id
  return await db.query(`SELECT * FROM users WHERE id = ${id}`)   // interpolated -> T4-SQLI
}
