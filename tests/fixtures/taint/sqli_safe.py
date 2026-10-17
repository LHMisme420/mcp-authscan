from flask import request
def q(cursor):
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))   # parameterized -> NO finding
