from flask import request
def q(cursor):
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + uid)   # concatenated -> T4-SQLI
