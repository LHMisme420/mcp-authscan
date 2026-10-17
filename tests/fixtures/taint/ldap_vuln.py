import ldap
from flask import request
def find(conn):
    user = request.args.get("user")
    return conn.search_s("dc=x", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")   # T14-LDAP
