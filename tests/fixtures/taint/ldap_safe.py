import ldap
from ldap.filter import escape_filter_chars
from flask import request
def find(conn):
    user = escape_filter_chars(request.args.get("user"))
    return conn.search_s("dc=x", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")   # escaped -> silent
