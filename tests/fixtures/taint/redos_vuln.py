import re
from flask import request
def search():
    pat = request.args.get("q")
    return re.compile(pat)   # T13-REDOS
