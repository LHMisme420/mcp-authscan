import re
from flask import request
def search():
    pat = re.escape(request.args.get("q"))
    return re.compile(pat)   # escaped -> silent
