from flask import request
def read():
    fn = request.args.get("file")   # SOURCE
    return open(fn).read()           # SINK -> T3-PATH
