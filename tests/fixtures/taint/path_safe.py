import os
from flask import request
def read():
    fn = os.path.basename(request.args.get("file"))  # sanitizer
    return open(fn).read()                            # NO finding
