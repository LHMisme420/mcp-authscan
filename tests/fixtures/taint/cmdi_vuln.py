import os
from flask import request

def run():
    name = request.args.get("host")   # SOURCE
    os.system("ping -c1 " + name)      # SINK (shell) -> T2-CMDI
