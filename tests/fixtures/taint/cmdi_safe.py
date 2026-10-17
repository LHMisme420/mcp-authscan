import shlex
import subprocess
from flask import request

def run():
    name = request.args.get("host")
    safe = shlex.quote(name)                        # sanitizer clears taint
    subprocess.run("ping -c1 " + safe, shell=True)  # NO finding
