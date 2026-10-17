# Cross-FUNCTION command injection: source in a helper, sink in the caller.
# OSS taint cannot connect these; the Semgrep Pro engine (--pro) can. Fires T2-CMDI under Pro.
import os
from flask import request


def _cmd():
    return request.args.get("c")


def run():
    os.system(_cmd())
