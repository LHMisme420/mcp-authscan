from flask import request, redirect
def go():
    return redirect(request.args.get("next"))   # T9-REDIR
