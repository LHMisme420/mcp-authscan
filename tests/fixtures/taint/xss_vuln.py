from flask import request, Markup
def page():
    return Markup(request.args.get("bio"))   # T8-XSS
