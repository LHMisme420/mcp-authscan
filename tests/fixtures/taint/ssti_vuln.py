from flask import request, render_template_string
def page():
    name = request.args.get("name")
    return render_template_string("Hello " + name)   # T5-SSTI
