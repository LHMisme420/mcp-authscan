from flask import request, render_template
def page():
    name = request.args.get("name")
    return render_template("page.html", name=name)   # template is fixed; name is data -> silent
