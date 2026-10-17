from lxml import etree
from flask import request
def q(tree):
    name = request.args.get("name")
    return tree.xpath("//user[@name='" + name + "']")   # T15-XPATH
