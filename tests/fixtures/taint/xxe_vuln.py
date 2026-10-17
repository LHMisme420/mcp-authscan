from lxml import etree
from flask import request
def parse():
    data = request.get_data()
    return etree.fromstring(data)   # lxml resolves entities -> T10-XXE
