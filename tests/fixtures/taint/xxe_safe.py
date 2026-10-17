import defusedxml.ElementTree as ET
from flask import request
def parse():
    return ET.fromstring(request.get_data())   # defused parser -> silent
