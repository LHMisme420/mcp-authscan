import yaml
from flask import request
def load():
    blob = request.get_data()
    return yaml.safe_load(blob)   # safe loader -> silent
