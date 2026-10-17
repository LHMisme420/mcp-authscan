import pickle
from flask import request
def load():
    blob = request.get_data()
    return pickle.loads(blob)   # T7-DESER
