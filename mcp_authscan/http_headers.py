class Headers(dict):
    """Case-insensitive HTTP header mapping."""
    def __init__(self, src=()):
        super().__init__((str(k).lower(), v) for k, v in dict(src).items())
    def get(self, key, default=None):
        return super().get(str(key).lower(), default)
    def __getitem__(self, key):
        return super().__getitem__(str(key).lower())
    def __contains__(self, key):
        return super().__contains__(str(key).lower())
