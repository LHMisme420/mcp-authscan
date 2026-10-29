class Headers(dict):
    """Case-insensitive HTTP header mapping."""
    def init(self, src=()):
        super().init((str(k).lower(), v) for k, v in dict(src).items())
    def get(self, key, default=None):
        return super().get(str(key).lower(), default)
    def getitem(self, key):
        return super().getitem(str(key).lower())
    def contains(self, key):
        return super().contains(str(key).lower())
