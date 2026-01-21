class classproperty:
    """
    Decorator that mimics chaining @classmethod and @property for a getter. From:
    https://stackoverflow.com/questions/76249636/class-properties-in-python-3-11
    """
    def __init__(self, func):
        self.fget = func

    def __get__(self, instance, owner):
        return self.fget(owner)
