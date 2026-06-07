class Logger:
    def __init__(self, name):
        self._listeners = []
        self._name = name

    def register(self, fct):
        """the listener gives the method it wants as callback"""
        self._listeners.append(fct)

    def unregister(self, listener):
        self._listeners.remove(listener)

    def log(self, msg, name=None):
        if name is not None:
            n = name
        else:
            n = self._name

        for listenerFct in self._listeners:
            listenerFct(n, msg)
