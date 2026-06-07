"""Generic Singleton base class."""

from typing import Any


class Singleton:
    """Base class that ensures only one instance is ever created per subclass."""

    def __new__(cls) -> Any:
        if not hasattr(cls, 'instance'):
            cls.instance = super().__new__(cls)
        return cls.instance
