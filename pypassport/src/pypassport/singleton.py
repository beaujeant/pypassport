"""Generic Singleton base class."""

from typing import Any


class Singleton:
    """Base class that ensures only one instance is ever created per subclass."""

    # Declared (not assigned) so mypy treats it as a class attribute while
    # hasattr() still reports False until the first instance is created.
    instance: Any

    def __new__(cls) -> Any:
        if not hasattr(cls, 'instance'):
            cls.instance = super().__new__(cls)
        return cls.instance
