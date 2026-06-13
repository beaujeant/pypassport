"""Import-check every GUI pane under the mocked smartcard stub.

CI has no PC/SC service and no display, but it must still catch a pane that
fails to import (a bad relative import, a missing symbol, a module-level call
into pypassport). conftest installs the ``smartcard`` stub before collection, so
importing the modules exercises every top-level import and class body without
touching real hardware or opening a window.
"""

import importlib

import pytest

PANE_MODULES = [
    "epassportviewer.app",
    "epassportviewer.viewer",
    "epassportviewer.decoder",
    "epassportviewer.traffic",
    "epassportviewer.forge",
    "epassportviewer.intercept",
    "epassportviewer.comparer",
    "epassportviewer.sequencer",
    "epassportviewer.analyze",
    "epassportviewer.log",
    "epassportviewer.menu",
]


@pytest.mark.parametrize("module_name", PANE_MODULES)
def test_pane_imports_cleanly(module_name):
    module = importlib.import_module(module_name)
    assert module is not None


def test_app_exposes_main_classes():
    app = importlib.import_module("epassportviewer.app")
    # The window class and its panes are wired up at import time; a broken
    # relative import would have already raised above.
    assert hasattr(app, "EPassportViewer")
