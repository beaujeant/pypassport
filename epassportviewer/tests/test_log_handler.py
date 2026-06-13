"""Unit tests for the single GUI logging bridge (GuiLogHandler).

The handler is the one place stdlib log records become text the Log pane shows.
These checks lock in that it buffers formatted records for the backlog view and
keeps working with no window attached — which is exactly the headless path CI
runs.
"""

import logging

from epassportviewer.log import GuiLogHandler, LOG_FORMAT


def _make_logger(handler):
    logger = logging.getLogger("test.gui.log.handler")
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger


def test_handler_buffers_formatted_records():
    handler = GuiLogHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger = _make_logger(handler)

    logger.info("hello world")
    logger.warning("careful now")

    assert len(handler.records) == 2
    # The configured format puts the level name in the line.
    assert "INFO - hello world" in handler.records[0]
    assert "WARNING - careful now" in handler.records[1]


def test_handler_buffers_without_a_window_attached():
    handler = GuiLogHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger = _make_logger(handler)

    # No widget attached: emit must not raise and must still record.
    assert handler._widget is None
    logger.error("boom")
    assert handler.records[-1].endswith("ERROR - boom")


def test_detach_only_clears_the_matching_widget():
    handler = GuiLogHandler()
    sentinel = object()
    other = object()

    handler.attach(sentinel)
    handler.detach(other)
    assert handler._widget is sentinel

    handler.detach(sentinel)
    assert handler._widget is None
