import threading

import pytest

from epassportviewer.operation import CardBusy, OperationCoordinator


def test_coordinator_allows_nested_work_on_the_owner_thread():
    events = []
    coordinator = OperationCoordinator(lambda kind, value: events.append((kind, value)))

    with coordinator.operation("outer"):
        with coordinator.operation("inner"):
            assert coordinator.owner == "inner"
        assert coordinator.owner == "outer"

    assert coordinator.owner == ""
    assert events == [
        ("busy", "outer"),
        ("busy", "inner"),
        ("busy", "outer"),
        ("busy", ""),
    ]


def test_coordinator_rejects_an_interleaved_card_workflow():
    coordinator = OperationCoordinator(lambda *_args: None)
    entered = threading.Event()
    release = threading.Event()

    def owner():
        with coordinator.operation("long operation"):
            entered.set()
            release.wait(2)

    thread = threading.Thread(target=owner)
    thread.start()
    assert entered.wait(1)
    try:
        with pytest.raises(CardBusy, match="long operation"):
            with coordinator.operation("other operation"):
                pass
    finally:
        release.set()
        thread.join(2)

    assert not thread.is_alive()
