import queue
from types import SimpleNamespace

from epassportviewer.traffic import TrafficPane


class FakeTree:
    def exists(self, _iid):
        return False


def test_new_transaction_is_rendered_from_main_thread_drain():
    tx = object()
    scheduled = []
    appended = []

    pane = TrafficPane.__new__(TrafficPane)
    pane._history = [tx]
    pane._pending_transactions = queue.Queue()
    pane._tree = FakeTree()
    pane.root = SimpleNamespace(after=lambda delay, callback: scheduled.append((delay, callback)))
    pane._append_transaction = lambda idx, item: appended.append((idx, item))
    pane._rebuild_tree = lambda: None

    pane._on_new_transaction(tx)
    assert appended == []

    pane._drain_pending_transactions()
    assert appended == [(0, tx)]
    assert scheduled == [(100, pane._drain_pending_transactions)]
