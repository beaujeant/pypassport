from epassportviewer.viewer import _sod_integrity_states, _sod_listed_dgs


def test_sod_listed_dgs_normalises_and_sorts_hash_entries():
    sod = {"dg_hashes": {14: "AA", "DG2": "BB", 1: "CC", "invalid": "DD"}}

    assert _sod_listed_dgs(sod) == ["DG1", "DG2", "DG14"]


def test_sod_integrity_states_marks_missing_results_as_unknown():
    sod = {"dg_hashes": {1: "AA", 2: "BB", 14: "CC"}}

    assert _sod_integrity_states(sod, {"DG1": True, "DG2": False}) == [
        ("DG1", "ok"),
        ("DG2", "mismatch"),
        ("DG14", "unknown"),
    ]
