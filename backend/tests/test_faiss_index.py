from app.search.faiss_index import FaissVectorIndex


def test_submission_faiss_build_and_incremental_id_mapping():
    index = FaissVectorIndex(dimension=3)

    assert index.rebuild(
        [
            (12, [1.0, 0.0, 0.0]),
            (27, [0.0, 1.0, 0.0]),
        ]
    )
    assert index.available
    assert index.count == 2
    assert index.search([1.0, 0.0, 0.0], 2)[0][0] == 12

    assert index.add(35, [0.0, 0.0, 1.0])
    assert index.count == 3
    assert index.search([0.0, 0.0, 1.0], 1) == [(35, 1.0)]


def test_submission_faiss_is_cold_until_rebuilt_and_invalidates_on_update():
    index = FaissVectorIndex(dimension=3)
    assert index.search([1.0, 0.0, 0.0], 1) is None
    assert index.rebuild([(12, [1.0, 0.0, 0.0])])

    assert not index.add(12, [0.0, 1.0, 0.0])
    assert not index.available
    assert index.search([1.0, 0.0, 0.0], 1) is None
