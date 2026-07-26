"""Regression coverage: ONE corrupt durable row must not poison the rest.

Startup recovery/restore iterate every pending ``async_delegations`` row and
deserialize a JSON payload per row. A single malformed payload (crash
mid-write, manual DB edit, schema drift) used to raise inside the loop and
abort the pass for ALL remaining rows — and because
``recover_abandoned_delegations`` shares one SQLite transaction, the escaping
exception also rolled back the rows already recovered in that pass. These run
at process start, so one bad row silently stranded every other session's
pending async-delegation results, on every boot.

Contract under test (behavior, not payload snapshots):
1. N abandoned rows where one has unreadable ``task_json`` -> all N are still
   classified ``unknown``; the bad one recovers with an empty task spec.
2. N pending completions where one has unreadable ``event_json`` -> the other
   N-1 are restored; the bad one is logged and converges to the terminal
   ``dropped`` state so it cannot re-poison the next boot.
3. A structurally-wrong (non-object) payload is treated the same way, so no
   garbage event reaches the shared completion queue.
4. A corrupt ``result_json`` degrades a status query to ``result=None``
   instead of raising.
"""

import json
import logging
import queue

import pytest

from tools import async_delegation as ad


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Point the durable store at a per-test SQLite file."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(ad, "_db_path", lambda: tmp_path / "state.db")
    yield
    ad._reset_for_tests()


def _dispatch(delegation_id, session_key="owner"):
    ad._persist_dispatch({
        "delegation_id": delegation_id,
        "session_key": session_key,
        "origin_ui_session_id": "",
        "parent_session_id": None,
        "dispatched_at": 1.0,
        "goal": f"goal for {delegation_id}",
    })


def _sql(statement, params):
    with ad._DB_LOCK, ad._connect() as conn:
        return conn.execute(statement, params).fetchall()


def _abandon(delegation_id):
    """Make the row look owned by a long-dead process."""
    _sql(
        "UPDATE async_delegations SET owner_pid=?, owner_started_at=NULL "
        "WHERE delegation_id=?",
        (99999999, delegation_id),
    )


def _complete(delegation_id, event_json, completed_at):
    _sql(
        "UPDATE async_delegations SET state='completed', completed_at=?, "
        "event_json=?, delivery_state='pending' WHERE delegation_id=?",
        (completed_at, event_json, delegation_id),
    )


def test_recovery_skips_one_unreadable_task_json_and_recovers_the_rest(caplog):
    for i in range(3):
        _dispatch(f"deleg_{i}")
        _abandon(f"deleg_{i}")
    # Row 1 is corrupt; rows 0 and 2 are fine.
    _sql(
        "UPDATE async_delegations SET task_json=? WHERE delegation_id=?",
        ("{not valid json", "deleg_1"),
    )

    with caplog.at_level(logging.WARNING, logger="tools.async_delegation"):
        assert ad.recover_abandoned_delegations() == 3

    for i in range(3):
        durable = ad.get_durable_delegation(f"deleg_{i}")
        assert durable["state"] == "unknown", f"deleg_{i} was not recovered"
        assert durable["delivery_state"] == "pending"
    assert "deleg_1" in caplog.text

    # The survivors keep their real task spec; the bad row degrades to empty.
    restored = queue.Queue()
    assert ad.restore_undelivered_completions(restored) == 3
    goals = {}
    while not restored.empty():
        evt = restored.get_nowait()
        goals[evt["delegation_id"]] = evt["goal"]
    assert goals["deleg_0"] == "goal for deleg_0"
    assert goals["deleg_2"] == "goal for deleg_2"
    assert goals["deleg_1"] == ""


@pytest.mark.parametrize(
    "bad_payload", ["{broken", '"a bare string"', "[1, 2, 3]"],
    ids=["unparseable", "non-object-string", "non-object-list"],
)
def test_restore_skips_one_corrupt_event_json_and_delivers_the_rest(
    bad_payload, caplog,
):
    for i in range(3):
        _dispatch(f"deleg_{i}")
        payload = bad_payload if i == 1 else json.dumps({
            "type": "async_delegation",
            "delegation_id": f"deleg_{i}",
            "session_key": "owner",
            "status": "completed",
            "summary": f"result {i}",
        })
        _complete(f"deleg_{i}", payload, float(i))

    target = queue.Queue()
    with caplog.at_level(logging.ERROR, logger="tools.async_delegation"):
        assert ad.restore_undelivered_completions(target) == 2

    delivered = [target.get_nowait() for _ in range(target.qsize())]
    assert [e["delegation_id"] for e in delivered] == ["deleg_0", "deleg_2"]
    assert all(e["restored"] is True for e in delivered)
    # The corrupt row is reported, never silently swallowed.
    assert "deleg_1" in caplog.text

    # ...and it converges to a terminal state, so the NEXT boot is clean and
    # does not re-log or re-abort. The survivors stay pending until delivered.
    assert ad.get_durable_delegation("deleg_1")["delivery_state"] == "dropped"
    second_boot = queue.Queue()
    assert ad.restore_undelivered_completions(second_boot) == 2


def test_corrupt_result_json_degrades_status_query_instead_of_raising():
    _dispatch("deleg_bad_result")
    _sql(
        "UPDATE async_delegations SET result_json=? WHERE delegation_id=?",
        ("{not valid json", "deleg_bad_result"),
    )

    durable = ad.get_durable_delegation("deleg_bad_result")
    assert durable is not None
    assert durable["result"] is None
    assert durable["delegation_id"] == "deleg_bad_result"
