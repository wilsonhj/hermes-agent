"""Every SessionDB runtime read must serialize on ``self._lock``.

``SessionDB`` shares ONE ``sqlite3`` connection across threads
(``check_same_thread=False``) and makes that safe by funnelling every
statement through ``self._lock``: writes via ``_execute_write`` (lock +
``BEGIN IMMEDIATE``), reads via ``with self._lock:``.

Three readers used to bypass the lock and touch ``self._conn`` directly:

* ``get_compression_lock_holder`` — no ``try``/``except``, so a collision
  propagated ``sqlite3.ProgrammingError``/``OperationalError`` to the caller.
* ``get_handoff_state`` — swallowed the error and returned ``None``.
* ``list_pending_handoffs`` — swallowed the error and returned ``[]``.

The last one is the dangerous one: it is polled by the gateway's handoff
watcher on a background thread while the agent thread writes on the same
connection, and a silent ``[]`` means a pending handoff is never picked up
(the CLI just poll-waits until it gives up).

These are contract tests, not timing races. The lock-held tests hold
``db._lock`` from the main thread and assert the reader *blocks* — which is
true if and only if the reader acquires the lock. Before the fix each reader
returned immediately.
"""

import threading

import pytest

from hermes_state import SessionDB


BLOCKED_TIMEOUT_S = 0.5
COMPLETE_TIMEOUT_S = 10.0


@pytest.fixture
def db(tmp_path):
    d = SessionDB(db_path=tmp_path / "state.db")
    yield d
    try:
        d.close()
    except Exception:
        pass


@pytest.fixture
def session_id(db):
    sid = "sess-handoff-1"
    db.create_session(sid, "cli")
    return sid


def _assert_blocks_until_db_lock_released(db, call):
    """Run *call* on a worker thread while holding ``db._lock``.

    Asserts the call makes no progress until the lock is released, then
    returns its result. A reader that touches ``self._conn`` without the
    lock finishes during the held window and fails the first assertion.
    """
    entered = threading.Event()
    finished = threading.Event()
    box = {}

    def _worker():
        entered.set()
        try:
            box["result"] = call()
        except BaseException as exc:  # pragma: no cover - surfaced below
            box["error"] = exc
        finally:
            finished.set()

    t = threading.Thread(target=_worker, daemon=True)
    with db._lock:
        t.start()
        assert entered.wait(COMPLETE_TIMEOUT_S), "worker thread never started"
        assert not finished.wait(BLOCKED_TIMEOUT_S), (
            "read completed while the SessionDB lock was held — it is "
            "touching the shared sqlite3 connection without serializing"
        )
    assert finished.wait(COMPLETE_TIMEOUT_S), "read never completed after unlock"
    t.join(COMPLETE_TIMEOUT_S)
    if "error" in box:
        raise box["error"]
    return box["result"]


class TestReadsSerializeOnDbLock:
    def test_list_pending_handoffs_takes_the_lock(self, db, session_id):
        db.request_handoff(session_id, "telegram")

        result = _assert_blocks_until_db_lock_released(db, db.list_pending_handoffs)

        assert [r["id"] for r in result] == [session_id]

    def test_get_handoff_state_takes_the_lock(self, db, session_id):
        db.request_handoff(session_id, "telegram")

        result = _assert_blocks_until_db_lock_released(
            db, lambda: db.get_handoff_state(session_id)
        )

        assert result == {
            "state": "pending",
            "platform": "telegram",
            "error": None,
        }

    def test_get_compression_lock_holder_takes_the_lock(self, db, session_id):
        assert db.try_acquire_compression_lock(session_id, "holder-a")

        result = _assert_blocks_until_db_lock_released(
            db, lambda: db.get_compression_lock_holder(session_id)
        )

        assert result == "holder-a"


class TestConcurrentReadsDuringWrites:
    def test_handoff_reads_never_fail_or_silently_empty_under_writes(
        self, db, session_id
    ):
        """The gateway's handoff-watcher scenario: a background thread polls
        the handoff tables while the agent thread writes on the same
        connection. No exception, and never a silent empty result."""
        db.request_handoff(session_id, "telegram")
        assert db.try_acquire_compression_lock(session_id, "holder-a")

        errors = []
        empty_results = []
        stop = threading.Event()

        def _reader():
            while not stop.is_set():
                try:
                    if not db.list_pending_handoffs():
                        empty_results.append("list_pending_handoffs")
                    if db.get_handoff_state(session_id) is None:
                        empty_results.append("get_handoff_state")
                    if db.get_compression_lock_holder(session_id) is None:
                        empty_results.append("get_compression_lock_holder")
                except BaseException as exc:
                    errors.append(exc)
                    return

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        try:
            for i in range(200):
                db.set_meta(f"concurrency-probe-{i}", str(i))
        finally:
            stop.set()
            t.join(COMPLETE_TIMEOUT_S)

        assert not errors, f"reads raised under concurrent writes: {errors!r}"
        assert not empty_results, (
            "reads silently returned empty under concurrent writes: "
            f"{sorted(set(empty_results))}"
        )
