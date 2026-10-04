from __future__ import annotations

import traceback

import pytest

from secure_agent_runtime.examples.notes import NotesApp, build_runtime
from secure_agent_runtime.store import Store


class Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture(autouse=True)
def every_store_is_closed(monkeypatch):
    """Ownership rule: whoever creates a Store closes it. Fails a test that leaves one open
    (a leaked SQLite connection), naming where it was created. Autouse, so it is torn down
    after the test's other fixtures, including ``store``."""
    created: list[tuple[Store, str]] = []
    real_init = Store.__init__

    def tracking_init(self, *a, **kw):
        real_init(self, *a, **kw)
        created.append((self, "".join(traceback.format_stack(limit=6)[:-1])))

    monkeypatch.setattr(Store, "__init__", tracking_init)
    yield
    leaked = [where for s, where in created if not s.closed]
    for s, _ in created:
        s.close()
    assert not leaked, f"{len(leaked)} Store(s) left open; created at:\n" + "\n---\n".join(leaked)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(clock: Clock) -> Store:
    s = Store(now=clock)
    yield s
    s.close()


@pytest.fixture
def app() -> NotesApp:
    return NotesApp({"todo": "buy milk"})


@pytest.fixture
def rt(store: Store, app: NotesApp):
    runtime, _ = build_runtime(store, app, timeout_s=2.0, approval_ttl_s=600)
    return runtime


def execution_events(store: Store) -> int:
    return len(store.events(kind="call.executing"))


def cred(rt, who: str, **kw) -> str:
    """A one-time approval credential for ``who`` (the demo authenticator stands in for the
    host's real identity system)."""
    return rt.authenticator.issue(who, **kw)
