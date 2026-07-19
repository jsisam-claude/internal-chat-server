"""Per-user condition variables so empty-queue long-polls park instead of
spin, and queue writers can wake exactly the waiting recipient."""
import threading

class Notifier:
    """Per-user condition variables so empty-queue polls park instead of spin."""

    def __init__(self):
        self._lock = threading.Lock()
        self._conds: dict[str, threading.Condition] = {}

    def _cond(self, user: str) -> threading.Condition:
        with self._lock:
            return self._conds.setdefault(user, threading.Condition())

    def notify(self, user: str) -> None:
        c = self._cond(user)
        with c:
            c.notify_all()

    def wait(self, user: str, timeout: float) -> None:
        c = self._cond(user)
        with c:
            c.wait(timeout)

