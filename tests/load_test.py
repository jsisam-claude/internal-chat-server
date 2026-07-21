#!/usr/bin/env python3
"""Concurrency LOAD test — deliberately NOT named test_*.py, so the default
`python3 -m unittest discover` (the fast unit pass) skips it. Run explicitly:

    python3 tests/load_test.py

It starts the real server and drives it under live concurrency to verify the
availability controls actually hold (things unit tests can't observe):
  1. the accept-side connection cap bounds live threads under a socket flood
     (incl. slowloris clients that open and never complete a request)
  2. the per-user parked-poll cap holds and its counter doesn't leak
  3. one user over their poll cap does NOT stall another user's polls
     (the poll-lock regression)

Exits non-zero if any check fails, so it is usable as a CI gate.
"""
import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import chatserver
from internalchat.config import MAX_POLLS_PER_USER

CONN_CAP = 20               # shrink caps so the test is fast and unambiguous
failures = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="load-")
    store = chatserver.Store(tmp, iters=500)
    for u in ("alice", "bob"):
        store.add_user(u, "pw", must_change=False)
    httpd, router, api = chatserver.build_server(store, "127.0.0.1", 0)
    httpd._conn_slots = threading.BoundedSemaphore(CONN_CAP)
    api.login_ip_limiter.limit = 10 ** 9
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    tok = {u: api.store.new_session(u) for u in ("alice", "bob")}

    def workers():
        return sum(1 for t in threading.enumerate()
                   if t.daemon and t is not threading.current_thread()
                   and t.name not in ("router", "janitor", "MainThread"))

    def call(method, path, token, timeout=30):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request(method, path, headers={"Authorization": "Bearer " + token})
        r = c.getresponse(); r.read(); c.close()
        return r.status

    print(f"TEST 1: connection cap ({CONN_CAP}) under a 100-socket slowloris flood")
    socks = []
    for _ in range(100):
        try:
            socks.append(socket.create_connection(("127.0.0.1", port), timeout=2))
        except OSError:
            pass
    time.sleep(1.5)
    wt = workers()
    check("threads bounded, not ~100", wt <= CONN_CAP + 5, f"{wt} worker threads")
    for s in socks:
        s.close()
    time.sleep(1.5)
    check("slots released after close", workers() <= 2, f"{workers()} threads")

    print(f"TEST 2: per-user parked-poll cap ({MAX_POLLS_PER_USER})")
    durations = []

    def park():
        t0 = time.time()
        call("GET", "/api/messages?wait=3", tok["alice"])
        durations.append(time.time() - t0)

    ts = [threading.Thread(target=park) for _ in range(MAX_POLLS_PER_USER + 5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    parked = sum(1 for d in durations if d > 2.0)
    fast = sum(1 for d in durations if d <= 2.0)
    check("at most cap parked, excess capped",
          parked <= MAX_POLLS_PER_USER and fast >= 5,
          f"{parked} parked, {fast} fast")
    with api._poll_lock:
        leaked = api._polls.get("alice", 0)
    check("parked-poll counter did not leak", leaked == 0, f"counter={leaked}")

    print("TEST 3: over-cap user must not stall another user (poll-lock fix)")
    for _ in range(MAX_POLLS_PER_USER + 3):
        threading.Thread(
            target=lambda: call("GET", "/api/messages?wait=8", tok["alice"], 12),
            daemon=True).start()
    time.sleep(0.5)
    t0 = time.time()
    call("GET", "/api/messages?wait=0", tok["bob"])
    dt = time.time() - t0
    check("bob's poll not blocked behind alice's over-cap sleep",
          dt < 0.4, f"{dt * 1000:.0f}ms")

    httpd.shutdown()
    print()
    if failures:
        print(f"LOAD TEST FAILED: {failures}")
        return 1
    print("LOAD TEST: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
