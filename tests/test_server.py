"""End-to-end tests: run the real server over HTTP and drive the full
WhatsApp-like flow — send → queue → dequeue → arrival flag → viewed flag →
groups → attachments — plus the security properties around uploads."""
import http.client
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import chatserver


class ChatServerTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="chat-test-")
        cls.store = chatserver.Store(cls.tmp, iters=1000)  # fast PBKDF2 for tests
        for u in ("alice", "bob", "carol"):
            cls.store.add_user(u, "pw-" + u, must_change=False)
        cls.httpd, cls.router, cls.api = chatserver.build_server(
            cls.store, "127.0.0.1", 0)
        # every test logs in from 127.0.0.1, so the per-IP login cap (a real
        # production defense) would otherwise trip mid-suite; lift it for tests.
        cls.api.login_ip_limiter.limit = 1_000_000
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.tokens = {u: cls.login(u, "pw-" + u)["token"]
                      for u in ("alice", "bob", "carol")}

    @classmethod
    def tearDownClass(cls):
        cls.router.stopping.set()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- helpers -----------------------------------------------------------
    @classmethod
    def req(cls, method, path, user=None, body=None, headers=None, raw=False):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=40)
        hdrs = dict(headers or {})
        if user:
            hdrs["Authorization"] = "Bearer " + cls.tokens[user]
        data = None
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif body is not None:
            data = body
        conn.request(method, path, data, hdrs)
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        if raw:
            return r, payload
        return r.status, (json.loads(payload) if payload else None)

    @classmethod
    def login(cls, user, password):
        status, body = cls.req("POST", "/api/login",
                               body={"user": user, "password": password})
        assert status == 200, body
        return body

    def send_msg(self, frm, text, to=None, gid=None, files=None):
        body = {"text": text, "nonce": "n-" + os.urandom(8).hex()}
        if to:
            body["to"] = to
        if gid:
            body["gid"] = gid
        if files:
            body["files"] = files
        status, resp = self.req("POST", "/api/messages", user=frm, body=body)
        self.assertEqual(status, 200, resp)
        return resp

    def poll(self, user, wait=10):
        status, resp = self.req("GET", f"/api/messages?wait={wait}", user=user)
        self.assertEqual(status, 200, resp)
        return resp["queue"]

    def confirm(self, user, entries):
        status, resp = self.req(
            "POST", "/api/message/dequeue/read/" + ",".join(entries), user=user)
        self.assertEqual(status, 200, resp)
        return resp

    def poll_until(self, user, entry_pred, tries=20):
        """Poll until an entry matching the predicate shows up (the long-poll
        returns as soon as the queue is non-empty, which may be before the
        router has routed the message this test just sent)."""
        for _ in range(tries):
            q = self.poll(user, wait=1)
            hits = [e for e in q if entry_pred(e)]
            if hits:
                return hits[0]
        self.fail(f"queue entry never arrived for {user}")

    # ---- tests ---------------------------------------------------------------
    def test_01_dm_full_tick_flow(self):
        sent = self.send_msg("alice", "hi bob", to="bob")
        mid, gid = sent["id"], sent["gid"]
        self.assertEqual(gid, "d-alice-bob")

        # bob's queue gets the message entry (long-poll picks up the router)
        q = self.poll("bob")
        entry = next(e for e in q if e["id"] == mid)
        self.assertEqual(entry["kind"], "msg")
        self.assertEqual(entry["gid"], gid)

        # peek: repeatable, no state change
        for _ in range(2):
            status, msg = self.req("GET", f"/api/message/dequeue/{mid}", user="bob")
            self.assertEqual(status, 200, msg)
            self.assertEqual(msg["text"], "hi bob")
            self.assertEqual(msg["from"], "alice")
            self.assertEqual(msg["deliveredto"], {})

        # confirm: symlink gone, arrival marker exists on disk
        self.assertEqual(self.confirm("bob", [mid])["confirmed"], 1)
        self.assertEqual([e for e in self.poll("bob", wait=0)
                          if e["id"] == mid and e["kind"] == "msg"], [])
        mdir = self.store.msg_dir(gid, mid)
        self.assertTrue((mdir / "deliveredto" / "bob").is_file())
        self.assertFalse((self.store.queue_dir("bob") / mid).exists())

        # alice receives the delivered flag event as a queue entry
        q = self.poll("alice")
        dev = next(e for e in q if e["entry"] == f"{mid}~d~bob")
        self.assertEqual((dev["kind"], dev["user"]), ("delivered", "bob"))
        self.confirm("alice", [dev["entry"]])

        # bob views -> readby marker -> alice gets the read flag event
        status, resp = self.req("POST", "/api/message/viewed", user="bob",
                                body={"gid": gid, "ids": [mid]})
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["marked"], 1)
        self.assertTrue((mdir / "readby" / "bob").is_file())
        q = self.poll("alice")
        red = next(e for e in q if e["entry"] == f"{mid}~r~bob")
        self.assertEqual(red["kind"], "read")
        self.confirm("alice", [red["entry"]])

        # history shows the flags; state endpoint agrees
        status, hist = self.req("GET", f"/api/groups/{gid}/messages", user="alice")
        self.assertEqual(status, 200)
        m = next(m for m in hist["messages"] if m["id"] == mid)
        self.assertIn("bob", m["deliveredto"])
        self.assertIn("bob", m["readby"])
        status, st = self.req("GET", f"/api/message/state/{gid}/{mid}", user="alice")
        self.assertEqual(status, 200)
        self.assertIn("bob", st["readby"])

    def test_02_send_dedup_by_nonce(self):
        body = {"to": "bob", "text": "once only", "nonce": "fixed-nonce-123"}
        _, first = self.req("POST", "/api/messages", user="alice", body=body)
        _, second = self.req("POST", "/api/messages", user="alice", body=body)
        self.assertEqual(first["id"], second["id"])

    def test_03_group_flow(self):
        status, g = self.req("POST", "/api/groups", user="alice",
                             body={"name": "eng", "members": ["bob", "carol"]})
        self.assertEqual(status, 200, g)
        gid = g["gid"]
        self.assertEqual(g["members"], ["alice", "bob", "carol"])

        mid = self.send_msg("alice", "hello team", gid=gid)["id"]
        for u in ("bob", "carol"):
            self.poll_until(u, lambda e: e["id"] == mid and e["kind"] == "msg")
            self.confirm(u, [mid])
        status, st = self.req("GET", f"/api/message/state/{gid}/{mid}", user="alice")
        self.assertEqual(sorted(st["deliveredto"]), ["bob", "carol"])

        # group list shows the conversation with a last-message preview
        status, groups = self.req("GET", "/api/groups", user="carol")
        entry = next(x for x in groups["groups"] if x["gid"] == gid)
        self.assertEqual(entry["name"], "eng")
        self.assertEqual(entry["last"]["text"], "hello team")

        # sender never receives their own message — only flag events for it
        q = self.poll("alice", wait=0)
        self.assertEqual([e for e in q if e["id"] == mid and e["kind"] == "msg"], [])
        self.assertEqual(sorted(e["user"] for e in q
                                if e["id"] == mid and e["kind"] == "delivered"),
                         ["bob", "carol"])
        self.confirm("alice", [e["entry"] for e in q if e["id"] == mid])

    def test_04_attachments_inert_and_authorized(self):
        payload = b"\x7fELF" + os.urandom(256)  # "executable" content
        status, up = self.req("POST", "/api/files", user="alice", body=payload,
                              headers={"X-File-Name": "../../evil.sh"})
        self.assertEqual(status, 200, up)
        self.assertEqual(up["name"], "evil.sh")  # path bits stripped

        sent = self.send_msg("alice", "see file", to="bob", files=[up["file_id"]])
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("bob", lambda e: e["id"] == mid)
        _, msg = self.req("GET", f"/api/message/dequeue/{mid}", user="bob")
        att = msg["attachments"][0]
        self.assertEqual((att["n"], att["name"], att["size"]),
                         (1, "evil.sh", len(payload)))

        # on disk: ordinal name, 0600, not executable, nothing named "evil"
        blob = self.store.msg_dir(gid, mid) / "attachments" / "1"
        self.assertTrue(blob.is_file())
        mode = stat.S_IMODE(blob.stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertFalse(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        for root, dirs, files in os.walk(self.tmp):
            for n in dirs + files:
                self.assertNotIn("evil", n, f"upload name leaked into path: {root}/{n}")

        # download: exact bytes, forced-download headers
        r, data = self.req("GET", f"/api/attachments/{gid}/{mid}/1",
                           user="bob", raw=True)
        self.assertEqual(r.status, 200)
        self.assertEqual(data, payload)
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")

        # non-member: denied
        status, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1", user="carol")
        self.assertEqual(status, 403)
        self.confirm("bob", [mid])

    def test_05_authz_and_validation(self):
        # anonymous and garbage tokens
        status, _ = self.req("GET", "/api/messages")
        self.assertEqual(status, 401)
        status, _ = self.req("GET", "/api/messages",
                             headers={"Authorization": "Bearer alice:nope"})
        self.assertEqual(status, 401)

        # carol can't read alice+bob's DM
        status, _ = self.req("GET", "/api/groups/d-alice-bob/messages", user="carol")
        self.assertEqual(status, 403)

        # malformed ids are rejected before touching the filesystem
        for path in ("/api/message/dequeue/zzz",
                     "/api/message/state/d-alice-bob/1234",
                     "/api/attachments/no%20group/123/1",
                     "/api/groups/..%2f..%2fusers/messages"):
            status, _ = self.req("GET", path, user="alice")
            self.assertIn(status, (400, 404), path)

        # bad login + per-user rate limiting (throwaway user so this doesn't
        # leave a shared account's login limiter saturated for later tests)
        seen = set()
        for i in range(12):
            status, _ = self.req("POST", "/api/login",
                                 body={"user": "ratelimitprobe",
                                       "password": "wrong"})
            seen.add(status)
        self.assertEqual(status, 429)
        self.assertIn(401, seen)  # first attempts are auth failures, not 429

        # messaging yourself or unknown users
        status, _ = self.req("POST", "/api/messages", user="alice",
                             body={"to": "alice", "text": "x", "nonce": "n" * 12})
        self.assertEqual(status, 400)
        status, _ = self.req("POST", "/api/messages", user="alice",
                             body={"to": "mallory", "text": "x", "nonce": "n" * 12})
        self.assertEqual(status, 404)

    def test_06_history_pagination(self):
        gid = None
        mids = []
        for i in range(5):
            sent = self.send_msg("alice", f"pg {i}", to="carol")
            gid, _ = sent["gid"], mids.append(sent["id"])
        for m in mids:      # wait until ALL are actually routed, not just one
            self.poll_until("carol", lambda e, m=m: e["id"] == m)
        status, page1 = self.req(
            "GET", f"/api/groups/{gid}/messages?limit=3", user="alice")
        self.assertEqual(len(page1["messages"]), 3)
        oldest = page1["messages"][-1]["id"]
        status, page2 = self.req(
            "GET", f"/api/groups/{gid}/messages?limit=50&before={oldest}",
            user="alice")
        got = {m["id"] for m in page1["messages"]} | {m["id"] for m in page2["messages"]}
        self.assertTrue(set(mids) <= got)
        self.assertEqual(len(got & {m["id"] for m in page2["messages"]}
                         & {m["id"] for m in page1["messages"]}), 0)

    def test_07_password_change_and_logout(self):
        self.store.add_user("dave", "pw-dave-initial")  # must_change defaults True
        resp = self.login("dave", "pw-dave-initial")
        self.assertTrue(resp["must_change"])
        tok = resp["token"]
        status, _ = self.req("POST", "/api/password",
                             headers={"Authorization": "Bearer " + tok},
                             body={"old": "pw-dave-initial", "new": "pw-dave-new-1"})
        self.assertEqual(status, 200)
        self.assertFalse(self.login("dave", "pw-dave-new-1")["must_change"])
        status, _ = self.req("POST", "/api/logout",
                             headers={"Authorization": "Bearer " + tok})
        self.assertEqual(status, 200)
        status, _ = self.req("GET", "/api/messages",
                             headers={"Authorization": "Bearer " + tok})
        self.assertEqual(status, 401)

    def test_08_password_change_kills_other_sessions(self):
        self.store.add_user("erin", "pw-erin-first", must_change=False)
        tok1 = self.login("erin", "pw-erin-first")["token"]
        tok2 = self.login("erin", "pw-erin-first")["token"]
        status, _ = self.req("POST", "/api/password",
                             headers={"Authorization": "Bearer " + tok1},
                             body={"old": "pw-erin-first", "new": "pw-erin-second"})
        self.assertEqual(status, 200)
        status, _ = self.req("GET", "/api/messages?wait=0",
                             headers={"Authorization": "Bearer " + tok1})
        self.assertEqual(status, 200)  # the changing session survives
        status, _ = self.req("GET", "/api/messages?wait=0",
                             headers={"Authorization": "Bearer " + tok2})
        self.assertEqual(status, 401)  # every other session is dead

    def test_09_join_time_bounds_history(self):
        import time as _t
        status, g = self.req("POST", "/api/groups", user="alice",
                             body={"name": "hist", "members": ["bob"]})
        gid = g["gid"]
        old = self.send_msg("alice", "before carol", gid=gid)["id"]
        _t.sleep(0.05)  # join marker mtime must land after the old message
        status, _ = self.req("POST", f"/api/groups/{gid}/members", user="alice",
                             body={"add": ["carol"]})
        self.assertEqual(status, 200)
        _t.sleep(0.05)
        new = self.send_msg("alice", "after carol", gid=gid)["id"]
        self.poll_until("carol", lambda e: e["id"] == new)

        _, hist = self.req("GET", f"/api/groups/{gid}/messages", user="carol")
        ids = {m["id"] for m in hist["messages"]}
        self.assertNotIn(old, ids)   # pre-join history is invisible
        self.assertIn(new, ids)
        _, hist = self.req("GET", f"/api/groups/{gid}/messages", user="bob")
        self.assertLessEqual({old, new},
                             {m["id"] for m in hist["messages"]})  # bob sees all
        _, groups = self.req("GET", "/api/groups", user="carol")
        entry = next(x for x in groups["groups"] if x["gid"] == gid)
        self.assertEqual(entry["last"]["id"], new)

    def test_10_leaving_sweeps_queue_and_access(self):
        status, g = self.req("POST", "/api/groups", user="alice",
                             body={"name": "leavers", "members": ["bob", "carol"]})
        gid = g["gid"]
        mid = self.send_msg("alice", "carol never reads this", gid=gid)["id"]
        self.poll_until("carol", lambda e: e["id"] == mid)  # queued, unconfirmed
        status, _ = self.req("POST", f"/api/groups/{gid}/members", user="carol",
                             body={"remove": ["carol"]})
        self.assertEqual(status, 200)
        self.assertEqual([e for e in self.poll("carol", wait=0)
                          if e["gid"] == gid], [])          # queue swept
        status, _ = self.req("GET", f"/api/groups/{gid}/messages", user="carol")
        self.assertEqual(status, 403)                       # access gone
        self.poll_until("bob", lambda e: e["id"] == mid)
        self.confirm("bob", [mid])

    def test_11_janitor_prunes_dangling_queue_links(self):
        import shutil as _sh
        mid = self.send_msg("alice", "will be archived", to="carol")["id"]
        self.poll_until("carol", lambda e: e["id"] == mid)  # symlink exists
        mdir = self.store.msg_dir("d-alice-carol", mid)
        _sh.rmtree(mdir)  # simulate retention archiving the day folder
        chatserver.Janitor(self.store).clean()
        self.assertFalse((self.store.queue_dir("carol") / mid).exists())

    def drain_events(self, user, gid, want, tries=20):
        """Dequeue system announcements for a group until `want` appears."""
        events = []
        for _ in range(tries):
            for e in self.poll(user, wait=1):
                if e["gid"] != gid or e["kind"] != "msg":
                    continue
                _, m = self.req("GET", f"/api/message/dequeue/{e['id']}", user=user)
                events.append(m.get("system", {}).get("event"))
                self.confirm(user, [e["entry"]])
            if want in events:
                return events
        self.fail(f"never saw {want!r} for {user}, got {events}")

    def test_12_group_lifecycle_announced_in_band(self):
        status, g = self.req("POST", "/api/groups", user="alice",
                             body={"name": "lifecycle", "members": ["bob"]})
        gid = g["gid"]

        # bob learns the group exists from his queue, then resolves the gid
        self.drain_events("bob", gid, "created")
        status, info = self.req("GET", f"/api/groups/{gid}", user="bob")
        self.assertEqual(status, 200)
        self.assertEqual((info["name"], info["members"]),
                         ("lifecycle", ["alice", "bob"]))

        # adding carol announces the join to carol herself (and to bob)
        status, _ = self.req("POST", f"/api/groups/{gid}/members", user="alice",
                             body={"add": ["carol"]})
        self.assertEqual(status, 200)
        self.drain_events("carol", gid, "join")
        self.drain_events("bob", gid, "join")

        # carol leaving is announced to those who remain, not to carol
        status, _ = self.req("POST", f"/api/groups/{gid}/members", user="carol",
                             body={"remove": ["carol"]})
        self.assertEqual(status, 200)
        self.drain_events("bob", gid, "leave")
        self.assertEqual([e for e in self.poll("carol", wait=0)
                          if e["gid"] == gid], [])

        # announcements never generate ticks back to anyone
        self.assertEqual([e for e in self.poll("alice", wait=0)
                          if e["gid"] == gid and e["kind"] != "msg"], [])

    def test_13_undeliverable_message_bounces_to_sender(self):
        # bypass the API's membership check to simulate a message that
        # becomes unroutable between accept and route
        mid = self.store.spool_message("alice", "g-deadbeef00", "boom",
                                       [], "bounce-nonce-01")
        self.router.wake.set()
        ev = self.poll_until("alice",
                             lambda e: e["kind"] == "failed" and e["id"] == mid)
        self.assertEqual(ev["user"], "server")
        self.confirm("alice", [ev["entry"]])
        self.assertTrue((self.store.root / "rejected" / mid).is_dir())

    def test_14_admin_password_reset(self):
        self.store.add_user("frank", "pw-frank-old", must_change=False)
        tok = self.login("frank", "pw-frank-old")["token"]
        chatserver.main(["passwd", "frank", "--data", self.tmp,
                         "--password", "pw-frank-new"])
        status, _ = self.req("GET", "/api/messages?wait=0",
                             headers={"Authorization": "Bearer " + tok})
        self.assertEqual(status, 401)  # reset kills existing sessions
        status, body = self.req("POST", "/api/login",
                                body={"user": "frank",
                                      "password": "pw-frank-new"})
        self.assertEqual(status, 200)
        self.assertTrue(body["must_change"])  # reset forces a change

    # ---- message-possibility unit tests (fresh users per test for isolation)

    def fresh(self, *names):
        for n in names:
            self.store.add_user(n, "pw-" + n, must_change=False)
            self.tokens[n] = self.login(n, "pw-" + n)["token"]

    def upload(self, user, data, name="f.bin"):
        status, up = self.req("POST", "/api/files", user=user, body=data,
                              headers={"X-File-Name": name})
        self.assertEqual(status, 200, up)
        return up

    def test_15_unicode_text_roundtrip(self):
        self.fresh("t15a", "t15b")
        text = "héllo 👋\nsecond line\ttab — dash"
        mid = self.send_msg("t15a", text, to="t15b")["id"]
        self.poll_until("t15b", lambda e: e["id"] == mid)
        _, m = self.req("GET", f"/api/message/dequeue/{mid}", user="t15b")
        self.assertEqual(m["text"], text)
        self.confirm("t15b", [mid])

    def test_16_file_only_and_empty_messages(self):
        self.fresh("t16a", "t16b")
        up = self.upload("t16a", b"PDFDATA", "doc.pdf")
        sent = self.send_msg("t16a", "", to="t16b", files=[up["file_id"]])
        self.poll_until("t16b", lambda e: e["id"] == sent["id"])
        _, m = self.req("GET", f"/api/message/dequeue/{sent['id']}", user="t16b")
        self.assertEqual(m["text"], "")
        self.assertEqual(m["attachments"][0]["name"], "doc.pdf")
        self.confirm("t16b", [sent["id"]])
        # no text and no files is not a message; neither is whitespace
        status, _ = self.req("POST", "/api/messages", user="t16a",
                             body={"to": "t16b", "text": "   ", "nonce": "x" * 12})
        self.assertEqual(status, 400)

    def test_17_multiple_attachments_ordered(self):
        self.fresh("t17a", "t17b")
        blobs = [os.urandom(64) for _ in range(3)]
        ups = [self.upload("t17a", b, f"f{i}.bin") for i, b in enumerate(blobs)]
        sent = self.send_msg("t17a", "3 files", to="t17b",
                             files=[u["file_id"] for u in ups])
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t17b", lambda e: e["id"] == mid)
        _, m = self.req("GET", f"/api/message/dequeue/{mid}", user="t17b")
        self.assertEqual([a["n"] for a in m["attachments"]], [1, 2, 3])
        self.assertEqual([a["name"] for a in m["attachments"]],
                         ["f0.bin", "f1.bin", "f2.bin"])
        for i, blob in enumerate(blobs, 1):
            r, data = self.req("GET", f"/api/attachments/{gid}/{mid}/{i}",
                               user="t17b", raw=True)
            self.assertEqual(data, blob, i)
        self.confirm("t17b", [mid])

    def test_18_attachment_errors(self):
        self.fresh("t18a", "t18b")
        up = self.upload("t18a", b"once", "once.bin")
        first = self.send_msg("t18a", "uses it", to="t18b",
                              files=[up["file_id"]])
        # a staged id is consumed by the send that references it
        status, _ = self.req("POST", "/api/messages", user="t18a",
                             body={"to": "t18b", "text": "again",
                                   "nonce": "n" * 12, "files": [up["file_id"]]})
        self.assertEqual(status, 400)
        # unknown (well-formed) id
        status, _ = self.req("POST", "/api/messages", user="t18a",
                             body={"to": "t18b", "text": "x", "nonce": "m" * 12,
                                   "files": ["ab" * 16]})
        self.assertEqual(status, 400)
        # more than MAX_ATTACHMENTS references
        status, _ = self.req("POST", "/api/messages", user="t18a",
                             body={"to": "t18b", "text": "x", "nonce": "o" * 12,
                                   "files": ["ab" * 16] * 9})
        self.assertEqual(status, 400)
        # attachment index out of range / absent
        gid, mid = first["gid"], first["id"]
        self.poll_until("t18b", lambda e: e["id"] == mid)
        for n in ("0", "9", "2"):
            status, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/{n}",
                                 user="t18b")
            self.assertIn(status, (400, 404), n)
        self.confirm("t18b", [mid])

    def test_19_text_and_nonce_limits(self):
        self.fresh("t19a", "t19b")
        self.assertTrue(self.send_msg("t19a", "x" * chatserver.MAX_TEXT,
                                      to="t19b")["id"])
        status, _ = self.req("POST", "/api/messages", user="t19a",
                             body={"to": "t19b",
                                   "text": "x" * (chatserver.MAX_TEXT + 1),
                                   "nonce": "p" * 12})
        self.assertEqual(status, 400)
        for nonce in ("short", "", "bad nonce!", None):
            body = {"to": "t19b", "text": "hi"}
            if nonce is not None:
                body["nonce"] = nonce
            status, _ = self.req("POST", "/api/messages", user="t19a", body=body)
            self.assertEqual(status, 400, repr(nonce))

    def test_20_group_send_authz(self):
        self.fresh("t20a", "t20b", "t20c")
        _, g = self.req("POST", "/api/groups", user="t20a",
                        body={"name": "closed", "members": ["t20b"]})
        status, _ = self.req("POST", "/api/messages", user="t20c",
                             body={"gid": g["gid"], "text": "let me in",
                                   "nonce": "q" * 12})
        self.assertEqual(status, 403)  # non-member cannot send
        status, _ = self.req("POST", "/api/messages", user="t20a",
                             body={"gid": "g-0123456789", "text": "x",
                                   "nonce": "r" * 12})
        self.assertEqual(status, 403)  # well-formed but nonexistent group
        status, _ = self.req("POST", "/api/messages", user="t20a",
                             body={"gid": "not-a-gid!", "text": "x",
                                   "nonce": "s" * 12})
        self.assertEqual(status, 400)  # malformed gid

    def test_21_viewed_edge_cases(self):
        self.fresh("t21a", "t21b", "t21c")
        sent = self.send_msg("t21a", "look", to="t21b")
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t21b", lambda e: e["id"] == mid)
        # sender viewing their own message is a no-op
        status, r = self.req("POST", "/api/message/viewed", user="t21a",
                             body={"gid": gid, "ids": [mid]})
        self.assertEqual((status, r["marked"]), (200, 0))
        # non-member is rejected
        status, _ = self.req("POST", "/api/message/viewed", user="t21c",
                             body={"gid": gid, "ids": [mid]})
        self.assertEqual(status, 403)
        # unknown mid is skipped, not an error
        status, r = self.req("POST", "/api/message/viewed", user="t21b",
                             body={"gid": gid,
                                   "ids": [f"{10**12 + 5:013d}-{'a' * 12}"]})
        self.assertEqual((status, r["marked"]), (200, 0))
        # double-view marks exactly once
        self.req("POST", "/api/message/viewed", user="t21b",
                 body={"gid": gid, "ids": [mid]})
        status, r = self.req("POST", "/api/message/viewed", user="t21b",
                             body={"gid": gid, "ids": [mid]})
        self.assertEqual(r["marked"], 0)

    def test_22_read_implies_delivered(self):
        self.fresh("t22a", "t22b")
        sent = self.send_msg("t22a", "view first", to="t22b")
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t22b", lambda e: e["id"] == mid)
        # view WITHOUT confirming the dequeue first
        self.req("POST", "/api/message/viewed", user="t22b",
                 body={"gid": gid, "ids": [mid]})
        mdir = self.store.msg_dir(gid, mid)
        self.assertTrue((mdir / "deliveredto" / "t22b").is_file())
        self.assertTrue((mdir / "readby" / "t22b").is_file())
        # sender gets both flag events, and delivered sorts before read
        d = self.poll_until("t22a", lambda e: e["entry"] == f"{mid}~d~t22b")
        r = self.poll_until("t22a", lambda e: e["entry"] == f"{mid}~r~t22b")
        q = self.poll("t22a", wait=0)
        order = [e["entry"] for e in q if e["id"] == mid]
        self.assertEqual(order, sorted(order))  # queue is chronological
        self.assertLess(order.index(f"{mid}~d~t22b"),
                        order.index(f"{mid}~r~t22b"))  # delivered before read
        self.confirm("t22a", [d["entry"], r["entry"]])
        # the later dequeue-confirm is harmless: no duplicate ~d~
        self.confirm("t22b", [mid])
        self.assertEqual([e for e in self.poll("t22a", wait=0)
                          if e["id"] == mid], [])

    def test_23_queue_isolation_and_double_confirm(self):
        self.fresh("t23a", "t23b", "t23c")
        mid = self.send_msg("t23a", "for b only", to="t23b")["id"]
        self.poll_until("t23b", lambda e: e["id"] == mid)
        # a user cannot peek an entry that isn't in their own queue
        status, _ = self.req("GET", f"/api/message/dequeue/{mid}", user="t23c")
        self.assertEqual(status, 404)
        # double confirm: the second is a counted no-op
        self.assertEqual(self.confirm("t23b", [mid])["confirmed"], 1)
        self.assertEqual(self.confirm("t23b", [mid])["confirmed"], 0)

    def test_24_burst_ordering(self):
        self.fresh("t24a", "t24b")
        mids = [self.send_msg("t24a", f"m{i}", to="t24b")["id"]
                for i in range(5)]
        for m in mids:
            self.poll_until("t24b", lambda e, m=m: e["id"] == m)
        q = self.poll("t24b", wait=0)
        entries = [e["entry"] for e in q if e["kind"] == "msg"]
        self.assertEqual(entries, sorted(entries))  # queue is chronological
        _, hist = self.req("GET", "/api/groups/d-t24a-t24b/messages",
                           user="t24a")
        ids = [m["id"] for m in hist["messages"]]
        self.assertEqual(ids, sorted(ids, reverse=True))  # newest-first
        self.assertTrue(set(mids) <= set(ids))
        self.confirm("t24b", entries)

    # ---- regression tests for round-1 bug sweep ------------------------------

    def test_25_mids_strictly_increasing(self):
        # even ids minted in the same millisecond must be strictly ordered
        ids = [self.store.next_mid() for _ in range(200)]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(set(i[:13] for i in ids)), 200)  # unique timestamps

    def test_26_mid_hwm_persists_across_restart(self):
        s1 = chatserver.Store(tempfile.mkdtemp(prefix="hwm-"), iters=1000)
        last = s1.next_mid()
        # a fresh Store on the same dir must not reissue ids <= the persisted hwm
        s2 = chatserver.Store(str(s1.root), iters=1000)
        self.assertGreater(s2.next_mid(), last)

    def test_27_dm_gid_collision_disambiguated(self):
        for u in ("jean-luc", "mary", "jean", "luc-mary"):
            if not self.store.user_exists(u):
                self.store.add_user(u, "pw", must_change=False)
                self.tokens[u] = self.login(u, "pw")["token"]
        # {jean-luc, mary} and {jean, luc-mary} both naively map to
        # d-jean-luc-mary; the second pair must still get its own DM
        g1 = self.send_msg("jean-luc", "hi", to="mary")["gid"]
        g2 = self.send_msg("jean", "hi", to="luc-mary")["gid"]
        self.assertNotEqual(g1, g2)
        self.assertEqual(sorted(self.store.members(g1)), ["jean-luc", "mary"])
        self.assertEqual(sorted(self.store.members(g2)), ["jean", "luc-mary"])

    def test_28_left_group_cannot_peek_stale_entry(self):
        self.fresh("t28a", "t28b")
        _, g = self.req("POST", "/api/groups", user="t28a",
                        body={"name": "leak", "members": ["t28b"]})
        gid = g["gid"]
        mid = self.send_msg("t28a", "secret", gid=gid)["id"]
        self.poll_until("t28b", lambda e: e["id"] == mid)  # queued, unconfirmed
        # forge the exact race: entry still in queue, but membership revoked
        self.req("POST", f"/api/groups/{gid}/members", user="t28b",
                 body={"remove": ["t28b"]})
        self.store.queue_add("t28b", mid, self.store.msg_dir(gid, mid))  # re-add
        status, _ = self.req("GET", f"/api/message/dequeue/{mid}", user="t28b")
        self.assertEqual(status, 403)  # content not served to a non-member

    def test_29_send_rate_limited(self):
        self.fresh("t29a", "t29b")
        hit = 0
        for i in range(chatserver.SEND_LIMIT + 5):
            status, _ = self.req("POST", "/api/messages", user="t29a",
                                 body={"to": "t29b", "text": f"m{i}",
                                       "nonce": f"rl-{i:03d}-{'x' * 6}"})
            if status == 429:
                hit += 1
        self.assertGreater(hit, 0)  # burst eventually throttled

    def test_30_ratelimiter_evicts_keys(self):
        import time as _t
        rl = chatserver.RateLimiter(limit=1, window=0.05, max_keys=50)
        for i in range(50):            # fill to the cap
            rl.check(f"k{i}")
        _t.sleep(0.06)                 # let every window expire
        for i in range(50, 60):        # new keys past the cap trigger eviction
            rl.check(f"k{i}")
        self.assertLessEqual(len(rl._hits), 50)  # expired keys were reclaimed
        rl.sweep()                     # janitor path also reclaims
        self.assertLessEqual(len(rl._hits), 10)

    def test_31_multi_attachment_all_or_nothing(self):
        self.fresh("t31a", "t31b")
        good = self.upload("t31a", b"keep me", "keep.bin")
        # one good fid + one bogus fid: the good upload must NOT be destroyed
        status, _ = self.req("POST", "/api/messages", user="t31a",
                             body={"to": "t31b", "text": "x", "nonce": "z" * 12,
                                   "files": [good["file_id"], "ab" * 16]})
        self.assertEqual(status, 400)
        # the good staged file survives, so a corrected resend works
        sent = self.send_msg("t31a", "retry", to="t31b",
                             files=[good["file_id"]])
        self.poll_until("t31b", lambda e: e["id"] == sent["id"])
        _, m = self.req("GET", f"/api/message/dequeue/{sent['id']}", user="t31b")
        self.assertEqual(m["attachments"][0]["name"], "keep.bin")
        self.confirm("t31b", [sent["id"]])

    def test_32_recipients_frozen_at_send_time(self):
        # a member added AFTER a message must not be an intended recipient of
        # it, so the message's ticks can't regress when the roster grows
        self.fresh("t32a", "t32b", "t32c")
        _, g = self.req("POST", "/api/groups", user="t32a",
                        body={"name": "grow", "members": ["t32b"]})
        gid = g["gid"]
        mid = self.send_msg("t32a", "before carol", gid=gid)["id"]
        self.poll_until("t32b", lambda e: e["id"] == mid)
        import time as _t
        _t.sleep(0.05)
        self.req("POST", f"/api/groups/{gid}/members", user="t32a",
                 body={"add": ["t32c"]})
        _, hist = self.req("GET", f"/api/groups/{gid}/messages", user="t32a")
        m = next(x for x in hist["messages"] if x["id"] == mid)
        self.assertEqual(m["recipients"], ["t32b"])  # carol excluded (joined later)
        self.confirm("t32b", [mid])

    def test_33_failed_send_releases_nonce(self):
        # a send that aborts (bad file id) must release its nonce claim, so a
        # corrected retry with the SAME nonce succeeds instead of returning a
        # phantom id for a message that was never spooled
        self.fresh("t33a", "t33b")
        nonce = "reuse-nonce-33xx"
        status, _ = self.req("POST", "/api/messages", user="t33a",
                             body={"to": "t33b", "text": "x", "nonce": nonce,
                                   "files": ["ab" * 16]})
        self.assertEqual(status, 400)
        # same nonce, now valid: must actually create and deliver a message
        status, resp = self.req("POST", "/api/messages", user="t33a",
                                body={"to": "t33b", "text": "fixed",
                                      "nonce": nonce})
        self.assertEqual(status, 200)
        ev = self.poll_until("t33b", lambda e: e["id"] == resp["id"])
        _, m = self.req("GET", f"/api/message/dequeue/{resp['id']}", user="t33b")
        self.assertEqual(m["text"], "fixed")
        self.confirm("t33b", [ev["entry"]])
        # and a genuine retry of the successful send dedups to the same id
        status, again = self.req("POST", "/api/messages", user="t33a",
                                 body={"to": "t33b", "text": "fixed",
                                       "nonce": nonce})
        self.assertEqual(again["id"], resp["id"])

    # a real 1x1 transparent PNG (magic + decodable by browsers)
    PNG_1PX = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000d4944415478da63fcffff3f030005fe02fea7566d33"
        "0000000049454e44ae426082")

    def test_34_image_detected_and_served_inline(self):
        self.fresh("t34a", "t34b")
        up = self.upload("t34a", self.PNG_1PX, "photo.png")
        self.assertEqual(up.get("image"), "image/png")  # detected at upload
        sent = self.send_msg("t34a", "", to="t34b", files=[up["file_id"]])
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t34b", lambda e: e["id"] == mid)
        _, m = self.req("GET", f"/api/message/dequeue/{mid}", user="t34b")
        self.assertEqual(m["attachments"][0]["image"], "image/png")

        # inline request on a VERIFIED image: image content-type + inline
        # disposition + sandbox CSP + nosniff
        r, data = self.req("GET",
                           f"/api/attachments/{gid}/{mid}/1?inline=1",
                           user="t34b", raw=True)
        self.assertEqual(r.status, 200)
        self.assertEqual(data, self.PNG_1PX)
        self.assertEqual(r.getheader("Content-Type"), "image/png")
        self.assertTrue(r.getheader("Content-Disposition").startswith("inline"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertIn("sandbox", r.getheader("Content-Security-Policy"))
        # without inline=1 the default stays a forced download
        r, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1",
                        user="t34b", raw=True)
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")
        self.assertTrue(r.getheader("Content-Disposition").startswith("attachment"))
        self.confirm("t34b", [mid])

    def test_35_forged_images_never_inline(self):
        self.fresh("t35a", "t35b")
        cases = {  # name lies about the content in every case
            "evil.png": b"<html><script>alert(1)</script></html>",
            "pic.jpg": b"\x89PNGnot-really" + b"x" * 20,   # wrong magic
            "art.svg": b'<svg xmlns="http://www.w3.org/2000/svg">'
                       b"<script>alert(1)</script></svg>",
        }
        for name, payload in cases.items():
            up = self.upload("t35a", payload, name)
            self.assertNotIn("image", up, name)   # never detected as image
            sent = self.send_msg("t35a", name, to="t35b",
                                 files=[up["file_id"]])
            mid, gid = sent["id"], sent["gid"]
            self.poll_until("t35b", lambda e, m=mid: e["id"] == m)
            _, m = self.req("GET", f"/api/message/dequeue/{mid}", user="t35b")
            self.assertNotIn("image", m["attachments"][0], name)
            # inline=1 CANNOT force rendering: still an octet-stream download
            r, _ = self.req("GET",
                            f"/api/attachments/{gid}/{mid}/1?inline=1",
                            user="t35b", raw=True)
            self.assertEqual(r.getheader("Content-Type"),
                             "application/octet-stream", name)
            self.assertTrue(r.getheader("Content-Disposition")
                            .startswith("attachment"), name)
            self.confirm("t35b", [mid])

    def test_36_other_image_magics_detected(self):
        self.fresh("t36a")
        for payload, mime in (
            (b"GIF89a" + b"\x00" * 16, "image/gif"),
            (b"\xff\xd8\xff\xe0" + b"\x00" * 16, "image/jpeg"),
            (b"RIFF\x24\x00\x00\x00WEBP" + b"\x00" * 8, "image/webp"),
        ):
            up = self.upload("t36a", payload, "f.bin")  # name is irrelevant
            self.assertEqual(up.get("image"), mime)

    # ---- regression tests for the quality+security round ---------------------

    def test_37_duplicate_file_id_rejected(self):
        self.fresh("t37a", "t37b")
        up = self.upload("t37a", b"only once", "x.bin")
        status, _ = self.req("POST", "/api/messages", user="t37a",
                             body={"to": "t37b", "text": "x", "nonce": "d" * 12,
                                   "files": [up["file_id"], up["file_id"]]})
        self.assertEqual(status, 400)  # duplicate fid rejected, not consumed+lost
        # the staged file survives, so a correct single-ref send works
        sent = self.send_msg("t37a", "ok", to="t37b", files=[up["file_id"]])
        self.poll_until("t37b", lambda e: e["id"] == sent["id"])
        self.confirm("t37b", [sent["id"]])

    def test_38_group_ops_rate_limited(self):
        self.fresh("t38a", "t38b")
        hits = 0
        for i in range(chatserver.GROUP_OP_LIMIT + 4):
            status, _ = self.req("POST", "/api/groups", user="t38a",
                                 body={"name": f"g{i}", "members": ["t38b"]})
            if status == 429:
                hits += 1
        self.assertGreater(hits, 0)  # group-creation spam is throttled

    def test_39_change_password_bad_old_is_400(self):
        self.store.add_user("t39", "pw-t39-init", must_change=False)
        tok = self.login("t39", "pw-t39-init")["token"]
        # a non-string 'old' must 400, not 500 (AttributeError on .encode)
        for bad in (123, None, ["x"], {"a": 1}):
            status, _ = self.req("POST", "/api/password",
                                 headers={"Authorization": "Bearer " + tok},
                                 body={"old": bad, "new": "pw-t39-new-1"})
            self.assertEqual(status, 400, repr(bad))

    def test_40_storage_quota_enforced(self):
        self.fresh("t40")
        udir = self.store.user_dir("t40")
        # pre-charge the counter to just under quota, then a small upload trips it
        (udir / "storage_used").write_text(str(chatserver.USER_STORAGE_QUOTA - 4))
        status, up = self.req("POST", "/api/files", user="t40", body=b"hello",
                              headers={"X-File-Name": "big.bin"})
        self.assertEqual(status, 413)  # 5 bytes over the remaining 4 → rejected

    # ---- regression tests for the second quality+security round --------------

    def test_41_janitor_credits_back_expired_staged(self):
        self.fresh("t41")
        self.upload("t41", b"x" * 1000, "a.bin")
        used = self.store.storage_used("t41")
        self.assertGreaterEqual(used, 1000)
        # age the staged files past 24h and run the janitor
        import time as _t
        staged = self.store.user_dir("t41") / "staged"
        old = _t.time() - 86400 - 10
        for p in staged.iterdir():
            os.utime(p, (old, old))
        chatserver.Janitor(self.store).clean()
        self.assertEqual(list(staged.iterdir()), [])       # pruned
        self.assertEqual(self.store.storage_used("t41"), used - 1000)  # credited

    def test_42_modify_members_atomic(self):
        self.fresh("t42a", "t42b", "t42c")
        _, g = self.req("POST", "/api/groups", user="t42a",
                        body={"name": "atomic", "members": ["t42b"]})
        gid = g["gid"]
        # add t42c together with an illegal remove of someone-else → must 403
        # WITHOUT having added t42c (validate-before-apply)
        status, _ = self.req("POST", f"/api/groups/{gid}/members", user="t42a",
                             body={"add": ["t42c"], "remove": ["t42b"]})
        self.assertEqual(status, 403)
        self.assertNotIn("t42c", self.store.members(gid))  # add not committed

    def test_43_pre_join_attachment_and_state_hidden(self):
        self.fresh("t43a", "t43b", "t43c")
        _, g = self.req("POST", "/api/groups", user="t43a",
                        body={"name": "prejoin", "members": ["t43b"]})
        gid = g["gid"]
        up = self.upload("t43a", b"secret pixels", "s.bin")
        sent = self.send_msg("t43a", "before c", gid=gid, files=[up["file_id"]])
        mid = sent["id"]
        self.poll_until("t43b", lambda e: e["id"] == mid)
        import time as _t
        _t.sleep(0.05)
        self.req("POST", f"/api/groups/{gid}/members", user="t43a",
                 body={"add": ["t43c"]})
        # t43c joined after the message: attachment + state must be hidden
        status, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1", user="t43c")
        self.assertEqual(status, 404)
        status, _ = self.req("GET", f"/api/message/state/{gid}/{mid}", user="t43c")
        self.assertEqual(status, 404)
        self.confirm("t43b", [mid])

    def test_44_per_instance_poll_state(self):
        # the parked-poll counter must be per-Api-instance, not global
        a2 = chatserver.Api(self.store, chatserver.Notifier(),
                            chatserver.Router(self.store, chatserver.Notifier()))
        self.assertIsNot(self.api._polls, a2._polls)

    def test_45_join_stamp_on_message_clock(self):
        # join time is stamped INTO the marker on the same monotonic clock as
        # message ids — not filesystem mtime — so the pre-join gate can't be
        # fooled by clock skew and needs no sleeps to order correctly
        self.fresh("t45a", "t45b", "t45c")
        _, g = self.req("POST", "/api/groups", user="t45a",
                        body={"name": "clock", "members": ["t45b"]})
        gid = g["gid"]
        mid = self.send_msg("t45a", "before c", gid=gid)["id"]
        self.req("POST", f"/api/groups/{gid}/members", user="t45a",
                 body={"add": ["t45c"]})
        marker = self.store.group_dir(gid) / "members" / "t45c"
        stamp = int(marker.read_text())          # numeric stamp in the marker
        self.assertGreater(stamp, int(mid[:13]))  # carol joined AFTER the msg id
        self.assertEqual(self.store.joined_at(gid, "t45c"), stamp)
        # and history hides the pre-join message from carol with no sleeps
        _, hist = self.req("GET", f"/api/groups/{gid}/messages", user="t45c")
        self.assertNotIn(mid, {m["id"] for m in hist["messages"]})

    # ---- v2 features: reactions, reply, edit/delete, search, star,
    # ---- presence, typing, voice-note audio ---------------------------------

    def test_46_reaction_roundtrip_and_event(self):
        self.fresh("t46a", "t46b")
        sent = self.send_msg("t46a", "react to me", to="t46b")
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t46b", lambda e: e["id"] == mid)
        # bob reacts; marker file appears; state carries it
        status, r = self.req("POST", "/api/message/react", user="t46b",
                             body={"gid": gid, "mid": mid, "emoji": "👍"})
        self.assertEqual(status, 200, r)
        self.assertEqual(r["reactions"], {"t46b": "👍"})
        self.assertEqual(
            (self.store.msg_dir(gid, mid) / "reactions" / "t46b").read_text(),
            "👍")
        # alice gets a ~a~ reaction event and refetches state
        ev = self.poll_until("t46a", lambda e: e["kind"] == "reaction"
                             and e["id"] == mid)
        self.assertEqual(ev["user"], "t46b")
        _, st = self.req("GET", f"/api/message/state/{gid}/{mid}", user="t46a")
        self.assertEqual(st["reactions"], {"t46b": "👍"})
        self.assertIn("deliveredto", st)   # still a superset of the old shape
        # removing = empty emoji; marker gone
        self.req("POST", "/api/message/react", user="t46b",
                 body={"gid": gid, "mid": mid, "emoji": ""})
        _, st = self.req("GET", f"/api/message/state/{gid}/{mid}", user="t46a")
        self.assertNotIn("reactions", st)

    def test_47_reaction_validation(self):
        self.fresh("t47a", "t47b", "t47x")
        sent = self.send_msg("t47a", "hi", to="t47b")
        mid, gid = sent["id"], sent["gid"]
        # non-member cannot react
        status, _ = self.req("POST", "/api/message/react", user="t47x",
                             body={"gid": gid, "mid": mid, "emoji": "👍"})
        self.assertEqual(status, 403)
        # junk emoji rejected (control chars / oversized)
        for bad in ("a\x00b", "x" * 40):
            status, _ = self.req("POST", "/api/message/react", user="t47a",
                                 body={"gid": gid, "mid": mid, "emoji": bad})
            self.assertEqual(status, 400, bad)

    def test_48_reply_roundtrip(self):
        self.fresh("t48a", "t48b")
        orig = self.send_msg("t48a", "original question", to="t48b")
        mid, gid = orig["id"], orig["gid"]
        self.poll_until("t48b", lambda e: e["id"] == mid)
        body = {"text": "the answer", "nonce": "n-" + os.urandom(8).hex(),
                "gid": gid, "reply_to": mid}
        status, rep = self.req("POST", "/api/messages", user="t48b", body=body)
        self.assertEqual(status, 200, rep)
        ev = self.poll_until("t48a", lambda e: e["id"] == rep["id"])
        _, msg = self.req("GET", f"/api/message/dequeue/{rep['id']}", user="t48a")
        self.assertEqual(msg["reply"]["id"], mid)
        self.assertEqual(msg["reply"]["from"], "t48a")
        self.assertEqual(msg["reply"]["text"], "original question")
        self.confirm("t48a", [ev["entry"]])
        # a reply to a nonexistent mid is rejected
        body = {"text": "x", "nonce": "n-" + os.urandom(8).hex(), "gid": gid,
                "reply_to": "9999999999999-aaaaaaaaaaaa"}
        status, _ = self.req("POST", "/api/messages", user="t48b", body=body)
        self.assertEqual(status, 404)

    def test_49_edit_message(self):
        self.fresh("t49a", "t49b")
        sent = self.send_msg("t49a", "teh typo", to="t49b")
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t49b", lambda e: e["id"] == mid)
        # only the author may edit
        status, _ = self.req("POST", "/api/message/edit", user="t49b",
                             body={"gid": gid, "mid": mid, "text": "hax"})
        self.assertEqual(status, 403)
        status, r = self.req("POST", "/api/message/edit", user="t49a",
                             body={"gid": gid, "mid": mid, "text": "the fix"})
        self.assertEqual(status, 200, r)
        # recipient gets an ~u~ updated event; state shows new text + edited ts
        ev = self.poll_until("t49b", lambda e: e["kind"] == "updated"
                             and e["id"] == mid)
        _, st = self.req("GET", f"/api/message/state/{gid}/{mid}", user="t49b")
        self.assertEqual(st["text"], "the fix")
        self.assertEqual(st["edited"], r["edited"])
        self.confirm("t49b", [ev["entry"]])

    def test_50_delete_message_tombstone_and_storage_credit(self):
        self.fresh("t50a", "t50b")
        up = self.upload("t50a", b"PAYLOAD" * 1000, name="doc.bin")
        sent = self.send_msg("t50a", "with file", to="t50b",
                             files=[up["file_id"]])
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t50b", lambda e: e["id"] == mid)
        used_before = self.store.storage_used("t50a")
        self.assertGreaterEqual(used_before, 7000)
        status, _ = self.req("POST", "/api/message/delete", user="t50a",
                             body={"gid": gid, "mid": mid})
        self.assertEqual(status, 200)
        # tombstone: text blank, deleted flag, attachments gone (404), quota back
        _, st = self.req("GET", f"/api/message/state/{gid}/{mid}", user="t50b")
        self.assertTrue(st["deleted"])
        self.assertEqual(st["text"], "")
        self.assertEqual(st["attachments"], [])
        status, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1",
                             user="t50b")
        self.assertEqual(status, 404)
        self.assertEqual(self.store.storage_used("t50a"), used_before - 7000)
        # idempotent; and the recipient saw an updated event
        status, _ = self.req("POST", "/api/message/delete", user="t50a",
                             body={"gid": gid, "mid": mid})
        self.assertEqual(status, 200)
        self.poll_until("t50b", lambda e: e["kind"] == "updated")

    def test_51_search_scope_and_join_gate(self):
        self.fresh("t51a", "t51b", "t51c")
        gid = self.send_msg("t51a", "zebra in the dm", to="t51b")["gid"]
        _, g = self.req("POST", "/api/groups", user="t51a",
                        body={"name": "srch", "members": ["t51b"]})
        self.send_msg("t51a", "zebra pre-join", gid=g["gid"])
        self.req("POST", f"/api/groups/{g['gid']}/members", user="t51a",
                 body={"add": ["t51c"]})
        self.send_msg("t51a", "zebra post-join", gid=g["gid"])
        # alice sees both group hits and the dm hit
        _, res = self.req("GET", "/api/search?q=zebra", user="t51a")
        texts = [r["snippet"] for r in res["results"]]
        self.assertEqual(len(texts), 3, texts)
        self.assertFalse(res["truncated"])
        # newest-first ordering across groups
        ats = [r["at"] for r in res["results"]]
        self.assertEqual(ats, sorted(ats, reverse=True))
        # carol joined late: pre-join message is invisible to search
        _, res = self.req("GET", "/api/search?q=zebra", user="t51c")
        self.assertEqual([r["snippet"] for r in res["results"]],
                         ["zebra post-join"])
        # non-member scoping to a gid is refused
        status, _ = self.req("GET", f"/api/search?q=zebra&gid={gid}",
                             user="t51c")
        self.assertEqual(status, 403)
        # attachment-name matches hit too
        up = self.upload("t51a", b"\x00binary", name="zebra-report.pdf")
        self.send_msg("t51a", "", to="t51b", files=[up["file_id"]])
        _, res = self.req("GET", "/api/search?q=zebra-report", user="t51b")
        self.assertEqual(len(res["results"]), 1)
        self.assertIn("zebra-report.pdf", res["results"][0]["snippet"])

    def test_52_star_roundtrip_and_selfheal(self):
        self.fresh("t52a", "t52b")
        sent = self.send_msg("t52a", "star me", to="t52b")
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t52b", lambda e: e["id"] == mid)
        status, _ = self.req("POST", "/api/message/star", user="t52b",
                             body={"gid": gid, "mid": mid, "on": True})
        self.assertEqual(status, 200)
        _, ls = self.req("GET", "/api/starred", user="t52b")
        self.assertEqual([m["id"] for m in ls["messages"]], [mid])
        self.assertEqual(ls["messages"][0]["text"], "star me")
        # stars are private: alice's list is empty
        _, ls = self.req("GET", "/api/starred", user="t52a")
        self.assertEqual(ls["messages"], [])
        # deleting the message self-heals the star list on next read
        self.req("POST", "/api/message/delete", user="t52a",
                 body={"gid": gid, "mid": mid})
        _, ls = self.req("GET", "/api/starred", user="t52b")
        self.assertEqual(ls["messages"], [])
        self.assertEqual(list((self.store.user_dir("t52b") / "starred")
                              .iterdir()), [])
        # unstar of something never starred is a no-op, not an error
        status, _ = self.req("POST", "/api/message/star", user="t52b",
                             body={"gid": gid, "mid": mid, "on": False})
        self.assertEqual(status, 200)

    def test_53_presence_in_users_list(self):
        self.fresh("t53a")
        _, res = self.req("GET", "/api/users", user="t53a")
        me = next(u for u in res["users"] if u["user"] == "t53a")
        self.assertTrue(me["online"])           # we just made a request
        self.assertGreater(me.get("last_seen", 0), 0)
        # a user who has never authenticated is offline
        self.store.add_user("t53ghost", "pw-x", must_change=False)
        _, res = self.req("GET", "/api/users", user="t53a")
        ghost = next(u for u in res["users"] if u["user"] == "t53ghost")
        self.assertFalse(ghost["online"])

    def test_54_typing_signal(self):
        self.fresh("t54a", "t54b")
        gid = self.send_msg("t54a", "warm up the dm", to="t54b")["gid"]
        for e in self.poll("t54b"):
            self.confirm("t54b", [e["entry"]])
        status, _ = self.req("POST", "/api/typing", user="t54a",
                             body={"gid": gid})
        self.assertEqual(status, 200)
        # bob's poll reports alice typing; alice's own poll must NOT echo her
        status, resp = self.req("GET", "/api/messages?wait=0", user="t54b")
        self.assertEqual(resp.get("typing"), {gid: ["t54a"]})
        status, resp = self.req("GET", "/api/messages?wait=0", user="t54a")
        self.assertNotIn("typing", resp)
        # non-member gets a 403 and no signal
        self.fresh("t54x")
        status, _ = self.req("POST", "/api/typing", user="t54x",
                             body={"gid": gid})
        self.assertEqual(status, 403)

    def test_55_voice_note_audio_verified_inline(self):
        self.fresh("t55a", "t55b")
        # a real-looking webm/EBML header → audio, inline allowed
        up = self.upload("t55a", b"\x1a\x45\xdf\xa3" + b"\x00" * 64,
                         name="voice.webm")
        self.assertEqual(up["audio"], "audio/webm")
        sent = self.send_msg("t55a", "", to="t55b", files=[up["file_id"]])
        mid, gid = sent["id"], sent["gid"]
        ev = self.poll_until("t55b", lambda e: e["id"] == mid)
        _, msg = self.req("GET", f"/api/message/dequeue/{mid}", user="t55b")
        self.assertEqual(msg["attachments"][0]["audio"], "audio/webm")
        r, payload = self.req("GET", f"/api/attachments/{gid}/{mid}/1?inline=1",
                              user="t55b", raw=True)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.headers["Content-Type"], "audio/webm")
        self.assertIn("sandbox", r.headers.get("Content-Security-Policy", ""))
        self.confirm("t55b", [ev["entry"]])
        # an html file named .webm is NOT audio and stays a forced download
        up = self.upload("t55a", b"<html><script>x</script></html>",
                         name="fake.webm")
        self.assertNotIn("audio", up)
        sent = self.send_msg("t55a", "", to="t55b", files=[up["file_id"]])
        ev = self.poll_until("t55b", lambda e: e["id"] == sent["id"])
        self.confirm("t55b", [ev["entry"]])   # wait until the router routed it
        r, payload = self.req(
            "GET", f"/api/attachments/{sent['gid']}/{sent['id']}/1?inline=1",
            user="t55b", raw=True)
        self.assertEqual(r.headers["Content-Type"], "application/octet-stream")
        self.assertIn("attachment", r.headers.get("Content-Disposition", ""))

    def test_56_edit_delete_guards(self):
        self.fresh("t56a", "t56b")
        sent = self.send_msg("t56a", "guard me", to="t56b")
        mid, gid = sent["id"], sent["gid"]
        # cannot edit a deleted message; cannot delete someone else's
        status, _ = self.req("POST", "/api/message/delete", user="t56b",
                             body={"gid": gid, "mid": mid})
        self.assertEqual(status, 403)
        self.req("POST", "/api/message/delete", user="t56a",
                 body={"gid": gid, "mid": mid})
        status, _ = self.req("POST", "/api/message/edit", user="t56a",
                             body={"gid": gid, "mid": mid, "text": "zombie"})
        self.assertEqual(status, 400)
        # reactions on system messages are refused
        _, g = self.req("POST", "/api/groups", user="t56a",
                        body={"name": "sys", "members": ["t56b"]})
        ev = self.poll_until("t56b", lambda e: e["gid"] == g["gid"])
        status, _ = self.req("POST", "/api/message/react", user="t56b",
                             body={"gid": g["gid"], "mid": ev["id"],
                                   "emoji": "👍"})
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
