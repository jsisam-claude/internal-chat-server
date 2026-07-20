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
        self.poll("carol")  # let routing finish
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
