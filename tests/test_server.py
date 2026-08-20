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

    def upload(self, user, data, name="f.bin", audio_hint=False):
        headers = {"X-File-Name": name}
        if audio_hint:          # what a client that RECORDED a voice note sends
            headers["X-Media-Kind"] = "audio"
        status, up = self.req("POST", "/api/files", user=user, body=data,
                              headers=headers)
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
        # alice gets an update event and refetches state. Reactions, edits and
        # deletes all use the ONE "message changed, refetch it" signal — the
        # separate ~a~ spelling was retired (still parsed, never emitted).
        ev = self.poll_until("t46a", lambda e: e["kind"] == "updated"
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
        # a real-looking webm/EBML header + the recorder's presentation hint
        # → audio, inline allowed. (Without the hint webm is ambiguous and
        # correctly defaults to video — see test_63.)
        up = self.upload("t55a", b"\x1a\x45\xdf\xa3" + b"\x00" * 64,
                         name="voice.webm", audio_hint=True)
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

    # ---- inline video / container disambiguation ---------------------------

    # Fixed-offset headers. ISO-BMFF: [size][ftyp][major brand]. The brand is
    # what distinguishes iTunes audio from everything that may carry video.
    @staticmethod
    def _bmff(brand: bytes) -> bytes:
        return (b"\x00\x00\x00\x20" + b"ftyp" + brand
                + b"\x00\x00\x02\x00" + brand * 2 + b"\x00" * 16)
    EBML = b"\x1a\x45\xdf\xa3" + b"\x01\x00\x00\x00\x00\x00\x00\x23" + b"\x00" * 32

    def test_63_container_kind_from_magic_bytes(self):
        from internalchat.util import av_mime
        # mp4 family: resolved by MAJOR BRAND, a fixed-offset field
        self.assertEqual(av_mime(self._bmff(b"M4A ")), ("audio", "audio/mp4"))
        self.assertEqual(av_mime(self._bmff(b"M4B ")), ("audio", "audio/mp4"))
        for brand in (b"isom", b"mp42", b"avc1", b"dash", b"M4V "):
            self.assertEqual(av_mime(self._bmff(brand)), ("video", "video/mp4"),
                             brand)
        # ISO-BMFF still images (HEIC/AVIF) share the box format but are NOT
        # playable containers: they must not become a video that shows nothing
        for brand in (b"heic", b"avif", b"mif1", b"msf1"):
            self.assertIsNone(av_mime(self._bmff(brand)), brand)
            # and the hint must not be able to turn one into audio either
            self.assertIsNone(av_mime(self._bmff(brand), audio_hint=True), brand)
        # brands whose real type isn't video/mp4 are declared correctly, since
        # nosniff pins whatever we send
        self.assertEqual(av_mime(self._bmff(b"qt  ")), ("video", "video/quicktime"))
        self.assertEqual(av_mime(self._bmff(b"3gp4")), ("video", "video/3gpp"))
        # webm/matroska is undecidable without parsing -> defaults to VIDEO,
        # because a <video> element plays audio-only fine while an <audio>
        # element cannot show a video at all
        self.assertEqual(av_mime(self.EBML), ("video", "video/webm"))
        self.assertEqual(av_mime(self.EBML, audio_hint=True),
                         ("audio", "audio/webm"))
        # unambiguous audio is never affected by the hint
        self.assertEqual(av_mime(b"ID3\x03\x00" + b"\x00" * 16),
                         ("audio", "audio/mpeg"))
        self.assertEqual(av_mime(b"OggS" + b"\x00" * 20), ("audio", "audio/ogg"))
        # non-media stays non-media, hint or not
        self.assertIsNone(av_mime(b"<html><script>x</script>"))
        self.assertIsNone(av_mime(b"<html><script>x</script>", audio_hint=True))
        self.assertIsNone(av_mime(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3", audio_hint=True))

    def test_64_video_upload_and_inline_playback(self):
        self.fresh("t64a", "t64b")
        up = self.upload("t64a", self._bmff(b"isom") + b"\x00" * 512,
                         name="clip.mp4")
        self.assertEqual(up["video"], "video/mp4")
        self.assertNotIn("audio", up)      # mutually exclusive
        self.assertNotIn("image", up)
        sent = self.send_msg("t64a", "", to="t64b", files=[up["file_id"]])
        mid, gid = sent["id"], sent["gid"]
        ev = self.poll_until("t64b", lambda e: e["id"] == mid)
        _, msg = self.req("GET", f"/api/message/dequeue/{mid}", user="t64b")
        self.assertEqual(msg["attachments"][0]["video"], "video/mp4")
        # inline playback is allowed, under the same sandbox as images
        r, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1?inline=1",
                        user="t64b", raw=True)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.headers["Content-Type"], "video/mp4")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("sandbox", r.headers.get("Content-Security-Policy", ""))
        self.assertIn("inline", r.headers.get("Content-Disposition", ""))
        self.confirm("t64b", [ev["entry"]])

    def test_65_media_hint_cannot_escalate(self):
        # The hint is PRESENTATION-ONLY. It must never grant inline rendering
        # to a non-media file, never change the container that gets served,
        # and never produce a scriptable Content-Type.
        self.fresh("t65a", "t65b")
        # 1. an HTML file claiming to be audio stays a forced download
        up = self.upload("t65a", b"<html><script>alert(1)</script></html>",
                         name="evil.webm", audio_hint=True)
        self.assertNotIn("audio", up)
        self.assertNotIn("video", up)
        self.assertNotIn("image", up)
        sent = self.send_msg("t65a", "", to="t65b", files=[up["file_id"]])
        ev = self.poll_until("t65b", lambda e: e["id"] == sent["id"])
        r, _ = self.req(
            "GET", f"/api/attachments/{sent['gid']}/{sent['id']}/1?inline=1",
            user="t65b", raw=True)
        self.assertEqual(r.headers["Content-Type"], "application/octet-stream")
        self.assertIn("attachment", r.headers.get("Content-Disposition", ""))
        self.confirm("t65b", [ev["entry"]])
        # 2. hinting audio on a real VIDEO only changes presentation; the
        # served type stays within the same verified container family
        up2 = self.upload("t65a", self.EBML + b"\x00" * 256,
                          name="clip.webm", audio_hint=True)
        self.assertEqual(up2["audio"], "audio/webm")
        self.assertNotIn("video", up2)
        # 3. an SVG is still never inline-able, hint or not
        up3 = self.upload("t65a", b"<svg xmlns='http://www.w3.org/2000/svg'/>",
                          name="x.svg", audio_hint=True)
        self.assertNotIn("image", up3)
        self.assertNotIn("audio", up3)
        self.assertNotIn("video", up3)

    def test_66_queue_is_paged(self):
        # A user offline while a group ran hot can accumulate thousands of
        # entries; one poll must return a bounded page (and every entry costs
        # a realpath+lstat, so this is work as well as bytes).
        from internalchat.config import QUEUE_PAGE
        self.fresh("t66a", "t66b")
        gid = self.send_msg("t66a", "seed", to="t66b")["gid"]
        qdir = self.store.queue_dir("t66b")
        target = self.store.msg_dir(gid, self.send_msg("t66a", "x", gid=gid)["id"])
        import time as _time
        for _ in range(60):          # wait for the router
            if target.is_dir():
                break
            _time.sleep(0.05)
        # fabricate a large backlog of flag events pointing at a real message
        for i in range(QUEUE_PAGE + 50):
            self.store.queue_add("t66b", f"{target.name}~d~u{i:04d}", target)
        q = self.poll("t66b", wait=0)
        self.assertLessEqual(len(q), QUEUE_PAGE, "poll must return one page")
        self.assertGreater(len(q), 0)

    def test_67_storage_recount_is_one_walk(self):
        # The janitor used to re-walk the whole tree once PER USER for the same
        # answer. One walk must produce every counter.
        self.fresh("t67a", "t67b")
        _, g = self.req("POST", "/api/groups", user="t67a",
                        body={"name": "s67", "members": ["t67b"]})
        gid = g["gid"]
        up = self.upload("t67a", b"A" * 4000, name="a.bin")
        self.send_msg("t67a", "", gid=gid, files=[up["file_id"]])
        up2 = self.upload("t67b", b"B" * 1000, name="b.bin")
        self.send_msg("t67b", "", gid=gid, files=[up2["file_id"]])
        totals = self.store.recount_all_storage()
        self.assertEqual(totals["t67a"], 4000)
        self.assertEqual(totals["t67b"], 1000)
        # and the counters on disk agree
        self.assertEqual(self.store.storage_used("t67a"), 4000)
        self.assertEqual(self.store.storage_used("t67b"), 1000)
        # leaving a group does NOT un-count bytes that are still on disk
        self.req("POST", f"/api/groups/{gid}/members", user="t67b",
                 body={"remove": ["t67b"]})
        self.assertEqual(self.store.recount_all_storage()["t67b"], 1000)

    def test_68_viewed_respects_the_join_gate(self):
        # Read receipts must not lie. Without the gate a member added later
        # could mark-read a message they are never shown, and the SENDER got a
        # blue tick claiming they had read it.
        self.fresh("t68a", "t68b", "t68c")
        _, g = self.req("POST", "/api/groups", user="t68a",
                        body={"name": "s68", "members": ["t68b"]})
        gid = g["gid"]
        pre = self.send_msg("t68a", "pre-join", gid=gid)["id"]
        self.poll_until("t68b", lambda e: e["id"] == pre)
        self.req("POST", f"/api/groups/{gid}/members", user="t68a",
                 body={"add": ["t68c"]})
        st, r = self.req("POST", "/api/message/viewed", user="t68c",
                         body={"gid": gid, "ids": [pre]})
        self.assertEqual(st, 200)
        self.assertEqual(r["marked"], 0, "must not mark an invisible message")
        self.assertFalse((self.store.msg_dir(gid, pre) / "readby" / "t68c").exists())
        # a member who CAN see it still works normally
        st, r = self.req("POST", "/api/message/viewed", user="t68b",
                         body={"gid": gid, "ids": [pre]})
        self.assertEqual(r["marked"], 1)

    def test_69_member_less_group_is_archived(self):
        # Everyone can leave a group; the folder then stays unreachable but was
        # still walked by list_groups and the storage recount forever.
        self.fresh("t69a", "t69b")
        _, g = self.req("POST", "/api/groups", user="t69a",
                        body={"name": "ghost", "members": ["t69b"]})
        gid = g["gid"]
        self.send_msg("t69a", "orphan", gid=gid)
        for u in ("t69a", "t69b"):
            self.req("POST", f"/api/groups/{gid}/members", user=u,
                     body={"remove": [u]})
        self.assertEqual(self.store.members(gid), [])
        chatserver.Janitor(self.store, interval=3600).clean()
        self.assertFalse(self.store.group_dir(gid).exists())
        # non-destructive: the data is parked, not deleted
        self.assertTrue((self.store.root / "archive" / gid).is_dir())

    # ---- security regressions (found in the v2 adversarial review) ----------

    def test_59_starred_enforces_join_gate(self):
        # "star, leave, rejoin, harvest": a star survives leaving the group, so
        # without a join-time gate the starred list serves content written
        # while the user was NOT a member — content history() correctly hides.
        self.fresh("t59a", "t59b")
        _, g = self.req("POST", "/api/groups", user="t59a",
                        body={"name": "s59", "members": ["t59b"]})
        gid = g["gid"]
        mid = self.send_msg("t59a", "v1 innocent", gid=gid)["id"]
        self.poll_until("t59b", lambda e: e["id"] == mid)
        self.req("POST", "/api/message/star", user="t59b",
                 body={"gid": gid, "mid": mid, "on": True})
        self.req("POST", f"/api/groups/{gid}/members", user="t59b",
                 body={"remove": ["t59b"]})
        self.req("POST", "/api/message/edit", user="t59a",
                 body={"gid": gid, "mid": mid, "text": "SECRET while away"})
        self.req("POST", f"/api/groups/{gid}/members", user="t59a",
                 body={"add": ["t59b"]})
        _, star = self.req("GET", "/api/starred", user="t59b")
        texts = [m["text"] for m in star["messages"]]
        self.assertNotIn("SECRET while away", texts)
        # and consistent with the other read paths
        status, _ = self.req("GET", f"/api/message/state/{gid}/{mid}",
                             user="t59b")
        self.assertEqual(status, 404)

    def test_60_reply_stub_hides_pre_join_content(self):
        # send() gates reply_to against the SENDER's join time, but the quote
        # is resolved at READ time — so a reply must not quote pre-join content
        # into a newly-added member's history.
        self.fresh("t60a", "t60b", "t60c")
        _, g = self.req("POST", "/api/groups", user="t60a",
                        body={"name": "s60", "members": ["t60b"]})
        gid = g["gid"]
        secret = self.send_msg("t60a", "SECRET pre-join content", gid=gid)["id"]
        self.poll_until("t60b", lambda e: e["id"] == secret)
        self.req("POST", f"/api/groups/{gid}/members", user="t60a",
                 body={"add": ["t60c"]})
        body = {"gid": gid, "text": "agreed", "reply_to": secret,
                "nonce": "n-" + os.urandom(8).hex()}
        status, rep = self.req("POST", "/api/messages", user="t60b", body=body)
        self.assertEqual(status, 200, rep)
        self.poll_until("t60c", lambda e: e["id"] == rep["id"])
        _, hist = self.req("GET", f"/api/groups/{gid}/messages", user="t60c")
        for m in hist["messages"]:
            self.assertNotIn("SECRET", (m.get("reply") or {}).get("text", ""))
        # the original member still sees the quote normally
        _, hist_b = self.req("GET", f"/api/groups/{gid}/messages", user="t60b")
        quoted = [(m.get("reply") or {}).get("text", "")
                  for m in hist_b["messages"] if m.get("reply")]
        self.assertTrue(any("SECRET" in q for q in quoted), quoted)

    def test_61_concurrent_delete_credits_storage_once(self):
        # The tombstone must be claimed atomically: two concurrent deletes both
        # passing the check credited the same bytes back twice, driving the
        # quota counter below reality and letting a user exceed their quota.
        import threading as _th
        self.fresh("t61a", "t61b")
        _, g = self.req("POST", "/api/groups", user="t61a",
                        body={"name": "s61", "members": ["t61b"]})
        gid = g["gid"]
        keep = self.upload("t61a", b"K" * 300_000, name="keep.bin")
        self.send_msg("t61a", "", gid=gid, files=[keep["file_id"]])
        up = self.upload("t61a", b"Z" * 100_000, name="drop.bin")
        mid = self.send_msg("t61a", "", gid=gid, files=[up["file_id"]])["id"]
        self.poll_until("t61b", lambda e: e["id"] == mid)
        barrier = _th.Barrier(2)

        def racer():
            barrier.wait()
            self.req("POST", "/api/message/delete", user="t61a",
                     body={"gid": gid, "mid": mid})
        ts = [_th.Thread(target=racer) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        # the counter must still agree with the bytes actually on disk
        self.assertEqual(self.store.storage_used("t61a"),
                         self.store.recount_storage("t61a"))

    def test_62_reactions_die_with_the_message(self):
        self.fresh("t62a", "t62b")
        sent = self.send_msg("t62a", "react then delete", to="t62b")
        mid, gid = sent["id"], sent["gid"]
        self.poll_until("t62b", lambda e: e["id"] == mid)
        self.req("POST", "/api/message/react", user="t62b",
                 body={"gid": gid, "mid": mid, "emoji": "👍"})
        self.req("POST", "/api/message/delete", user="t62a",
                 body={"gid": gid, "mid": mid})
        _, st = self.req("GET", f"/api/message/state/{gid}/{mid}", user="t62b")
        self.assertTrue(st["deleted"])
        self.assertFalse(st.get("reactions"), st.get("reactions"))
        # and you cannot react to a tombstone
        status, _ = self.req("POST", "/api/message/react", user="t62b",
                             body={"gid": gid, "mid": mid, "emoji": "❤️"})
        self.assertEqual(status, 400)

    def test_58_typing_is_rate_limited(self):
        # One typing ping wakes EVERY other member's parked long-poll, so it is
        # cheap to send and costs fan-out to serve. Without a cap a member can
        # spin every other member's client (and a server thread each) for free.
        self.fresh("t58a", "t58b")
        gid = self.send_msg("t58a", "hi", to="t58b")["gid"]
        seen = set()
        for _ in range(200):
            st, _ = self.req("POST", "/api/typing", user="t58a", body={"gid": gid})
            seen.add(st)
            if st == 429:
                break
        self.assertIn(429, seen, "typing must be rate limited")

    def test_57_storage_counter_self_heals(self):
        # The running counter is a CACHE, not a ledger: the janitor recomputes
        # it from the files, so drift (a missed credit-back, a crash, an admin
        # deleting files by hand) can't permanently inflate a user's usage and
        # lock them out of uploading.
        self.fresh("t57a", "t57b")
        up = self.upload("t57a", b"Z" * 5000, name="blob.bin")
        self.send_msg("t57a", "keep", to="t57b", files=[up["file_id"]])
        real = self.store.recount_storage("t57a")
        self.assertEqual(real, 5000)
        # simulate drift: pretend a credit-back was missed entirely
        self.store.write_atomic(
            self.store.user_dir("t57a") / "storage_used", b"999999999")
        self.assertEqual(self.store.storage_used("t57a"), 999999999)
        chatserver.Janitor(self.store, interval=3600).clean()   # one sweep
        self.assertEqual(self.store.storage_used("t57a"), 5000)

    def test_56_edit_delete_guards(self):
        self.fresh("t56a", "t56b")
        sent = self.send_msg("t56a", "guard me", to="t56b")
        mid, gid = sent["id"], sent["gid"]
        # wait for the router to move it into the group folder — until then it
        # legitimately 404s (it isn't in the group yet), which would mask the
        # 403 this test is actually about
        self.poll_until("t56b", lambda e: e["id"] == mid)
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

    # ---- hardening regressions (found by the input/crash fuzzers) -----------

    def test_70_lone_surrogate_body_is_rejected_not_500(self):
        # JSON permits "\ud800" (a lone surrogate) but UTF-8 cannot encode it,
        # so any endpoint that .encode()s the value used to 500. Every JSON body
        # must reject it at the door with a 400.
        self.fresh("t70a", "t70b")
        surrogate = "\ud800"
        # login password, send text, react emoji, edit text, group name
        st, _ = self.req("POST", "/api/login",
                         body={"user": "t70a", "password": surrogate})
        self.assertEqual(st, 400)
        st, _ = self.req("POST", "/api/messages", user="t70a",
                         body={"to": "t70b", "text": surrogate,
                               "nonce": "n-" + os.urandom(6).hex()})
        self.assertEqual(st, 400)
        st, _ = self.req("POST", "/api/groups", user="t70a",
                         body={"name": surrogate, "members": ["t70b"]})
        self.assertEqual(st, 400)

    def test_71_deeply_nested_json_is_rejected_not_500(self):
        # A "[[[[..." body blows json's C recursion limit; RecursionError must
        # be caught and turned into a 400, not surface as a 500. The body must
        # stay UNDER MAX_JSON (64 KB) or the size guard rejects it first and
        # this test never reaches json.loads at all.
        from internalchat.config import MAX_JSON
        body = b"[" * 60000
        self.assertLessEqual(len(body), MAX_JSON)
        r, _ = self.req("POST", "/api/login", raw=True, body=body,
                        headers={"Content-Type": "application/json"})
        self.assertEqual(r.status, 400)

    def test_72_non_ascii_digit_attachment_index_is_400(self):
        # str.isdigit() is True for "¹" (superscript one) but int("¹") raises
        # ValueError → 500. The index must be pinned to ASCII 0-9. (Driven at
        # the API layer: http.client can't put a non-ASCII byte in the request
        # line, which is why only a raw-socket fuzzer surfaced this.)
        from internalchat.errors import ApiError
        self.fresh("t72a", "t72b")
        gid = self.send_msg("t72a", "hi", to="t72b")["gid"]
        mid = self.send_msg("t72a", "hi2", gid=gid)["id"]
        with self.assertRaises(ApiError) as cm:
            self.api.attachment("t72a", gid, mid, "¹")
        self.assertEqual(cm.exception.status, 400)

    def test_73_deleted_attachment_is_not_downloadable(self):
        # "Delete for everyone" is a confidentiality promise: once a message is
        # tombstoned its attachment bytes must never be served, even if a crash
        # left the blobs on disk (attachment() consults the tombstone, not just
        # blob.is_file()).
        self.fresh("t73a", "t73b")
        up = self.upload("t73a", b"secret-bytes" * 50, name="s.bin")
        sent = self.send_msg("t73a", "", to="t73b", files=[up["file_id"]])
        gid, mid = sent["gid"], sent["id"]
        self.poll_until("t73b", lambda e: e["id"] == mid)  # wait for routing
        # it downloads before deletion
        r, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1",
                        user="t73a", raw=True)
        self.assertEqual(r.status, 200)
        # simulate a crash mid-delete: tombstone claimed, blobs NOT yet removed
        (self.store.msg_dir(gid, mid) / "deleted").touch()
        r, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1",
                        user="t73a", raw=True)
        self.assertEqual(r.status, 404)

    def test_75_id_clock_floor_survives_lost_hwm(self):
        # The persisted hwm is best-effort. If it is lost AND the wall clock
        # steps back, a fresh Store must still reconstruct a floor above every
        # existing join stamp (join-gate) and message id (history order, day
        # archiving) from the durable tree alone.
        self.fresh("t75a", "t75b")
        gid = self.send_msg("t75a", "before restart", to="t75b")["gid"]
        mid = self.send_msg("t75a", "newest", gid=gid)["id"]
        import time as _time
        for _ in range(60):          # wait for the router to file it
            if self.store.msg_dir(gid, mid).is_dir():
                break
            _time.sleep(0.05)
        (self.store.root / "id_hwm").unlink()          # simulate the lost hwm
        # ...and the backward clock step (without it, next_ts passes trivially
        # via now_ms and the floor is never exercised)
        import internalchat.store as smod
        real_now = smod.now_ms
        try:
            smod.now_ms = lambda: 1_000_000
            reopened = chatserver.Store(self.tmp, iters=1000)
            ts = reopened.next_ts()
        finally:
            smod.now_ms = real_now
        self.assertGreater(ts, int(mid[:13]))
        self.assertGreater(ts, self.store.joined_at(gid, "t75b"))

    def test_74_nan_wait_does_not_wedge_the_poll(self):
        # wait=nan used to leave the poll deadline as nan (never elapses),
        # wedging a worker thread. It must return promptly like wait=0.
        self.fresh("t74a")
        st, resp = self.req("GET", "/api/messages?wait=nan", user="t74a")
        self.assertEqual(st, 200)
        self.assertIn("queue", resp)

    # ---- blob caching / ranges / HEAD (the _send_blob hardening round) -------

    def routed_attachment(self, a, b, payload, name="blob.bin"):
        """Upload `payload` as `a`, send it to `b`, wait until routed;
        returns (gid, mid, upload-response). The wait is load-bearing, not
        politeness: the attachment path 404s while the message is still in
        incoming/, and poll_until only returns once the router has filed it
        into the group folder and queued b's entry."""
        up = self.upload(a, payload, name)
        sent = self.send_msg(a, "", to=b, files=[up["file_id"]])
        self.poll_until(b, lambda e: e["id"] == sent["id"])
        return sent["gid"], sent["id"], up

    def test_76_range_windows_are_byte_exact(self):
        # Seeking media is the point of ranges: every window must be
        # byte-exact — including the suffix ('bytes=-N') and open-ended
        # ('bytes=a-') forms — and a 206 must carry the same header set a
        # 200 does, or a ranged fetch becomes the weakest response.
        self.fresh("t76a", "t76b")
        payload = bytes(range(256)) * 4          # 1024 bytes, position-coded
        gid, mid, up = self.routed_attachment("t76a", "t76b", payload)
        url = f"/api/attachments/{gid}/{mid}/1"
        r, data = self.req("GET", url, user="t76b", raw=True)
        self.assertEqual((r.status, data), (200, payload))
        self.assertEqual(r.getheader("Accept-Ranges"), "bytes")  # advertised
        for hdr, s, e in (("bytes=0-99", 0, 99),
                          ("bytes=100-199", 100, 199),
                          ("bytes=1000-", 1000, 1023),     # open-ended tail
                          ("bytes=-24", 1000, 1023),       # suffix form
                          ("bytes=-9999", 0, 1023),        # suffix > file
                          ("bytes=500-9999", 500, 1023)):  # end clamped
            r, data = self.req("GET", url, user="t76b", raw=True,
                               headers={"Range": hdr})
            self.assertEqual(r.status, 206, hdr)
            self.assertEqual(data, payload[s:e + 1], hdr)
            self.assertEqual(r.getheader("Content-Range"),
                             f"bytes {s}-{e}/1024", hdr)
            self.assertEqual(r.getheader("Content-Length"), str(e - s + 1))
            # the full 200 header set rides on every 206
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
            self.assertEqual(r.getheader("Cross-Origin-Resource-Policy"),
                             "same-origin")
            self.assertEqual(r.getheader("ETag"), f'"{up["sha256"]}"')
            self.assertIn("immutable", r.getheader("Cache-Control"))
            self.assertIn("attachment", r.getheader("Content-Disposition"))
        self.confirm("t76b", [mid])

    def test_77_range_416_and_malformed_fall_back_to_200(self):
        self.fresh("t77a", "t77b")
        payload = os.urandom(300)
        gid, mid, _ = self.routed_attachment("t77a", "t77b", payload)
        url = f"/api/attachments/{gid}/{mid}/1"
        # a start at/past EOF and the zero-byte suffix are unsatisfiable
        for hdr in ("bytes=300-", "bytes=300-400", "bytes=5000-6000",
                    "bytes=-0"):
            r, data = self.req("GET", url, user="t77b", raw=True,
                               headers={"Range": hdr})
            self.assertEqual(r.status, 416, hdr)
            self.assertEqual(r.getheader("Content-Range"), "bytes */300", hdr)
            self.assertEqual(data, b"", hdr)
        # malformed and multipart ranges are IGNORED (RFC-permitted): full
        # 200. "¹" exercises the ASCII pin (isdigit() passes, int() raises).
        for hdr in ("bytes=abc", "bytes=5-2", "bytes=0-5,10-20", "bytes=¹-5",
                    "bites=0-5", "bytes=--3", "bytes=", "bytes=5"):
            r, data = self.req("GET", url, user="t77b", raw=True,
                               headers={"Range": hdr})
            self.assertEqual(r.status, 200, hdr)
            self.assertEqual(data, payload, hdr)
        self.confirm("t77b", [mid])

    def test_78_if_range_gates_the_partial(self):
        # If-Range: a resuming client proves it holds the same bytes; on any
        # mismatch the server must send the WHOLE file, or the client would
        # splice halves of two different representations together.
        self.fresh("t78a", "t78b")
        payload = os.urandom(512)
        gid, mid, up = self.routed_attachment("t78a", "t78b", payload)
        url = f"/api/attachments/{gid}/{mid}/1"
        etag = f'"{up["sha256"]}"'
        r, data = self.req("GET", url, user="t78b", raw=True,
                           headers={"Range": "bytes=100-199",
                                    "If-Range": etag})
        self.assertEqual((r.status, data), (206, payload[100:200]))
        # wrong etag, and a weak validator (If-Range is strong-only per RFC)
        for stale in ('"deadbeef"', "W/" + etag):
            r, data = self.req("GET", url, user="t78b", raw=True,
                               headers={"Range": "bytes=100-199",
                                        "If-Range": stale})
            self.assertEqual(r.status, 200, stale)
            self.assertEqual(data, payload, stale)
        self.confirm("t78b", [mid])

    def test_79_if_none_match_returns_bodiless_304(self):
        self.fresh("t79a", "t79b")
        payload = os.urandom(256)
        gid, mid, up = self.routed_attachment("t79a", "t79b", payload)
        url = f"/api/attachments/{gid}/{mid}/1"
        etag = f'"{up["sha256"]}"'
        r, _ = self.req("GET", url, user="t79b", raw=True)
        self.assertEqual(r.getheader("ETag"), etag)
        self.assertEqual(r.getheader("Cache-Control"),
                         "private, max-age=31536000, immutable")
        # exact, weak-prefixed, listed, and wildcard forms all revalidate
        for inm in (etag, "W/" + etag, f'"nope", {etag}', "*"):
            r, data = self.req("GET", url, user="t79b", raw=True,
                               headers={"If-None-Match": inm})
            self.assertEqual(r.status, 304, inm)
            self.assertEqual(data, b"", inm)          # NO body on a 304
            self.assertEqual(r.getheader("ETag"), etag, inm)
            self.assertIn("immutable", r.getheader("Cache-Control"), inm)
        # a non-matching validator serves the bytes
        r, data = self.req("GET", url, user="t79b", raw=True,
                           headers={"If-None-Match": '"deadbeef"'})
        self.assertEqual((r.status, data), (200, payload))
        self.confirm("t79b", [mid])

    def test_80_head_mirrors_get_without_a_body(self):
        self.fresh("t80a", "t80b")
        payload = os.urandom(400)
        gid, mid, _ = self.routed_attachment("t80a", "t80b", payload)
        url = f"/api/attachments/{gid}/{mid}/1"
        g, _ = self.req("GET", url, user="t80b", raw=True)
        h, hbody = self.req("HEAD", url, user="t80b", raw=True)
        self.assertEqual(h.status, 200)
        self.assertEqual(hbody, b"")
        for hdr in ("Content-Type", "Content-Length", "Content-Disposition",
                    "X-Content-Type-Options", "Cross-Origin-Resource-Policy",
                    "Accept-Ranges", "ETag", "Cache-Control"):
            self.assertEqual(h.getheader(hdr), g.getheader(hdr), hdr)
        self.assertEqual(h.getheader("Content-Length"), str(len(payload)))
        # HEAD rides the same dispatch for JSON endpoints too: the true
        # Content-Length of the body that a GET would send, and no body
        _, jbody = self.req("GET", f"/api/groups/{gid}", user="t80b",
                            raw=True)
        hj, hjbody = self.req("HEAD", f"/api/groups/{gid}", user="t80b",
                              raw=True)
        self.assertEqual((hj.status, hjbody), (200, b""))
        self.assertEqual(hj.getheader("Content-Length"), str(len(jbody)))
        # HEAD then GET on the SAME socket: the bodiless HEAD must not desync
        # framing, and the suppress flag must reset per request (a sticky
        # flag would silently strip the GET's body too)
        auth = {"Authorization": "Bearer " + self.tokens["t80b"]}
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=40)
        try:
            conn.request("HEAD", url, headers=auth)
            r = conn.getresponse()
            self.assertEqual((r.status, r.read()), (200, b""))
            conn.request("GET", url, headers=auth)
            r = conn.getresponse()
            self.assertEqual((r.status, r.read()), (200, payload))
        finally:
            conn.close()
        self.confirm("t80b", [mid])

    def test_81_keepalive_survives_206_304_and_truncation(self):
        # THE framing pin: after a 206, a 304, and a response for a blob
        # whose file was hand-truncated behind its meta, the SAME connection
        # must serve a next request that still parses. Any Content-Length
        # that doesn't match the bytes actually sent makes the client read
        # the next response's status line as body tail (or hang forever) —
        # the bug class the fstat-based sizing exists to kill.
        self.fresh("t81a", "t81b")
        payload = bytes(range(256)) * 2               # 512 bytes
        gid, mid, up = self.routed_attachment("t81a", "t81b", payload)
        url = f"/api/attachments/{gid}/{mid}/1"
        etag = f'"{up["sha256"]}"'
        auth = {"Authorization": "Bearer " + self.tokens["t81b"]}
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=40)
        try:
            # (i) a 206, then a full GET on the SAME socket
            conn.request("GET", url, headers=dict(auth, Range="bytes=10-19"))
            r = conn.getresponse()
            self.assertEqual((r.status, r.read()), (206, payload[10:20]))
            conn.request("GET", url, headers=auth)
            r = conn.getresponse()
            self.assertEqual((r.status, r.read()), (200, payload))
            # (ii) a 304, then a full GET on the SAME socket
            conn.request("GET", url,
                         headers=dict(auth, **{"If-None-Match": etag}))
            r = conn.getresponse()
            self.assertEqual((r.status, r.read()), (304, b""))
            conn.request("GET", url, headers=auth)
            r = conn.getresponse()
            self.assertEqual((r.status, r.read()), (200, payload))
            # (iii) truncate the blob BEHIND its meta: Content-Length must
            # come from the file (fstat), not meta['size'], and the
            # connection must stay usable afterwards
            blob = self.store.msg_dir(gid, mid) / "attachments" / "1"
            with open(blob, "r+b") as bf:
                bf.truncate(100)
            conn.request("GET", url, headers=auth)
            r = conn.getresponse()
            self.assertEqual(r.getheader("Content-Length"), "100")
            self.assertEqual((r.status, r.read()), (200, payload[:100]))
            conn.request("GET", url, headers=auth)     # framing still sound
            r = conn.getresponse()
            self.assertEqual((r.status, r.read()), (200, payload[:100]))
        finally:
            conn.close()
        self.confirm("t81b", [mid])

    def test_82_corrupt_meta_is_404_not_500(self):
        # A crash-partial or hand-edited .meta must degrade to "not found",
        # mirroring render_msg's tolerant parse — never a 500, and never a
        # blob served under headers derived from garbage.
        self.fresh("t82a", "t82b")
        gid, mid, _ = self.routed_attachment("t82a", "t82b", b"bytes here")
        metaf = self.store.msg_dir(gid, mid) / "attachments" / "1.meta"
        for garbage in (b"not json {{{", b"[1, 2, 3]", b'{"nope": 1}'):
            metaf.write_bytes(garbage)
            status, resp = self.req("GET", f"/api/attachments/{gid}/{mid}/1",
                                    user="t82b")
            self.assertEqual(status, 404, (garbage, resp))
        self.confirm("t82b", [mid])

    def test_83_blob_header_posture(self):
        # HSTS is only ever sent over TLS (the spec forbids it on plain HTTP
        # and _hsts() checks the socket), so over this plain-HTTP test server
        # we assert its ABSENCE plus the presence of everything else the blob
        # path promises: CORP on downloads AND inline (no longer
        # inline-only), immutable caching, and the sha256 ETag.
        self.fresh("t83a", "t83b")
        gid, mid, up = self.routed_attachment("t83a", "t83b", self.PNG_1PX,
                                              name="p.png")
        for q in ("", "?inline=1"):
            r, _ = self.req("GET", f"/api/attachments/{gid}/{mid}/1{q}",
                            user="t83b", raw=True)
            self.assertEqual(r.status, 200, q)
            self.assertIsNone(r.getheader("Strict-Transport-Security"), q)
            self.assertEqual(r.getheader("Cross-Origin-Resource-Policy"),
                             "same-origin", q)
            self.assertEqual(r.getheader("Cache-Control"),
                             "private, max-age=31536000, immutable", q)
            self.assertEqual(r.getheader("ETag"), f'"{up["sha256"]}"', q)
            self.assertEqual(r.getheader("X-Content-Type-Options"),
                             "nosniff", q)
        self.confirm("t83b", [mid])

    def test_84_hostile_upload_matrix_posture(self):
        # The posture net (see 'Security posture — do NOT weaken' in API.md):
        # media keys appear ONLY per the util.py magic-byte allowlists, the
        # filename and X-Media-Kind can never escalate a non-media file,
        # unverified bytes stay forced octet-stream downloads even with
        # inline=1, and every inline grant carries the sandbox CSP.
        self.fresh("t84a", "t84b")
        matrix = [   # (name-that-lies, hostile bytes, media key or None, hint)
            ("doc.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3 1 0 obj<<>>",
             None, True),
            ("art.svg", b'<svg xmlns="http://www.w3.org/2000/svg">'
                        b"<script>alert(1)</script></svg>", None, True),
            ("shot.png", b"<html><body><script>alert(1)</script>",
             None, True),
            ("data.xml", b'<?xml version="1.0"?><r/>', None, True),
            ("pix.bmp", b"BM\x36\x00\x00\x00" + b"\x00" * 32, None, True),
            ("scan.tiff", b"II*\x00\x08\x00\x00\x00" + b"\x00" * 24,
             None, True),
            ("scan2.tiff", b"MM\x00*\x00\x00\x00\x08" + b"\x00" * 24,
             None, True),
            ("icon.ico", b"\x00\x00\x01\x00\x01\x00" + b"\x00" * 32,
             None, True),
            # real mp4 bytes behind a lying .png name: the magic bytes win
            # (video), the name is irrelevant. No hint here — on a genuine
            # A/V container the hint may legitimately narrow video → audio,
            # which is presentation, not escalation (test_65 covers it).
            ("clip.png", self._bmff(b"isom") + b"\x00" * 64, "video", False),
        ]
        for name, payload, want, hint in matrix:
            up = self.upload("t84a", payload, name, audio_hint=hint)
            for key in ("image", "audio", "video"):
                if key != want:
                    self.assertNotIn(key, up,
                                     f"{name}: {key} granted off-allowlist")
            if want:
                self.assertIn(want, up, name)
            sent = self.send_msg("t84a", "", to="t84b",
                                 files=[up["file_id"]])
            self.poll_until("t84b", lambda e, m=sent["id"]: e["id"] == m)
            r, _ = self.req(
                "GET",
                f"/api/attachments/{sent['gid']}/{sent['id']}/1?inline=1",
                user="t84b", raw=True)
            self.assertEqual(r.status, 200, name)
            self.assertEqual(r.getheader("X-Content-Type-Options"),
                             "nosniff", name)
            if want is None:
                # unverified bytes: inline=1 is ignored outright
                self.assertEqual(r.getheader("Content-Type"),
                                 "application/octet-stream", name)
                self.assertTrue(r.getheader("Content-Disposition")
                                .startswith("attachment"), name)
                self.assertIsNone(r.getheader("Content-Security-Policy"),
                                  name)
            else:
                # every inline grant carries the sandbox CSP
                self.assertIn("sandbox",
                              r.getheader("Content-Security-Policy"), name)
                self.assertTrue(r.getheader("Content-Disposition")
                                .startswith("inline"), name)
            self.confirm("t84b", [sent["id"]])


    # ---- sender-generated thumbnails (rank 7 of the media plan) -------------

    PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200

    def send_thumb(self, user, fid, body, dims=None):
        headers = {}
        if dims is not None:
            headers["X-Media-Dims"] = dims
        return self.req("POST", f"/api/files/{fid}/thumb", user=user,
                        body=body, headers=headers)

    def test_85_thumbnail_roundtrip(self):
        self.fresh("t85a", "t85b")
        up = self.upload("t85a", self.PNG + b"orig" * 500, name="photo.png")
        thumb = self.PNG + b"tiny"
        st, r = self.send_thumb("t85a", up["file_id"], thumb, dims="800x600")
        self.assertEqual(st, 200, r)
        self.assertEqual(r["thumb"], "image/png")
        sent = self.send_msg("t85a", "pic", to="t85b", files=[up["file_id"]])
        gid, mid = sent["gid"], sent["id"]
        ev = self.poll_until("t85b", lambda e: e["id"] == mid)
        _, m = self.req("GET", f"/api/message/dequeue/{mid}", user="t85b")
        a = m["attachments"][0]
        self.assertTrue(a.get("thumb"))
        self.assertEqual((a.get("w"), a.get("h")), (800, 600))
        # the preview serves through the same hardened blob path: verified
        # inline type, its own sha256 ETag, sandbox CSP
        r2, body = self.req(
            "GET", f"/api/attachments/{gid}/{mid}/1?thumb=1&inline=1",
            user="t85b", raw=True)
        self.assertEqual(r2.status, 200)
        self.assertEqual(body, thumb)
        self.assertEqual(r2.headers["Content-Type"], "image/png")
        self.assertIn("sandbox", r2.headers.get("Content-Security-Policy", ""))
        self.assertEqual(r2.headers.get("ETag"),
                         '"%s"' % __import__("hashlib").sha256(thumb).hexdigest())
        # the original is untouched under the plain path
        r3, body3 = self.req(f"GET", f"/api/attachments/{gid}/{mid}/1",
                             user="t85b", raw=True)
        self.assertEqual(body3, self.PNG + b"orig" * 500)
        # an attachment whose sender provided no thumb 404s under ?thumb=1
        up2 = self.upload("t85a", self.PNG + b"other", name="p2.png")
        sent2 = self.send_msg("t85a", "", gid=gid, files=[up2["file_id"]])
        self.poll_until("t85b", lambda e: e["id"] == sent2["id"])
        st4, _ = self.req(
            "GET", f"/api/attachments/{gid}/{sent2['id']}/1?thumb=1",
            user="t85b")
        self.assertEqual(st4, 404)
        self.confirm("t85b", [ev["entry"]])

    def test_86_thumbnail_posture_and_edges(self):
        self.fresh("t86a", "t86b")
        up = self.upload("t86a", self.PNG + b"x", name="a.png")
        fid = up["file_id"]
        # non-image bytes can never become a servable "image" preview
        st, _ = self.send_thumb("t86a", fid, b"<html>not an image</html>")
        self.assertEqual(st, 400)
        # over the 64 KiB cap
        st, _ = self.send_thumb("t86a", fid, self.PNG + b"\x00" * (64 * 1024))
        self.assertEqual(st, 413)
        # unknown fid / someone else's fid (staged dirs are per-user)
        st, _ = self.send_thumb("t86a", "0" * 32, self.PNG)
        self.assertEqual(st, 404)
        st, _ = self.send_thumb("t86b", fid, self.PNG)
        self.assertEqual(st, 404)
        # garbage dims are ignored, not an error; then a second thumb is a 409
        st, r = self.send_thumb("t86a", fid, self.PNG + b"t", dims="0x999999")
        self.assertEqual(st, 200, r)
        # a pathologically long digit string must be IGNORED, not crash int()
        # (Python's 4300-digit conversion limit) and get dropped as a bad 409
        up2 = self.upload("t86a", self.PNG + b"z", name="b.png")
        st, r = self.send_thumb("t86a", up2["file_id"], self.PNG + b"t",
                                dims=("1" * 5000) + "x5")
        self.assertEqual(st, 200, r)   # accepted; over-long dims just ignored
        st, _ = self.send_thumb("t86a", fid, self.PNG + b"t2")
        self.assertEqual(st, 409)
        sent = self.send_msg("t86a", "", to="t86b", files=[fid])
        self.poll_until("t86b", lambda e: e["id"] == sent["id"])
        _, m = self.req("GET", f"/api/message/dequeue/{sent['id']}",
                        user="t86b")
        a = m["attachments"][0]
        self.assertTrue(a.get("thumb"))
        self.assertNotIn("w", a)     # the bad dims header left no dimensions

    def test_87_thumbnail_quota_accounting(self):
        self.fresh("t87a", "t87b")
        base = self.store.storage_used("t87a")
        # exact byte budgets (PNG magic is 8 bytes): blob 1000, thumb 200
        blob = b"\x89PNG\r\n\x1a\n" + b"B" * 992
        thumb = b"\x89PNG\r\n\x1a\n" + b"T" * 192
        up = self.upload("t87a", blob, name="q.png")
        st, _ = self.send_thumb("t87a", up["file_id"], thumb)
        self.assertEqual(st, 200)
        self.assertEqual(self.store.storage_used("t87a"), base + 1200)
        sent = self.send_msg("t87a", "", to="t87b", files=[up["file_id"]])
        self.poll_until("t87b", lambda e: e["id"] == sent["id"])
        # the recount (janitor truth) agrees: routed blob + thumb both counted
        self.assertEqual(self.store.recount_all_storage()["t87a"], base + 1200)
        # delete-for-everyone credits blob AND thumb back
        self.req("POST", "/api/message/delete", user="t87a",
                 body={"gid": sent["gid"], "mid": sent["id"]})
        self.assertEqual(self.store.storage_used("t87a"), base)
        # an expired staged pair (blob+meta+thumb) is pruned and credited
        up2 = self.upload("t87a", blob, name="q2.png")
        st, _ = self.send_thumb("t87a", up2["file_id"], thumb)
        self.assertEqual(st, 200)
        staged = self.store.user_dir("t87a") / "staged"
        for suffix in ("", ".meta", ".thumb"):
            f = staged / (up2["file_id"] + suffix)
            os.utime(f, (1, 1))               # ancient: way past the 24h TTL
        chatserver.Janitor(self.store, interval=3600).clean()
        self.assertEqual(self.store.storage_used("t87a"), base)
        self.assertFalse((staged / (up2["file_id"] + ".thumb")).exists())


    # ---- the passwd-style roster: only pre-approved users may connect ------

    def roster_server(self, roster_text=None, users=("ra", "rb", "rc", "rd")):
        """An isolated server (the class fixture must stay allowlist-free).
        Accounts are provisioned BEFORE the roster file exists, so a test can
        describe an account the roster then revokes — and so add_user's own
        roster check isn't what's under test here."""
        tmp = tempfile.mkdtemp(prefix="chat-roster-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        boot = chatserver.Store(tmp, iters=1000)
        for u in users:
            boot.add_user(u, "pw-" + u, must_change=False)
        pw = chatserver.Path(tmp) / "passwd"
        if roster_text is not None:
            pw.write_text(roster_text)
        store = chatserver.Store(tmp, iters=1000)   # arms enforcement, or not
        httpd, router, api = chatserver.build_server(store, "127.0.0.1", 0)
        api.login_ip_limiter.limit = 1_000_000
        api.login_limiter.limit = 1_000_000
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        self.addCleanup(router.stopping.set)
        return store, httpd.server_address[1], pw

    @staticmethod
    def rreq(port, method, path, token=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        hdrs = {}
        if token:
            hdrs["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, data, hdrs)
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        return r.status, (json.loads(payload) if payload else None)

    def rlogin(self, port, user):
        return self.rreq(port, "POST", "/api/login",
                         body={"user": user, "password": "pw-" + user})

    def test_88_roster_gates_login_and_live_sessions(self):
        store, port, pw = self.roster_server("# who may connect\nra:Ray A\n")
        st, body = self.rlogin(port, "ra")
        self.assertEqual(st, 200, body)
        self.assertEqual(body["display"], "Ray A")   # roster display wins
        token = body["token"]
        # rb's password is correct and the account is fine — it is simply not
        # approved, and the answer is byte-identical to a wrong password
        st, denied = self.rlogin(port, "rb")
        self.assertEqual(st, 401)
        self.assertEqual(denied["error"], "bad credentials")
        st, _ = self.rreq(port, "GET", "/api/groups", token=token)
        self.assertEqual(st, 200)
        # REVOCATION REACHES A LIVE SESSION: removing the line must log ra
        # out of an already-issued token, not merely stop the next login
        pw.write_text("# everyone revoked\n")
        st, _ = self.rreq(port, "GET", "/api/groups", token=token)
        self.assertEqual(st, 401)
        # ...and the session marker is kept, so re-approving restores access
        # without forcing a fresh login (a transient denial isn't destructive)
        pw.write_text("ra\n")
        st, _ = self.rreq(port, "GET", "/api/groups", token=token)
        self.assertEqual(st, 200)

    def test_89_roster_parsing_edges(self):
        store, port, pw = self.roster_server(
            "\n"
            "# a comment\n"
            "   \n"
            "  ra : Ray Anderson \n"      # surrounding whitespace tolerated
            "rb:Bee B:disabled\n"         # record kept, account blocked
            "rc:See C:disbaled\n"         # TYPO'd flag must fail CLOSED
            "NOT A NAME:x\n"              # invalid username, ignored
            "rd:First\n"
            "rd:Second\n")                # duplicate: first wins
        r = store.roster
        self.assertTrue(r.enforcing)
        self.assertTrue(r.allows("ra"))
        self.assertEqual(r.display("ra"), "Ray Anderson")
        self.assertFalse(r.allows("rb"))     # disabled
        self.assertFalse(r.allows("rc"))     # unknown flag -> denied, not allowed
        self.assertTrue(r.allows("rd"))
        self.assertEqual(r.display("rd"), "First")
        self.assertFalse(r.allows("nobody"))
        for user, want in (("ra", 200), ("rb", 401), ("rc", 401), ("rd", 200)):
            st, _ = self.rlogin(port, user)
            self.assertEqual(st, want, user)

    def test_90_unreadable_roster_denies_everyone(self):
        store, port, pw = self.roster_server("ra\n")
        st, body = self.rlogin(port, "ra")
        self.assertEqual(st, 200)
        token = body["token"]
        sessions = store.user_dir("ra") / "sessions"
        # a corrupt roster is NOT evidence that everyone is allowed
        pw.write_bytes(b"ra\n\xff\xfe not utf-8\n")
        st, _ = self.rreq(port, "GET", "/api/groups", token=token)
        self.assertEqual(st, 401)
        self.assertEqual(len(list(sessions.iterdir())), 1)  # marker kept
        # nor is deleting it: `rm passwd` must not switch the control off
        pw.unlink()
        st, _ = self.rreq(port, "GET", "/api/groups", token=token)
        self.assertEqual(st, 401)
        st, _ = self.rlogin(port, "ra")
        self.assertEqual(st, 401)
        pw.write_text("ra\n")                    # restored -> access returns
        st, _ = self.rreq(port, "GET", "/api/groups", token=token)
        self.assertEqual(st, 200)

    def test_91_enforcement_is_pinned_at_startup(self):
        # started with no roster: the allowlist is OFF for this process, and
        # writing the file later must not silently arm it mid-flight (that
        # would lock out every account not yet listed)
        store, port, pw = self.roster_server(None)
        self.assertFalse(store.roster.enforcing)
        for user in ("ra", "rb"):
            st, _ = self.rlogin(port, user)
            self.assertEqual(st, 200)
        pw.write_text("ra\n")
        st, _ = self.rlogin(port, "rb")
        self.assertEqual(st, 200, "arming needs a restart, by design")
        # a fresh Store over the same dir DOES pick it up
        self.assertTrue(chatserver.Store(store.root, iters=1000).roster.enforcing)

    def test_92_revoked_user_is_not_addressable(self):
        store, port, pw = self.roster_server("ra\nrb\n")
        _, a = self.rlogin(port, "ra")
        ta = a["token"]
        st, users = self.rreq(port, "GET", "/api/users", token=ta)
        self.assertEqual(sorted(u["user"] for u in users["users"]), ["ra", "rb"])
        pw.write_text("ra\n")               # rb revoked
        st, users = self.rreq(port, "GET", "/api/users", token=ta)
        self.assertEqual([u["user"] for u in users["users"]], ["ra"])
        # nothing sent to a revoked account could ever be read, so refuse it
        st, _ = self.rreq(port, "POST", "/api/messages", token=ta,
                          body={"to": "rb", "text": "hi",
                                "nonce": "nonce-revoked-1"})
        self.assertEqual(st, 404)
        st, _ = self.rreq(port, "POST", "/api/groups", token=ta,
                          body={"name": "g", "members": ["rb"]})
        self.assertEqual(st, 404)
        st, g = self.rreq(port, "POST", "/api/groups", token=ta,
                          body={"name": "g", "members": ["rc"]})
        self.assertEqual(st, 404)           # rc has an account but no entry
        # provisioning an account that could never log in is refused too
        with self.assertRaises(chatserver.ApiError) as cm:
            store.add_user("newbie", "pw-newbie")
        self.assertEqual(cm.exception.status, 403)

    def test_93_cli_roster_flow(self):
        tmp = tempfile.mkdtemp(prefix="chat-cli-roster-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        pw = chatserver.Path(tmp) / "passwd"
        pw.write_text("listed:Listed User\n")
        # an approved name provisions, and takes the roster's display name
        chatserver.main(["adduser", "listed", "--data", tmp,
                         "--password", "pw-listed", "--no-change"])
        store = chatserver.Store(tmp, iters=1000)
        auth = json.loads((store.user_dir("listed") / "auth.json").read_text())
        self.assertEqual(auth["display"], "Listed User")
        # an unlisted one is refused...
        with self.assertRaises(SystemExit):
            chatserver.main(["adduser", "walkin", "--data", tmp,
                             "--password", "pw-walkin"])
        self.assertFalse((store.user_dir("walkin")).exists())
        # ...unless the operator approves it in the same breath
        chatserver.main(["adduser", "walkin", "--data", tmp, "--approve",
                         "--display", "Walk In", "--password", "pw-walkin",
                         "--no-change"])
        self.assertIn("walkin:Walk In", pw.read_text())
        self.assertTrue(chatserver.Store(tmp, iters=1000).roster.allows("walkin"))
        # a mistyped --roster must NOT be read as "no allowlist"
        with self.assertRaises(SystemExit):
            chatserver.main(["roster", "--data", tmp,
                             "--roster", os.path.join(tmp, "nope")])
        chatserver.main(["roster", "--data", tmp])   # prints, must not raise

    def test_94_revocation_interrupts_a_parked_long_poll(self):
        # a poll parked for 30s was authorized when it started; revoking must
        # cut the live feed promptly, not when its deadline happens to expire
        import time as _time
        store, port, pw = self.roster_server("ra\n")
        _, a = self.rlogin(port, "ra")
        token = a["token"]
        out = {}

        def poll():
            out["r"] = self.rreq(port, "GET", "/api/messages?wait=25",
                                 token=token)
        t = threading.Thread(target=poll)
        t.start()
        _time.sleep(0.5)                 # let it park
        pw.write_text("# revoked\n")
        t.join(timeout=10)
        self.assertFalse(t.is_alive(), "parked poll ignored the revocation")
        self.assertEqual(out["r"][0], 401)

    def test_95_roster_reload_under_concurrent_rewrite(self):
        """Hammer the auth paths while the file is rewritten underneath them.
        The invariant that must never bend: a user who is not in ANY version
        of the file never gets a 200 — a half-read or mid-swap roster has to
        deny, never guess."""
        import time as _time
        store, port, pw = self.roster_server("ra\n")
        toks = {}
        for u in ("ra", "rc"):
            # rc is briefly listed only to obtain a token, then never again
            pw.write_text("ra\nrc\n")
            st, b = self.rlogin(port, u)
            self.assertEqual(st, 200, b)
            toks[u] = b["token"]
        pw.write_text("ra\n")
        stop = threading.Event()
        seen = {"ra": set(), "rc": set()}
        errors = []

        def hammer(user):
            try:
                while not stop.is_set():
                    st, _ = self.rreq(port, "GET", "/api/groups",
                                      token=toks[user])
                    seen[user].add(st)
            except Exception as e:      # a connection error is a failure too
                errors.append(repr(e))

        threads = [threading.Thread(target=hammer, args=(u,))
                   for u in ("ra", "ra", "rc", "rc")]
        for t in threads:
            t.start()
        # rewrite ATOMICALLY (tmp + rename), the way an editor does: a reader
        # then sees one whole version or the other, never a torn file
        tmp = pw.with_suffix(".tmp")
        for i in range(60):
            tmp.write_text("ra:Ray\n" if i % 2 else "ra:Ray\n# churn\n")
            os.replace(tmp, pw)
            _time.sleep(0.005)
        stop.set()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(seen["rc"], {401}, "an unlisted user was let in")
        self.assertIn(200, seen["ra"], "the listed user was never served")
        self.assertNotIn(500, seen["ra"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
