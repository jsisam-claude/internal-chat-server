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

        # bad login + rate limiting
        for i in range(12):
            status, _ = self.req("POST", "/api/login",
                                 body={"user": "carol", "password": "wrong"})
        self.assertEqual(status, 429)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
