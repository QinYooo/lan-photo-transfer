import concurrent.futures
import contextlib
import hashlib
import http.client
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import receiver
from verify_received import verify


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.TemporaryDirectory()
        cls.state = receiver.TransferState(Path(cls.root.name), token="test-strong-session-secret", max_file_bytes=4 * 1024**2)
        cls.server = receiver.ReceiverServer(("127.0.0.1", 0), cls.state)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.root.cleanup()

    def request(self, path, body=None, headers=None, method="GET", auth=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        all_headers = {"Authorization": "Bearer " + self.state.token} if auth else {}
        all_headers.update(headers or {})
        conn.request(method, path, body=body, headers=all_headers)
        response = conn.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        conn.close()
        return result

    def upload(self, data=b"photo-original-bytes", name="IMG_0001.JPG", upload_id=None, digest=True, extra=None):
        headers = {"X-File-Name": quote(name, safe=""), "X-File-Size": str(len(data)),
                   "X-Upload-ID": upload_id or receiver.secrets.token_hex(16)}
        if digest:
            headers["X-File-SHA256"] = hashlib.sha256(data).hexdigest() if digest is True else digest
        headers.update(extra or {})
        status, reply_headers, body = self.request("/api/upload", data, headers, "POST")
        return status, json.loads(body)

    def test_01_auth_required(self):
        for route in ("/api/status", "/api/receipt?upload_id=abcdefghijklmnop"):
            self.assertEqual(self.request(route, auth=False)[0], 401)
            self.assertEqual(self.request(route, headers={"Authorization": "Bearer bad"})[0], 401)

    def test_02_status(self):
        status, headers, body = self.request("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["hash_algorithm"], "SHA-256")
        self.assertNotIn(str(Path(self.root.name).parent), body.decode())
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_03_static_paths(self):
        for route in ("/", "/static/app.js", "/static/style.css", "/static/hash.js", "/static/hash-worker.js"):
            status, headers, body = self.request(route, auth=False)
            self.assertEqual(status, 200, route)
            self.assertTrue(body)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_04_no_file_or_directory_serving(self):
        for route in ("/../receiver.py", "/static/../receiver.py", "/Photos_Inbox/", "/transfer_manifest.jsonl", "/api/report"):
            self.assertEqual(self.request(route)[0], 404)

    def test_05_host_and_origin_guard(self):
        self.assertEqual(self.request("/api/status", headers={"Host": "evil.example:" + str(self.port)})[0], 403)
        self.assertEqual(self.request("/api/status", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request("/api/status", headers={"Origin": "null"})[0], 403)
        self.assertEqual(self.request("/api/status", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.request("/api/status", headers={"Origin": "http://127.0.0.1:" + str(self.port)})[0], 200)

    def test_06_verified_exact_bytes(self):
        data = bytes(range(256)) * 8193
        status, receipt = self.upload(data, "原片🖼️.HEIC", extra={"X-File-Last-Modified": "1700000000123"})
        self.assertEqual(status, 200)
        self.assertEqual(receipt["verification"], "client_sha256_match")
        self.assertEqual(receipt["source_last_modified_ms"], 1700000000123)
        self.assertEqual((self.state.output / receipt["saved_name"]).read_bytes(), data)
        self.assertEqual(receipt["sha256"], hashlib.sha256(data).hexdigest())

    def test_07_empty_file(self):
        status, receipt = self.upload(b"", "empty.jpg")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["size"], 0)
        self.assertEqual(receipt["sha256"], hashlib.sha256(b"").hexdigest())

    def test_08_server_only_is_distinct(self):
        status, receipt = self.upload(digest=False)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["verification"], "server_only")
        self.assertIsNone(receipt["client_sha256"])

    def test_09_mismatch_rejected_and_cleaned(self):
        before = set(self.state.output.iterdir())
        status, _ = self.upload(digest="0" * 64)
        self.assertEqual(status, 422)
        self.assertEqual(set(self.state.output.iterdir()), before)
        self.assertEqual(list(self.state.partial.iterdir()), [])

    def test_10_no_overwrite(self):
        status1, first = self.upload(b"first", "same.jpg")
        status2, second = self.upload(b"second", "same.jpg")
        self.assertEqual((status1, status2), (200, 200))
        self.assertNotEqual(first["saved_name"], second["saved_name"])
        self.assertEqual((self.state.output / first["saved_name"]).read_bytes(), b"first")

    def test_11_idempotent_retry_and_receipt(self):
        key = receiver.secrets.token_hex(16)
        status, first = self.upload(upload_id=key)
        status2, again = self.upload(upload_id=key)
        self.assertEqual((status, status2), (200, 200))
        self.assertTrue(again["replayed"])
        self.assertEqual(first["saved_name"], again["saved_name"])
        status, _, body = self.request("/api/receipt?upload_id=" + key)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["saved_name"], first["saved_name"])
        status, _ = self.upload(data=b"different", upload_id=key)
        self.assertEqual(status, 409)

    def test_12_unknown_and_inflight_receipt(self):
        key = receiver.secrets.token_hex(16)
        self.assertEqual(self.request("/api/receipt?upload_id=" + key)[0], 404)
        with self.state.lock:
            self.state.inflight.add(key)
        try:
            self.assertEqual(self.request("/api/receipt?upload_id=" + key)[0], 202)
            self.assertEqual(self.upload(upload_id=key)[0], 409)
        finally:
            self.state.inflight.remove(key)

    def test_13_size_mismatch(self):
        self.assertEqual(self.upload(extra={"X-File-Size": "999"})[0], 400)

    def test_14_oversize_early_rejection(self):
        headers = {"Content-Length": str(5 * 1024**2), "X-File-Size": str(5 * 1024**2),
                   "X-File-Name": "large.mp4", "X-Upload-ID": receiver.secrets.token_hex(16)}
        self.assertEqual(self.request("/api/upload", body=b"", headers=headers, method="POST")[0], 413)

    def test_15_malformed_values(self):
        for header in ({"X-File-SHA256": "bad"}, {"X-Upload-ID": "../bad"}, {"X-File-Name": ""},
                       {"X-File-Size": "-1"}, {"X-File-Last-Modified": "garbage"}, {"Content-Encoding": "gzip"}):
            self.assertEqual(self.upload(extra=header)[0], 400, header)

    def test_16_windows_path_traversal(self):
        status, receipt = self.upload(name="C:\\Users\\..\\CON:bad?.jpg")
        self.assertEqual(status, 200)
        self.assertTrue((self.state.output / receipt["saved_name"]).is_file())
        self.assertNotIn(":", receipt["saved_name"])
        self.assertNotIn("\\", receipt["saved_name"])

    def test_17_disk_full_rejection(self):
        with patch("receiver.shutil.disk_usage", return_value=type("Usage", (), {"free": 0})()):
            self.assertEqual(self.upload()[0], 507)

    def test_18_busy_limit(self):
        self.state.upload_slots.acquire()
        self.state.upload_slots.acquire()
        try:
            self.assertEqual(self.upload()[0], 429)
        finally:
            self.state.upload_slots.release()
            self.state.upload_slots.release()

    def test_19_short_body_rejected(self):
        key = receiver.secrets.token_hex(16)
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        request = ("POST /api/upload HTTP/1.0\r\nHost: 127.0.0.1:%s\r\nAuthorization: Bearer %s\r\n"
                   "Content-Length: 20\r\nX-File-Size: 20\r\nX-File-Name: short.jpg\r\nX-Upload-ID: %s\r\n\r\nabc") % (self.port, self.state.token, key)
        sock.sendall(request.encode())
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk
        sock.close()
        self.assertIn(b"408", response.split(b"\r\n")[0])
        self.assertEqual(self.request("/api/receipt?upload_id=" + key)[0], 404)
        self.assertEqual(list(self.state.partial.iterdir()), [])

    def test_20_readback_corruption_rejected(self):
        before = set(self.state.output.iterdir())
        with patch("receiver.file_sha256", return_value="0" * 64):
            self.assertEqual(self.upload()[0], 500)
        self.assertEqual(set(self.state.output.iterdir()), before)

    def test_21_manifest_failure_preserves_verified_file(self):
        before = set(self.state.output.iterdir())
        with patch.object(self.state, "record", side_effect=OSError("manifest failure")):
            status, response = self.upload(b"preserve-on-manifest-failure", "preserved.jpg")
        self.assertEqual(status, 500)
        added = set(self.state.output.iterdir()) - before
        self.assertEqual(len(added), 1)
        self.assertEqual(next(iter(added)).read_bytes(), b"preserve-on-manifest-failure")
        self.assertIn("可能已保存", response["error"])

    def test_22_concurrent_uploads(self):
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda n: self.upload(bytes([n]) * 50000, "parallel.jpg"), (1, 2)))
        self.assertEqual([r[0] for r in results], [200, 200])
        self.assertNotEqual(results[0][1]["saved_name"], results[1][1]["saved_name"])

    def test_23_no_source_deletion_routes(self):
        self.assertEqual(self.request("/api/delete", b"", method="POST")[0], 404)
        self.assertEqual(self.request("/api/upload", method="DELETE")[0], 501)

    def test_24_manifest_recheck_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "x.jpg").write_bytes(b"abc")
            digest = hashlib.sha256(b"abc").hexdigest()
            (root / "transfer_manifest.jsonl").write_text(json.dumps({"saved_name": "x.jpg", "size": 3,
                "sha256": digest, "client_sha256": digest, "verification": "client_sha256_match"}) + "\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verify(root), 0)
                (root / "x.jpg").write_bytes(b"bad")
                self.assertEqual(verify(root), 1)


class FilenameTests(unittest.TestCase):
    def test_safe_names(self):
        for name in ("../../hi.jpg", "..\\..\\hi.jpg", "CON", "NUL.jpg", "CON.foo.jpg", "COM¹.raw", "a:b?.jpeg", " . ", "相" * 500 + ".jpg", "foo\u202eexe.jpg"):
            safe = receiver.clean_filename(name)
            self.assertNotRegex(safe, r'[<>:"/\\|?*\x00-\x1f]')
            self.assertNotIn("\u202e", safe)
            self.assertLess(len(safe.encode("utf-8")), 160)
            self.assertFalse(safe.endswith((".", " ")))
        self.assertTrue(receiver.clean_filename("CON.foo.jpg").startswith("_CON"))
        self.assertTrue(receiver.clean_filename("COM¹.raw").startswith("_COM"))

    def test_commit_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a", Path(directory) / "b"
            a.write_bytes(b"new")
            b.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                receiver.commit_new(a, b)
            self.assertEqual(b.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
