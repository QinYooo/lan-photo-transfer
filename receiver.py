#!/usr/bin/env python3
"""Offline, Windows-friendly LAN file receiver. Python 3.10+, stdlib only."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit
import webbrowser

VERSION = "1.0.0"
CHUNK = 1024 * 1024
STATIC = Path(__file__).resolve().parent / "static"
UPLOAD_ID = re.compile(r"^[a-zA-Z0-9_-]{16,64}$")
SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(CHUNK):
            digest.update(block)
    return digest.hexdigest()


def clean_filename(raw: str) -> str:
    """Never interpret a sender's filename as a path; safe on Windows too."""
    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f]', "_", name)
    name = "".join(c for c in name if not 0x202A <= ord(c) <= 0x202E
                   and not 0x2066 <= ord(c) <= 0x2069)
    name = name.strip(" .") or "unnamed"
    # Keep comfortably below common 255-byte component limits, even in UTF-8.
    suffix = Path(name).suffix
    if len(suffix.encode("utf-8")) > 24:
        suffix = ""
    stem = name[:-len(suffix)] if suffix else name
    while len(stem.encode("utf-8")) > 120:
        stem = stem[:-1]
    stem = stem.strip(" .") or "file"
    if re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])", stem.split(".", 1)[0]):
        stem = "_" + stem
    return stem + suffix


def commit_new(temp: Path, destination: Path) -> None:
    """Atomically expose complete bytes, refusing an existing destination."""
    if os.name == "nt":
        # Windows rename fails if destination already exists (also on exFAT).
        os.rename(temp, destination)
    else:
        # POSIX rename overwrites; exclusive hard-link creation does not.
        os.link(temp, destination)
        temp.unlink()


def local_ipv4_addresses() -> list[str]:
    addresses = {"127.0.0.1"}
    try:
        addresses.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    # UDP connect chooses the LAN interface without sending data to this address.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            addresses.add(probe.getsockname()[0])
    except OSError:
        pass
    return sorted(a for a in addresses if ":" not in a and a != "0.0.0.0")


class TransferState:
    def __init__(self, output: Path, token: str | None = None,
                 max_file_bytes: int = 8 * 1024**3, max_uploads: int = 2):
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.partial = self.output / ".partial"
        self.partial.mkdir(exist_ok=True)
        self.manifest = self.output / "transfer_manifest.jsonl"
        self.token = token or secrets.token_urlsafe(24)
        self.session_id = secrets.token_hex(8)
        self.max_file_bytes = max_file_bytes
        self.lock = threading.Lock()
        self.upload_slots = threading.BoundedSemaphore(max_uploads)
        self.receipts: dict[str, dict] = {}
        self.inflight: set[str] = set()

    def record(self, upload_id: str, receipt: dict) -> None:
        with self.lock:
            # Only successful uploads enter the manifest. fsync before success.
            with self.manifest.open("a", encoding="utf-8", newline="\n") as log:
                log.write(json.dumps(receipt, ensure_ascii=False) + "\n")
                log.flush()
                os.fsync(log.fileno())
            self.receipts[upload_id] = receipt


class ReceiverServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, state: TransferState, allowed_hosts=None):
        self.state = state
        self.allowed_hosts = set(allowed_hosts or local_ipv4_addresses())
        self.allowed_hosts.update({"localhost", "127.0.0.1"})
        if address[0] not in ("", "0.0.0.0"):
            self.allowed_hosts.add(address[0].lower())
        self.connection_slots = threading.BoundedSemaphore(24)
        super().__init__(address, ReceiverHandler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(15)
        return sock, address

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()


class ReceiverHandler(BaseHTTPRequestHandler):
    server_version = "LANPhotoReceiver/" + VERSION
    sys_version = ""
    # One request per connection: unread rejected upload bodies cannot be reused.
    protocol_version = "HTTP/1.0"

    @property
    def state(self):
        return self.server.state

    def log_message(self, fmt, *args):
        # Never print request URLs, Authorization, filenames or the bearer token.
        pass

    def send_error(self, code, message=None, explain=None):
        self.json_reply(code, {"ok": False, "error": "请求无效。", "code": code})

    def common_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                         "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
                         "worker-src 'self'; object-src 'none'; base-uri 'none'; "
                         "form-action 'none'; frame-ancestors 'none'")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Connection", "close")

    def json_reply(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(code)
            self.common_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        self.close_connection = True

    def request_is_local_origin(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            self.json_reply(400, {"ok": False, "error": "缺少有效 Host。"})
            return False
        try:
            parsed = urlsplit("http://" + hosts[0])
            expected_port = self.server.server_address[1]
            if (parsed.hostname not in self.server.allowed_hosts
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path or parsed.query or parsed.fragment
                    or (parsed.port or 80) != expected_port):
                raise ValueError()
            origins = self.headers.get_all("Origin", [])
            if len(origins) > 1 or (origins and origins[0] != "http://" + hosts[0]):
                self.json_reply(403, {"ok": False, "error": "不允许跨站请求。"})
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self.json_reply(403, {"ok": False, "error": "不允许跨站请求。"})
                return False
        except (ValueError, AttributeError):
            self.json_reply(403, {"ok": False, "error": "请使用电脑显示的局域网 IP 地址。"})
            return False
        return True

    def authenticated(self) -> bool:
        auth = self.headers.get_all("Authorization", [])
        wanted = ("Bearer " + self.state.token).encode("ascii")
        if len(auth) != 1 or not hmac.compare_digest(auth[0].encode("utf-8"), wanted):
            self.json_reply(401, {"ok": False, "error": "连接码无效或已过期，请重新打开电脑显示的链接，或输入新连接码。"})
            return False
        return True

    def do_GET(self):
        if not self.request_is_local_origin():
            return
        parts = urlsplit(self.path)
        route = parts.path
        if route.startswith("/api/"):
            if not self.authenticated():
                return
            if route == "/api/status" and not parts.query:
                self.json_reply(200, {"ok": True, "version": VERSION,
                    "output_name": self.state.output.name,
                    "max_file_bytes": self.state.max_file_bytes,
                    "hash_algorithm": "SHA-256", "session_id": self.state.session_id})
            elif route == "/api/receipt":
                from urllib.parse import parse_qs
                params = parse_qs(parts.query)
                upload_id = params.get("upload_id", [""])[0]
                if not UPLOAD_ID.fullmatch(upload_id):
                    self.json_reply(400, {"ok": False, "error": "上传编号无效。"})
                    return
                with self.state.lock:
                    receipt = self.state.receipts.get(upload_id)
                    inflight = upload_id in self.state.inflight
                if receipt:
                    self.json_reply(200, {**receipt, "replayed": True})
                else:
                    self.json_reply(202 if inflight else 404,
                        {"ok": False, "in_progress": inflight,
                         "error": "文件仍在接收/校验，请稍后重试。" if inflight else "本次接收会话尚无此文件的成功记录。"})
            else:
                self.json_reply(404, {"ok": False, "error": "接口不存在。"})
            return
        allowed = {"/": "index.html", "/index.html": "index.html",
                   "/app.js": "app.js", "/style.css": "style.css",
                   "/hash.js": "hash.js", "/hash-worker.js": "hash-worker.js"}
        allowed.update({"/static/" + name: name for name in
                        ("app.js", "style.css", "hash.js", "hash-worker.js")})
        if route not in allowed or parts.query:
            self.json_reply(404, {"ok": False, "error": "页面不存在。"})
            return
        filename = allowed[route]
        try:
            body = (STATIC / filename).read_bytes()
        except OSError:
            self.json_reply(500, {"ok": False, "error": "程序文件缺失，请完整解压后启动。"})
            return
        mime = "text/html" if filename.endswith(".html") else "text/css" if filename.endswith(".css") else "text/javascript"
        self.send_response(200)
        self.common_headers()
        self.send_header("Content-Type", mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_POST(self):
        if not self.request_is_local_origin() or not self.authenticated():
            return
        if self.path != "/api/upload":
            self.json_reply(404, {"ok": False, "error": "接口不存在。"})
            return
        for key in ("Content-Length", "X-File-Name", "X-File-Size", "X-Upload-ID"):
            if len(self.headers.get_all(key, [])) != 1:
                self.json_reply(400, {"ok": False, "error": "缺少或重复上传参数：" + key})
                return
        if (self.headers.get("Transfer-Encoding") is not None
                or self.headers.get("Content-Encoding") is not None
                or len(self.headers.get_all("X-File-SHA256", [])) > 1):
            self.json_reply(400, {"ok": False, "error": "不支持该上传编码。"})
            return
        try:
            if not self.headers["Content-Length"].isdigit() or not self.headers["X-File-Size"].isdigit():
                raise ValueError()
            size = int(self.headers["Content-Length"])
            if size != int(self.headers["X-File-Size"]) or size < 0:
                raise ValueError()
            original = unquote(self.headers["X-File-Name"], encoding="utf-8", errors="strict")
            if not original or len(original.encode("utf-8")) > 1024:
                raise ValueError()
            expected_hash = self.headers.get("X-File-SHA256", "").lower()
            if expected_hash and not SHA256.fullmatch(expected_hash):
                raise ValueError()
            upload_id = self.headers["X-Upload-ID"]
            if not UPLOAD_ID.fullmatch(upload_id):
                raise ValueError()
            modified_value = self.headers.get("X-File-Last-Modified", "")
            if len(self.headers.get_all("X-File-Last-Modified", [])) > 1:
                raise ValueError()
            if modified_value and (not modified_value.isdigit() or len(modified_value) > 16):
                raise ValueError()
            modified_ms = int(modified_value) if modified_value else None
        except (ValueError, UnicodeError):
            self.json_reply(400, {"ok": False, "error": "文件参数无效。"})
            return
        if size > self.state.max_file_bytes:
            self.json_reply(413, {"ok": False, "error": "文件超过接收端的单文件大小限制。"})
            return
        with self.state.lock:
            previous = self.state.receipts.get(upload_id)
            inflight = upload_id in self.state.inflight
            if not previous and not inflight:
                self.state.inflight.add(upload_id)
        if previous:
            matches = (previous["original_name"] == original and previous["size"] == size
                       and previous["client_sha256"] == (expected_hash or None))
            self.json_reply(200 if matches else 409, {**previous, "replayed": True} if matches
                else {"ok": False, "error": "上传编号已用于另一个文件。"})
            return
        if inflight:
            self.json_reply(409, {"ok": False, "error": "同一文件仍在上传/校验，请稍后重试。"})
            return
        if not self.state.upload_slots.acquire(blocking=False):
            with self.state.lock:
                self.state.inflight.discard(upload_id)
            self.json_reply(429, {"ok": False, "error": "接收端正忙，请稍后重试。"})
            return
        temporary = None
        destination = None
        disk_verified = False
        try:
            # Maintain a small reserve; concurrent uploads may still exhaust disk.
            if shutil.disk_usage(self.state.output).free < size + 16 * 1024**2:
                self.json_reply(507, {"ok": False, "error": "电脑磁盘空间不足。"})
                return
            self.connection.settimeout(60)
            descriptor, temporary_name = tempfile.mkstemp(prefix="upload_", suffix=".part", dir=self.state.partial)
            temporary = Path(temporary_name)
            digest = hashlib.sha256()
            remaining = size
            with os.fdopen(descriptor, "wb") as output:
                while remaining:
                    block = self.rfile.read(min(CHUNK, remaining))
                    if not block:
                        raise EOFError("上传中断，文件不完整。")
                    output.write(block)
                    digest.update(block)
                    remaining -= len(block)
                output.flush()
                os.fsync(output.fileno())
            received_hash = digest.hexdigest()
            if expected_hash and not hmac.compare_digest(received_hash, expected_hash):
                self.json_reply(422, {"ok": False, "error": "手机与电脑的 SHA-256 不一致，已拒收；请保留手机原文件后重试。"})
                return
            safe = clean_filename(original)
            suffix = Path(safe).suffix
            stem = safe[:-len(suffix)] if suffix else safe
            for _ in range(5):
                candidate = self.state.output / (stem + "__" + secrets.token_hex(6) + suffix)
                try:
                    commit_new(temporary, candidate)
                    destination = candidate
                    break
                except FileExistsError:
                    continue
            if destination is None:
                raise OSError("无法生成唯一文件名。")
            saved_hash = file_sha256(destination)
            if (destination.stat().st_size != size
                    or not hmac.compare_digest(saved_hash, received_hash)):
                raise OSError("电脑写入后复读校验失败，请检查磁盘。")
            disk_verified = True
            receipt = {"ok": True, "receipt_id": upload_id,
                "session_id": self.state.session_id, "original_name": original,
                "saved_name": destination.name, "size": size,
                "sha256": saved_hash, "client_sha256": expected_hash or None,
                "source_last_modified_ms": modified_ms,
                "verification": "client_sha256_match" if expected_hash else "server_only",
                "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            self.state.record(upload_id, receipt)
            print("已接收并复读校验：%s（%s 字节，%s）" % (
                destination.name, size, "两端 SHA-256 一致" if expected_hash else "仅电脑端校验"), flush=True)
            self.json_reply(200, receipt)
        except (TimeoutError, socket.timeout, EOFError):
            self.json_reply(408, {"ok": False, "error": "传输中断或超时。保留手机原件，恢复网络后重试。"})
        except OSError:
            self.json_reply(500, {"ok": False, "error":
                "文件可能已保存，但成功清单写入失败。请保留手机原件，先在电脑核对文件，避免重复传输。" if disk_verified
                else "电脑写入或校验失败；请检查空间、文件夹权限和磁盘，再重试。"})
        finally:
            # Only remove files created by this incomplete request, never sources.
            for path in (temporary, destination if not disk_verified else None):
                if path is not None:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
            with self.state.lock:
                self.state.inflight.discard(upload_id)
            self.state.upload_slots.release()


def main():
    parser = argparse.ArgumentParser(description="局域网照片接收器：原文件上传与 SHA-256 校验")
    parser.add_argument("--host", default="0.0.0.0", help="绑定的 IPv4 地址，默认所有网卡")
    parser.add_argument("--port", type=int, default=8765, help="监听端口，默认 8765")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "Photos_Inbox", help="保存根目录")
    parser.add_argument("--max-file-mb", type=int, default=8192, help="单文件上限（MiB），默认 8192")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开电脑浏览器")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.max_file_mb <= 0:
        parser.error("端口必须为 1–65535，大小限制必须为正数。")
    try:
        ipaddress.IPv4Address(args.host)
    except ValueError:
        parser.error("--host 请输入 IPv4 地址，如 0.0.0.0、127.0.0.1 或电脑的局域网 IP。")
    session_folder = args.output / (time.strftime("transfer-%Y%m%d-%H%M%S-") + secrets.token_hex(3))
    state = TransferState(session_folder, max_file_bytes=args.max_file_mb * 1024**2)
    addresses = local_ipv4_addresses()
    try:
        server = ReceiverServer((args.host, args.port), state, addresses)
    except OSError as error:
        print("启动失败：%s\n请换一个端口，例如：python receiver.py --port 8766" % error)
        return 1
    print("\n局域网原文件接收器 " + VERSION)
    print("保存位置：" + str(state.output))
    print("\n仅在自己信任的私人 Wi-Fi 使用。HTTP 不加密，连接码也不是加密。")
    print("Windows 防火墙如有提示，只允许【专用网络】，不要允许公用网络。")
    print("不要端口转发，不要在公共 Wi-Fi 使用。完成后关闭窗口或按 Ctrl+C。")
    print("\n手机与电脑连接同一 Wi-Fi。手机浏览器打开下面的局域网地址：")
    visible = [a for a in addresses if not a.startswith("127.")] if args.host == "0.0.0.0" else [args.host]
    if not visible:
        print("未发现局域网 IP。连接 Wi-Fi 后重启，或用 ipconfig 查看 IPv4 地址。")
    for address in visible:
        print("  http://%s:%s/#token=%s" % (address, args.port, state.token))
    print("\n也可只输入 http://电脑IPv4:%s/，然后填写连接码：%s" % (args.port, state.token))
    print("每次重启会换新连接码。保留此窗口，手机上传时不要锁屏。\n", flush=True)
    if not args.no_browser:
        address = "127.0.0.1" if args.host == "0.0.0.0" else args.host
        webbrowser.open("http://%s:%s/#token=%s" % (address, args.port, state.token))
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\n接收器已停止。未完成的文件不要当作已备份。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    if sys.version_info < (3, 10):
        sys.exit("需要 Python 3.10 或更高版本。")
    raise SystemExit(main())
