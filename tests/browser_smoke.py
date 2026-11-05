"""Optional development smoke test. Requires Playwright + local Chromium."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import receiver
from playwright.sync_api import sync_playwright, expect


def main():
    with tempfile.TemporaryDirectory() as directory:
        state = receiver.TransferState(Path(directory))
        server = receiver.ReceiverServer(("127.0.0.1", 0), state, {"photo-transfer.test"})
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://photo-transfer.test:" + str(server.server_address[1])
        errors = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM", "/usr/bin/chromium"),
                    headless=True, args=["--no-sandbox", "--host-resolver-rules=MAP photo-transfer.test 127.0.0.1", "--no-proxy-server"])
                context = browser.new_context(viewport={"width": 390, "height": 844}, is_mobile=True,
                                              has_touch=True, accept_downloads=True)
                page = context.new_page()
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(base + "/#token=" + state.token)
                expect(page.locator("#connection-status")).to_contain_text("已连接")
                assert page.evaluate("isSecureContext") is False, "Must test insecure LAN-like HTTP origin"
                assert page.evaluate("Boolean(crypto.subtle)") is False
                assert page.evaluate("location.hash") == ""
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                payload = bytes(range(256)) * 8193
                page.locator("#files").set_input_files({"name": "手机原片测试.HEIC", "mimeType": "image/heic", "buffer": payload})
                page.locator("#start").click()
                expect(page.locator("#summary")).to_contain_text("两端一致 1", timeout=30000)
                receipt = next(iter(state.receipts.values()))
                assert (state.output / receipt["saved_name"]).read_bytes() == payload
                assert receipt["sha256"] == hashlib.sha256(payload).hexdigest()
                assert isinstance(receipt["source_last_modified_ms"], int)
                with page.expect_download() as download_info:
                    page.locator("#export").click()
                exported = Path(download_info.value.path()).read_text("utf-8")
                assert state.token not in exported
                assert json.loads(exported)["results"][0]["server_receipt"]["verification"] == "client_sha256_match"
                # Existing successes survive a second selection and upload.
                page.locator("#files").set_input_files({"name": "second.jpg", "mimeType": "image/jpeg", "buffer": b"second"})
                page.locator("#start").click()
                expect(page.locator("#summary")).to_contain_text("两端一致 2")
                # Pause during hashing; retry must complete with stable queue state.
                page.locator("#files").set_input_files({"name": "pause-test.bin", "mimeType": "application/octet-stream", "buffer": b"z" * (32 * 1024**2)})
                page.locator("#start").click()
                page.locator("#stop").click()
                expect(page.locator("#notice")).to_contain_text("已停止")
                page.locator("#retry").click()
                expect(page.locator("#summary")).to_contain_text("两端一致 3", timeout=30000)
                # Force unsupported Worker and explicitly approve fallback.
                page.evaluate("window.Worker = undefined")
                dialogs = []
                page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
                page.locator("#files").set_input_files({"name": "fallback.jpg", "mimeType": "image/jpeg", "buffer": b"fallback"})
                page.locator("#start").click()
                expect(page.locator("#summary")).to_contain_text("仅电脑自检 1")
                assert dialogs and "不要据此删除" in dialogs[0]
                expect(page.locator(".item.warning .status")).to_contain_text("未校验手机与电脑")
                assert "两端一致 3" in page.locator("#summary").inner_text()
                output = Path(os.environ.get("SCREENSHOT_DIR", str(Path(__file__).resolve().parents[1] / "test_artifacts")))
                output.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(output / "mobile-smoke.png"), full_page=True)
                # Incorrect token can be corrected without refreshing the page.
                other = context.new_page()
                other.goto(base + "/#token=wrong")
                expect(other.locator("#token-form")).to_be_visible()
                other.locator("#token").fill(state.token)
                other.locator("#token-form button").click()
                expect(other.locator("#connection-status")).to_contain_text("已连接")
                other.set_viewport_size({"width": 1280, "height": 900})
                other.screenshot(path=str(output / "desktop-smoke.png"), full_page=True)
                assert not errors, errors
                browser.close()
            print("PASS: insecure-HTTP Chromium upload, pure-JS SHA-256, exact bytes, receipts export, repeated selection, stop/retry, explicit fallback, invalid-token recovery, mobile layout; no page errors")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
