#!/usr/bin/env python3
"""Re-check a transfer folder against its local manifest. Never modifies files."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def verify(folder):
    folder = Path(folder).resolve()
    manifest = folder / "transfer_manifest.jsonl"
    passed = fallback = failed = 0
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError:
        print("找不到传输清单：" + str(manifest))
        return 2
    for index, line in enumerate(lines, 1):
        try:
            receipt = json.loads(line)
            name = receipt["saved_name"]
            if not isinstance(name, str) or Path(name).name != name or "/" in name or "\\" in name:
                raise ValueError("清单中的文件名无效")
            path = folder / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("文件不存在或不是普通文件")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            if path.stat().st_size != receipt["size"] or digest.hexdigest() != receipt["sha256"]:
                raise ValueError("大小或 SHA-256 与清单不一致")
            if receipt["verification"] == "client_sha256_match" and receipt.get("client_sha256") == receipt["sha256"]:
                passed += 1
                print("[两端校验记录 + 当前复检通过] " + name)
            else:
                fallback += 1
                print("[仅电脑自检通过；未证明与手机原件一致] " + name)
        except (OSError, ValueError, KeyError, TypeError) as error:
            failed += 1
            print("[失败] 清单第 %s 行：%s" % (index, error))
    print("\n两端一致记录复检通过 %s；仅电脑自检 %s；失败 %s。" % (passed, fallback, failed))
    print("复检不是独立备份；请打开文件抽查，并做好第二份备份。")
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="复检已接收文件，只读，不修改任何文件")
    parser.add_argument("folder", help="包含 transfer_manifest.jsonl 的单次 transfer-... 文件夹")
    raise SystemExit(verify(parser.parse_args().folder))
