# v1.0 · 原片直达

Android → Windows 局域网照片与视频传输工具，手机浏览器发送，电脑使用 Python 3.10+ 接收，无需额外 Python 依赖。

## 下载

请下载附件 `PhotoTransfer_Windows_Web_v1.0.zip`，完整解压后双击 `PhotoTransfer/START_WINDOWS.bat`，按 `README_先看这里.md` 操作。

## 本版功能

- 原始字节传输，不压缩、不转码；手机与电脑两端 SHA-256 校验。
- 分块读取、串行上传、停止和重试、上传回执与只读复检。
- 随机连接码、同名文件不覆盖、原子保存和错误检测。
- 手机无需安装 App；不提供删除手机原件功能。

## 已知边界

只适合可信私人 Wi-Fi：HTTP 不加密，不要暴露到公网。先核验并保留独立备份，再手动整理手机原件。

Linux 自动化测试通过；浏览器自动化测试受环境限制未完成，真实 Windows / Android 跨设备测试尚未完成。详见仓库测试记录。

## SHA-256

```text
ecf44f46d10ad02246bd8618c8ae25705433aa63d65fc8f7918140bb10e9504c  PhotoTransfer_Windows_Web_v1.0.zip
```
