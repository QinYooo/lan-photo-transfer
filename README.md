# 原片直达 · LAN Photo Transfer v1.0

Android → Windows 局域网照片与视频传输工具。手机无需安装 App，电脑需要 Python 3.10 或更高版本，无需额外 Python 依赖。

## 下载与启动

1. 下载 [PhotoTransfer_Windows_Web_v1.0.zip](./PhotoTransfer_Windows_Web_v1.0.zip?raw=true)。
2. 完整解压，打开 `PhotoTransfer` 文件夹，双击 `START_WINDOWS.bat`。
3. 手机和电脑连接同一可信私人 Wi-Fi，在手机浏览器打开接收窗口显示的地址，输入本次连接码，选择文件传输。

详细说明见 [README_先看这里.md](./README_先看这里.md)，验证范围见 [TEST_REPORT_测试记录.md](./TEST_REPORT_测试记录.md)。

## 重要边界

- 原始字节传输，不压缩、不转码；手机和电脑分别计算 SHA-256。
- HTTP 传输不加密，只在可信私人网络使用，不要开放公网。
- 不删除手机原件。完成核验并保留独立备份后，再手动整理原件。
- 本版已通过 Linux 端自动化测试，尚未完成真实 Windows / Android 跨设备测试，浏览器自动化测试因运行环境限制未完成。

## 下载包校验

`PhotoTransfer_Windows_Web_v1.0.zip` 的 SHA-256：

```text
ecf44f46d10ad02246bd8618c8ae25705433aa63d65fc8f7918140bb10e9504c
```
