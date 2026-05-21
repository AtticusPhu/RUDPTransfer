Copyright (c) 2026 AtticusPhu. All rights reserved.

This repository is published for demonstration, academic, and review purposes only.
No permission is granted to copy, modify, distribute, sublicense, or use this code commercially without written permission from the author.

# RUDPTransfer Kivy + NSIS Windows Folder Build

This package is a Windows-oriented Kivy GUI version of the RUDP file-transfer tool.
It keeps the existing RUDP protocol core and replaces the Tkinter GUI with a Kivy GUI.
The final Windows release path is:

1. Build a folder-mode executable with PyInstaller.
2. Package that folder into a normal installer with NSIS.

## Main files

```text
main_kivy.py                         Kivy GUI and packed worker entry
client.py                            RUDP sender worker
server.py                            RUDP receiver worker
file_transfer_common.py              File metadata, LAN discovery and IP helpers
protocol.py / crypto.py / congestion.py / utils.py
assets/app.ico                       Windows executable and installer icon
RUDPTransfer.spec                    PyInstaller folder-mode spec
installer/RUDPTransfer.nsi           NSIS installer script
build_windows_folder.bat             One-click Windows build script
run_app.bat                          Source-mode launcher for development
allow_firewall_udp_9999_admin.bat    Windows firewall helper
```

## Development run

Install runtime dependencies:

```cmd
python -m pip install -r requirements.txt
```

Run the Kivy GUI:

```cmd
run_app.bat
```

or:

```cmd
python main_kivy.py
```

## Build folder-mode executable

Install build dependencies and build:

```cmd
build_windows_folder.bat
```

This creates:

```text
dist\RUDPTransfer\RUDPTransfer.exe
```

This is the folder-version application. The user can run the application by double-clicking `RUDPTransfer.exe`.
Do not distribute only the exe file from this folder; distribute the whole `dist\RUDPTransfer` folder, or build the NSIS installer.

## Build NSIS installer

Install NSIS first and ensure `makensis.exe` is available in PATH. Then run:

```cmd
makensis installer\RUDPTransfer.nsi
```

The installer output is:

```text
dist\RUDPTransfer_Setup.exe
```

The NSIS installer is per-user by default and installs to:

```text
%LOCALAPPDATA%\Programs\RUDPTransfer
```

It creates Desktop and Start Menu shortcuts and registers an uninstaller in Windows Apps & Features.

## Runtime data location

The packaged application stores identity and TOFU pin files under:

```text
%LOCALAPPDATA%\RUDPTransfer
```

This avoids writing key files under `Program Files` or the installed application directory.

## LAN discovery

Receiver discovery uses UDP port `9998` and file transfer uses UDP port `9999` by default.
If discovery fails but manual IP transfer works, check Windows Firewall or enterprise Wi-Fi broadcast restrictions.
The GUI includes a button to launch the firewall helper with administrator privileges.

## GUI modes

The GUI supports:

- Chinese / English switching.
- Receiver discovery on LAN.
- Manual receiver IP entry.
- File chooser for sender.
- Directory chooser for receiver.
- Progress, average speed and ETA display.
- Receiver start / stop.
- Sender start / stop.

## Notes

The packaged executable is self-contained through PyInstaller. The user does not need to see or run Python source files.
NSIS only creates the installer; PyInstaller creates the actual runnable folder application.

## v2 UI fixes

- Registers an available system CJK font at runtime. On Windows it tries Microsoft YaHei, SimHei, SimSun, and DengXian from `C:\Windows\Fonts`; no font file is bundled.
- Applies the selected UI font to Kivy labels, buttons, text inputs, spinners, tab headers, popups, and log boxes.
- Reworks the top bar into two responsive rows and lowers the minimum window size to 680x520.
- Uses expandable button rows and resizable form fields so controls follow normal window resize behavior.

If Chinese is still not visible, verify that at least one of these fonts exists on the target Windows machine: `msyh.ttc`, `simhei.ttf`, `simsun.ttc`, or `Deng.ttf`.


## v3 UI 修复

- 将 Kivy TabbedPanel 替换为显式的发送/接收按钮，避免页签中文字体在部分 Windows/Kivy 环境下不显示。
- 根布局改为固定顶部区域 + 固定页签栏 + 可伸缩内容区；窗口纵向缩放时日志区域承担伸缩，减少底部空白和控件漂移。
- 保持文件夹版 PyInstaller 与 NSIS 安装包构建方式不变。
