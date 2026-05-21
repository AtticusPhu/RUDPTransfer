#!/usr/bin/env python3
"""Kivy GUI entry point for RUDPTransfer.

The same executable is used in two modes:
- GUI mode: no special arguments, starts the Kivy desktop UI.
- Worker mode: --worker sender|receiver ..., runs the CLI sender/receiver logic.

This design keeps the PyInstaller folder build self-contained. The GUI does not
need an external python.exe or visible source files after packaging.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional

APP_NAME = "RUDPTransfer"
IS_WINDOWS = os.name == "nt"
FROZEN = bool(getattr(sys, "frozen", False))
APP_DIR = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))

PROGRESS_RE = re.compile(
    r"Progress:\s+(?P<sent>\d+)/(?:\s*)?(?P<total>\d+)\s+bytes\s+\((?P<pct>[0-9.]+)%\).*?"
    r"avg=(?P<avg>[0-9.]+)\s+Mbps.*?eta=(?P<eta>[^,\s]+)"
)
COMPLETE_RE = re.compile(r"Transfer complete:\s+(?P<total>\d+)\s+bytes.*?avg=(?P<avg>[0-9.]+)\s+Mbps")


def user_data_dir() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        path = Path(base) / APP_NAME
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        path = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def format_file_size(num_bytes: int) -> str:
    n = float(max(0, int(num_bytes)))
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if n < 1024.0 or unit == units[-1]:
            return f"{int(n)} B" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{int(num_bytes)} B"


def configure_stdio_utf8() -> None:
    """Force UTF-8 text I/O for worker logs.

    In packaged Windows builds, worker processes write logs through stdout/stderr
    pipes. Some environments still default to an ANSI code page, which can turn
    Chinese file names into mojibake before the GUI reads them. Reconfiguring the
    streams here keeps subprocess logs Unicode-safe.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")


def run_worker(argv: List[str]) -> int:
    """Run sender/receiver logic without importing Kivy."""
    if len(argv) < 2:
        print("missing worker role", file=sys.stderr)
        return 2
    role = argv[1].strip().lower()
    worker_args = argv[2:]
    if role == "sender":
        import client
        parser = client.build_argparser()
        args = parser.parse_args(worker_args)
        try:
            return int(client.run_client(args))
        except KeyboardInterrupt:
            return 130
        except Exception as exc:
            client.setup_logger("RUDP-Sender").error(f"Fatal: {exc}")
            return 2
    if role == "receiver":
        import server
        parser = server.build_argparser()
        args = parser.parse_args(worker_args)
        receiver = server.RUDPFileReceiver(args)
        try:
            receiver.start()
        except KeyboardInterrupt:
            return 130
        finally:
            receiver.stop()
        return 0
    print(f"unknown worker role: {role}", file=sys.stderr)
    return 2


if len(sys.argv) >= 2 and sys.argv[1] == "--worker":
    configure_stdio_utf8()
    raise SystemExit(run_worker(sys.argv[1:]))


# GUI imports are intentionally below the worker dispatch.
from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.core.text import LabelBase, DEFAULT_FONT
from kivy.metrics import dp
from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.textinput import TextInput

from file_transfer_common import DEFAULT_DISCOVERY_PORT, TRANSFER_REQUEST_LOG_PREFIX, discover_receivers, get_local_ip_candidates


I18N: Dict[str, Dict[str, str]] = {
    "zh": {
        "title": "RUDP 文件传输",
        "toggle_lang": "English",
        "send_tab": "发送文件",
        "recv_tab": "接收文件",
        "local_ip": "本机 IPv4：{ips}",
        "receiver_ip": "接收端 IP",
        "port": "端口",
        "discovery_port": "发现端口",
        "manual_hint": "可手动输入 IP，也可搜索接收端",
        "search": "搜索接收端",
        "search_working": "搜索中",
        "choose_receiver": "发现结果",
        "no_receiver": "未发现接收端",
        "searching": "正在搜索局域网接收端...",
        "search_done": "发现完成：{n} 个接收端",
        "search_none": "没有发现接收端，请确认接收端已启动；若仍失败，请手动输入 IP。搜索会尝试 UDP 9998 和传输端口 9999。",
        "file": "待发送文件",
        "choose_file": "选择文件",
        "send": "开始发送",
        "stop": "停止",
        "payload": "Payload 大小",
        "complete_timeout": "完成等待秒数",
        "progress": "进度",
        "eta": "剩余时间：{eta}",
        "speed": "平均速度：{speed}",
        "size": "大小：{size}",
        "save_dir": "保存目录",
        "choose_dir": "选择目录",
        "bind": "监听地址",
        "allow_peer": "只允许发送端 IP，可空",
        "receiver_name": "接收端名称，可空",
        "once": "接收一次后停止",
        "start_recv": "启动接收端",
        "stop_recv": "停止接收端",
        "firewall": "放行 Windows 防火墙端口",
        "clear": "清空日志",
        "need_ip": "请填写接收端 IP，或先搜索接收端。",
        "need_file": "请选择有效文件。",
        "running": "进程仍在运行。",
        "stopped": "已停止。",
        "started": "已启动。",
        "ready": "就绪",
        "unknown": "未知",
        "browse": "浏览",
        "cancel": "取消",
        "select": "选择",
        "request_timeout": "确认等待秒数",
        "approval_timeout": "确认等待秒数",
        "incoming_request_title": "收到传输请求",
        "incoming_request": "发送端：{sender}\n文件名：{name}\n大小：{size}\n保存路径：{path}\nSHA256：{sha256}",
        "accept": "接收",
        "reject": "拒绝",
        "request_waiting": "已提交传输请求，等待接收端确认...",
        "approval_hint": "发送端提交请求后，将在这里弹出确认窗口",
        "transfer_finished": "本次传输结束。",
        "receive_transfer_finished": "本次传输完成。",
        "native_dialog_failed": "系统文件选择窗口打开失败，已切换为内置选择窗口。",
    },
    "en": {
        "title": "RUDP File Transfer",
        "toggle_lang": "中文",
        "send_tab": "Send File",
        "recv_tab": "Receive File",
        "local_ip": "Local IPv4: {ips}",
        "receiver_ip": "Receiver IP",
        "port": "Port",
        "discovery_port": "Discovery Port",
        "manual_hint": "Enter IP manually or search LAN receivers",
        "search": "Search Receivers",
        "search_working": "Searching",
        "choose_receiver": "Discovered Receivers",
        "no_receiver": "No receiver found",
        "searching": "Searching LAN receivers...",
        "search_done": "Discovery finished: {n} receiver(s)",
        "search_none": "No receiver found. Make sure the receiver is running. Search tries UDP 9998 and transfer port 9999; manual IP mode can still be used.",
        "file": "File to Send",
        "choose_file": "Choose File",
        "send": "Start Sending",
        "stop": "Stop",
        "payload": "Payload Size",
        "complete_timeout": "Complete Timeout (s)",
        "progress": "Progress",
        "eta": "ETA: {eta}",
        "speed": "Average Speed: {speed}",
        "size": "Size: {size}",
        "save_dir": "Save Directory",
        "choose_dir": "Choose Directory",
        "bind": "Bind Address",
        "allow_peer": "Allowed Sender IP, optional",
        "receiver_name": "Receiver Name, optional",
        "once": "Stop after one transfer",
        "start_recv": "Start Receiver",
        "stop_recv": "Stop Receiver",
        "firewall": "Allow Windows Firewall Ports",
        "clear": "Clear Log",
        "need_ip": "Enter a receiver IP, or search receivers first.",
        "need_file": "Choose a valid file.",
        "running": "The process is still running.",
        "stopped": "Stopped.",
        "started": "Started.",
        "ready": "Ready",
        "unknown": "unknown",
        "browse": "Browse",
        "cancel": "Cancel",
        "select": "Select",
        "request_timeout": "Approval Timeout (s)",
        "approval_timeout": "Approval Timeout (s)",
        "incoming_request_title": "Incoming Transfer Request",
        "incoming_request": "Sender: {sender}\nFile: {name}\nSize: {size}\nSave path: {path}\nSHA256: {sha256}",
        "accept": "Accept",
        "reject": "Reject",
        "request_waiting": "Transfer request submitted; waiting for receiver approval...",
        "approval_hint": "After a sender submits a request, a confirmation dialog appears here.",
        "transfer_finished": "This transfer has finished.",
        "receive_transfer_finished": "This transfer has completed.",
        "native_dialog_failed": "The system file dialog failed. Falling back to the built-in chooser.",
    },
}


def find_cjk_font() -> Optional[str]:
    """Return a font that can render Chinese.

    Priority is:
    1. bundled fonts under assets/fonts, when the project owner supplies them;
    2. common system CJK fonts already installed on the operating system.
    """
    candidates: List[Path] = []
    bundled_font_dir = RESOURCE_DIR / "assets" / "fonts"
    if bundled_font_dir.exists():
        for pattern in ("*.ttf", "*.ttc", "*.otf"):
            candidates.extend(sorted(bundled_font_dir.glob(pattern)))
    if IS_WINDOWS:
        win = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
        candidates.extend([
            win / "msyh.ttc",       # Microsoft YaHei
            win / "msyh.ttf",
            win / "simhei.ttf",
            win / "simsun.ttc",
            win / "Deng.ttf",
        ])
    elif sys.platform == "darwin":
        candidates.extend([
            Path("/System/Library/Fonts/PingFang.ttc"),
            Path("/System/Library/Fonts/STHeiti Light.ttc"),
            Path("/System/Library/Fonts/Supplemental/Songti.ttc"),
        ])
    else:
        candidates.extend([
            Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
            Path("/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"),
            Path("/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"),
            Path("/usr/share/fonts/truetype/arphic/uming.ttc"),
        ])
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def register_ui_font() -> str:
    font_path = find_cjk_font()
    if font_path:
        try:
            LabelBase.register(name="RUDP_UI", fn_regular=font_path)
            return "RUDP_UI"
        except Exception:
            pass
    return DEFAULT_FONT


UI_FONT = register_ui_font()


# Centralized UI theme. Kivy color values are RGBA floats in the range 0..1.
# Change these values if you want a different visual style.
THEME = {
    # White-first application style. Kivy color values are RGBA floats.
    "window_bg": (0.985, 0.990, 0.995, 1),
    "panel_bg": (1.000, 1.000, 1.000, 1),
    "primary": (0.145, 0.365, 0.760, 1),
    "primary_active": (0.095, 0.255, 0.620, 1),
    "secondary": (0.955, 0.965, 0.985, 1),
    "secondary_active": (0.900, 0.925, 0.970, 1),
    "success": (0.150, 0.560, 0.320, 1),
    "success_active": (0.090, 0.430, 0.230, 1),
    "danger": (0.780, 0.200, 0.200, 1),
    "danger_active": (0.610, 0.130, 0.130, 1),
    "text": (0.070, 0.085, 0.115, 1),
    "muted_text": (0.390, 0.425, 0.500, 1),
    "on_primary": (1.000, 1.000, 1.000, 1),
    "on_secondary": (0.070, 0.085, 0.115, 1),
    "input_bg": (1.000, 1.000, 1.000, 1),
    "input_text": (0.070, 0.085, 0.115, 1),
    "input_cursor": (0.145, 0.365, 0.760, 1),
    "log_bg": (0.985, 0.990, 0.995, 1),
    "log_text": (0.080, 0.095, 0.125, 1),
    "disabled": (0.720, 0.750, 0.800, 1),
}

_BUTTON_ROLES = {
    "primary": ("primary", "on_primary"),
    "active": ("primary_active", "on_primary"),
    "secondary": ("secondary", "on_secondary"),
    "success": ("success", "on_primary"),
    "danger": ("danger", "on_primary"),
    "input": ("input_bg", "input_text"),
}


def style_button(button: Button, role: str = "secondary") -> Button:
    bg_key, fg_key = _BUTTON_ROLES.get(role, _BUTTON_ROLES["secondary"])
    button.font_name = UI_FONT
    button.background_normal = ""
    button.background_down = ""
    button.background_disabled_normal = ""
    button.background_color = THEME[bg_key]
    button.color = THEME[fg_key]
    return button


def make_button(role: str = "secondary", **kwargs) -> Button:
    kwargs.setdefault("font_name", UI_FONT)
    btn = Button(**kwargs)
    return style_button(btn, role)


def make_input(**kwargs) -> TextInput:
    kwargs.setdefault("font_name", UI_FONT)
    kwargs.setdefault("background_color", THEME["input_bg"])
    kwargs.setdefault("foreground_color", THEME["input_text"])
    kwargs.setdefault("cursor_color", THEME["input_cursor"])
    kwargs.setdefault("selection_color", (0.10, 0.35, 0.72, 0.24))
    return TextInput(**kwargs)


def make_label(**kwargs) -> Label:
    kwargs.setdefault("font_name", UI_FONT)
    kwargs.setdefault("color", THEME["text"])
    return Label(**kwargs)


def style_spinner(spinner: Spinner) -> Spinner:
    spinner.font_name = UI_FONT
    spinner.background_normal = ""
    spinner.background_down = ""
    spinner.background_color = THEME["input_bg"]
    spinner.color = THEME["input_text"]
    return spinner


def apply_ui_font(widget) -> None:
    if hasattr(widget, "font_name"):
        try:
            widget.font_name = UI_FONT
        except Exception:
            pass
    if hasattr(widget, "title_font"):
        try:
            widget.title_font = UI_FONT
        except Exception:
            pass
    for child in getattr(widget, "children", []) or []:
        apply_ui_font(child)


def style_popup(popup: Popup) -> Popup:
    popup.title_font = UI_FONT
    try:
        popup.background = ""
    except Exception:
        pass
    try:
        popup.background_color = THEME["panel_bg"]
    except Exception:
        pass
    try:
        popup.separator_color = THEME["secondary_active"]
    except Exception:
        pass
    return popup


def bind_label_wrap(label: Label) -> Label:
    label.bind(size=lambda inst, val: setattr(inst, "text_size", val))
    return label


def row(label: str, widget, label_width: int = 150) -> BoxLayout:
    box = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(40), spacing=dp(8))
    lab = Label(
        text=label,
        font_name=UI_FONT,
        color=THEME["muted_text"],
        size_hint_x=None,
        width=dp(label_width),
        halign="right",
        valign="middle",
        shorten=True,
        shorten_from="right",
    )
    bind_label_wrap(lab)
    box.add_widget(lab)
    box.add_widget(widget)
    return box


class WorkerProcess:
    def __init__(self, role: str, log_callback, exit_callback, progress_callback=None):
        self.role = role
        self.log_callback = log_callback
        self.exit_callback = exit_callback
        self.progress_callback = progress_callback
        self.proc: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, args: List[str]) -> None:
        if self.is_running():
            self.log_callback("Process is already running.\n")
            return
        cmd = self._base_cmd() + ["--worker", self.role] + args
        env = os.environ.copy()
        env.setdefault("PYTHONUTF8", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        kwargs = dict(
            cwd=str(user_data_dir()),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
        )
        if IS_WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        self.proc = subprocess.Popen(cmd, **kwargs)
        self.reader_thread = threading.Thread(target=self._reader, daemon=True)
        self.reader_thread.start()

    def _base_cmd(self) -> List[str]:
        if FROZEN:
            return [sys.executable]
        return [sys.executable, str(APP_DIR / "main_kivy.py")]

    def _reader(self) -> None:
        assert self.proc is not None
        try:
            for line in self.proc.stdout or []:
                self.log_callback(line)
                if self.progress_callback is not None:
                    self._try_progress(line)
        finally:
            rc = self.proc.wait() if self.proc is not None else None
            self.exit_callback(rc)

    def _try_progress(self, line: str) -> None:
        m = PROGRESS_RE.search(line)
        if m:
            try:
                self.progress_callback({
                    "sent": int(m.group("sent")),
                    "total": int(m.group("total")),
                    "pct": float(m.group("pct")),
                    "avg": float(m.group("avg")),
                    "eta": m.group("eta"),
                    "complete": False,
                })
            except Exception:
                pass
            return
        m = COMPLETE_RE.search(line)
        if m:
            try:
                total = int(m.group("total"))
                self.progress_callback({
                    "sent": total,
                    "total": total,
                    "pct": 100.0,
                    "avg": float(m.group("avg")),
                    "eta": "0:00",
                    "complete": True,
                })
            except Exception:
                pass

    def stop(self) -> None:
        if not self.is_running():
            return
        assert self.proc is not None
        try:
            self.proc.terminate()
        except Exception:
            pass


class LogBox(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.text = make_input(readonly=True, multiline=True, size_hint_y=1, background_color=THEME["log_bg"], foreground_color=THEME["log_text"], cursor_color=THEME["log_text"])
        self.add_widget(self.text)

    def append(self, s: str) -> None:
        def _append(_dt):
            self.text.text += s
            self.text.cursor = (0, len(self.text.text.splitlines()))
        Clock.schedule_once(_append, 0)

    def clear(self) -> None:
        self.text.text = ""


class RUDPTransferRoot(BoxLayout):
    def __init__(self, app: "RUDPTransferApp", **kwargs):
        super().__init__(orientation="vertical", spacing=dp(8), padding=dp(10), **kwargs)
        self.app = app
        self.lang = app.lang
        self.discovered: List[Dict[str, object]] = []
        self.search_in_progress = False
        self.pending_request_popups = set()
        self.seen_request_files = set()
        self.approval_dir = user_data_dir() / "approvals"
        self.approval_dir.mkdir(parents=True, exist_ok=True)
        self.sender_worker = WorkerProcess("sender", self.sender_log, self.sender_exit, self.sender_progress)
        self.receiver_worker = WorkerProcess("receiver", self.receiver_log, self.receiver_exit)
        self._build()
        self.refresh_texts()
        self.refresh_local_ips()
        Clock.schedule_interval(self.poll_approval_requests, 0.5)

    def t(self, key: str, **kwargs) -> str:
        text = I18N[self.lang].get(key, key)
        return text.format(**kwargs) if kwargs else text

    def _build(self) -> None:
        Window.minimum_width = 680
        Window.minimum_height = 520

        top = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(44), spacing=dp(8))
        self.title_label = make_label(font_size="20sp", bold=True, halign="left", valign="middle")
        bind_label_wrap(self.title_label)
        top.add_widget(self.title_label)
        self.lang_btn = make_button("primary", size_hint_x=None, width=dp(120), on_release=lambda *_: self.toggle_lang())
        top.add_widget(self.lang_btn)
        self.add_widget(top)

        self.local_ip_label = make_label(size_hint_y=None, height=dp(30), halign="left", valign="middle", shorten=True)
        bind_label_wrap(self.local_ip_label)
        self.add_widget(self.local_ip_label)

        # Use explicit tab buttons instead of Kivy TabbedPanel headers.
        # TabbedPanel headers use their own internal button class and may ignore
        # the application font on some Windows/Kivy builds, which causes Chinese
        # text to disappear. Normal Buttons give deterministic font behavior.
        self.tab_bar = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(44), spacing=dp(8))
        self.send_tab_btn = make_button("active", on_release=lambda *_: self.show_page("send"))
        self.recv_tab_btn = make_button("secondary", on_release=lambda *_: self.show_page("recv"))
        self.tab_bar.add_widget(self.send_tab_btn)
        self.tab_bar.add_widget(self.recv_tab_btn)
        self.add_widget(self.tab_bar)

        # The content host is the only vertically expanding area below the fixed
        # header. This keeps the top controls anchored while the log panel expands
        # or shrinks with the window, avoiding unused space at the bottom.
        self.page_host = BoxLayout(orientation="vertical", size_hint_y=1)
        self.add_widget(self.page_host)
        self.send_page = self._build_send_tab()
        self.recv_page = self._build_recv_tab()
        self.current_page = ""
        self.show_page("send")
        apply_ui_font(self)

    def _build_send_tab(self) -> None:
        root = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(8))
        form = GridLayout(cols=1, size_hint_y=None, spacing=dp(6))
        form.bind(minimum_height=form.setter("height"))
        self.receiver_ip = make_input(text="", multiline=False)
        self.receiver_port = make_input(text="9999", multiline=False, input_filter="int")
        self.discovery_port = make_input(text=str(DEFAULT_DISCOVERY_PORT), multiline=False, input_filter="int")
        self.receiver_spinner = style_spinner(Spinner(text="", values=[], font_name=UI_FONT))
        self.receiver_spinner.bind(text=self.on_receiver_selected)
        self.file_input = make_input(text="", multiline=False)
        self.payload_input = make_input(text="1300", multiline=False, input_filter="int")
        self.complete_timeout_input = make_input(text="180", multiline=False, input_filter="float")
        self.request_timeout_input = make_input(text="300", multiline=False, input_filter="float")
        self.manual_hint = make_label(size_hint_y=None, height=dp(30), halign="left", valign="middle", shorten=True)
        bind_label_wrap(self.manual_hint)
        form.add_widget(self.manual_hint)
        form.add_widget(row("", self.receiver_ip))
        form.add_widget(row("", self.receiver_port))
        discovery_line = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(38), spacing=dp(8))
        discovery_line.add_widget(make_label(text="", size_hint_x=None, width=dp(150), halign="right", valign="middle", shorten=True, color=THEME["muted_text"]))
        discovery_line.add_widget(self.discovery_port)
        self.search_btn = make_button("primary", size_hint_x=None, width=dp(150), on_release=lambda *_: self.search_receivers())
        discovery_line.add_widget(self.search_btn)
        form.add_widget(discovery_line)
        form.add_widget(row("", self.receiver_spinner))
        file_line = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(38), spacing=dp(8))
        file_line.add_widget(make_label(text="", size_hint_x=None, width=dp(150), halign="right", valign="middle", shorten=True, color=THEME["muted_text"]))
        file_line.add_widget(self.file_input)
        self.choose_file_btn = make_button("secondary", size_hint_x=None, width=dp(110), on_release=lambda *_: self.choose_file())
        file_line.add_widget(self.choose_file_btn)
        form.add_widget(file_line)
        form.add_widget(row("", self.payload_input))
        form.add_widget(row("", self.complete_timeout_input))
        form.add_widget(row("", self.request_timeout_input))
        root.add_widget(form)
        progress_box = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(95), spacing=dp(4))
        self.progress = ProgressBar(max=100.0, value=0.0, size_hint_y=None, height=dp(24))
        self.progress_label = make_label(size_hint_y=None, height=dp(24), halign="left", valign="middle", shorten=True)
        self.eta_label = make_label(size_hint_y=None, height=dp(24), halign="left", valign="middle", shorten=True)
        self.speed_label = make_label(size_hint_y=None, height=dp(24), halign="left", valign="middle", shorten=True)
        for lab in (self.progress_label, self.eta_label, self.speed_label):
            lab.bind(size=lambda inst, val: setattr(inst, "text_size", val))
        progress_box.add_widget(self.progress)
        progress_box.add_widget(self.progress_label)
        progress_box.add_widget(self.eta_label)
        progress_box.add_widget(self.speed_label)
        root.add_widget(progress_box)
        action = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(42), spacing=dp(8))
        self.send_btn = make_button("success", on_release=lambda *_: self.start_sender())
        self.stop_send_btn = make_button("danger", on_release=lambda *_: self.sender_worker.stop())
        self.clear_send_btn = make_button("secondary", on_release=lambda *_: self.sender_log_box.clear())
        action.add_widget(self.send_btn)
        action.add_widget(self.stop_send_btn)
        action.add_widget(self.clear_send_btn)
        root.add_widget(action)
        self.sender_log_box = LogBox()
        root.add_widget(self.sender_log_box)
        return root

    def _build_recv_tab(self) -> None:
        root = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(8))
        form = GridLayout(cols=1, size_hint_y=None, spacing=dp(6))
        form.bind(minimum_height=form.setter("height"))
        self.bind_input = make_input(text="0.0.0.0", multiline=False)
        self.recv_port = make_input(text="9999", multiline=False, input_filter="int")
        self.recv_discovery_port = make_input(text=str(DEFAULT_DISCOVERY_PORT), multiline=False, input_filter="int")
        self.save_dir_input = make_input(text=str(user_data_dir() / "received"), multiline=False)
        self.allow_peer_input = make_input(text="", multiline=False)
        self.receiver_name_input = make_input(text="", multiline=False)
        self.approval_timeout_input = make_input(text="300", multiline=False, input_filter="float")
        self.once_checkbox = CheckBox(active=False, size_hint_x=None, width=dp(40))
        form.add_widget(row("", self.bind_input))
        form.add_widget(row("", self.recv_port))
        form.add_widget(row("", self.recv_discovery_port))
        save_line = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(38), spacing=dp(8))
        save_line.add_widget(make_label(text="", size_hint_x=None, width=dp(150), halign="right", valign="middle", shorten=True, color=THEME["muted_text"]))
        save_line.add_widget(self.save_dir_input)
        self.choose_dir_btn = make_button("secondary", size_hint_x=None, width=dp(110), on_release=lambda *_: self.choose_dir())
        save_line.add_widget(self.choose_dir_btn)
        form.add_widget(save_line)
        form.add_widget(row("", self.allow_peer_input))
        form.add_widget(row("", self.receiver_name_input))
        form.add_widget(row("", self.approval_timeout_input))
        once_line = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(38), spacing=dp(8))
        self.once_label = make_label(size_hint_x=None, width=dp(150), halign="right", valign="middle", shorten=True, color=THEME["muted_text"])
        once_line.add_widget(self.once_label)
        once_line.add_widget(self.once_checkbox)
        form.add_widget(once_line)
        root.add_widget(form)
        action = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(42), spacing=dp(8))
        self.start_recv_btn = make_button("success", on_release=lambda *_: self.start_receiver())
        self.stop_recv_btn = make_button("danger", on_release=lambda *_: self.receiver_worker.stop())
        self.firewall_btn = make_button("primary", on_release=lambda *_: self.allow_firewall())
        self.clear_recv_btn = make_button("secondary", on_release=lambda *_: self.receiver_log_box.clear())
        action.add_widget(self.start_recv_btn)
        action.add_widget(self.stop_recv_btn)
        action.add_widget(self.firewall_btn)
        action.add_widget(self.clear_recv_btn)
        root.add_widget(action)
        self.receiver_log_box = LogBox()
        root.add_widget(self.receiver_log_box)
        return root


    def show_page(self, page: str) -> None:
        if page == self.current_page:
            return
        self.page_host.clear_widgets()
        if page == "recv":
            self.page_host.add_widget(self.recv_page)
            self.current_page = "recv"
        else:
            self.page_host.add_widget(self.send_page)
            self.current_page = "send"
        self._refresh_tab_button_state()

    def _refresh_tab_button_state(self) -> None:
        # Keep both buttons enabled so users can always click them; use text mark
        # rather than disabled styling because disabled Kivy buttons may render
        # text poorly with some fonts.
        if not hasattr(self, "send_tab_btn"):
            return
        send_text = self.t("send_tab")
        recv_text = self.t("recv_tab")
        self.send_tab_btn.text = ("● " + send_text) if self.current_page == "send" else send_text
        self.recv_tab_btn.text = ("● " + recv_text) if self.current_page == "recv" else recv_text
        style_button(self.send_tab_btn, "active" if self.current_page == "send" else "secondary")
        style_button(self.recv_tab_btn, "active" if self.current_page == "recv" else "secondary")

    def refresh_texts(self) -> None:
        self.title_label.text = self.t("title")
        self.lang_btn.text = self.t("toggle_lang")
        self.send_tab_btn.text = self.t("send_tab")
        self.recv_tab_btn.text = self.t("recv_tab")
        self.manual_hint.text = self.t("manual_hint")
        # Row labels are kept by position; recreate label texts through parent children.
        self._set_row_label(self.receiver_ip, self.t("receiver_ip"))
        self._set_row_label(self.receiver_port, self.t("port"))
        self._set_discovery_line_label(self.discovery_port, self.t("discovery_port"))
        self._set_row_label(self.receiver_spinner, self.t("choose_receiver"))
        self._set_discovery_line_label(self.file_input, self.t("file"))
        self._set_row_label(self.payload_input, self.t("payload"))
        self._set_row_label(self.complete_timeout_input, self.t("complete_timeout"))
        self._set_row_label(self.request_timeout_input, self.t("request_timeout"))
        self.search_btn.text = self.t("search")
        self.choose_file_btn.text = self.t("choose_file")
        self.send_btn.text = self.t("send")
        self.stop_send_btn.text = self.t("stop")
        self.clear_send_btn.text = self.t("clear")
        self._set_row_label(self.bind_input, self.t("bind"))
        self._set_row_label(self.recv_port, self.t("port"))
        self._set_row_label(self.recv_discovery_port, self.t("discovery_port"))
        self._set_discovery_line_label(self.save_dir_input, self.t("save_dir"))
        self._set_row_label(self.allow_peer_input, self.t("allow_peer"))
        self._set_row_label(self.receiver_name_input, self.t("receiver_name"))
        self._set_row_label(self.approval_timeout_input, self.t("approval_timeout"))
        self.once_label.text = self.t("once")
        self.choose_dir_btn.text = self.t("choose_dir")
        self.start_recv_btn.text = self.t("start_recv")
        self.stop_recv_btn.text = self.t("stop_recv")
        self.firewall_btn.text = self.t("firewall")
        self.clear_recv_btn.text = self.t("clear")
        self._refresh_tab_button_state()
        self.update_progress_labels(0, 0, 0.0, self.t("unknown"), 0.0)

    def _set_row_label(self, widget, text: str) -> None:
        parent = widget.parent
        if parent and parent.children:
            # BoxLayout children are stored reverse order; label was added before widget.
            for child in parent.children:
                if isinstance(child, Label):
                    child.text = text
                    break

    def _set_discovery_line_label(self, widget, text: str) -> None:
        parent = widget.parent
        if parent and parent.children:
            for child in parent.children:
                if isinstance(child, Label):
                    child.text = text
                    break

    def toggle_lang(self) -> None:
        self.lang = "en" if self.lang == "zh" else "zh"
        self.app.lang = self.lang
        self.refresh_texts()
        self.refresh_local_ips()

    def refresh_local_ips(self) -> None:
        try:
            ips = get_local_ip_candidates()
        except Exception:
            ips = []
        text = ", ".join(ips) if ips else self.t("unknown")
        self.local_ip_label.text = self.t("local_ip", ips=text)

    def choose_file(self) -> None:
        self._native_file_dialog(select_dir=False, callback=lambda path: self._set_file(path))

    def _set_file(self, path: str) -> None:
        self.file_input.text = path
        try:
            size = os.path.getsize(path)
            self.update_progress_labels(0, size, 0.0, self.t("unknown"), 0.0)
        except Exception:
            pass

    def choose_dir(self) -> None:
        self._native_file_dialog(select_dir=True, callback=lambda path: setattr(self.save_dir_input, "text", path))

    def _native_file_dialog(self, select_dir: bool, callback) -> None:
        """Use the operating system file dialog first.

        On Windows this gives users the familiar Explorer-style picker and
        avoids Kivy FileChooser path-encoding issues with Chinese file names. If
        Tkinter is unavailable in a packaged build, fall back to the built-in
        Kivy chooser.
        """
        try:
            import tkinter as tk
            from tkinter import filedialog

            root = tk.Tk()
            root.withdraw()
            try:
                root.attributes("-topmost", True)
            except Exception:
                pass
            if select_dir:
                selected = filedialog.askdirectory(parent=root, title=self.t("choose_dir"))
            else:
                selected = filedialog.askopenfilename(parent=root, title=self.t("choose_file"))
            root.destroy()
            if selected:
                callback(str(selected))
            return
        except Exception:
            self.sender_log_box.append(self.t("native_dialog_failed") + "\n")
            self._file_popup(select_dir=select_dir, callback=callback)

    def _file_popup(self, select_dir: bool, callback) -> None:
        chooser = FileChooserListView(path=str(Path.home()), dirselect=select_dir)
        content = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(8))
        content.add_widget(chooser)
        buttons = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(42), spacing=dp(8))
        popup = style_popup(Popup(title=self.t("browse"), title_font=UI_FONT, content=content, size_hint=(0.9, 0.9)))
        def _select(_btn):
            selected = chooser.selection
            if selected:
                callback(selected[0])
                popup.dismiss()
        buttons.add_widget(make_button("primary", text=self.t("select"), on_release=_select))
        buttons.add_widget(make_button("secondary", text=self.t("cancel"), on_release=lambda *_: popup.dismiss()))
        content.add_widget(buttons)
        apply_ui_font(content)
        popup.open()

    def _receiver_endpoint(self, rec: Dict[str, object]) -> tuple[str, int]:
        ip = str(rec.get("endpoint_ip") or rec.get("ip") or "").strip()
        if not ip:
            ips = rec.get("ips") or []
            if isinstance(ips, (list, tuple)) and ips:
                ip = str(ips[0] or "").strip()
        try:
            port = int(rec.get("endpoint_port") or rec.get("port") or 9999)
        except Exception:
            port = 9999
        return ip, port

    def on_receiver_selected(self, _spinner, value: str) -> None:
        for rec in self.discovered:
            label = self._receiver_label(rec)
            if label == value:
                ip, port = self._receiver_endpoint(rec)
                if ip:
                    self.receiver_ip.text = ip
                    self.receiver_port.text = str(port)
                return

    def _receiver_label(self, rec: Dict[str, object]) -> str:
        name = str(rec.get("name") or rec.get("hostname") or "receiver")
        ip, port = self._receiver_endpoint(rec)
        return f"{name}  {ip}:{port}"

    def search_receivers(self) -> None:
        """Search LAN receivers without blocking the Kivy UI thread."""
        if getattr(self, "search_in_progress", False):
            return

        self.search_in_progress = True
        self.search_btn.disabled = True
        self.search_btn.text = self.t("search_working")
        self.sender_log_box.append(self.t("searching") + "\n")

        def _finish(found=None, error: Optional[str] = None):
            found = found or []
            self.discovered = found
            values = [self._receiver_label(x) for x in found]
            self.receiver_spinner.values = values
            self.receiver_spinner.text = values[0] if values else self.t("no_receiver")
            if found:
                self.on_receiver_selected(self.receiver_spinner, values[0])
                ip, port = self._receiver_endpoint(found[0])
                if ip:
                    self.receiver_ip.text = ip
                    self.receiver_port.text = str(port)
                    self.sender_log_box.append(f"Selected receiver: {ip}:{port}\n")
            if error:
                self.sender_log_box.append(f"Discovery failed: {error}\n")
            else:
                self.sender_log_box.append(self.t("search_done", n=len(found)) + "\n")
                if not found:
                    self.sender_log_box.append(self.t("search_none") + "\n")
            self.search_in_progress = False
            self.search_btn.disabled = False
            self.search_btn.text = self.t("search")
            style_button(self.search_btn, "primary")

        def _run():
            try:
                discovery_port = int(self.discovery_port.text or DEFAULT_DISCOVERY_PORT)
                transfer_port = int(self.receiver_port.text or 9999)
                manual_ip = self.receiver_ip.text.strip()
                found = discover_receivers(
                    discovery_port=discovery_port,
                    timeout=20.0,
                    extra_ports=[transfer_port],
                    manual_targets=[manual_ip] if manual_ip else None,
                    max_probe_hosts=2048,
                )
            except Exception as exc:
                Clock.schedule_once(lambda _dt, msg=str(exc): _finish([], msg), 0)
                return
            Clock.schedule_once(lambda _dt, result=found: _finish(result, None), 0)

        threading.Thread(target=_run, daemon=True).start()

    def start_sender(self) -> None:
        ip = self.receiver_ip.text.strip()
        if not ip:
            self.sender_log_box.append(self.t("need_ip") + "\n")
            return
        file_path = self.file_input.text.strip().strip('"')
        if not file_path or not os.path.isfile(file_path):
            self.sender_log_box.append(self.t("need_file") + "\n")
            return
        pin_file = str(user_data_dir() / "rudp_receiver_ed25519.pin")
        args = [
            "--server-ip", ip,
            "--server-port", self.receiver_port.text.strip() or "9999",
            "--file", file_path,
            "--payload-size", self.payload_input.text.strip() or "1300",
            "--complete-timeout", self.complete_timeout_input.text.strip() or "180",
            "--final-ack-timeout", self.complete_timeout_input.text.strip() or "180",
            "--request-timeout", self.request_timeout_input.text.strip() or "300",
            "--stats-interval", "0.5",
            "--server-pin-file", pin_file,
        ]
        self.progress.value = 0
        try:
            total = os.path.getsize(file_path)
            self.update_progress_labels(0, total, 0.0, self.t("unknown"), 0.0)
        except Exception:
            pass
        self.sender_worker.start(args)
        self.sender_log_box.append(self.t("started") + "\n")
        self.sender_log_box.append(self.t("request_waiting") + "\n")

    def start_receiver(self) -> None:
        save_dir = self.save_dir_input.text.strip() or str(user_data_dir() / "received")
        Path(save_dir).mkdir(parents=True, exist_ok=True)
        key_file = str(user_data_dir() / "rudp_receiver_ed25519.key")
        approval_dir = self.approval_dir
        approval_dir.mkdir(parents=True, exist_ok=True)
        self.seen_request_files.clear()
        for pattern in ("*.request.json", "*.accept", "*.reject"):
            for pth in approval_dir.glob(pattern):
                try:
                    pth.unlink()
                except Exception:
                    pass
        approval_timeout_text = self.approval_timeout_input.text.strip() or "300"
        try:
            idle_timeout_text = str(max(90.0, float(approval_timeout_text) + 60.0))
        except Exception:
            idle_timeout_text = "360"
        args = [
            "--bind", self.bind_input.text.strip() or "0.0.0.0",
            "--port", self.recv_port.text.strip() or "9999",
            "--save-dir", save_dir,
            "--discovery-port", self.recv_discovery_port.text.strip() or str(DEFAULT_DISCOVERY_PORT),
            "--server-id-key-file", key_file,
            "--require-approval",
            "--approval-dir", str(approval_dir),
            "--approval-timeout", approval_timeout_text,
            "--idle-timeout", idle_timeout_text,
        ]
        allow_peer = self.allow_peer_input.text.strip()
        if allow_peer:
            args += ["--allow-peer-ip", allow_peer]
        name = self.receiver_name_input.text.strip()
        if name:
            args += ["--receiver-name", name]
        if self.once_checkbox.active:
            args.append("--once")
        self.receiver_worker.start(args)
        self.receiver_log_box.append(self.t("started") + "\n")

    def allow_firewall(self) -> None:
        if not IS_WINDOWS:
            self.receiver_log_box.append("Firewall helper is Windows-only.\n")
            return
        script = RESOURCE_DIR / "allow_firewall_udp_9999_admin.bat"
        if not script.exists():
            self.receiver_log_box.append(f"Firewall script not found: {script}\n")
            return
        try:
            import ctypes
            rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", str(script), None, str(RESOURCE_DIR), 1)
            self.receiver_log_box.append(f"Firewall helper started, ShellExecute rc={rc}.\n")
        except Exception as exc:
            self.receiver_log_box.append(f"Failed to start firewall helper: {exc}\n")

    def sender_log(self, text: str) -> None:
        self.sender_log_box.append(text)

    def poll_approval_requests(self, _dt=None) -> bool:
        try:
            self.approval_dir.mkdir(parents=True, exist_ok=True)
            files = sorted(self.approval_dir.glob("*.request.json"), key=lambda p: p.stat().st_mtime)
        except Exception:
            return True
        for pth in files:
            key = str(pth)
            if key in self.seen_request_files:
                continue
            try:
                req = json.loads(pth.read_text(encoding="utf-8"))
            except Exception:
                continue
            conn_id = int(req.get("conn_id") or 0)
            if conn_id in self.pending_request_popups:
                continue
            self.seen_request_files.add(key)
            self.show_transfer_request(req)
        return True

    def receiver_log(self, text: str) -> None:
        self.receiver_log_box.append(text)
        if "end reason=complete" in text:
            self.receiver_log_box.append(self.t("receive_transfer_finished") + "\n")
        marker = TRANSFER_REQUEST_LOG_PREFIX
        if marker in text:
            payload = text.split(marker, 1)[1].strip()
            try:
                req = json.loads(payload)
            except Exception:
                return
            Clock.schedule_once(lambda _dt, data=req: self.show_transfer_request(data), 0)

    def show_transfer_request(self, req: Dict[str, object]) -> None:
        conn_id = int(req.get("conn_id") or 0)
        if conn_id in self.pending_request_popups:
            return
        self.pending_request_popups.add(conn_id)
        approval_dir = self.approval_dir
        approval_dir.mkdir(parents=True, exist_ok=True)
        request_path = approval_dir / f"{conn_id}.request.json"

        message = self.t(
            "incoming_request",
            sender=str(req.get("sender") or ""),
            name=str(req.get("name") or ""),
            size=format_file_size(int(req.get("size") or 0)),
            path=str(req.get("save_path") or ""),
            sha256=str(req.get("sha256") or ""),
        )
        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(12))
        lbl = make_label(text=message, halign="left", valign="top")
        bind_label_wrap(lbl)
        content.add_widget(lbl)
        buttons = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(42), spacing=dp(8))
        popup = style_popup(Popup(title=self.t("incoming_request_title"), title_font=UI_FONT, content=content, size_hint=(0.72, 0.55), auto_dismiss=False))

        def _decision(accepted: bool):
            target = approval_dir / (f"{conn_id}.accept" if accepted else f"{conn_id}.reject")
            try:
                target.write_text("accepted" if accepted else "rejected", encoding="utf-8")
                try:
                    request_path.unlink()
                except Exception:
                    pass
                self.seen_request_files.discard(str(request_path))
                self.receiver_log_box.append(("Accepted" if accepted else "Rejected") + f" transfer request conn_id={conn_id}\n")
            except Exception as exc:
                self.receiver_log_box.append(f"Failed to write approval file: {exc}\n")
            self.pending_request_popups.discard(conn_id)
            popup.dismiss()

        buttons.add_widget(make_button("success", text=self.t("accept"), on_release=lambda *_: _decision(True)))
        buttons.add_widget(make_button("danger", text=self.t("reject"), on_release=lambda *_: _decision(False)))
        content.add_widget(buttons)
        apply_ui_font(content)
        popup.bind(on_dismiss=lambda *_: self.pending_request_popups.discard(conn_id))
        popup.open()

    def sender_exit(self, rc) -> None:
        self.sender_log_box.append(f"Process exited, rc={rc}\n")
        if int(rc or 0) == 0:
            self.sender_log_box.append(self.t("transfer_finished") + "\n")

    def receiver_exit(self, rc) -> None:
        self.receiver_log_box.append(f"Process exited, rc={rc}\n")

    def sender_progress(self, data: Dict[str, object]) -> None:
        def _update(_dt):
            sent = int(data.get("sent") or 0)
            total = int(data.get("total") or 0)
            pct = float(data.get("pct") or 0.0)
            avg = float(data.get("avg") or 0.0)
            eta = str(data.get("eta") or self.t("unknown"))
            self.update_progress_labels(sent, total, pct, eta, avg)
        Clock.schedule_once(_update, 0)

    def update_progress_labels(self, sent: int, total: int, pct: float, eta: str, avg: float) -> None:
        self.progress.value = max(0.0, min(100.0, float(pct)))
        self.progress_label.text = f"{self.t('progress')}: {pct:.2f}%  {format_file_size(sent)} / {format_file_size(total)}"
        self.eta_label.text = self.t("eta", eta=eta or self.t("unknown"))
        self.speed_label.text = self.t("speed", speed=f"{avg:.2f} Mbps") + "    " + self.t("size", size=format_file_size(total))

    def on_stop(self) -> None:
        self.sender_worker.stop()
        self.receiver_worker.stop()


class RUDPTransferApp(App):
    lang = StringProperty("zh")
    title = "RUDPTransfer"
    icon = str(RESOURCE_DIR / "assets" / "app.png")

    def build(self):
        Window.size = (980, 720)
        Window.clearcolor = THEME["window_bg"]
        self.root_widget = RUDPTransferRoot(self)
        return self.root_widget

    def on_stop(self):
        try:
            self.root_widget.on_stop()
        except Exception:
            pass


if __name__ == "__main__":
    RUDPTransferApp().run()
