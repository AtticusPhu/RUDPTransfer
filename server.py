#!/usr/bin/env python3
"""RUDP file receiver for real two-machine transfer.

Example:
    python3 server.py --bind 0.0.0.0 --port 9999 --save-dir ./received --ask
"""

from __future__ import annotations

import sys

for _stream_name in ("stdout", "stderr"):
    _stream = getattr(sys, _stream_name, None)
    if _stream is not None:
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

import argparse
import errno
import hashlib
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from file_transfer_common import (
    DEFAULT_DISCOVERY_PORT,
    DISCOVERY_MAGIC,
    EOF_PAYLOAD,
    build_discovery_response,
    allocate_output_path,
    build_transfer_decision,
    build_transfer_request_log,
    build_transfer_request_obj,
    build_user_error,
    output_conflict_info,
    parse_file_header,
    print_local_ip_candidates,
    probe_save_directory,
    unique_path,
    resume_candidate_info,
    write_resume_meta,
    remove_resume_meta,
    sha256_file,
)
from protocol import ReliableUDPSession, SYN_PAYLOAD_TAG
from utils import FLAG_SYN, Packet, setup_logger


def _format_duration(seconds: float) -> str:
    try:
        seconds = float(seconds)
    except Exception:
        return "unknown"
    if seconds < 0 or seconds == float("inf"):
        return "unknown"
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{sec:02d}"
    return f"{m:d}:{sec:02d}"


def load_or_create_server_identity_key(path: str, logger=None):
    path = str(path or "").strip()
    if not path:
        raise ValueError("server identity key path is empty")

    key_path = os.path.abspath(path)
    parent = os.path.dirname(key_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    created = False
    if os.path.exists(key_path):
        raw = open(key_path, "rb").read().strip()
        if not raw:
            raise ValueError(f"server identity key file is empty: {key_path}")
        key = None
        try:
            if len(raw) == 32:
                key = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
            else:
                text = raw.decode("ascii")
                if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
                    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))
        except Exception:
            key = None
        if key is None:
            raise ValueError(f"unsupported server identity key format: {key_path}")
    else:
        key = ed25519.Ed25519PrivateKey.generate()
        seed = key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        tmp_path = key_path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(seed.hex().encode("ascii") + b"\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, key_path)
        created = True

    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if logger is not None:
        fp = hashlib.sha256(pub).hexdigest()
        action = "Created" if created else "Loaded"
        logger.info(f"{action} receiver identity key: path={key_path}, fingerprint={fp}")
    return key, pub, created


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Receive files through the RUDP protocol.")
    p.add_argument("--bind", default="0.0.0.0", help="Bind address; usually keep 0.0.0.0")
    p.add_argument("--port", type=int, default=9999, help="UDP listen port")
    p.add_argument("--save-dir", default="./received", help="Directory for received files")
    p.add_argument("--ask", action="store_true", help="Ask before accepting each file in console mode")
    p.add_argument("--require-approval", action="store_true", help="Require GUI/file approval before accepting each file")
    p.add_argument("--approval-dir", default="", help="Directory used for GUI approval files")
    p.add_argument("--approval-timeout", type=float, default=300.0, help="Seconds to wait for GUI approval")
    p.add_argument("--allow-peer-ip", default="", help="Only accept sender from this IPv4 address")
    p.add_argument("--sock-rcvbuf", type=int, default=8 * 1024 * 1024)
    p.add_argument("--sock-sndbuf", type=int, default=8 * 1024 * 1024)
    p.add_argument("--handshake-timeout", type=float, default=5.0)
    p.add_argument("--final-ack-wait-timeout", type=float, default=75.0)
    p.add_argument("--idle-timeout", type=float, default=60.0)
    p.add_argument("--complete-ack-timeout", type=float, default=60.0)
    p.add_argument("--stats-interval", type=float, default=1.0)
    p.add_argument("--app-queue-max-items", type=int, default=65536)
    p.add_argument("--server-id-key-file", default="./rudp_receiver_ed25519.key", help="Receiver Ed25519 identity key")
    p.add_argument("--show-ips", action="store_true", help="Print local IP candidates at startup")
    p.add_argument("--discovery-port", type=int, default=DEFAULT_DISCOVERY_PORT, help="UDP broadcast discovery port")
    p.add_argument("--disable-discovery", action="store_true", help="Disable LAN broadcast discovery response")
    p.add_argument("--receiver-name", default="", help="Friendly name shown during LAN discovery")
    p.add_argument("--once", action="store_true", help="Stop receiver after one completed or failed transfer")
    p.add_argument("--keep-part-on-failure", action="store_true", default=True, help="Keep incomplete .part files for resume support")
    p.add_argument("--verbose-protocol", action="store_true", help="Show high-volume internal ACK logs")
    return p


class RUDPFileReceiver:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        if not bool(getattr(args, "verbose_protocol", False)):
            os.environ.setdefault("RUDP_VERBOSE_PROTOCOL", "0")
        self.logger = setup_logger("RUDP-Receiver")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(args.sock_rcvbuf))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(args.sock_sndbuf))
        self.sock.settimeout(0.5)
        self.sock.bind((str(args.bind), int(args.port)))
        self.running = True
        self.lock = threading.RLock()
        self.sessions: Dict[int, ReliableUDPSession] = {}
        self.discovery_sock: Optional[socket.socket] = None
        self.session_created_ts: Dict[int, float] = {}
        self.session_key_ready_ts: Dict[int, Optional[float]] = {}
        self.server_identity_key, self.server_identity_pub, _ = load_or_create_server_identity_key(
            str(args.server_id_key_file), logger=self.logger
        )

    def start(self) -> None:
        if self.args.show_ips:
            print_local_ip_candidates()
        self.logger.info(f"Listening on {self.sock.getsockname()}, save_dir={Path(self.args.save_dir).resolve()}")
        if not bool(getattr(self.args, "disable_discovery", False)):
            threading.Thread(target=self._discovery_listener, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        self._udp_listener()

    def stop(self) -> None:
        self.running = False
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for sess in sessions:
            try:
                sess.stop()
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            if self.discovery_sock is not None:
                self.discovery_sock.close()
        except Exception:
            pass

    def _discovery_listener(self) -> None:
        port = int(getattr(self.args, "discovery_port", DEFAULT_DISCOVERY_PORT) or DEFAULT_DISCOVERY_PORT)
        try:
            dsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            dsock.settimeout(0.5)
            dsock.bind(("0.0.0.0", port))
            self.discovery_sock = dsock
            self.logger.info(f"LAN discovery enabled on UDP port {port}")
        except Exception as exc:
            self.logger.warning(f"LAN discovery disabled: cannot bind UDP port {port}: {exc}")
            return

        magic = DISCOVERY_MAGIC.encode("ascii")
        while self.running:
            try:
                data, addr = dsock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if bytes(data).strip() != magic:
                continue
            allow_peer = str(getattr(self.args, "allow_peer_ip", "") or "").strip()
            if allow_peer and addr[0] != allow_peer:
                continue
            try:
                payload = build_discovery_response(
                    receiver_port=int(self.args.port),
                    receiver_name=str(getattr(self.args, "receiver_name", "") or ""),
                )
                dsock.sendto(payload, addr)
                self.logger.info(f"Discovery response sent to {addr[0]}:{addr[1]}")
            except OSError as exc:
                self.logger.warning(f"Discovery response failed to {addr}: {exc}")

    def _peer_allowed(self, addr: Tuple[str, int]) -> bool:
        allow_ip = str(self.args.allow_peer_ip or "").strip()
        return (not allow_ip) or (addr[0] == allow_ip)

    def _cleanup_loop(self) -> None:
        while self.running:
            time.sleep(0.2)
            now = time.time()
            drop = []
            with self.lock:
                for cid, sess in list(self.sessions.items()):
                    created = float(self.session_created_ts.get(cid, now))
                    last = max(created, float(getattr(sess, "last_activity", created) or created))
                    if sess.is_session_key_ready and self.session_key_ready_ts.get(cid) is None:
                        self.session_key_ready_ts[cid] = now
                    if sess.has_fatal_error():
                        drop.append((cid, "fatal_error"))
                        continue
                    if not sess.handshake_completed_local:
                        if not sess.is_session_key_ready:
                            if now - last > float(self.args.handshake_timeout):
                                drop.append((cid, "handshake_timeout"))
                        else:
                            ref = float(self.session_key_ready_ts.get(cid) or last)
                            if now - ref > float(self.args.final_ack_wait_timeout):
                                drop.append((cid, "final_ack_wait_timeout"))
                    elif not getattr(sess, "running", True):
                        drop.append((cid, "session_stopped"))

            for cid, reason in drop:
                self.logger.warning(f"Dropping session {cid}: {reason}")
                self._end_session(cid)

    def _end_session(self, cid: int) -> None:
        with self.lock:
            sess = self.sessions.pop(cid, None)
            self.session_created_ts.pop(cid, None)
            self.session_key_ready_ts.pop(cid, None)
        if sess is not None:
            try:
                sess.stop()
            except Exception:
                pass

    def _udp_listener(self) -> None:
        while self.running:
            start_app = False
            sess_for_app = None
            try:
                data, addr = self.sock.recvfrom(65535)

                # Also answer LAN discovery on the transfer port. This makes
                # discovery work even when Windows Firewall allows UDP 9999 for
                # file transfer but blocks the separate discovery port 9998.
                if bytes(data).strip() == DISCOVERY_MAGIC.encode("ascii"):
                    allow_peer = str(getattr(self.args, "allow_peer_ip", "") or "").strip()
                    if allow_peer and addr[0] != allow_peer:
                        continue
                    try:
                        payload = build_discovery_response(
                            receiver_port=int(self.args.port),
                            receiver_name=str(getattr(self.args, "receiver_name", "") or ""),
                        )
                        self.sock.sendto(payload, addr)
                        self.logger.info(f"Discovery response sent on transfer port to {addr[0]}:{addr[1]}")
                    except OSError as exc:
                        self.logger.warning(f"Discovery response on transfer port failed to {addr}: {exc}")
                    continue

                pkt, _payload = Packet.unpack_header(data)
                if pkt is None:
                    continue
                cid = int(pkt.conn_id)

                with self.lock:
                    sess = self.sessions.get(cid)
                    if sess is None:
                        if not (pkt.flags & FLAG_SYN):
                            continue
                        if not self._peer_allowed(addr):
                            self.logger.warning(f"Reject SYN from {addr}: allow_peer_ip={self.args.allow_peer_ip}")
                            continue
                        if not pkt.payload.startswith(SYN_PAYLOAD_TAG):
                            continue

                        self.logger.info(f"New session {cid} from {addr}")
                        sess = ReliableUDPSession(
                            cid,
                            addr,
                            self.sock,
                            is_client=False,
                            server_sign_private_key=self.server_identity_key,
                        )
                        sess.configure_app_delivery(
                            len_only=False,
                            small_payload_threshold=0,
                            queue_max_items=int(self.args.app_queue_max_items),
                        )
                        sess.start_threads(start_receiver=False)
                        self.sessions[cid] = sess
                        self.session_created_ts[cid] = time.time()
                        self.session_key_ready_ts[cid] = None
                        start_app = True
                        sess_for_app = sess

                if start_app and sess_for_app is not None:
                    threading.Thread(target=self._app_handler, args=(sess_for_app,), daemon=True).start()

                if sess is not None:
                    sess.handle_packet(data, addr)

            except socket.timeout:
                continue
            except OSError as exc:
                err_no = getattr(exc, "errno", None)
                if (not self.running) or err_no in (errno.EBADF, errno.ENOTSOCK):
                    break
                self.logger.error(f"socket error: {exc}")
                time.sleep(0.05)
            except Exception as exc:
                self.logger.error(f"listener error: {exc}")
                time.sleep(0.05)

    def _wait_gui_approval(self, conn_id: int, peer_addr, meta: Dict[str, object], suggested_path: Path, conflict: Dict[str, object]) -> Tuple[bool, str, Dict[str, object]]:
        approval_dir = str(getattr(self.args, "approval_dir", "") or "").strip()
        if not approval_dir:
            approval_dir = str(Path(self.args.save_dir).resolve())
        adir = Path(approval_dir).expanduser().resolve()
        adir.mkdir(parents=True, exist_ok=True)
        accept_path = adir / f"{int(conn_id)}.accept"
        reject_path = adir / f"{int(conn_id)}.reject"
        for pth in (accept_path, reject_path):
            try:
                if pth.exists():
                    pth.unlink()
            except Exception:
                pass

        req_obj = build_transfer_request_obj(
            int(conn_id),
            peer_addr,
            meta,
            suggested_path,
            original_path=str(conflict.get("original_path") or suggested_path),
            part_path=str(conflict.get("part_path") or (str(suggested_path) + ".part")),
            file_exists=bool(conflict.get("file_exists")),
            part_exists=bool(conflict.get("part_exists")),
            conflict=bool(conflict.get("conflict")),
            resume_available=bool(conflict.get("resume_available")),
            resume_offset=int(conflict.get("resume_offset") or 0),
            resume_pct=float(conflict.get("resume_pct") or 0.0),
            resume_reason=str(conflict.get("resume_reason") or conflict.get("reason") or ""),
            default_file_policy="resume" if bool(conflict.get("resume_available")) else ("rename" if bool(conflict.get("conflict")) else "overwrite"),
        )
        request_path = adir / f"{int(conn_id)}.request.json"
        try:
            tmp = request_path.with_suffix(request_path.suffix + ".tmp")
            tmp.write_text(json.dumps(req_obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, request_path)
        except Exception as exc:
            self.logger.warning(f"Session {conn_id}: failed to write approval request file: {exc}")
        self.logger.info(build_transfer_request_log(
            int(conn_id),
            peer_addr,
            meta,
            suggested_path,
            original_path=req_obj.get("original_path"),
            part_path=req_obj.get("part_path"),
            file_exists=req_obj.get("file_exists"),
            part_exists=req_obj.get("part_exists"),
            conflict=req_obj.get("conflict"),
            resume_available=req_obj.get("resume_available"),
            resume_offset=req_obj.get("resume_offset"),
            resume_pct=req_obj.get("resume_pct"),
            default_file_policy=req_obj.get("default_file_policy"),
        ))
        self.logger.info(f"Session {conn_id}: waiting for receiver approval")
        deadline = time.time() + max(1.0, float(getattr(self.args, "approval_timeout", 300.0) or 300.0))
        while self.running and time.time() < deadline:
            if accept_path.exists():
                decision = {"file_policy": str(req_obj.get("default_file_policy") or "overwrite")}
                try:
                    txt = accept_path.read_text(encoding="utf-8", errors="ignore").strip()
                    if txt:
                        try:
                            obj = json.loads(txt)
                            if isinstance(obj, dict):
                                decision.update(obj)
                            else:
                                decision["note"] = txt[:200]
                        except Exception:
                            decision["note"] = txt[:200]
                    accept_path.unlink()
                except Exception:
                    pass
                try:
                    request_path.unlink()
                except Exception:
                    pass
                return True, "accepted", decision
            if reject_path.exists():
                reason = "rejected"
                decision = {}
                try:
                    txt = reject_path.read_text(encoding="utf-8", errors="ignore").strip()
                    if txt:
                        try:
                            obj = json.loads(txt)
                            if isinstance(obj, dict):
                                decision.update(obj)
                                reason = str(obj.get("reason") or obj.get("code") or reason)
                            else:
                                reason = txt[:200]
                        except Exception:
                            reason = txt[:200]
                    reject_path.unlink()
                except Exception:
                    pass
                try:
                    request_path.unlink()
                except Exception:
                    pass
                return False, reason, decision
            time.sleep(0.1)
        try:
            request_path.unlink()
        except Exception:
            pass
        return False, "approval_timeout", {}

    def _ask_accept(self, conn_id: int, peer_addr, meta: Dict[str, object], suggested_path: Path, conflict: Dict[str, object]) -> Tuple[bool, str, Dict[str, object]]:
        if bool(getattr(self.args, "require_approval", False)):
            return self._wait_gui_approval(int(conn_id), peer_addr, meta, suggested_path, conflict)
        if not bool(self.args.ask):
            # Console-less/default mode: keep backward-compatible behavior. If a
            # conflict exists, choose a unique name rather than overwriting.
            return True, "accepted", {"file_policy": "resume" if bool(conflict.get("resume_available")) else ("rename" if bool(conflict.get("conflict")) else "overwrite")}
        print("\nIncoming file-transfer request")
        print(f"Sender: {peer_addr[0]}:{peer_addr[1]}")
        print(f"File name: {meta.get('name')}")
        print(f"Size: {meta.get('size')} bytes")
        print(f"SHA256: {meta.get('sha256')}")
        print(f"Suggested save path: {suggested_path}")
        policy = "resume" if bool(conflict.get("resume_available")) else ("rename" if bool(conflict.get("conflict")) else "overwrite")
        if bool(conflict.get("resume_available")):
            print(f"Resume candidate found: offset={int(conflict.get('resume_offset') or 0)} bytes ({float(conflict.get('resume_pct') or 0.0):.2f}%).")
            ans_policy = input("Choose policy: [r]esume/[o]verwrite/[c]ancel? ").strip().lower()
            if ans_policy in ("o", "overwrite"):
                policy = "overwrite"
            elif ans_policy in ("c", "cancel", "n", "no"):
                return False, "file_exists_cancelled", {"file_policy": "cancel"}
            else:
                policy = "resume"
        elif bool(conflict.get("conflict")):
            print("Target file or .part file already exists.")
            ans_policy = input("Choose policy: [r]ename/[o]verwrite/[c]ancel? ").strip().lower()
            if ans_policy in ("o", "overwrite"):
                policy = "overwrite"
            elif ans_policy in ("c", "cancel", "n", "no"):
                return False, "file_exists_cancelled", {"file_policy": "cancel"}
        ans = input("Accept this file? [y/N] ").strip().lower()
        ok = ans in ("y", "yes")
        return ok, ("accepted" if ok else "rejected"), {"file_policy": policy}

    def _app_handler(self, session: ReliableUDPSession) -> None:
        cid = int(session.conn_id)
        peer_addr = session.peer_addr
        header_seen = False
        eof_seen = False
        meta: Optional[Dict[str, object]] = None
        out_path: Optional[Path] = None
        part_path: Optional[Path] = None
        out_f = None
        sha = hashlib.sha256()
        expected_total: Optional[int] = None
        bytes_recv = 0
        pkts_recv = 0
        start_ts = time.time()
        last_report_ts = start_ts
        last_report_bytes = 0
        last_meta_update_ts = start_ts
        last_meta_update_bytes = 0
        exit_reason = "unknown"

        try:
            while True:
                if session.has_fatal_error():
                    exit_reason = "fatal_protocol_error"
                    break

                item = session.get_app_item(timeout=0.05)
                now = time.time()

                if item is None:
                    if not getattr(session, "running", True):
                        exit_reason = "session_stopped"
                        break
                    idle_ref = max(float(getattr(session, "last_activity", start_ts) or start_ts), start_ts)
                    if now - idle_ref > float(self.args.idle_timeout):
                        exit_reason = "idle_timeout"
                        session.abort(exit_reason)
                        break
                    continue

                seq, data_or_len, is_len = item
                if is_len:
                    exit_reason = "unexpected_len_only_payload"
                    session.abort(exit_reason)
                    break
                data = bytes(data_or_len or b"")

                if not header_seen:
                    if data == EOF_PAYLOAD:
                        exit_reason = "eof_before_header"
                        session.abort(exit_reason)
                        break
                    meta = parse_file_header(data)
                    expected_total = int(meta["size"])

                    save_check = probe_save_directory(str(self.args.save_dir), required_bytes=expected_total)
                    if not bool(save_check.get("ok")):
                        exit_reason = str(save_check.get("code") or "save_dir_error")
                        detail = str(save_check.get("detail") or "")
                        self.logger.error(build_user_error(exit_reason, "Receiver cannot save the incoming file", detail))
                        try:
                            session.send_app_data(1, build_transfer_decision(False, exit_reason, cid, detail=detail))
                        except Exception as exc:
                            self.logger.warning(f"Session {cid}: failed to send transfer decision: {exc}")
                        time.sleep(0.2)
                        session.abort(exit_reason)
                        break

                    conflict = output_conflict_info(str(self.args.save_dir), str(meta["name"]))
                    resume_info = resume_candidate_info(str(self.args.save_dir), meta)
                    conflict.update({
                        "resume_available": bool(resume_info.get("resume_available")),
                        "resume_offset": int(resume_info.get("resume_offset") or 0),
                        "resume_pct": float(resume_info.get("resume_pct") or 0.0),
                        "resume_reason": str(resume_info.get("reason") or ""),
                    })
                    if bool(conflict.get("resume_available")):
                        suggested_path = Path(str(resume_info.get("out_path")))
                    else:
                        suggested_path = allocate_output_path(str(self.args.save_dir), str(meta["name"]), policy="rename" if bool(conflict.get("conflict")) else "overwrite")

                    accepted, decision_reason, decision = self._ask_accept(cid, peer_addr, meta, suggested_path, conflict)
                    policy = str((decision or {}).get("file_policy") or ("resume" if bool(conflict.get("resume_available")) else ("rename" if bool(conflict.get("conflict")) else "overwrite"))).strip().lower()
                    if policy not in ("resume", "rename", "overwrite"):
                        policy = "rename" if bool(conflict.get("conflict")) else "overwrite"

                    resume_offset = 0
                    if policy == "resume" and bool(conflict.get("resume_available")):
                        out_path = Path(str(resume_info.get("out_path")))
                        part_path = Path(str(resume_info.get("part_path")))
                        resume_offset = int(resume_info.get("resume_offset") or 0)
                        payload = max(1, int(meta.get("payload_size") or 1))
                        resume_offset -= resume_offset % payload
                        if resume_offset <= 0 or resume_offset >= int(expected_total or 0):
                            policy = "overwrite"
                            resume_offset = 0
                    if policy != "resume":
                        out_path = allocate_output_path(str(self.args.save_dir), str(meta["name"]), policy=policy)
                        part_path = Path(str(out_path) + ".part")

                    resume_pct = (resume_offset * 100.0 / max(int(expected_total or 0), 1)) if resume_offset > 0 else 0.0
                    try:
                        session.send_app_data(1, build_transfer_decision(
                            bool(accepted), str(decision_reason), cid,
                            file_policy=policy, resume=(policy == "resume" and resume_offset > 0),
                            resume_offset=int(resume_offset), resume_pct=float(resume_pct),
                        ))
                    except Exception as exc:
                        self.logger.warning(f"Session {cid}: failed to send transfer decision: {exc}")
                    if not accepted:
                        exit_reason = "user_rejected" if decision_reason == "rejected" else str(decision_reason or "user_rejected")
                        time.sleep(0.2)
                        session.abort(exit_reason)
                        break

                    try:
                        if policy == "resume" and resume_offset > 0 and part_path is not None:
                            with open(part_path, "r+b") as fp:
                                fp.truncate(int(resume_offset))
                            out_f = open(part_path, "ab")
                            bytes_recv = int(resume_offset)
                            last_report_bytes = int(resume_offset)
                            self.logger.info(
                                f"Session {cid}: resume accepted; offset={resume_offset}/{expected_total} bytes "
                                f"({resume_pct:.2f}%) -> {out_path}"
                            )
                        else:
                            try:
                                if part_path is not None and part_path.exists():
                                    part_path.unlink()
                                    remove_resume_meta(part_path)
                            except Exception:
                                pass
                            out_f = open(part_path, "wb")
                            bytes_recv = 0
                            last_report_bytes = 0
                    except Exception as exc:
                        exit_reason = "output_open_failed"
                        detail = str(exc)
                        self.logger.error(build_user_error(exit_reason, "Receiver failed to open output file", detail))
                        try:
                            session.send_app_data(1, build_transfer_decision(False, exit_reason, cid, detail=detail))
                        except Exception:
                            pass
                        session.abort(exit_reason)
                        break

                    try:
                        if part_path is not None and out_path is not None:
                            write_resume_meta(part_path, meta, out_path, int(bytes_recv))
                    except Exception as exc:
                        self.logger.warning(f"Session {cid}: failed to write resume meta: {exc}")
                    header_seen = True
                    self.logger.info(
                        f"Session {cid}: transfer accepted; receiving {meta['name']} from {peer_addr}, "
                        f"size={expected_total} bytes -> {out_path}, policy={policy}, resume_offset={resume_offset}"
                    )
                    continue

                if data == EOF_PAYLOAD:
                    eof_seen = True
                    if out_f is not None:
                        out_f.flush()
                        os.fsync(out_f.fileno())
                        out_f.close()
                        out_f = None
                    break

                if out_f is None:
                    exit_reason = "output_not_open"
                    session.abort(exit_reason)
                    break

                out_f.write(data)
                sha.update(data)
                bytes_recv += len(data)
                pkts_recv += 1

                if part_path is not None and out_path is not None and (bytes_recv - last_meta_update_bytes >= 4 * 1024 * 1024 or now - last_meta_update_ts >= 1.0):
                    try:
                        write_resume_meta(part_path, meta or {}, out_path, int(bytes_recv))
                        last_meta_update_bytes = int(bytes_recv)
                        last_meta_update_ts = now
                    except Exception as exc:
                        self.logger.warning(f"Session {cid}: failed to update resume meta: {exc}")

                if now - last_report_ts >= float(self.args.stats_interval):
                    elapsed = max(now - start_ts, 1e-6)
                    interval = max(now - last_report_ts, 1e-6)
                    avg_mbps = (bytes_recv * 8.0) / elapsed / 1e6
                    int_mbps = ((bytes_recv - last_report_bytes) * 8.0) / interval / 1e6
                    pct = (bytes_recv * 100.0 / expected_total) if expected_total else 0.0
                    remaining_bytes = max(int(expected_total or 0) - int(bytes_recv), 0)
                    interval_bytes = int(bytes_recv) - int(last_report_bytes)
                    rate_bps = (interval_bytes / interval) if interval_bytes > 0 else ((bytes_recv / elapsed) if bytes_recv > 0 else 0.0)
                    eta_text = _format_duration(remaining_bytes / rate_bps) if rate_bps > 0 else "unknown"
                    self.logger.info(
                        f"Session {cid}: {bytes_recv}/{expected_total} bytes ({pct:.2f}%), "
                        f"pkts={pkts_recv}, avg={avg_mbps:.2f} Mbps, interval={int_mbps:.2f} Mbps, eta={eta_text}"
                    )
                    last_report_ts = now
                    last_report_bytes = bytes_recv

            if eof_seen and header_seen and meta is not None and expected_total is not None:
                if part_path is not None and part_path.exists():
                    try:
                        received_sha = sha256_file(str(part_path))
                    except Exception:
                        received_sha = sha.hexdigest()
                else:
                    received_sha = sha.hexdigest()
                expected_sha = str(meta.get("sha256") or "").lower()
                if bytes_recv != expected_total:
                    exit_reason = "size_mismatch"
                    session.abort(exit_reason)
                    self.logger.error(f"Session {cid}: size mismatch {bytes_recv}/{expected_total}")
                elif expected_sha and received_sha != expected_sha:
                    exit_reason = "sha256_mismatch"
                    session.abort(exit_reason)
                    self.logger.error(f"Session {cid}: sha256 mismatch expected={expected_sha} got={received_sha}")
                else:
                    if part_path is not None and out_path is not None:
                        os.replace(part_path, out_path)
                        remove_resume_meta(part_path)
                    complete_res = session.send_complete_commit(int(expected_total), int(bytes_recv))
                    if not bool((complete_res or {}).get("ok")):
                        exit_reason = f"complete_commit_failed:{(complete_res or {}).get('status')}"
                        session.abort(exit_reason)
                    elif not session.wait_for_complete_ack(timeout=float(self.args.complete_ack_timeout)):
                        exit_reason = "complete_ack_timeout"
                        session.abort(exit_reason)
                    else:
                        exit_reason = "complete"
                        elapsed = max(time.time() - start_ts, 1e-6)
                        self.logger.info(
                            f"Session {cid}: saved {out_path}, bytes={bytes_recv}, "
                            f"sha256={received_sha}, elapsed={elapsed:.3f}s, "
                            f"avg={(bytes_recv * 8.0 / elapsed / 1e6):.2f} Mbps"
                        )

        except Exception as exc:
            exit_reason = f"app_error:{exc}"
            self.logger.error(f"Session {cid}: app error: {exc}")
            try:
                session.abort(exit_reason)
            except Exception:
                pass
        finally:
            if out_f is not None:
                try:
                    out_f.close()
                except Exception:
                    pass
            if exit_reason != "complete" and part_path is not None:
                try:
                    if out_path is not None and part_path.exists() and meta is not None:
                        write_resume_meta(part_path, meta, out_path, int(bytes_recv))
                        self.logger.info(f"Session {cid}: kept partial file for resume: {part_path}, bytes={bytes_recv}")
                except Exception as exc:
                    self.logger.warning(f"Session {cid}: failed to preserve resume meta: {exc}")
            self.logger.info(f"Session {cid}: end reason={exit_reason}, bytes_recv={bytes_recv}")
            # A short linger keeps the receiver alive for duplicate EOF/COMPLETE_ACK traffic.
            if exit_reason == "complete":
                time.sleep(1.0)
            self._end_session(cid)
            if bool(getattr(self.args, "once", False)):
                self.logger.info("One-shot mode: stopping receiver")
                self.running = False
                try:
                    self.sock.close()
                except Exception:
                    pass


def main() -> int:
    args = build_argparser().parse_args()
    receiver = RUDPFileReceiver(args)
    try:
        receiver.start()
    except KeyboardInterrupt:
        return 130
    finally:
        receiver.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
