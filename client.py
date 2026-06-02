#!/usr/bin/env python3
"""RUDP file sender for real two-machine transfer.

Example:
    python3 client.py --server-ip 192.168.1.25 --server-port 9999 --file ./demo.zip
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
import json
import math
import os
import secrets
import socket
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from congestion import CubicCongestionControl
from file_transfer_common import (
    BATCH_TRANSFER_STATUS_ACTIVE,
    DATA_SEQ_UPPER_EXCLUSIVE,
    EOF_PAYLOAD,
    FILE_BODY_OFFSET_HEADER_LEN,
    FILE_TRANSFER_STATUS_ACTIVE,
    MAX_DATA_SEQ,
    SEQ_FIRST_BODY,
    SEQ_HEADER,
    TRANSFER_MODE_LARGE_RANGE,
    BatchTransferTask,
    FileBatchScheduler,
    FileTransferTask,
    choose_file_transfer_slice_bytes,
    build_file_body_frame,
    build_file_header,
    build_file_offer,
    build_file_offer_item,
    build_user_error,
    build_user_status,
    classify_file_transfer_network_state,
    consume_scheduled_range,
    missing_ranges_from_received,
    normalize_ranges,
    parse_file_offer_accept,
    parse_transfer_decision,
    print_local_ip_candidates,
    ranges_total_bytes,
    schedule_missing_ranges,
    sha256_file,
)
from protocol import (
    AEAD_TAG_LEN,
    DATA_FRAME_HEADER_LEN,
    MAX_DATA_APP_PAYLOAD,
    UDP_MAX_DATAGRAM_PAYLOAD,
    ReliableUDPSession,
    data_packet_wire_size,
)
from utils import HEADER_SIZE, setup_logger


def _sha256_hex_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(bytes(data or b"")).hexdigest()


def _load_pinned_server_pub(path: str) -> Optional[bytes]:
    path = str(path or "").strip()
    if not path or not os.path.exists(path):
        return None
    raw = open(path, "rb").read().strip()
    if not raw:
        return None
    try:
        text = raw.decode("ascii")
        if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
            return bytes.fromhex(text)
    except Exception:
        pass
    return bytes(raw)


def _store_pinned_server_pub(path: str, pub_bytes: bytes) -> None:
    path = str(path or "").strip()
    if not path:
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(bytes(pub_bytes).hex().encode("ascii") + b"\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def make_server_identity_validator(pin_file: str, logger, require_existing_pin: bool = False):
    state = {
        "pinned": _load_pinned_server_pub(pin_file),
        "announced": False,
        "identity_mismatch": None,
        "pin_file": str(pin_file or ""),
    }

    def validator(server_pub: bytes) -> bool:
        server_pub = bytes(server_pub or b"")
        if len(server_pub) != 32:
            state["identity_mismatch"] = {"reason": "invalid_receiver_identity", "pin_file": str(pin_file or "")}
            return False
        pinned = state.get("pinned")
        fingerprint = _sha256_hex_bytes(server_pub)
        if pinned is None:
            if require_existing_pin:
                logger.error(f"No pinned server key found: {pin_file}")
                return False
            _store_pinned_server_pub(pin_file, server_pub)
            state["pinned"] = server_pub
            logger.info(f"Pinned receiver identity by TOFU: fingerprint={fingerprint}, pin_file={pin_file}")
            return True
        if pinned != server_pub:
            expected = _sha256_hex_bytes(pinned)
            state["identity_mismatch"] = {
                "reason": "receiver_identity_changed",
                "expected": expected,
                "got": fingerprint,
                "pin_file": str(pin_file or ""),
            }
            logger.error(f"Pinned receiver key mismatch: expected={expected} got={fingerprint} pin_file={pin_file}")
            return False
        if not state.get("announced"):
            state["announced"] = True
            logger.info(f"Verified pinned receiver identity: fingerprint={fingerprint}, pin_file={pin_file}")
        return True

    validator.state = state  # type: ignore[attr-defined]
    return validator


class TokenBucketPacer:
    def __init__(self, rate_tokens_per_s: float, burst_seconds: float = 0.05):
        self.rate = float(rate_tokens_per_s)
        self.capacity = max(1.0, self.rate * float(burst_seconds)) if self.rate > 0 else 0.0
        self.tokens = self.capacity
        self.ts = time.time()

    def wait(self, tokens_needed: float) -> None:
        if self.rate <= 0:
            return
        need = float(tokens_needed)
        while True:
            now = time.time()
            elapsed = now - self.ts
            if elapsed > 0:
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.ts = now
            if self.tokens >= need:
                self.tokens -= need
                return
            time.sleep(min(max((need - self.tokens) / self.rate, 0.0), 0.01))


def _format_duration(seconds: float) -> str:
    if seconds is None or not math.isfinite(float(seconds)) or float(seconds) < 0:
        return "unknown"
    seconds = int(round(float(seconds)))
    h, rem = divmod(seconds, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{sec:02d}"
    return f"{m:d}:{sec:02d}"


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Send one or more files through the RUDP protocol.")
    p.add_argument("--server-ip", required=True, help="Receiver IP or hostname")
    p.add_argument("--server-port", type=int, default=9999, help="Receiver UDP port")
    p.add_argument("--file", action="append", required=True, help="File to send; repeat this option for multi-file transfer")
    p.add_argument("--bind-ip", default="0.0.0.0", help="Local bind IP; usually keep 0.0.0.0")
    p.add_argument("--bind-port", type=int, default=0, help="Local bind port; 0 means auto")
    p.add_argument("--payload-size", type=int, default=1300, help="Application payload bytes per DATA packet")
    p.add_argument("--sock-rcvbuf", type=int, default=8 * 1024 * 1024)
    p.add_argument("--sock-sndbuf", type=int, default=8 * 1024 * 1024)
    p.add_argument("--handshake-timeout", type=float, default=3.0)
    p.add_argument("--handshake-max-retries", type=int, default=100)
    p.add_argument("--handshake-tail-timeout", type=float, default=60.0)
    p.add_argument("--final-ack-timeout", type=float, default=60.0)
    p.add_argument("--complete-timeout", type=float, default=60.0)
    p.add_argument("--request-timeout", type=float, default=300.0, help="Seconds to wait for receiver approval after sending metadata")
    p.add_argument("--no-request-confirmation", action="store_true", help="Do not wait for receiver approval before sending file body")
    p.add_argument("--stats-interval", type=float, default=1.0)
    p.add_argument("--no-progress-timeout", type=float, default=120.0, help="Fail if sender sees no effective transfer progress for this many seconds")
    p.add_argument("--server-pin-file", default="./rudp_receiver_ed25519.pin", help="TOFU receiver public-key pin file")
    p.add_argument("--require-existing-server-pin", action="store_true")
    p.add_argument("--disable-cc", action="store_true", help="Disable CUBIC congestion control")
    p.add_argument("--max-unacked-pkts", type=int, default=0, help="Optional hard cap for outstanding DATA packets")
    p.add_argument("--send-rate-mbps", type=float, default=0.0, help="Optional sender-side rate limit")
    p.add_argument("--initial-rtt-ms", type=float, default=0.0)
    p.add_argument("--min-data-rto-sec", type=float, default=0.2)
    p.add_argument("--max-data-rto-sec", type=float, default=4.0)
    p.add_argument("--show-ips", action="store_true", help="Print local IP candidates before sending")
    p.add_argument("--verbose-protocol", action="store_true", help="Show high-volume internal ACK logs")
    p.add_argument("--control-dir", default="", help="Directory used by GUI to add files to this running sender")
    p.add_argument("--idle-add-timeout", type=float, default=1.0, help="When current work is done, wait this many seconds for GUI add-file commands before sending EOF")
    return p


def _wait_for_handshake(session: ReliableUDPSession, args, logger, validator=None) -> None:
    session.begin_client_handshake(
        initial_rto=float(args.handshake_timeout),
        max_retries=max(0, int(args.handshake_max_retries)),
        handshake_tail_timeout=float(args.handshake_tail_timeout),
        final_ack_rto_cap=max(float(args.handshake_timeout), min(float(args.handshake_tail_timeout), 60.0)),
    )

    def check_identity_mismatch() -> None:
        state = getattr(validator, "state", {}) if validator is not None else {}
        mismatch = state.get("identity_mismatch") if isinstance(state, dict) else None
        if mismatch:
            try:
                session.abort("receiver_identity_changed")
            except Exception:
                pass
            expected = str(mismatch.get("expected") or "")
            got = str(mismatch.get("got") or "")
            pin_file = str(mismatch.get("pin_file") or "")
            detail = f"expected={expected} got={got} pin_file={pin_file}"
            raise RuntimeError("receiver_identity_changed:" + detail)

    while not session.wait_session_key_ready(timeout=0.1):
        check_identity_mismatch()
        if session.has_fatal_error():
            raise RuntimeError(session.get_fatal_error() or "fatal protocol error during handshake")
        if not session.running:
            raise RuntimeError("session stopped during handshake")

    while not session.wait_peer_established(timeout=0.1):
        check_identity_mismatch()
        if session.has_fatal_error():
            raise RuntimeError(session.get_fatal_error() or "fatal protocol error while confirming handshake")
        if not session.running:
            raise RuntimeError("session stopped while confirming handshake")

    logger.info("Handshake established")


def _wait_for_receiver_decision(session: ReliableUDPSession, timeout: float, logger) -> dict:
    deadline = time.time() + max(1.0, float(timeout or 300.0))
    logger.info("Transfer request submitted; waiting for receiver approval")
    while time.time() < deadline:
        if session.has_fatal_error():
            raise RuntimeError(session.get_fatal_error() or "fatal protocol error while waiting receiver approval")
        item = session.get_app_item(timeout=0.1)
        if item is None:
            continue
        _seq, data_or_len, is_len = item
        if is_len:
            continue
        raw = bytes(data_or_len or b"")
        try:
            decision = parse_file_offer_accept(raw)
        except Exception:
            try:
                decision = parse_transfer_decision(raw)
            except Exception:
                continue
        if bool(decision.get("accepted")):
            accepted_files = decision.get("accepted_files") if isinstance(decision.get("accepted_files"), list) else []
            if accepted_files:
                first = accepted_files[0]
                if isinstance(first, dict):
                    for key in ("resume_offset", "resume_pct", "resume", "received_ranges", "missing_ranges", "received_bytes_total", "transfer_mode", "file_id", "receiver_file_key", "content_file_key"):
                        if key in first and key not in decision:
                            decision[key] = first.get(key)
            resume_offset = max(0, int(decision.get("resume_offset") or 0))
            if bool(decision.get("resume")) and resume_offset > 0:
                logger.info(
                    f"Receiver accepted transfer; resuming from offset={resume_offset} "
                    f"({float(decision.get('resume_pct') or 0.0):.2f}%)"
                )
                logger.info(build_user_status("resume_enabled", "Receiver requested resume", resume_offset=resume_offset, resume_pct=float(decision.get("resume_pct") or 0.0)))
            else:
                logger.info("Receiver accepted transfer; starting file body transmission")
            return decision
        reason = str(decision.get("reason") or "rejected")
        session.abort("receiver_rejected")
        raise PermissionError(f"{reason}")
    session.abort("receiver_approval_timeout")
    raise TimeoutError("approval_timeout")



def _collect_input_files(raw_files) -> List[Path]:
    if isinstance(raw_files, (str, bytes, os.PathLike)):
        values = [raw_files]
    else:
        values = list(raw_files or [])
    out: List[Path] = []
    seen = set()
    for raw in values:
        text = str(raw or "").strip().strip('"')
        if not text:
            continue
        # GUI may pass a semicolon-separated list for compatibility with older
        # packaged builds; repeated --file arguments are preferred.
        candidates = [text]
        if ";" in text and not os.path.exists(text):
            candidates = [x.strip().strip('"') for x in text.split(";") if x.strip()]
        for item in candidates:
            pth = Path(item).expanduser().resolve()
            if not pth.is_file():
                raise FileNotFoundError(str(pth))
            key = str(pth).lower() if os.name == "nt" else str(pth)
            if key not in seen:
                seen.add(key)
                out.append(pth)
    if not out:
        raise FileNotFoundError("no input files")
    return out



def _prepare_offer_items(input_files: List[Path], payload_size: int, logger) -> Tuple[List[Dict[str, object]], Dict[str, Path], Dict[str, Path], int]:
    offer_items: List[Dict[str, object]] = []
    local_by_file_id: Dict[str, Path] = {}
    local_by_content_key: Dict[str, Path] = {}
    total_offer_bytes = 0
    for input_file in input_files:
        input_file = Path(input_file).expanduser().resolve()
        total_offer_bytes += int(input_file.stat().st_size)
        logger.info(f"Calculating SHA256: {input_file}")
        file_sha256 = sha256_file(str(input_file))
        item = build_file_offer_item(str(input_file), payload_size=payload_size, sha256_hex=file_sha256, relative_path=input_file.name)
        offer_items.append(item)
        local_by_file_id[str(item.get("file_id") or "")] = input_file
        local_by_content_key[str(item.get("content_file_key") or "")] = input_file
        logger.info(
            f"Prepared file offer item: {input_file.name}, size={int(item.get('size') or 0)} bytes, "
            f"sha256={file_sha256}, transfer_mode={item.get('transfer_mode')}, file_id={item.get('file_id')}"
        )
    return offer_items, local_by_file_id, local_by_content_key, int(total_offer_bytes)


def _control_dirs(raw_dir: str) -> Tuple[Optional[Path], Optional[Path], Optional[Path]]:
    text = str(raw_dir or "").strip()
    if not text:
        return None, None, None
    root = Path(text).expanduser().resolve()
    incoming = root / "commands"
    done = root / "done"
    incoming.mkdir(parents=True, exist_ok=True)
    done.mkdir(parents=True, exist_ok=True)
    return root, incoming, done


def _read_next_add_files_command(commands_dir: Optional[Path], done_dir: Optional[Path], logger) -> Optional[List[Path]]:
    if commands_dir is None:
        return None
    try:
        files = sorted(commands_dir.glob("add_*.json"), key=lambda p: p.stat().st_mtime)
    except Exception:
        return None
    for pth in files:
        try:
            obj = json.loads(pth.read_text(encoding="utf-8"))
            raw_files = obj.get("files") if isinstance(obj, dict) else []
            paths = _collect_input_files(raw_files)
            target = (done_dir / (pth.name + ".done")) if done_dir is not None else None
            if target is not None:
                try:
                    pth.replace(target)
                except Exception:
                    pth.unlink(missing_ok=True)
            else:
                pth.unlink(missing_ok=True)
            logger.info(f"Loaded add-files command: {len(paths)} file(s)")
            return paths
        except Exception as exc:
            logger.warning(f"Ignoring invalid add-files command {pth}: {exc}")
            try:
                bad = (done_dir / (pth.name + ".bad")) if done_dir is not None else None
                if bad is not None:
                    pth.replace(bad)
                else:
                    pth.unlink(missing_ok=True)
            except Exception:
                pass
    return None

def run_client(args: argparse.Namespace) -> int:
    if not bool(getattr(args, "verbose_protocol", False)):
        os.environ.setdefault("RUDP_VERBOSE_PROTOCOL", "0")
    logger = setup_logger("RUDP-Sender")
    if args.show_ips:
        print_local_ip_candidates()

    input_files = _collect_input_files(args.file)
    payload_size = int(args.payload_size)
    if payload_size <= 0 or payload_size > MAX_DATA_APP_PAYLOAD:
        raise ValueError(
            "payload-size must be in (0, {max_payload}], because wire size = "
            "HEADER_SIZE({header}) + DATA_FRAME_HEADER_LEN({frame}) + payload + AES-GCM tag({tag}) "
            "must stay <= UDP payload limit {udp_limit}".format(
                max_payload=MAX_DATA_APP_PAYLOAD,
                header=HEADER_SIZE,
                frame=DATA_FRAME_HEADER_LEN,
                tag=AEAD_TAG_LEN,
                udp_limit=UDP_MAX_DATAGRAM_PAYLOAD,
            )
        )

    # FILE_BODY frames carry file_id + offset. Keep payload size conservative.
    estimated_body_overhead = FILE_BODY_OFFSET_HEADER_LEN + 1 + 128
    if payload_size + estimated_body_overhead > MAX_DATA_APP_PAYLOAD:
        raise ValueError(f"payload-size too large for FILE_BODY offset/file_id frame: {payload_size}")

    offer_items, local_by_file_id, local_by_content_key, total_offer_bytes = _prepare_offer_items(input_files, payload_size, logger)
    control_root, control_commands_dir, control_done_dir = _control_dirs(str(getattr(args, "control_dir", "") or ""))
    if control_root is not None:
        logger.info(f"Sender control directory enabled: {control_root}")

    offer_msg = build_file_offer(offer_items)
    if len(offer_msg) > MAX_DATA_APP_PAYLOAD:
        raise ValueError(f"file offer too large for one metadata frame: {len(offer_msg)} bytes; select fewer files or compress them")

    max_total_data_pkts = MAX_DATA_SEQ - SEQ_FIRST_BODY
    max_total_bytes = max_total_data_pkts * int(payload_size)
    if total_offer_bytes > max_total_bytes:
        raise ValueError(f"selected files too large for DATA sequence space; max_total_bytes={max_total_bytes}")

    sock = None
    session = None
    start_ts = time.time()
    bytes_sent = 0
    pkts_sent = 0
    last_report_ts = start_ts
    last_report_bytes = 0
    last_effective_progress_ts = start_ts
    last_unacked_snapshot = -1

    def note_effective_progress(unacked_count: Optional[int] = None) -> None:
        nonlocal last_effective_progress_ts, last_unacked_snapshot
        try:
            uc = int(session.get_unacked_count() if unacked_count is None and session is not None else unacked_count)
        except Exception:
            uc = -1
        if uc != last_unacked_snapshot:
            last_unacked_snapshot = uc
            last_effective_progress_ts = time.time()

    def check_no_progress(stage: str) -> None:
        timeout = max(0.0, float(getattr(args, "no_progress_timeout", 120.0) or 0.0))
        if timeout <= 0:
            return
        if time.time() - last_effective_progress_ts > timeout:
            if session is not None:
                session.abort("network_no_progress")
            raise TimeoutError(f"network_no_progress:{stage}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(args.sock_rcvbuf))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(args.sock_sndbuf))
        sock.bind((str(args.bind_ip), int(args.bind_port)))
        logger.info(f"Local socket: {sock.getsockname()}")
        logger.info(f"Receiver: {(args.server_ip, args.server_port)}")
        logger.info(f"Offer: files={len(offer_items)}, total_size={total_offer_bytes} bytes")

        conn_id = secrets.randbits(64)
        validator = make_server_identity_validator(
            str(args.server_pin_file),
            logger,
            require_existing_pin=bool(args.require_existing_server_pin),
        )
        session = ReliableUDPSession(
            conn_id,
            (str(args.server_ip), int(args.server_port)),
            sock,
            is_client=True,
            server_identity_validator=validator,
        )
        session.configure_app_delivery(len_only=False, small_payload_threshold=0)
        session.recovery_pacing_enabled = True
        session.send_max_unacked_pkts = max(0, int(args.max_unacked_pkts or 0))

        min_data_rto = max(0.05, float(args.min_data_rto_sec or 0.2))
        max_data_rto = max(min_data_rto, float(args.max_data_rto_sec or 4.0))
        session.min_data_rto = min_data_rto
        session.max_rto = max_data_rto
        session.base_rto = min_data_rto

        initial_rtt_s = max(0.0, float(args.initial_rtt_ms or 0.0) / 1000.0)
        if not args.disable_cc:
            session.cc = CubicCongestionControl(
                min_rto=min_data_rto,
                max_rto=max_data_rto,
                initial_rtt=(initial_rtt_s if initial_rtt_s > 0.0 else None),
            )
            session.app_pacing_enabled = True
            logger.info("Congestion control: CUBIC enabled")
        else:
            session.cc = None
            session.app_pacing_enabled = False
            logger.info("Congestion control: disabled")

        byte_pacer = None
        if float(args.send_rate_mbps or 0.0) > 0.0:
            byte_pacer = TokenBucketPacer(float(args.send_rate_mbps) * 1_000_000.0 / 8.0)
            logger.info(f"Application rate limit: {float(args.send_rate_mbps):.3f} Mbps")

        session.start_threads(start_receiver=True)
        _wait_for_handshake(session, args, logger, validator=validator)
        note_effective_progress()

        def send_payload(seq: int, payload: bytes) -> None:
            if session.has_fatal_error():
                raise RuntimeError(session.get_fatal_error() or "fatal protocol error")
            wire_size = data_packet_wire_size(len(payload))
            if byte_pacer is not None:
                byte_pacer.wait(wire_size)
            session.send_app_data(seq, payload)

        def _tasks_from_decision(decision: Dict[str, object], items: List[Dict[str, object]], by_file_id: Dict[str, Path], by_content_key: Dict[str, Path]) -> Tuple[List[FileTransferTask], int, int]:
            accepted_files = decision.get("accepted_files") if isinstance(decision.get("accepted_files"), list) else []
            out_tasks: List[FileTransferTask] = []
            accepted_total = 0
            already_received = 0
            for accepted in accepted_files:
                if not isinstance(accepted, dict):
                    continue
                file_id = str(accepted.get("file_id") or "")
                content_key = str(accepted.get("content_file_key") or "")
                local_path = by_file_id.get(file_id) or by_content_key.get(content_key)
                if local_path is None:
                    logger.warning(f"Receiver accepted unknown file_id={file_id} content_key={content_key}; skipping")
                    continue
                size = int(local_path.stat().st_size)
                accepted_total += size
                transfer_mode = str(accepted.get("transfer_mode") or "")
                if not transfer_mode:
                    for item in items:
                        if str(item.get("file_id") or "") == file_id or str(item.get("content_file_key") or "") == content_key:
                            transfer_mode = str(item.get("transfer_mode") or "small_sequential")
                            break
                received_ranges = normalize_ranges(accepted.get("received_ranges") or [], size)
                missing_ranges = normalize_ranges(accepted.get("missing_ranges") or [], size)
                if not missing_ranges:
                    missing_ranges = missing_ranges_from_received(received_ranges, size)
                task = FileTransferTask(
                    transfer_id=str(accepted.get("transfer_id") or accepted.get("sha256") or content_key),
                    file_id=file_id or content_key[:24],
                    path=str(local_path),
                    size=size,
                    sha256=str(next((x.get("sha256") for x in items if str(x.get("file_id") or "") == file_id), "") or ""),
                    mode=transfer_mode or "small_sequential",
                    received_ranges=received_ranges,
                    missing_ranges=missing_ranges,
                    status=FILE_TRANSFER_STATUS_ACTIVE,
                    relative_path=str(accepted.get("relative_path") or local_path.name),
                    content_file_key=content_key,
                    receiver_file_key=str(accepted.get("receiver_file_key") or ""),
                )
                already_received += int(task.received_bytes)
                if task.missing_ranges:
                    out_tasks.append(task)
                else:
                    logger.info(f"File already complete at receiver: {task.relative_path}")
            return out_tasks, int(accepted_total), int(already_received)

        total_bytes = total_offer_bytes
        total_body_bytes_to_send = total_offer_bytes
        file_count_for_report = len(offer_items)

        def report(force: bool = False) -> None:
            nonlocal last_report_ts, last_report_bytes
            now = time.time()
            if not force and (now - last_report_ts) < float(args.stats_interval):
                return
            elapsed = max(now - start_ts, 1e-6)
            interval = max(now - last_report_ts, 1e-6)
            avg_mbps = (bytes_sent * 8.0) / elapsed / 1e6
            int_mbps = ((bytes_sent - last_report_bytes) * 8.0) / interval / 1e6
            pct = (bytes_sent * 100.0 / total_bytes) if total_bytes > 0 else 100.0
            remaining_bytes = max(int(total_bytes) - int(bytes_sent), 0)
            interval_bytes = int(bytes_sent) - int(last_report_bytes)
            rate_bps = (interval_bytes / interval) if interval_bytes > 0 else ((bytes_sent / elapsed) if bytes_sent > 0 else 0.0)
            eta_text = _format_duration(remaining_bytes / rate_bps) if rate_bps > 0 else "unknown"
            unacked_count = session.get_unacked_count()
            note_effective_progress(unacked_count)
            logger.info(
                f"Progress: {bytes_sent}/{total_bytes} bytes ({pct:.2f}%), "
                f"files={file_count_for_report}, pkts={pkts_sent}, avg={avg_mbps:.2f} Mbps, interval={int_mbps:.2f} Mbps, "
                f"eta={eta_text}, unacked={unacked_count}"
            )
            last_report_ts = now
            last_report_bytes = bytes_sent

        send_payload(SEQ_HEADER, offer_msg)
        decision: Dict[str, object] = {}
        if not bool(getattr(args, "no_request_confirmation", False)):
            decision = _wait_for_receiver_decision(session, float(args.request_timeout), logger)

        tasks, accepted_total_bytes, already_received_bytes = _tasks_from_decision(decision, offer_items, local_by_file_id, local_by_content_key)
        bytes_sent = int(already_received_bytes)
        if accepted_total_bytes > 0:
            total_bytes = int(accepted_total_bytes)
        if not tasks:
            logger.info("All initially accepted files were already complete at receiver")

        scheduler = FileBatchScheduler(tasks, max_active_files=20)
        seq = SEQ_FIRST_BODY
        logger.info(
            f"Accepted files: active={scheduler.active_count}, pending={scheduler.pending_count}, "
            f"missing_bytes={sum(sum(end - start for start, end in task.missing_ranges) for task in scheduler.files.values())}"
        )

        _last_sched_snapshot: Optional[Dict[str, object]] = None
        last_scheduler_log_ts = 0.0

        def _scheduler_network_info() -> Tuple[Dict[str, object], Dict[str, object]]:
            nonlocal _last_sched_snapshot
            try:
                snap = session.get_stats_snapshot()
            except Exception:
                snap = {}
            info = classify_file_transfer_network_state(snap, _last_sched_snapshot)
            _last_sched_snapshot = dict(snap or {})
            return info, dict(snap or {})

        idle_empty_since: Optional[float] = None

        def _process_add_files_command() -> bool:
            nonlocal seq, total_bytes, bytes_sent, total_body_bytes_to_send, file_count_for_report
            add_paths = _read_next_add_files_command(control_commands_dir, control_done_dir, logger)
            if not add_paths:
                return False
            new_items, by_fid, by_ckey, offer_total = _prepare_offer_items(add_paths, payload_size, logger)
            offer = build_file_offer(new_items)
            if len(offer) > MAX_DATA_APP_PAYLOAD:
                logger.error(build_user_error("file_offer_too_large", "Additional file offer is too large", str(len(offer))))
                return False
            logger.info(f"Adding files to running transfer: files={len(new_items)}, total_size={offer_total}")
            send_payload(seq, offer)
            seq += 1
            decision2 = _wait_for_receiver_decision(session, timeout=float(args.request_timeout), logger=logger)
            new_tasks, accepted_total, already_received = _tasks_from_decision(decision2, new_items, by_fid, by_ckey)
            total_bytes += int(accepted_total)
            bytes_sent += int(already_received)
            total_body_bytes_to_send += sum(sum(end - start for start, end in task.missing_ranges) for task in new_tasks)
            file_count_for_report += len(new_items)
            for task in new_tasks:
                scheduler.add_file(task)
            logger.info(f"Added accepted files to active transfer: new_tasks={len(new_tasks)}, active={scheduler.active_count}, pending={scheduler.pending_count}")
            return True

        while True:
            _process_add_files_command()
            if not scheduler.has_work():
                if idle_empty_since is None:
                    idle_empty_since = time.time()
                if _process_add_files_command():
                    idle_empty_since = None
                    continue
                if time.time() - idle_empty_since >= max(0.1, float(getattr(args, "idle_add_timeout", 1.0) or 1.0)):
                    break
                report(force=False)
                time.sleep(0.1)
                continue
            idle_empty_since = None
            active_task = scheduler.next_task()
            if active_task is None:
                time.sleep(0.05)
                continue
            pending_ranges = normalize_ranges(active_task.missing_ranges, active_task.size)
            if not pending_ranges:
                scheduler.mark_completed(active_task.file_id)
                continue
            net_info, _snap = _scheduler_network_info()
            network_mode = str(net_info.get("mode") or "stable")
            if active_task.mode == TRANSFER_MODE_LARGE_RANGE:
                ordered = schedule_missing_ranges(pending_ranges, active_task.size, received_bytes=int(active_task.received_bytes), network_mode=network_mode)
            else:
                ordered = pending_ranges
            if not ordered:
                scheduler.mark_completed(active_task.file_id)
                continue
            selected_start, selected_end = int(ordered[0][0]), int(ordered[0][1])
            slice_bytes = max(int(payload_size), int(choose_file_transfer_slice_bytes(active_task.size)))
            if active_task.mode == TRANSFER_MODE_LARGE_RANGE:
                slice_bytes = min(slice_bytes, max(int(payload_size), int(net_info.get("slice_bytes") or slice_bytes)))
            # Credit keeps all active files moving; if a task has low credit, still
            # allow at least one packet once selected so large files do not stall.
            if active_task.scheduler_credit > payload_size:
                slice_bytes = min(slice_bytes, max(int(payload_size), int(active_task.scheduler_credit)))
            send_until = min(selected_end, selected_start + slice_bytes)
            now = time.time()
            if (now - last_scheduler_log_ts) >= 10.0:
                logger.info(
                    f"File scheduler: active={scheduler.active_count}, pending={scheduler.pending_count}, "
                    f"file={active_task.relative_path}, mode={network_mode}, selected=[{selected_start},{selected_end}), "
                    f"slice_until={send_until}, credit={active_task.scheduler_credit:.0f}"
                )
                last_scheduler_log_ts = now
            with open(active_task.path, "rb") as f:
                offset = selected_start
                f.seek(offset)
                while offset < send_until:
                    read_size = min(int(payload_size), int(send_until) - offset)
                    chunk = f.read(read_size)
                    if not chunk:
                        break
                    send_payload(seq, build_file_body_frame(offset, chunk, active_task.file_id))
                    bytes_sent += len(chunk)
                    pkts_sent += 1
                    seq += 1
                    offset += len(chunk)
                    active_task.add_received_range(offset - len(chunk), offset)
                    active_task.set_missing_ranges(consume_scheduled_range(active_task.missing_ranges, [selected_start, selected_end], offset, active_task.size))
                    scheduler.note_slice_sent(active_task.file_id, len(chunk))
                    last_effective_progress_ts = time.time()
                    report(force=False)
                    check_no_progress("transferring")
            if offset <= selected_start:
                raise IOError(f"failed to read scheduled range at file={active_task.relative_path} offset={selected_start}")
            if active_task.is_complete() or not active_task.missing_ranges:
                scheduler.mark_completed(active_task.file_id)

        seq_eof = seq

        drain_start = time.time()
        while session.get_unacked_count() > 0:
            if session.has_fatal_error():
                raise RuntimeError(session.get_fatal_error() or "fatal protocol error while draining DATA")
            if time.time() - drain_start > float(args.final_ack_timeout):
                session.abort("data_drain_timeout_before_eof")
                raise TimeoutError("data drain timeout before EOF")
            report(force=False)
            check_no_progress("waiting_ack")
            time.sleep(0.1)

        send_payload(seq_eof, EOF_PAYLOAD)
        report(force=True)

        drain_start = time.time()
        while session.get_unacked_count() > 0:
            if session.has_fatal_error():
                raise RuntimeError(session.get_fatal_error() or "fatal protocol error while draining EOF")
            if time.time() - drain_start > float(args.final_ack_timeout):
                session.abort("eof_drain_timeout")
                raise TimeoutError("EOF drain timeout")
            report(force=False)
            check_no_progress("waiting_ack")
            time.sleep(0.1)

        complete_deadline = time.time() + max(1.0, float(args.complete_timeout))
        while not session.wait_for_complete(timeout=0.2):
            if session.has_fatal_error():
                raise RuntimeError(session.get_fatal_error() or "fatal protocol error while waiting COMPLETE")
            check_no_progress("waiting_complete")
            if time.time() >= complete_deadline:
                session.abort("complete_timeout")
                raise TimeoutError("complete_timeout")

        complete_info = session.get_received_complete_info() or {}
        ok = (
            int(complete_info.get("ack_base", -1)) == seq_eof + 1
            and int(complete_info.get("seen_max", -1)) == seq_eof
            and int(complete_info.get("expected_total", -1)) == total_bytes
            and int(complete_info.get("body_bytes_recv", -1)) == total_bytes
        )
        if not ok:
            session.abort("complete_sanity_mismatch")
            raise RuntimeError(f"receiver COMPLETE mismatch: {complete_info}")

        elapsed = max(time.time() - start_ts, 1e-6)
        logger.info(f"Transfer complete: {bytes_sent} bytes in {elapsed:.3f}s, avg={(max(0, total_body_bytes_to_send) * 8.0 / elapsed / 1e6):.2f} Mbps")
        return 0

    finally:
        try:
            if session is not None:
                session.stop()
        except Exception:
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass

def _classify_user_error(exc: Exception) -> tuple[str, str]:
    text = str(exc or "")
    if isinstance(exc, TimeoutError):
        if "approval_timeout" in text or "receiver approval" in text:
            return "approval_timeout", "Receiver confirmation timed out"
        if "network_no_progress" in text:
            return "network_no_progress", "Network made no progress for too long"
        if "complete_timeout" in text or "COMPLETE" in text:
            return "complete_timeout", "File data was sent, but receiver completion confirmation timed out"
        if "EOF" in text:
            return "eof_timeout", "EOF acknowledgement timed out"
        if "data drain" in text:
            return "data_drain_timeout", "Data acknowledgement timed out"
    if "receiver_identity_changed" in text or "Pinned receiver key mismatch" in text:
        return "receiver_identity_changed", "Receiver identity changed"
    if "save_dir_not_writable" in text or "save_dir_create_failed" in text or "save_dir_not_directory" in text:
        return "save_dir_not_writable", "The receiver save directory is not writable"
    if "disk_space_not_enough" in text:
        return "disk_space_not_enough", "The receiver does not have enough disk space"
    if "output_open_failed" in text:
        return "output_open_failed", "The receiver could not create the output file"
    if isinstance(exc, PermissionError) or "receiver_rejected" in text or "rejected" in text or "file_exists_cancelled" in text:
        return "receiver_rejected", "Receiver rejected the transfer"
    if isinstance(exc, FileNotFoundError):
        return "local_file_not_found", "Local file was not found"
    if "network_no_progress" in text:
        return "network_no_progress", "Network made no progress for too long"
    return "transfer_failed", "Transfer failed"


def main() -> int:
    args = build_argparser().parse_args()
    try:
        return run_client(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        logger = setup_logger("RUDP-Sender")
        code, message = _classify_user_error(exc)
        logger.error(build_user_error(code, message, str(exc)))
        logger.error(f"Fatal: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
