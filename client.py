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
import math
import os
import secrets
import socket
import time
from pathlib import Path
from typing import Optional

from congestion import CubicCongestionControl
from file_transfer_common import (
    DATA_SEQ_UPPER_EXCLUSIVE,
    EOF_PAYLOAD,
    MAX_DATA_SEQ,
    SEQ_FIRST_BODY,
    SEQ_HEADER,
    build_file_header,
    parse_transfer_decision,
    print_local_ip_candidates,
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
    state = {"pinned": _load_pinned_server_pub(pin_file), "announced": False}

    def validator(server_pub: bytes) -> bool:
        server_pub = bytes(server_pub or b"")
        if len(server_pub) != 32:
            return False
        pinned = state.get("pinned")
        fingerprint = _sha256_hex_bytes(server_pub)
        if pinned is None:
            if require_existing_pin:
                logger.error(f"No pinned server key found: {pin_file}")
                return False
            _store_pinned_server_pub(pin_file, server_pub)
            state["pinned"] = server_pub
            logger.info(f"Pinned receiver identity by TOFU: fingerprint={fingerprint}")
            return True
        if pinned != server_pub:
            logger.error(f"Pinned receiver key mismatch: expected={_sha256_hex_bytes(pinned)} got={fingerprint}")
            return False
        if not state.get("announced"):
            state["announced"] = True
            logger.info(f"Verified pinned receiver identity: fingerprint={fingerprint}")
        return True

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
    p = argparse.ArgumentParser(description="Send one file through the RUDP protocol.")
    p.add_argument("--server-ip", required=True, help="Receiver IP or hostname")
    p.add_argument("--server-port", type=int, default=9999, help="Receiver UDP port")
    p.add_argument("--file", required=True, help="File to send")
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
    return p


def _wait_for_handshake(session: ReliableUDPSession, args, logger) -> None:
    session.begin_client_handshake(
        initial_rto=float(args.handshake_timeout),
        max_retries=max(0, int(args.handshake_max_retries)),
        handshake_tail_timeout=float(args.handshake_tail_timeout),
        final_ack_rto_cap=max(float(args.handshake_timeout), min(float(args.handshake_tail_timeout), 60.0)),
    )

    while not session.wait_session_key_ready(timeout=0.1):
        if session.has_fatal_error():
            raise RuntimeError(session.get_fatal_error() or "fatal protocol error during handshake")
        if not session.running:
            raise RuntimeError("session stopped during handshake")

    while not session.wait_peer_established(timeout=0.1):
        if session.has_fatal_error():
            raise RuntimeError(session.get_fatal_error() or "fatal protocol error while confirming handshake")
        if not session.running:
            raise RuntimeError("session stopped while confirming handshake")

    logger.info("Handshake established")


def _wait_for_receiver_decision(session: ReliableUDPSession, timeout: float, logger) -> None:
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
        try:
            decision = parse_transfer_decision(bytes(data_or_len or b""))
        except Exception:
            continue
        if bool(decision.get("accepted")):
            logger.info("Receiver accepted transfer; starting file body transmission")
            return
        reason = str(decision.get("reason") or "rejected")
        session.abort("receiver_rejected")
        raise PermissionError(f"receiver rejected transfer: {reason}")
    session.abort("receiver_approval_timeout")
    raise TimeoutError("receiver approval timeout")



def run_client(args: argparse.Namespace) -> int:
    if not bool(getattr(args, "verbose_protocol", False)):
        os.environ.setdefault("RUDP_VERBOSE_PROTOCOL", "0")
    logger = setup_logger("RUDP-Sender")
    if args.show_ips:
        print_local_ip_candidates()

    input_file = Path(args.file).expanduser().resolve()
    if not input_file.is_file():
        raise FileNotFoundError(str(input_file))

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

    total_bytes = input_file.stat().st_size
    logger.info(f"Calculating SHA256: {input_file}")
    file_sha256 = sha256_file(str(input_file))
    header_msg = build_file_header(str(input_file), payload_size=payload_size, sha256_hex=file_sha256)
    if len(header_msg) > MAX_DATA_APP_PAYLOAD:
        raise ValueError(f"file metadata header too large: {len(header_msg)} bytes")

    total_data_pkts = int(math.ceil(total_bytes / payload_size)) if total_bytes > 0 else 0
    seq_eof = SEQ_FIRST_BODY + total_data_pkts
    if seq_eof >= DATA_SEQ_UPPER_EXCLUSIVE:
        max_total_data_pkts = MAX_DATA_SEQ - SEQ_FIRST_BODY
        max_total_bytes = max_total_data_pkts * int(payload_size)
        raise ValueError(f"file too large for DATA sequence space; max_total_bytes={max_total_bytes}")

    sock = None
    session = None
    start_ts = time.time()
    bytes_sent = 0
    pkts_sent = 0
    last_report_ts = start_ts
    last_report_bytes = 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(args.sock_rcvbuf))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(args.sock_sndbuf))
        sock.bind((str(args.bind_ip), int(args.bind_port)))
        logger.info(f"Local socket: {sock.getsockname()}")
        logger.info(f"Receiver: {(args.server_ip, args.server_port)}")
        logger.info(f"File: {input_file.name}, size={total_bytes} bytes, sha256={file_sha256}")

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
        _wait_for_handshake(session, args, logger)

        session.set_complete_expectations(seq_eof, total_bytes)
        session.send_range_announce(SEQ_HEADER, seq_eof)

        def send_payload(seq: int, payload: bytes) -> None:
            if session.has_fatal_error():
                raise RuntimeError(session.get_fatal_error() or "fatal protocol error")
            wire_size = data_packet_wire_size(len(payload))
            if byte_pacer is not None:
                byte_pacer.wait(wire_size)
            session.send_app_data(seq, payload)

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
            logger.info(
                f"Progress: {bytes_sent}/{total_bytes} bytes ({pct:.2f}%), "
                f"pkts={pkts_sent}, avg={avg_mbps:.2f} Mbps, interval={int_mbps:.2f} Mbps, "
                f"eta={eta_text}, unacked={session.get_unacked_count()}"
            )
            last_report_ts = now
            last_report_bytes = bytes_sent

        send_payload(SEQ_HEADER, header_msg)
        if not bool(getattr(args, "no_request_confirmation", False)):
            _wait_for_receiver_decision(session, float(args.request_timeout), logger)

        seq = SEQ_FIRST_BODY
        with open(input_file, "rb") as f:
            while True:
                chunk = f.read(payload_size)
                if not chunk:
                    break
                send_payload(seq, chunk)
                bytes_sent += len(chunk)
                pkts_sent += 1
                seq += 1
                report(force=False)

        if seq != seq_eof:
            raise AssertionError(f"seq mismatch: seq={seq}, expected={seq_eof}")

        drain_start = time.time()
        while session.get_unacked_count() > 0:
            if session.has_fatal_error():
                raise RuntimeError(session.get_fatal_error() or "fatal protocol error while draining DATA")
            if time.time() - drain_start > float(args.final_ack_timeout):
                session.abort("data_drain_timeout_before_eof")
                raise TimeoutError("data drain timeout before EOF")
            report(force=False)
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
            time.sleep(0.1)

        if not session.wait_for_complete(timeout=float(args.complete_timeout)):
            if session.has_fatal_error():
                raise RuntimeError(session.get_fatal_error() or "fatal protocol error while waiting COMPLETE")
            session.abort("complete_timeout")
            raise TimeoutError("receiver COMPLETE timeout")

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
        logger.info(f"Transfer complete: {bytes_sent} bytes in {elapsed:.3f}s, avg={(bytes_sent * 8.0 / elapsed / 1e6):.2f} Mbps")
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


def main() -> int:
    args = build_argparser().parse_args()
    try:
        return run_client(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        setup_logger("RUDP-Sender").error(f"Fatal: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
