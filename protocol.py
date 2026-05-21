# protocol.py
import socket
import threading
from collections import deque
import time
import math
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from utils import *
from crypto import CryptoContext, ReplayProtector

class _DualTokenBucketPacer:
    """Internal pacer used by recovery retransmissions.

    It enforces both a byte budget and a packet budget so fast retransmit / RTO
    do not burst even when many losses are discovered in a single ACK epoch or
    timeout scan.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._byte_tokens = 0.0
        self._pkt_tokens = 0.0
        self._ts = time.time()

    def wait(self, packet_bytes: int, byte_rate: float, byte_burst: float, pkt_rate: float, pkt_burst: float):
        need_b = max(0.0, float(packet_bytes or 0))
        need_p = 1.0

        while True:
            with self._lock:
                now = time.time()
                elapsed = max(0.0, now - self._ts)
                self._ts = now

                if byte_rate > 0:
                    cap_b = max(need_b, float(byte_burst or 0.0))
                    self._byte_tokens = min(cap_b, self._byte_tokens + elapsed * float(byte_rate))
                else:
                    self._byte_tokens = need_b

                if pkt_rate > 0:
                    cap_p = max(need_p, float(pkt_burst or 0.0))
                    self._pkt_tokens = min(cap_p, self._pkt_tokens + elapsed * float(pkt_rate))
                else:
                    self._pkt_tokens = need_p

                byte_ok = (self._byte_tokens >= need_b)
                pkt_ok = (self._pkt_tokens >= need_p)
                if byte_ok and pkt_ok:
                    self._byte_tokens = max(0.0, self._byte_tokens - need_b)
                    self._pkt_tokens = max(0.0, self._pkt_tokens - need_p)
                    return False

                sleep_b = 0.0
                if (not byte_ok) and byte_rate > 0:
                    sleep_b = (need_b - self._byte_tokens) / float(byte_rate)

                sleep_p = 0.0
                if (not pkt_ok) and pkt_rate > 0:
                    sleep_p = (need_p - self._pkt_tokens) / float(pkt_rate)

            sleep_s = max(sleep_b, sleep_p, 0.0)
            time.sleep(min(sleep_s, 0.01))

CTRL_SEQ_BIT = 1 << 63
CTRL_DIR_BIT = 1 << 62  # split ctrl seq space by direction
CTRL_SEQ_COUNTER_MASK = CTRL_DIR_BIT - 1
META_TYPE_RANGE = 1
META_TYPE_PATH_CHALLENGE = 2
META_TYPE_PATH_RESPONSE = 3
META_TYPE_HANDSHAKE_CONFIRM = 4
PATH_CHALLENGE_LEN = 8
PATH_VALIDATION_TIMEOUT = 1.0
PATH_RETIRE_GRACE = 10.0
PATH_MIGRATION_INIT_CWND_PKTS = 10
KX_PAYLOAD_TAG = b"KX1"
KX_PUBKEY_LEN = 32
KX_FINISHED_LEN = 16
SYN_PAYLOAD_TAG = b"KS1"
SERVER_ID_PUBKEY_LEN = 32
HELLO_RANDOM_LEN = 16
SERVER_SIG_LEN = 64
DATA_FRAME_TAG = b"D2"
DATA_FRAME_HEADER_LEN = 2 + 8  # tag + sender tx timestamp echo (us, monotonic clock domain)
UDP_MAX_DATAGRAM_PAYLOAD = 65507
AEAD_TAG_LEN = 16
MAX_DATA_APP_PAYLOAD = UDP_MAX_DATAGRAM_PAYLOAD - HEADER_SIZE - DATA_FRAME_HEADER_LEN - AEAD_TAG_LEN

COMPLETE_PAYLOAD_TAG = b"CP1"
COMPLETE_PAYLOAD_LEN = len(COMPLETE_PAYLOAD_TAG) + 8 + 8 + 8 + 8


def data_packet_wire_size(app_payload_len: int) -> int:
    app_len = max(0, int(app_payload_len or 0))
    return int(HEADER_SIZE + DATA_FRAME_HEADER_LEN + app_len + AEAD_TAG_LEN)


def data_frame_payload_size(app_payload_len: int) -> int:
    app_len = max(0, int(app_payload_len or 0))
    return int(DATA_FRAME_HEADER_LEN + app_len)


ACK_STATE_V1 = 1
ACK_STATE_V2 = 2
ACK_DELAY_US_MAX = 0xFFFFFFFF

class ReliableUDPSession:

    def __init__(
        self,
        conn_id,
        addr,
        socket_obj,
        is_client: bool = False,
        server_sign_private_key=None,
        server_identity_validator=None,
    ):
        self.conn_id = conn_id
        self.sock = socket_obj
        self._sock_lock = threading.RLock()
        self._sock_rcvbuf = None
        self._sock_sndbuf = None
        self._local_addr = None
        self._refresh_socket_config_from_sock(socket_obj)

        self.crypto = CryptoContext(None, is_client=is_client)
        self._kx_private_key = None
        self._kx_public_bytes = None
        self._peer_kx_public_bytes = None
        self._session_key_ready = False
        self._finished_token = None
        self._server_sign_private_key = server_sign_private_key
        self._server_identity_validator = server_identity_validator
        self._server_identity_pub_bytes = None
        if self._server_sign_private_key is not None:
            self._server_identity_pub_bytes = self._server_sign_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._client_hello_random = None
        self._server_hello_random = None
        self._syn_received = False
        self.cc = None  
        self._cc_lock = threading.Lock()  

        self.logger = setup_logger(f"Session-{conn_id}")

        self.running = True
        self.lock = threading.RLock()
        self.peer_addr = addr
        self.addr = addr

        # 握手
        self.handshake_completed_local = False
        self.peer_confirmed_established = False

        self._hs_lock = threading.RLock()
        self._hs_event = threading.Event()
        self._hs_state = "idle"
        self._hs_next_deadline = None
        self._hs_rto = 0.0
        self._hs_initial_rto = 0.0
        self._hs_final_ack_rto_cap = 0.0
        self._hs_tail_timeout = None
        self._hs_tail_deadline = None
        self._hs_max_retries = 0
        self._hs_retries = 0
        self._hs_started = False
        self._session_key_ready_event = threading.Event()
        self._peer_established_event = threading.Event()
        self._handshake_thread = None

        self._peer_data_seen = False
       
        self._path_validation = {}  
        self._retired_paths = {}     
        self._path_validation_timeout = float(PATH_VALIDATION_TIMEOUT)
        self._path_retire_grace = float(PATH_RETIRE_GRACE)
        self._path_migration_init_cwnd_pkts = int(PATH_MIGRATION_INIT_CWND_PKTS)


        self.is_client = bool(is_client)
        self._ctrl_seq_base = int(CTRL_SEQ_BIT | (CTRL_DIR_BIT if self.is_client else 0))
        self._ctrl_seq_max = int(self._ctrl_seq_base | CTRL_SEQ_COUNTER_MASK)
        self.ctrl_seq = int(self._ctrl_seq_base)
        self.ctrl_replay_protector = ReplayProtector(window_size=4096, max_window_size=65535, auto_expand_margin=4096)

        # 发送端：未确认队列
        self.unacked = {}  # seq -> {'enc_data','ts','retries','size','tx_ts','fast_cnt'}

 
        self.send_max_unacked_pkts = 0

        # 统计口径：
        # Backward-compatible data-plane counters. _total_wire_bytes_sent / acked are kept
        # as DATA-only byte counters so older plotting scripts do not silently change meaning.
        self._total_bytes_sent = 0
        self._total_bytes_acked = 0
        self._total_wire_bytes_sent = 0
        self._total_wire_bytes_acked = 0
        self.fast_retx_count = 0
        self.rto_retx_count = 0
        self.ack1_sent_count = 0
        self.ack1_resend_count = 0
        self.dropped_data_count = 0

        # DATA packet/byte counters.
        self.data_packets_sent_original = 0
        self.data_packets_sent_total = 0
        self.data_packets_retx_total = 0
        self.data_packets_retx_fast = 0
        self.data_packets_retx_rto = 0
        self.data_packets_recv_total = 0
        self.data_packets_recv_new = 0
        self.data_packets_recv_duplicate = 0
        self.data_packets_delivered = 0
        self.data_packets_dropped_retry_exhausted = 0
        self.data_wire_bytes_sent_original = 0
        self.data_wire_bytes_sent_retx = 0
        self.data_wire_bytes_sent_total = 0
        self.data_wire_bytes_recv_total = 0
        self.app_bytes_delivered = 0

        # Control packet/byte counters. Control includes cleartext SYN/SYN-ACK and
        # encrypted session control packets. DATA is deliberately excluded.
        self.ctrl_packets_sent_total = 0
        self.ctrl_packets_recv_total = 0
        self.ctrl_packets_retx_total = 0
        self.ctrl_packets_drop_total = 0
        self.ctrl_bytes_sent_total = 0
        self.ctrl_bytes_recv_total = 0
        self.ctrl_bytes_retx_total = 0
        self.ctrl_wire_bytes_sent_total = 0
        self.ctrl_wire_bytes_recv_total = 0

        # ACK2 counters.
        self.ack2_sent_count = 0
        self.ack2_recv_count = 0
        self.ack2_cover_count = 0
        self.ack2_stale_count = 0
        self.ack2_malformed_count = 0

        # RANGE META counters.
        self.range_meta_sent_count = 0
        self.range_meta_retx_count = 0
        self.range_meta_ack_sent_count = 0
        self.range_meta_ack_recv_count = 0
        self.range_meta_failed_count = 0

        # Path validation / migration counters.
        self.path_challenge_sent_count = 0
        self.path_challenge_recv_count = 0
        self.path_response_sent_count = 0
        self.path_response_recv_count = 0
        self.path_response_valid_count = 0
        self.path_response_invalid_count = 0
        self.path_migration_commit_count = 0
        self.path_migration_validation_rtt_ms = None

        # Control replay diagnostics. A non-zero too_far counter used to indicate
        # that the control-plane freshness window had been pinned by a lost
        # untracked ACK. The high-water replay window should keep this at zero
        # under ordinary loss/reordering.
        self.ctrl_replay_duplicate_old_count = 0
        self.ctrl_replay_too_far_right_count = 0

        # Completion counters. Existing private counters are retained below for state handling;
        # these public counters are exported through get_experiment_snapshot().
        self.complete_recv_count = 0
        self.complete_ack_recv_count = 0

        # Derived totals exported in snapshots.
        self.all_wire_bytes_sent_total = 0
        self.all_wire_bytes_recv_total = 0
  
        self._fr_last_ack_base = None
        self._fr_dup_acks = 0
        self._fr_dup_thresh = 3         
        self._fr_nack_starts_max = 16     
        self._fr_max_per_ack = 24          
        self._fr_max_fast_cnt = 64        
        self._fr_min_interval_default = 0.05   
        self._fr_min_interval_floor = 0.02     
        self._fr_min_interval_cap = 0.20       
     
        self._fr_missing_report_streak = {}
        self._fr_missing_reports_required_base = 2
        self._fr_missing_reports_required_cap = 4


        self.app_pacing_enabled = True
        self._app_send_pacer = _DualTokenBucketPacer()
        self._app_pacing_gain = 1.0
        self._app_pacing_min_rtt = 0.005
        self._app_pacing_fallback_rtt = 0.1
        self._app_pacing_min_bps = float(4 * MSS) / 0.05
        self._app_pacing_min_pps = 16.0
        self._app_pacing_burst_pkts = 2.0
        self._app_pacing_burst_bytes = float(2 * MSS)
        self._app_last_pacing_bps = None
        self._pacing_stats_lock = threading.Lock()
        self._late_cleartext_retransmit_count = 0
        self._unexpected_cleartext_handshake_count = 0

        self.recovery_pacing_enabled = True
        self._recovery_pacer = _DualTokenBucketPacer()
        self._recovery_send_queue = deque()
        self._recovery_send_queued = set()
        self._recovery_send_event = threading.Event()
        self._recovery_pacing_gain = 1.0
        self._recovery_pacing_min_rtt = 0.005
        self._recovery_pacing_fallback_bps = float(32 * MSS) / 0.05
        self._recovery_pacing_min_bps = float(4 * MSS) / 0.05
        self._recovery_pacing_min_pps = 32.0
        self._recovery_pacing_burst_pkts = 2.0
        self._recovery_pacing_burst_bytes = float(2 * MSS)

       
        self.recv_buffer = {}            
        self.recv_ranges = []            
        self.next_seq_expected = 1

        self._ordered_ready = deque()
        self._ordered_ready_cv = threading.Condition()
        self._ordered_ready_closed = False
        self._ordered_ready_max_items = 0
        self._delivery_thread = None

   
        self.app_len_only = False
        self._small_payload_threshold = 256  
        self._app_queue = deque()
        self._app_queue_cv = threading.Condition()
        self._app_queue_max_items = 65536
        self._app_stream_closed = False

        
        self.range_start = None
        self.range_end = None

        # 乱序容忍：
    
        self._adaptive_ooo_window_floor_pkts = 8
        self._adaptive_ooo_window_cap_pkts = 65535
        self._adaptive_ooo_bdp_gain = 1.25
        self._adaptive_ooo_gap_gain = 1.50
        self._adaptive_replay_extra_pkts = 4
        self._adaptive_replay_margin_mult = 1.0
        self._adaptive_replay_margin_floor_pkts = 8
        self._adaptive_ooo_window_pkts = int(self._adaptive_ooo_window_floor_pkts)
        self._adaptive_peer_desired_ooo = None
        self._adaptive_peer_accepted_ooo = None
        self._adaptive_last_gap_depth = 0
        self._adaptive_gap_depth_ewma = 0.0
        self._adaptive_gap_depth_max = 0

        # ACK1/ACK2
        self.ack1_last_sent_ts = 0.0
        self.ack1_last_payload = b""
        self.ack1_last_ack_base = 0
 
        self.ack1_dirty = False           
        self.ack1_last_update_ts = 0.0    
        self.ack1_grace_period = 1.0       
        self.ack1_rto = 0.2                
        self.ack1_min_interval = 0.01      
        self._ack1_min_interval_gain = 0.20
        self._ack1_min_interval_floor = 0.001
        self._ack1_min_interval_cap = 0.050
        self._ack1_rto_floor = 0.050
        self._ack1_rto_cap = 2.000
        self._ack1_grace_period_mult = 3.0
        self._ack1_grace_period_floor = 0.250
        self._ack1_grace_period_cap = 2.000
        self._ack1_resender_sleep_floor = 0.001
        self._ack1_resender_sleep_cap = 0.020
        self._ack1_rtt_ref_seq = 0
        self._ack1_rtt_ref_tx_ts_us = 0
        self._ack1_rtt_ref_recv_mono_us = 0

        # 活性
        self.last_activity = time.time()

        # 重传参数

        self.base_rto = 0.25
        self.min_data_rto = 0.05
        self.max_rto = 4.0
        self.max_retries = 50

        self.ctrl_unacked = {}
        self.ctrl_base_rto = 0.15
        self.ctrl_max_rto = 1.0
        self.ctrl_max_retries = 30
        
        self.last_error_reason = None  
        self.fatal_error_reason = None
        self._fatal_error = False
        self._fatal_error_event = threading.Event()
        self._rst_sent = False
        self.dropped_data_seqs = []   # DATA seqs dropped due to retry exhaustion
        self.dropped_ctrl_ids = []    # ctrl pkt_nums dropped due to retry exhaustion
        self._range_meta_failed = threading.Event()  # RANGE META gave up retransmit

        # RANGE META 的确认（可选给 client 用于“等待 RANGE ACK 再发 burst”）
        self._range_meta_id = None
        self._range_meta_acked = threading.Event()
        self._range_meta_accepted_ooo = None  # optional: peer-accepted max out-of-order window

        # Completion-commit tail closure
        self._complete_sent_payload = b""
        self._complete_sent_pkt_num = None
        self._complete_received_payload = b""
        self._complete_received_info = None
        self._complete_received_event = threading.Event()
        self._complete_ack_received_event = threading.Event()
        self._complete_sent_count = 0
        self._complete_ack_sent_count = 0
        self._complete_commit_status = "idle"
        self._complete_commit_detail = None
        self._complete_expected_final_seq = None
        self._complete_expected_total_bytes = None
        self._complete_raw_received_event = threading.Event()
        self._complete_raw_received_info = None
        self._complete_validation_error = None


    @property
    def is_session_key_ready(self) -> bool:
        return bool(self._session_key_ready)

    def _set_session_key_ready(self, ready: bool) -> None:
        ready = bool(ready)
        self._session_key_ready = ready
        if ready:
            self._session_key_ready_event.set()
        else:
            self._session_key_ready_event.clear()

    def configure_app_delivery(self, len_only: bool = False, small_payload_threshold: int = 256, queue_max_items=None):
        """Configure the queue-based application delivery boundary.

        Ordered items are always enqueued by the protocol core. Application code must
        drain them with get_app_item() or get_app_items(). queue_max_items <= 0 means
        the queue is treated as unbounded.
        """
        with self._app_queue_cv:
            self.app_len_only = bool(len_only)
            self._small_payload_threshold = max(0, int(small_payload_threshold))
            if queue_max_items is not None:
                try:
                    qmax = int(queue_max_items)
                except Exception:
                    qmax = self._app_queue_max_items
                self._app_queue_max_items = max(0, qmax)
            self._app_queue_cv.notify_all()

    def set_small_payload_threshold(self, small_payload_threshold: int):
        """Update the len-only threshold used when buffering large DATA payloads."""
        with self.lock:
            self._small_payload_threshold = max(0, int(small_payload_threshold))

    def close_app_stream(self):
        """Close the application delivery stream and wake blocked queue consumers."""
        with self._app_queue_cv:
            self._app_stream_closed = True
            self._app_queue_cv.notify_all()

    def is_app_stream_closed(self) -> bool:
        with self._app_queue_cv:
            return bool(self._app_stream_closed)

    def get_app_item(self, timeout=None):
        """Return one ordered application item as (seq, data_or_len, is_len).

        Returns None on timeout or after the stream has been closed and drained.
        """
        deadline = None if timeout is None else (time.time() + max(0.0, float(timeout)))
        with self._app_queue_cv:
            while True:
                if self._app_queue:
                    item = self._app_queue.popleft()
                    self._app_queue_cv.notify_all()
                    return item
                if self._app_stream_closed or (not self.running):
                    return None
                if deadline is None:
                    self._app_queue_cv.wait()
                    continue
                remaining = deadline - time.time()
                if remaining <= 0.0:
                    return None
                self._app_queue_cv.wait(timeout=remaining)

    def get_app_items(self, max_items, timeout=None):
        """Return up to max_items ordered application items.

        Returns an empty list on timeout or after the stream has been closed and drained.
        """
        try:
            max_items = max(1, int(max_items))
        except Exception:
            max_items = 1

        first = self.get_app_item(timeout=timeout)
        if first is None:
            return []

        items = [first]
        with self._app_queue_cv:
            popped = False
            while self._app_queue and len(items) < max_items:
                items.append(self._app_queue.popleft())
                popped = True
            if popped:
                self._app_queue_cv.notify_all()
        return items

    def _enqueue_ordered_ready_batch(self, items):
        """Stage ordered items in the internal ready queue without blocking protocol recv handling."""
        if not items:
            return

        with self._ordered_ready_cv:
            for seq, data_or_len in items:
                self._ordered_ready.append((int(seq), data_or_len, isinstance(data_or_len, int)))
            self._ordered_ready_cv.notify_all()

    def _push_ready_batch_to_app_queue(self, items):
    
        if not items:
            return

        with self._app_queue_cv:
            for seq, data_or_len, is_len in items:
                while (
                    self.running
                    and (not self._app_stream_closed)
                    and self._app_queue_max_items > 0
                    and len(self._app_queue) >= self._app_queue_max_items
                ):
                    self._app_queue_cv.wait(timeout=0.05)

                if self._app_stream_closed or (not self.running):
                    return

                self._app_queue.append((int(seq), data_or_len, bool(is_len)))

            self._app_queue_cv.notify_all()

    def _delivery_loop(self):
        while True:
            batch = []

            with self._ordered_ready_cv:
                while self.running and (not self._ordered_ready) and (not self._ordered_ready_closed):
                    self._ordered_ready_cv.wait(timeout=0.1)

                if ((not self.running) or self._ordered_ready_closed) and (not self._ordered_ready):
                    break

                while self._ordered_ready and len(batch) < 256:
                    batch.append(self._ordered_ready.popleft())

            if not batch:
                continue

            self._push_ready_batch_to_app_queue(batch)

        with self._app_queue_cv:
            self._app_stream_closed = True
            self._app_queue_cv.notify_all()

    def _deliver_ordered_batch(self, items):
        
        self._enqueue_ordered_ready_batch(items)

    def _deliver_ordered(self, seq: int, data_or_len):
 
        self._enqueue_ordered_ready_batch([(seq, data_or_len)])

    def _refresh_socket_config_from_sock(self, sock_obj):
        if sock_obj is None:
            return
        try:
            self._sock_rcvbuf = int(sock_obj.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
        except Exception:
            pass
        try:
            self._sock_sndbuf = int(sock_obj.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
        except Exception:
            pass
        try:
            self._local_addr = sock_obj.getsockname()
        except Exception:
            pass

    def get_local_addr(self):
        with self._sock_lock:
            return self._local_addr

    def _sock_sendto(self, payload: bytes, addr):
        with self._sock_lock:
            sock_obj = self.sock
        if sock_obj is None:
            raise OSError('session socket is not available')
        return sock_obj.sendto(payload, addr)

    def _sock_recvfrom(self, bufsize: int):
        with self._sock_lock:
            sock_obj = self.sock
        if sock_obj is None:
            raise OSError('session socket is not available')
        return sock_obj.recvfrom(int(bufsize))

    def _is_range_meta_ack_payload(self, payload: bytes) -> bool:
        return bool(isinstance(payload, (bytes, bytearray)) and len(payload) >= 1 and int(payload[0]) == META_TYPE_RANGE)

    def _record_ctrl_sent_locked(self, flags, payload: bytes, wire_len: int, mtype=None) -> None:
        flags = int(flags or 0)
        payload = bytes(payload or b"")
        wire_len = max(0, int(wire_len or 0))
        self.ctrl_packets_sent_total += 1
        self.ctrl_bytes_sent_total += wire_len
        self.ctrl_wire_bytes_sent_total += wire_len
        if flags & FLAG_ACK2:
            self.ack2_sent_count += 1
        if flags & FLAG_META:
            payload_mtype = int(payload[0]) if payload else None
            effective_mtype = payload_mtype if mtype is None else mtype
            if flags & FLAG_ACK:
                if effective_mtype == META_TYPE_RANGE:
                    self.range_meta_ack_sent_count += 1
            else:
                if effective_mtype == META_TYPE_RANGE:
                    self.range_meta_sent_count += 1
                elif effective_mtype == META_TYPE_PATH_CHALLENGE:
                    self.path_challenge_sent_count += 1
                elif effective_mtype == META_TYPE_PATH_RESPONSE:
                    self.path_response_sent_count += 1

    def _record_ctrl_recv(self, raw_len: int, pkt: Packet = None) -> None:
        raw_len = max(0, int(raw_len or 0))
        with self.lock:
            self.ctrl_packets_recv_total += 1
            self.ctrl_bytes_recv_total += raw_len
            self.ctrl_wire_bytes_recv_total += raw_len

    def _record_data_recv_wire(self, raw_len: int) -> None:
        raw_len = max(0, int(raw_len or 0))
        with self.lock:
            self.data_packets_recv_total += 1
            self.data_wire_bytes_recv_total += raw_len

    def _record_ctrl_retx_success_locked(self, wire_len: int, mtype=None) -> None:
        wire_len = max(0, int(wire_len or 0))
        self.ctrl_packets_sent_total += 1
        self.ctrl_packets_retx_total += 1
        self.ctrl_bytes_retx_total += wire_len
        self.ctrl_bytes_sent_total += wire_len
        self.ctrl_wire_bytes_sent_total += wire_len
        if mtype == META_TYPE_RANGE:
            self.range_meta_retx_count += 1

    def _recompute_wire_totals_locked(self) -> None:
        self.data_wire_bytes_sent_total = int(self.data_wire_bytes_sent_original) + int(self.data_wire_bytes_sent_retx)
        self.all_wire_bytes_sent_total = int(self.data_wire_bytes_sent_total) + int(self.ctrl_wire_bytes_sent_total)
        self.all_wire_bytes_recv_total = int(self.data_wire_bytes_recv_total) + int(self.ctrl_wire_bytes_recv_total)

    def _swap_socket(self, new_socket, new_local_addr=None):
        if new_socket is None:
            raise ValueError('new_socket is required')
        self._refresh_socket_config_from_sock(new_socket)
        with self._sock_lock:
            old_socket = self.sock
            self.sock = new_socket
            if new_local_addr is None:
                try:
                    new_local_addr = new_socket.getsockname()
                except Exception:
                    new_local_addr = None
            self._local_addr = new_local_addr
        return old_socket

    def rebind_local_path(self, new_local_ip, new_local_port=0, new_peer_addr=None, close_old_socket: bool = True):
        new_local_ip = str(new_local_ip or '').strip()
        if not new_local_ip:
            raise ValueError('new_local_ip is required')

        try:
            new_local_port = int(new_local_port or 0)
        except Exception as exc:
            raise ValueError(f'invalid new_local_port: {new_local_port}') from exc

        old_local_addr = self.get_local_addr()
        with self.lock:
            old_peer_addr = self.peer_addr

        new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if self._sock_rcvbuf is not None:
                new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(self._sock_rcvbuf))
            if self._sock_sndbuf is not None:
                new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(self._sock_sndbuf))
            new_sock.bind((new_local_ip, int(new_local_port)))
            new_local_addr = new_sock.getsockname()

            with self.lock:
                retargeted_session_ctrl = 0
                if new_peer_addr is not None:
                    self.peer_addr = tuple(new_peer_addr)
                    self.addr = tuple(new_peer_addr)
                    retargeted_session_ctrl = self._retarget_session_scoped_ctrl_unacked_locked(self.addr)
                target_peer_addr = self.addr

            old_socket = self._swap_socket(new_sock, new_local_addr=new_local_addr)

            probe_token = None
            if target_peer_addr is not None:
                probe_token = self.start_path_probe(target_peer_addr)

            if close_old_socket and old_socket is not None and old_socket is not new_sock:
                try:
                    old_socket.close()
                except Exception:
                    pass

            try:
                self.logger.info(
                    f'Local path rebound: local {old_local_addr} -> {new_local_addr}, '
                    f'peer {old_peer_addr} -> {target_peer_addr}, retargeted_session_ctrl={retargeted_session_ctrl}'
                )
            except Exception:
                pass

            return {
                'old_local_addr': old_local_addr,
                'new_local_addr': new_local_addr,
                'old_peer_addr': old_peer_addr,
                'new_peer_addr': target_peer_addr,
                'retargeted_session_ctrl': int(retargeted_session_ctrl),
                'probe_token_hex': (None if probe_token is None else bytes(probe_token).hex()),
            }
        except Exception:
            try:
                new_sock.close()
            except Exception:
                pass
            raise

    def _next_ctrl_seq(self):
        with self.lock:
            n = int(self.ctrl_seq)
            if n > int(self._ctrl_seq_max):
                reason = f"control sequence space exhausted for session {self.conn_id}: next={n}, max={self._ctrl_seq_max}"
                self.logger.error(reason)
                self._set_error(reason, fatal=True)
                raise OverflowError(reason)
            self.ctrl_seq = int(n + 1)
            return n

    def _send_ctrl_to(self, flags, payload=b"", addr=None, track=False, mtype=None, cleartext: bool = False):
      
        if not self.running:
            return None
        if payload is None:
            payload = b""
        target_addr = self.addr if addr is None else addr
        try:
            pkt_num = self._next_ctrl_seq()
        except OverflowError:
            return None
        pkt = Packet(flags, self.conn_id, pkt_num, payload)
        wire = pkt.pack_header() + bytes(payload) if cleartext else self.crypto.encrypt(pkt)

        try:
            self._sock_sendto(wire, target_addr)
        except Exception as e:
            self.logger.error(f"Send ctrl error: {e}")
            return None

        with self.lock:
            self._record_ctrl_sent_locked(flags, payload, len(wire), mtype=mtype)
            self._recompute_wire_totals_locked()

        if track:
            now = time.time()
            addr_scope = self._tracked_ctrl_scope(flags, mtype)
            with self.lock:
                self.ctrl_unacked[pkt_num] = {
                    "enc_data": wire,
                    "ts": now,
                    "retries": 0,
                    "flags": int(flags),
                    "mtype": mtype,
                    "addr": self._addr_key(target_addr) if target_addr is not None else None,
                    "addr_scope": addr_scope,
                }
        return pkt_num

    def _send_ctrl(self, flags, payload=b"", track=False, mtype=None, cleartext: bool = False):
        #控制包发送
        
        return self._send_ctrl_to(
            flags,
            payload=payload,
            addr=None,
            track=track,
            mtype=mtype,
            cleartext=cleartext,
        )

    @staticmethod
    def _addr_key(addr):
        if isinstance(addr, list):
            return tuple(addr)
        return addr

    def _tracked_ctrl_scope(self, flags, mtype):
        try:
            flags = int(flags or 0)
        except Exception:
            flags = 0

        if flags & FLAG_META:
            if mtype in (META_TYPE_PATH_CHALLENGE, META_TYPE_PATH_RESPONSE):
                return "path"
            return "session"

        if flags & FLAG_FIN:
            return "session"

        return "session"

    def _ctrl_entry_scope(self, meta) -> str:
        meta = meta or {}
        scope = str(meta.get("addr_scope") or "").strip().lower()
        if scope in ("session", "path"):
            return scope
        return self._tracked_ctrl_scope(meta.get("flags"), meta.get("mtype"))

    def _ctrl_retransmit_addr_locked(self, meta):
        if self._ctrl_entry_scope(meta) == "session":
            return self.addr
        target_addr = (meta or {}).get("addr", None)
        return self.addr if target_addr is None else target_addr

    def _retarget_session_scoped_ctrl_unacked_locked(self, new_addr) -> int:
        new_key = self._addr_key(new_addr) if new_addr is not None else None
        updated = 0
        for meta in self.ctrl_unacked.values():
            if self._ctrl_entry_scope(meta) != "session":
                continue
            if meta.get("addr") != new_key:
                meta["addr"] = new_key
                updated += 1
            meta["addr_scope"] = "session"
        return updated

    def _prune_path_state(self):
        now = time.time()
        stale_cutoff = max(float(self._path_validation_timeout or 1.0) * 4.0, float(self._path_retire_grace or 10.0))
        with self.lock:
            for k, expiry in list(self._retired_paths.items()):
                if float(expiry or 0.0) <= now:
                    self._retired_paths.pop(k, None)
            for k, meta in list(self._path_validation.items()):
                sent_ts = float(meta.get("sent_ts", 0.0) or 0.0)
                first_seen_ts = float(meta.get("first_seen_ts", sent_ts) or sent_ts or 0.0)
                ref_ts = max(sent_ts, first_seen_ts)
                if ref_ts > 0.0 and (now - ref_ts) > stale_cutoff:
                    self._path_validation.pop(k, None)

    def _path_migration_allowed(self, pkt: Packet) -> bool:
        if self.is_client:
            return bool(((pkt.flags & FLAG_SYN) and (pkt.flags & FLAG_ACK)) or self.handshake_completed_local or (pkt.flags & FLAG_DATA))
        return bool((pkt.flags & FLAG_DATA) or self._peer_data_seen)

    def _send_path_challenge(self, addr, force: bool = False):
        addr_key = self._addr_key(addr)
        now = time.time()
        with self.lock:
            meta = self._path_validation.get(addr_key)
            if meta is not None and (not force):
                sent_ts = float(meta.get("sent_ts", 0.0) or 0.0)
                if sent_ts > 0.0 and (now - sent_ts) < float(self._path_validation_timeout or 1.0):
                    return bytes(meta.get("token", b""))

            token = os.urandom(PATH_CHALLENGE_LEN)
            first_seen_ts = now
            if meta is not None:
                first_seen_ts = float(meta.get("first_seen_ts", now) or now)
            self._path_validation[addr_key] = {
                "token": token,
                "sent_ts": now,
                "first_seen_ts": first_seen_ts,
            }

        payload = bytes([META_TYPE_PATH_CHALLENGE]) + bytes(token)
        self._send_ctrl_to(FLAG_META, payload, addr=addr)
        try:
            self.logger.info(f"PATH_CHALLENGE sent to {addr} for session {self.conn_id}")
        except Exception:
            pass
        return token

    def start_path_probe(self, addr):
        """Public hook for proactive path validation after a local socket / network rebinding event."""
        return self._send_path_challenge(addr, force=True)

    def _send_path_response(self, addr, token: bytes):
        token = bytes(token or b"")[:PATH_CHALLENGE_LEN]
        if len(token) != PATH_CHALLENGE_LEN:
            return
        payload = bytes([META_TYPE_PATH_RESPONSE]) + token
        self._send_ctrl_to(FLAG_META, payload, addr=addr)

    def cc_on_path_migrated(self, rtt_sample=None, initial_cwnd_packets: int = 10) -> None:
        with self._cc_lock:
            if self.cc is None:
                return
            resetter = getattr(self.cc, "reset_after_migration", None)
            if callable(resetter):
                resetter(rtt_sample=rtt_sample, initial_cwnd_pkts=int(initial_cwnd_packets))
                return

            try:
                fresh_cwnd = max(1, int(initial_cwnd_packets)) * MSS
                self.cc.cwnd = fresh_cwnd
                self.cc.inflight_bytes = 0
                if hasattr(self.cc, "ssthresh"):
                    self.cc.ssthresh = max(int(fresh_cwnd), int(1 << 60))
                if hasattr(self.cc, "_epoch_start"):
                    self.cc._epoch_start = None
                if hasattr(self.cc, "_origin_point_cwnd"):
                    self.cc._origin_point_cwnd = float(fresh_cwnd)
                if hasattr(self.cc, "_last_max_cwnd"):
                    self.cc._last_max_cwnd = float(fresh_cwnd)
                if hasattr(self.cc, "_tcp_cwnd"):
                    self.cc._tcp_cwnd = float(fresh_cwnd)
                if hasattr(self.cc, "_k"):
                    self.cc._k = 0.0
                if rtt_sample is not None:
                    sample = max(0.001, float(rtt_sample))
                    self.cc.srtt = sample
                    self.cc.rttvar = sample / 2.0
                    self.cc.min_rtt = sample
                    self.cc.last_rtt_sample = sample
                    if hasattr(self.cc, "rto"):
                        min_rto = float(getattr(self.cc, "min_rto", sample))
                        max_rto = float(getattr(self.cc, "max_rto", max(sample, min_rto)))
                        tail_guard_gain = float(getattr(self.cc, "tail_guard_gain", 1.25) or 1.25)
                        if hasattr(self.cc, "tail_rtt"):
                            self.cc.tail_rtt = sample
                        if hasattr(self.cc, "_tail_rtt_ts"):
                            self.cc._tail_rtt_ts = time.time()
                        est_rto = max(
                            sample + max(0.010, 4.0 * (sample / 2.0)),
                            tail_guard_gain * sample,
                        )
                        self.cc.rto = min(max_rto, max(min_rto, est_rto))
            except Exception:
                pass

    def _promote_validated_path(self, new_addr, validation_rtt=None):
        new_key = self._addr_key(new_addr)
        now = time.time()
        retargeted_session_ctrl = 0
        with self.lock:
            old_addr = self.peer_addr
            if old_addr == new_addr:
                self._path_validation.pop(new_key, None)
                return False

            self.peer_addr = new_addr
            self.addr = new_addr
            retargeted_session_ctrl = self._retarget_session_scoped_ctrl_unacked_locked(new_addr)
            self._path_validation.pop(new_key, None)
            self._retired_paths.pop(new_key, None)
            if old_addr is not None and old_addr != new_addr:
                self._retired_paths[self._addr_key(old_addr)] = now + float(self._path_retire_grace or 10.0)
            self.path_migration_commit_count += 1
            if validation_rtt is not None:
                try:
                    self.path_migration_validation_rtt_ms = float(validation_rtt) * 1000.0
                except Exception:
                    self.path_migration_validation_rtt_ms = None

        self.cc_on_path_migrated(
            rtt_sample=validation_rtt,
            initial_cwnd_packets=int(self._path_migration_init_cwnd_pkts),
        )
        self._sync_cc_inflight_bytes()
        try:
            if validation_rtt is None:
                self.logger.info(
                    f"Path migration committed: {old_addr} -> {new_addr}, retargeted_session_ctrl={retargeted_session_ctrl}"
                )
            else:
                self.logger.info(
                    f"Path migration committed: {old_addr} -> {new_addr}, validation_rtt={float(validation_rtt) * 1000.0:.1f}ms, "
                    f"retargeted_session_ctrl={retargeted_session_ctrl}"
                )
        except Exception:
            pass
        return True

    def start_threads(self, start_receiver=True):
        threading.Thread(target=self._recovery_sender, daemon=True).start()
        threading.Thread(target=self._retransmit_checker, daemon=True).start()
        threading.Thread(target=self._ack1_resender, daemon=True).start()

        if self._delivery_thread is None or (not self._delivery_thread.is_alive()):
            self._delivery_thread = threading.Thread(target=self._delivery_loop, daemon=True)
            self._delivery_thread.start()

        if self.is_client and (self._handshake_thread is None or (not self._handshake_thread.is_alive())):
            self._handshake_thread = threading.Thread(target=self._handshake_timer_worker, daemon=True)
            self._handshake_thread.start()

        if start_receiver:
            threading.Thread(target=self._receiver_thread, daemon=True).start()

    def stop(self):
        self.running = False
        with self._hs_lock:
            self._hs_state = "stopped"
            self._hs_next_deadline = None
            self._hs_tail_deadline = None
        self._hs_event.set()
        self.close_app_stream()
        try:
            self._recovery_send_event.set()
        except Exception:
            pass
        try:
            with self._app_queue_cv:
                self._app_queue_cv.notify_all()
        except Exception:
            pass
        try:
            with self._ordered_ready_cv:
                self._ordered_ready_closed = True
                self._ordered_ready_cv.notify_all()
        except Exception:
            pass

    def begin_client_handshake(
        self,
        initial_rto: float,
        max_retries: int,
        handshake_tail_timeout: float = None,
        final_ack_rto_cap: float = None,
    ):
        if not self.is_client:
            raise RuntimeError("only client sessions can start active handshake")

        initial_rto = max(0.05, float(initial_rto or 0.0))
        max_retries = max(0, int(max_retries or 0))

        if final_ack_rto_cap is None:
            final_ack_rto_cap = initial_rto
        final_ack_rto_cap = max(initial_rto, float(final_ack_rto_cap))

        if handshake_tail_timeout is None or float(handshake_tail_timeout) <= 0.0:
            handshake_tail_timeout = None
        else:
            handshake_tail_timeout = max(initial_rto, float(handshake_tail_timeout))

        now = time.time()

        with self._hs_lock:
            self._hs_initial_rto = float(initial_rto)
            self._hs_rto = float(initial_rto)
            self._hs_final_ack_rto_cap = float(final_ack_rto_cap)
            self._hs_tail_timeout = handshake_tail_timeout
            self._hs_tail_deadline = None
            self._hs_max_retries = int(max_retries)
            self._hs_retries = 0
            self._hs_state = "wait_synack"
            self._hs_started = True
            self._hs_next_deadline = now + float(self._hs_rto)

        self.send_syn()
        self._hs_event.set()

    def get_handshake_state(self) -> str:
        if not self.is_client:
            with self.lock:
                if self.handshake_completed_local:
                    return "established"
                if self.is_session_key_ready:
                    return "key_ready_unconfirmed"
                return "stopped" if (not self.running) else "idle"
        with self._hs_lock:
            return str(self._hs_state)

    def _wait_event_or_terminal(self, ev: threading.Event, timeout=None) -> bool:
        deadline = None if timeout is None else (time.time() + max(0.0, float(timeout)))
        while True:
            if ev.is_set():
                return True
            if self.has_fatal_error() or (not self.running):
                return False
            wait_s = 0.05
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 0.0:
                    return bool(ev.is_set())
                wait_s = min(wait_s, remaining)
            ev.wait(timeout=wait_s)

    def wait_session_key_ready(self, timeout=None) -> bool:
        if self.is_session_key_ready:
            return True
        return bool(self._wait_event_or_terminal(self._session_key_ready_event, timeout=timeout))

    def wait_peer_established(self, timeout=None) -> bool:
        return bool(self._wait_event_or_terminal(self._peer_established_event, timeout=timeout))

    def _handshake_timer_worker(self):
        while self.running:
            if self.has_fatal_error():
                return

            with self._hs_lock:
                started = bool(self._hs_started)
                state = str(self._hs_state)
                deadline = self._hs_next_deadline
                tail_deadline = self._hs_tail_deadline

            if (not started) or state in ("idle", "established", "failed", "stopped"):
                self._hs_event.wait(timeout=0.1)
                self._hs_event.clear()
                continue

            now = time.time()
            if deadline is None or now < float(deadline):
                wait_s = 0.1 if deadline is None else max(0.0, min(0.1, float(deadline) - now))
                self._hs_event.wait(timeout=wait_s)
                self._hs_event.clear()
                continue

            reason = None
            retry_mode = None
            retry_no = 0
            state_for_log = state
            next_rto = None

            if state == "key_ready_unconfirmed" and tail_deadline is not None and now >= float(tail_deadline):
                with self._hs_lock:
                    if self._hs_state == "key_ready_unconfirmed":
                        self._hs_state = "failed"
                        self._hs_next_deadline = None
                        self._hs_tail_deadline = None
                        reason = (
                            f"handshake tail timeout exceeded "
                            f"retries={self._hs_retries}/{self._hs_max_retries}"
                        )
                self._set_error(reason, fatal=True)
                return

            with self._hs_lock:
                state = str(self._hs_state)
                tail_deadline = self._hs_tail_deadline
                if (not self._hs_started) or state in ("idle", "established", "failed", "stopped"):
                    continue

                if self._hs_retries >= int(self._hs_max_retries):
                    self._hs_state = "failed"
                    self._hs_next_deadline = None
                    self._hs_tail_deadline = None
                    reason = (
                        f"handshake retries exhausted state={state} "
                        f"retries={self._hs_retries}/{self._hs_max_retries}"
                    )
                else:
                    self._hs_retries += 1
                    retry_no = int(self._hs_retries)
                    state_for_log = state

                    cur_rto = float(self._hs_rto or self._hs_initial_rto or 0.05)
                    if state == "wait_synack":
                        retry_mode = "syn"
                        next_rto = max(float(self._hs_initial_rto or 0.05), cur_rto * 2.0)
                    else:
                        retry_mode = "final_ack"
                        next_rto = min(
                            float(self._hs_final_ack_rto_cap or cur_rto),
                            max(float(self._hs_initial_rto or 0.05), cur_rto * 2.0),
                        )

                    next_deadline = time.time() + float(next_rto)
                    if retry_mode == "final_ack" and tail_deadline is not None:
                        next_deadline = min(next_deadline, float(tail_deadline))

                    self._hs_rto = float(next_rto)
                    self._hs_next_deadline = float(next_deadline)

            if reason is not None:
                self._set_error(reason, fatal=True)
                return

            try:
                if retry_mode == "syn":
                    self.logger.warning(
                        f"Handshake timer retry via SYN: state={state_for_log}, "
                        f"retry={retry_no}/{self._hs_max_retries}, next_rto={float(next_rto):.3f}s"
                    )
                    self.send_syn()
                elif retry_mode == "final_ack":
                    self.logger.warning(
                        f"Handshake timer retry via final ACK: state={state_for_log}, "
                        f"retry={retry_no}/{self._hs_max_retries}, next_rto={float(next_rto):.3f}s"
                    )
                    self._send_final_handshake_ack()
            except Exception as e:
                self._set_error(f"handshake timer retry failed: {e}", fatal=True)
                return

    # ---------------- 握手 / 票据 / 0-RTT ----------------
    def _ensure_kx_keypair(self):
        if self._kx_private_key is None:
            self._kx_private_key = x25519.X25519PrivateKey.generate()
            self._kx_public_bytes = self._kx_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return self._kx_public_bytes

    def _build_kx_pub_payload(self) -> bytes:
        return bytes(KX_PAYLOAD_TAG) + bytes(self._ensure_kx_keypair())

    def _ensure_client_hello_random(self) -> bytes:
        if self._client_hello_random is None:
            self._client_hello_random = os.urandom(HELLO_RANDOM_LEN)
        return bytes(self._client_hello_random)

    def _ensure_server_hello_random(self) -> bytes:
        if self._server_hello_random is None:
            self._server_hello_random = os.urandom(HELLO_RANDOM_LEN)
        return bytes(self._server_hello_random)

    def _build_server_auth_transcript(self, server_pub_bytes: bytes = None) -> bytes:
        client_pub = bytes(self._peer_kx_public_bytes or b'') if not self.is_client else bytes(self._kx_public_bytes or b'')
        server_pub = bytes(server_pub_bytes or self._kx_public_bytes or b'') if not self.is_client else bytes(server_pub_bytes or self._peer_kx_public_bytes or b'')
        client_random = bytes(self._client_hello_random or b'')
        server_random = bytes(self._server_hello_random or b'')
        if len(client_pub) != KX_PUBKEY_LEN or len(server_pub) != KX_PUBKEY_LEN:
            raise ValueError('handshake transcript missing X25519 public keys')
        if len(client_random) != HELLO_RANDOM_LEN or len(server_random) != HELLO_RANDOM_LEN:
            raise ValueError('handshake transcript missing hello randoms')
        transcript = bytearray()
        transcript.extend(int(self.conn_id).to_bytes(8, 'big'))
        transcript.extend(client_pub)
        transcript.extend(server_pub)
        transcript.extend(client_random)
        transcript.extend(server_random)
        return bytes(transcript)

    def _build_server_handshake_signature(self, server_pub_bytes: bytes = None) -> bytes:
        if self._server_sign_private_key is None:
            raise RuntimeError('server signing key unavailable')
        transcript = self._build_server_auth_transcript(server_pub_bytes=server_pub_bytes)
        return self._server_sign_private_key.sign(transcript)

    def _verify_server_handshake_signature(self, server_identity_pub_bytes: bytes, signature: bytes, server_pub_bytes: bytes = None) -> bool:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes(server_identity_pub_bytes or b''))
            transcript = self._build_server_auth_transcript(server_pub_bytes=server_pub_bytes)
            pub.verify(bytes(signature or b''), transcript)
            return True
        except Exception:
            return False

    def _parse_kx_pub_payload(self, payload: bytes):
        if not isinstance(payload, (bytes, bytearray)):
            return None
        payload = bytes(payload)
        if not payload.startswith(KX_PAYLOAD_TAG):
            return None
        body = payload[len(KX_PAYLOAD_TAG):]
        if len(body) < KX_PUBKEY_LEN:
            return None
        pub = body[:KX_PUBKEY_LEN]
        extra = body[KX_PUBKEY_LEN:]
        flags = int(extra[0]) if len(extra) >= 1 else 0
        return {"pub": pub, "flags": flags}

    def _parse_finished_payload(self, payload: bytes):
        if not isinstance(payload, (bytes, bytearray)):
            return None
        payload = bytes(payload)
        if not payload.startswith(KX_PAYLOAD_TAG):
            return None
        body = payload[len(KX_PAYLOAD_TAG):]
        if len(body) != KX_FINISHED_LEN:
            return None
        return body

    def _derive_session_key_from_peer(self, peer_pub_bytes: bytes):
        peer_pub_bytes = bytes(peer_pub_bytes or b"")
        if len(peer_pub_bytes) != KX_PUBKEY_LEN:
            raise ValueError("invalid peer X25519 public key length")

        self._ensure_kx_keypair()
        self._peer_kx_public_bytes = peer_pub_bytes
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared_secret = self._kx_private_key.exchange(peer_pub)

        if self.is_client:
            client_pub = bytes(self._kx_public_bytes)
            server_pub = bytes(peer_pub_bytes)
        else:
            client_pub = bytes(peer_pub_bytes)
            server_pub = bytes(self._kx_public_bytes)

        client_random = bytes(self._client_hello_random or b'')
        server_random = bytes(self._server_hello_random or b'')
        if len(client_random) != HELLO_RANDOM_LEN or len(server_random) != HELLO_RANDOM_LEN:
            raise ValueError('missing hello randoms for session key derivation')

        transcript = bytearray()
        transcript.extend(b'rudp-session-v2')
        transcript.extend(int(self.conn_id).to_bytes(8, 'big'))
        transcript.extend(client_pub)
        transcript.extend(server_pub)
        transcript.extend(client_random)
        transcript.extend(server_random)
        transcript_hash = hashlib.sha256(bytes(transcript)).digest()
        info = b'rudp-session-v2' + transcript_hash
        key, nonce_secret, finished = self.crypto.derive_session_material(
            shared_secret,
            salt=transcript_hash,
            info=info,
        )
        self.crypto.update_key(key, nonce_secret=nonce_secret)
        self._set_session_key_ready(True)
        self._finished_token = finished
        return finished

    def _send_final_handshake_ack(self, addr=None):
        if not self._session_key_ready or self._finished_token is None:
            raise RuntimeError("session key not ready")
        payload = bytes(KX_PAYLOAD_TAG) + bytes(self._finished_token)
        return self._send_ctrl_to(FLAG_ACK, payload, addr=addr)

    def _build_handshake_confirm_payload(self) -> bytes:
        if self._finished_token is None:
            raise RuntimeError("finished token unavailable")
        return bytes([META_TYPE_HANDSHAKE_CONFIRM]) + bytes(self._finished_token)

    def _send_handshake_confirm(self, addr=None):
        return self._send_ctrl_to(
            FLAG_META,
            self._build_handshake_confirm_payload(),
            addr=addr,
            track=False,
            mtype=META_TYPE_HANDSHAKE_CONFIRM,
        )

    def _mark_handshake_completed_local(self, reason: str):
        just_marked = False
        with self.lock:
            if not self.handshake_completed_local:
                self.handshake_completed_local = True
                just_marked = True
        if just_marked:
            try:
                self.logger.info(str(reason))
            except Exception:
                pass
        return just_marked

    def _mark_peer_confirmed_established(self, reason: str):
        just_marked = False
        with self.lock:
            if not self.peer_confirmed_established:
                self.peer_confirmed_established = True
                just_marked = True
        if just_marked:
            self._peer_established_event.set()
            if self.is_client:
                with self._hs_lock:
                    self._hs_state = "established"
                    self._hs_next_deadline = None
                    self._hs_tail_deadline = None
                self._hs_event.set()
            try:
                self.logger.info(str(reason))
            except Exception:
                pass
        return just_marked

    def _mark_handshake_complete(self, reason: str):
        return self._mark_handshake_completed_local(reason)

    def _commit_handshake_tail_addr(self, addr):
        with self.lock:
            self.peer_addr = addr
            self.addr = addr

    def _classify_cleartext_handshake_packet(self, raw_data):
        pkt, _ = Packet.unpack_header(raw_data)
        if pkt is None:
            return None, None

        if not (pkt.flags & FLAG_SYN):
            return None, None

        # Cleartext handshake packets are limited to SYN / SYN-ACK only.
        if pkt.flags & (FLAG_META | FLAG_ACK2 | FLAG_DATA | FLAG_RST | FLAG_FIN):
            return None, None

        if self.is_client:
            # Client only accepts cleartext SYN-ACK.
            if not (pkt.flags & FLAG_ACK):
                return None, None
            if self._parse_synack_payload(pkt.payload) is None:
                return None, None
            return pkt, "cleartext-synack"

        # Server only accepts cleartext SYN.
        if pkt.flags & FLAG_ACK:
            return None, None
        if self._parse_syn_payload(pkt.payload) is None:
            return None, None
        return pkt, "cleartext-syn"

    def _is_consistent_late_cleartext_handshake(self, pkt) -> bool:
        if pkt is None:
            return False

        if self.is_client:
            parsed = self._parse_synack_payload(pkt.payload)
            if parsed is None:
                return False
            if self._peer_kx_public_bytes is not None and bytes(parsed["server_pub"]) != bytes(self._peer_kx_public_bytes):
                return False
            if self._server_hello_random is not None and bytes(parsed["server_random"]) != bytes(self._server_hello_random):
                return False
            if self._server_identity_pub_bytes is not None and bytes(parsed["server_identity_pub"]) != bytes(self._server_identity_pub_bytes):
                return False
            if not self._verify_server_handshake_signature(
                parsed["server_identity_pub"],
                parsed["signature"],
                server_pub_bytes=parsed["server_pub"],
            ):
                return False
            return True

        parsed = self._parse_syn_payload(pkt.payload)
        if parsed is None:
            return False
        if self._peer_kx_public_bytes is not None and bytes(parsed["client_pub"]) != bytes(self._peer_kx_public_bytes):
            return False
        if self._client_hello_random is not None and bytes(parsed["client_random"]) != bytes(self._client_hello_random):
            return False
        return True

    def _decrypt_packet(self, raw_data):
        clear_pkt, clear_kind = self._classify_cleartext_handshake_packet(raw_data)

        pkt = self.crypto.decrypt(raw_data, count_auth_fail=False)
        if pkt is not None:
            source = "session" if self._session_key_ready else "active"
            return pkt, source

        # Recognized cleartext handshake packets must not pollute AEAD auth-fail stats,
        # even if they arrive late after the session key path has already completed the handshake.
        if clear_pkt is not None:
            if self._session_key_ready or self.handshake_completed_local:
                return clear_pkt, "late-cleartext-handshake"
            return clear_pkt, "cleartext-handshake"

        self.crypto.decrypt(raw_data, count_auth_fail=True)
        return None, None

    def _build_syn_payload(self) -> bytes:
        client_pub = bytes(self._ensure_kx_keypair())
        client_random = bytes(self._ensure_client_hello_random())
        return bytes(SYN_PAYLOAD_TAG) + client_pub + client_random

    def _parse_syn_payload(self, payload: bytes):
        if not isinstance(payload, (bytes, bytearray)):
            return None
        payload = bytes(payload)
        if not payload.startswith(SYN_PAYLOAD_TAG):
            return None
        off = len(SYN_PAYLOAD_TAG)
        if len(payload) != off + KX_PUBKEY_LEN + HELLO_RANDOM_LEN:
            return None
        client_pub = payload[off:off + KX_PUBKEY_LEN]
        off += KX_PUBKEY_LEN
        client_random = payload[off:off + HELLO_RANDOM_LEN]
        return {"client_pub": client_pub, "client_random": bytes(client_random)}

    def _build_synack_payload(self) -> bytes:
        server_pub = bytes(self._ensure_kx_keypair())
        server_random = bytes(self._ensure_server_hello_random())
        server_id_pub = bytes(self._server_identity_pub_bytes or b'')
        if len(server_id_pub) != SERVER_ID_PUBKEY_LEN:
            raise RuntimeError('server identity public key unavailable')
        sig = self._build_server_handshake_signature(server_pub_bytes=server_pub)
        if len(sig) != SERVER_SIG_LEN:
            raise RuntimeError('invalid server handshake signature length')
        return bytes(KX_PAYLOAD_TAG) + server_pub + server_random + server_id_pub + sig

    def _parse_synack_payload(self, payload: bytes):
        if not isinstance(payload, (bytes, bytearray)):
            return None
        payload = bytes(payload)
        if not payload.startswith(KX_PAYLOAD_TAG):
            return None
        off = len(KX_PAYLOAD_TAG)
        need = KX_PUBKEY_LEN + HELLO_RANDOM_LEN + SERVER_ID_PUBKEY_LEN + SERVER_SIG_LEN
        if len(payload) != off + need:
            return None
        server_pub = payload[off:off + KX_PUBKEY_LEN]
        off += KX_PUBKEY_LEN
        server_random = payload[off:off + HELLO_RANDOM_LEN]
        off += HELLO_RANDOM_LEN
        server_identity_pub = payload[off:off + SERVER_ID_PUBKEY_LEN]
        off += SERVER_ID_PUBKEY_LEN
        signature = payload[off:off + SERVER_SIG_LEN]
        return {
            "server_pub": server_pub,
            "server_random": bytes(server_random),
            "server_identity_pub": bytes(server_identity_pub),
            "signature": bytes(signature),
        }

    def send_syn(self):
        self._send_ctrl(FLAG_SYN, self._build_syn_payload(), cleartext=True)

    def _send_synack_cleartext(self, addr=None):
        return self._send_ctrl_to(FLAG_SYN | FLAG_ACK, self._build_synack_payload(), addr=addr, cleartext=True)

    @staticmethod
    def data_packet_wire_size(app_payload_len: int) -> int:
        return data_packet_wire_size(app_payload_len)

    @staticmethod
    def data_frame_payload_size(app_payload_len: int) -> int:
        return data_frame_payload_size(app_payload_len)

    def send_precise(self, seq: int, payload: bytes) -> int:
        """
        发送一个指定 seq 的 DATA 包，并纳入重传/确认跟踪。

        返回值：
        - 成功时返回该次真正上链路的 wire_size
        - 本地 sendto 失败时抛出 RuntimeError，此时不会记入 sent/unacked/in-flight

        注意：重传时必须重发同一份 enc_data（不能重新加密，否则 nonce/seq 语义会崩）。
        """
        seq = int(seq)
        if seq <= 0 or seq >= CTRL_SEQ_BIT:
            raise ValueError("DATA seq must be in (0, 1<<63)")

        app_payload = bytes(payload or b"")
        if len(app_payload) > MAX_DATA_APP_PAYLOAD:
            raise ValueError(
                f"DATA app payload too large: {len(app_payload)} > {MAX_DATA_APP_PAYLOAD} "
                f"(udp_limit={UDP_MAX_DATAGRAM_PAYLOAD}, header={HEADER_SIZE}, data_frame={DATA_FRAME_HEADER_LEN}, aead_tag={AEAD_TAG_LEN})"
            )
        tx_echo_us = self._mono_now_us()
        pkt = Packet(FLAG_DATA, self.conn_id, seq, self._build_data_wire_payload(app_payload, tx_ts_us=tx_echo_us))
        enc = self.crypto.encrypt(pkt)
        app_size = int(len(app_payload))
        wire_size = int(len(enc))
        now = time.time()

        try:
            self._sock_sendto(enc, self.addr)
        except Exception as e:
            reason = f"local data send failed seq={seq}: {e}"
            self.logger.error(reason)
            self._set_error(reason, fatal=True)
            raise RuntimeError(reason) from e

        with self.lock:
            self._total_bytes_sent += app_size
            self._total_wire_bytes_sent += wire_size
            self.data_packets_sent_original += 1
            self.data_packets_sent_total += 1
            self.data_wire_bytes_sent_original += wire_size
            self.data_wire_bytes_sent_total += wire_size
            self._recompute_wire_totals_locked()
            self.unacked[seq] = {
                # "ts" is the data-recovery timer reference.
                # It starts at the initial send time and is refreshed after each actual recovery retransmission
                # so fast-retransmit and RTO share one recovery timeline instead of racing independently.
                # "tx_ts" tracks the most recent actual transmit time (initial / fast / RTO) for rate-limiting.
                # "retries" is consumed ONLY by RTO-based retransmissions.
                "enc_data": enc,
                "ts": now,
                "tx_ts": now,
                "retries": 0,
                "fast_cnt": 0,
                "app_size": app_size,
                "wire_size": wire_size,
                "tx_echo_us": tx_echo_us,
            }

        return wire_size

    def get_unacked_count(self):
        with self.lock:
            return len(self.unacked)

    def is_seq_unacked(self, seq: int) -> bool:
        with self.lock:
            return int(seq) in self.unacked

    def get_total_bytes_sent(self) -> int:
        with self.lock:
            return int(self._total_bytes_sent)

    def get_total_bytes_acked(self) -> int:
        with self.lock:
            return int(self._total_bytes_acked)

    def get_total_app_bytes_sent(self) -> int:
        return self.get_total_bytes_sent()

    def get_total_app_bytes_acked(self) -> int:
        return self.get_total_bytes_acked()

    def get_total_wire_bytes_sent(self) -> int:
        with self.lock:
            return int(self._total_wire_bytes_sent)

    def get_total_wire_bytes_acked(self) -> int:
        with self.lock:
            return int(self._total_wire_bytes_acked)

    def get_total_data_wire_bytes_sent(self) -> int:
        with self.lock:
            self._recompute_wire_totals_locked()
            return int(self.data_wire_bytes_sent_total)

    def get_total_ctrl_wire_bytes_sent(self) -> int:
        with self.lock:
            self._recompute_wire_totals_locked()
            return int(self.ctrl_wire_bytes_sent_total)

    def get_total_all_wire_bytes_sent(self) -> int:
        with self.lock:
            self._recompute_wire_totals_locked()
            return int(self.all_wire_bytes_sent_total)

    def get_total_data_wire_bytes_recv(self) -> int:
        with self.lock:
            self._recompute_wire_totals_locked()
            return int(self.data_wire_bytes_recv_total)

    def get_total_ctrl_wire_bytes_recv(self) -> int:
        with self.lock:
            self._recompute_wire_totals_locked()
            return int(self.ctrl_wire_bytes_recv_total)

    def get_total_all_wire_bytes_recv(self) -> int:
        with self.lock:
            self._recompute_wire_totals_locked()
            return int(self.all_wire_bytes_recv_total)

    def get_overhead_counters(self):
        """Return the extended protocol-overhead counter set used by experiment summaries."""
        return self.get_protocol_counters()

    def _export_protocol_counters_locked(self):
        self._recompute_wire_totals_locked()
        crypto_stats = {}
        try:
            crypto_stats = dict(getattr(self.crypto, "_replay_stats", {}) or {})
        except Exception:
            crypto_stats = {}
        return {
            "fast_retx_count": int(self.fast_retx_count),
            "rto_retx_count": int(self.rto_retx_count),
            "ack1_sent_count": int(self.ack1_sent_count),
            "ack1_resend_count": int(self.ack1_resend_count),
            "dropped_data_count": int(self.dropped_data_count),
            "data_packets_sent_original": int(self.data_packets_sent_original),
            "data_packets_sent_total": int(self.data_packets_sent_total),
            "data_packets_retx_total": int(self.data_packets_retx_total),
            "data_packets_retx_fast": int(self.data_packets_retx_fast),
            "data_packets_retx_rto": int(self.data_packets_retx_rto),
            "data_packets_recv_total": int(self.data_packets_recv_total),
            "data_packets_recv_new": int(self.data_packets_recv_new),
            "data_packets_recv_duplicate": int(self.data_packets_recv_duplicate),
            "data_packets_delivered": int(self.data_packets_delivered),
            "data_packets_dropped_retry_exhausted": int(self.data_packets_dropped_retry_exhausted),
            "ctrl_packets_sent_total": int(self.ctrl_packets_sent_total),
            "ctrl_packets_recv_total": int(self.ctrl_packets_recv_total),
            "ctrl_packets_retx_total": int(self.ctrl_packets_retx_total),
            "ctrl_packets_drop_total": int(self.ctrl_packets_drop_total),
            "ctrl_bytes_sent_total": int(self.ctrl_bytes_sent_total),
            "ctrl_bytes_recv_total": int(self.ctrl_bytes_recv_total),
            "ctrl_bytes_retx_total": int(self.ctrl_bytes_retx_total),
            "ctrl_wire_bytes_sent_total": int(self.ctrl_wire_bytes_sent_total),
            "ctrl_wire_bytes_recv_total": int(self.ctrl_wire_bytes_recv_total),
            "ctrl_replay_duplicate_old_count": int(self.ctrl_replay_duplicate_old_count),
            "ctrl_replay_too_far_right_count": int(self.ctrl_replay_too_far_right_count),
            "data_wire_bytes_sent_original": int(self.data_wire_bytes_sent_original),
            "data_wire_bytes_sent_retx": int(self.data_wire_bytes_sent_retx),
            "data_wire_bytes_sent_total": int(self.data_wire_bytes_sent_total),
            "data_wire_bytes_recv_total": int(self.data_wire_bytes_recv_total),
            "all_wire_bytes_sent_total": int(self.all_wire_bytes_sent_total),
            "all_wire_bytes_recv_total": int(self.all_wire_bytes_recv_total),
            "app_bytes_delivered": int(self.app_bytes_delivered),
            "ack2_sent_count": int(self.ack2_sent_count),
            "ack2_recv_count": int(self.ack2_recv_count),
            "ack2_cover_count": int(self.ack2_cover_count),
            "ack2_stale_count": int(self.ack2_stale_count),
            "ack2_malformed_count": int(self.ack2_malformed_count),
            "range_meta_sent_count": int(self.range_meta_sent_count),
            "range_meta_retx_count": int(self.range_meta_retx_count),
            "range_meta_ack_sent_count": int(self.range_meta_ack_sent_count),
            "range_meta_ack_recv_count": int(self.range_meta_ack_recv_count),
            "range_meta_failed_count": int(self.range_meta_failed_count),
            "range_meta_accepted_ooo": (None if self._range_meta_accepted_ooo is None else int(self._range_meta_accepted_ooo)),
            "path_challenge_sent_count": int(self.path_challenge_sent_count),
            "path_challenge_recv_count": int(self.path_challenge_recv_count),
            "path_response_sent_count": int(self.path_response_sent_count),
            "path_response_recv_count": int(self.path_response_recv_count),
            "path_response_valid_count": int(self.path_response_valid_count),
            "path_response_invalid_count": int(self.path_response_invalid_count),
            "path_migration_commit_count": int(self.path_migration_commit_count),
            "path_migration_validation_rtt_ms": self.path_migration_validation_rtt_ms,
            "complete_sent_count": int(self._complete_sent_count),
            "complete_recv_count": int(self.complete_recv_count),
            "complete_ack_sent_count": int(self._complete_ack_sent_count),
            "complete_ack_recv_count": int(self.complete_ack_recv_count),
            "crypto_auth_fail_count": int(crypto_stats.get("auth_fail", 0) or 0),
            "crypto_data_duplicate_old_count": int(crypto_stats.get("duplicate_old", 0) or 0),
            "crypto_data_too_far_right_drop_count": int(crypto_stats.get("too_far_right", 0) or 0),
            "dropped_data_seqs": list(self.dropped_data_seqs),
            "dropped_ctrl_ids": list(self.dropped_ctrl_ids),
        }

    def get_protocol_counters(self):
        with self.lock:
            return self._export_protocol_counters_locked()

    def get_experiment_snapshot(self):
        self._sync_cc_inflight_bytes()
        with self.lock:
            unacked_pkts = int(len(self.unacked))
            recovery_pacing_enabled = bool(self.recovery_pacing_enabled)
            total_app_bytes_sent = int(self._total_bytes_sent)
            total_app_bytes_acked = int(self._total_bytes_acked)
            total_wire_bytes_sent = int(self._total_wire_bytes_sent)
            total_wire_bytes_acked = int(self._total_wire_bytes_acked)
            counters = self._export_protocol_counters_locked()

        ack1_min_interval_s, ack1_rto_s, ack1_grace_period_s, ack1_srtt_s, ack1_rttvar_s = self._ack1_timing_params()

        cc_stats = {
            "cwnd": None,
            "bytes_in_flight": None,
            "ssthresh": None,
            "srtt": None,
            "rto": None,
        }
        try:
            with self._cc_lock:
                cc = self.cc
                if cc is not None:
                    getter = getattr(cc, "get_debug_stats", None)
                    if callable(getter):
                        snap = getter() or {}
                        cc_stats.update({
                            "cwnd": snap.get("cwnd"),
                            "bytes_in_flight": snap.get("bytes_in_flight"),
                            "ssthresh": snap.get("ssthresh"),
                            "srtt": snap.get("srtt"),
                            "rto": snap.get("rto"),
                        })
                    else:
                        cc_stats.update({
                            "cwnd": getattr(cc, "cwnd", None),
                            "bytes_in_flight": getattr(cc, "inflight_bytes", None),
                            "ssthresh": getattr(cc, "ssthresh", None),
                            "srtt": getattr(cc, "srtt", None),
                            "rto": getattr(cc, "rto", None),
                        })
        except Exception:
            pass

        with self._pacing_stats_lock:
            app_pacing_rate_bps = (
                None if self._app_last_pacing_bps is None else float(self._app_last_pacing_bps)
            )

        out = {
            "session_key_ready": int(bool(self.is_session_key_ready)),
            "handshake_completed_local": int(bool(self.handshake_completed_local)),
            "peer_confirmed_established": int(bool(self.peer_confirmed_established)),
            "fully_established": int(bool(self.handshake_completed_local and self.peer_confirmed_established)),
            "handshake_state": self.get_handshake_state(),
            "total_bytes_sent": total_app_bytes_sent,
            "total_bytes_acked": total_app_bytes_acked,
            "total_app_bytes_sent": total_app_bytes_sent,
            "total_app_bytes_acked": total_app_bytes_acked,
            "total_wire_bytes_sent": total_wire_bytes_sent,
            "total_wire_bytes_acked": total_wire_bytes_acked,
            "unacked_pkts": unacked_pkts,
            "app_pacing_enabled": bool(self.app_pacing_enabled),
            "app_pacing_rate_bps": app_pacing_rate_bps,
            "recovery_pacing_enabled": recovery_pacing_enabled,
            "ack1_min_interval_s": float(ack1_min_interval_s),
            "ack1_rto_s": float(ack1_rto_s),
            "ack1_grace_period_s": float(ack1_grace_period_s),
            "ack1_srtt_s": (None if ack1_srtt_s is None else float(ack1_srtt_s)),
            "ack1_rttvar_s": (None if ack1_rttvar_s is None else float(ack1_rttvar_s)),
        }
        try:
            rp = getattr(self.crypto, "replay_protector", None)
            replay_window_pkts = int(getattr(rp, "window_size", 0) or 0) if rp is not None else 0
            replay_auto_expand_margin_pkts = int(getattr(rp, "auto_expand_margin", 0) or 0) if rp is not None else 0
        except Exception:
            replay_window_pkts = 0
            replay_auto_expand_margin_pkts = 0

        with self.lock:
            adaptive_ooo_window_pkts = int(getattr(self, "_adaptive_ooo_window_pkts", 0) or 0)
            adaptive_last_gap_depth = int(getattr(self, "_adaptive_last_gap_depth", 0) or 0)
            adaptive_gap_depth_ewma = float(getattr(self, "_adaptive_gap_depth_ewma", 0.0) or 0.0)
            adaptive_gap_depth_max = int(getattr(self, "_adaptive_gap_depth_max", 0) or 0)
            adaptive_peer_desired_ooo = getattr(self, "_adaptive_peer_desired_ooo", None)
            adaptive_peer_accepted_ooo = getattr(self, "_adaptive_peer_accepted_ooo", None)

        with self.lock:
            late_cleartext_retransmit_count = int(getattr(self, "_late_cleartext_retransmit_count", 0) or 0)
            unexpected_cleartext_handshake_count = int(getattr(self, "_unexpected_cleartext_handshake_count", 0) or 0)

        out.update(counters)
        out.update(cc_stats)
        with self.lock:
            complete_received = int(bool(self._complete_received_event.is_set()))
            complete_ack_received = int(bool(self._complete_ack_received_event.is_set()))
            complete_sent = int(bool(self._complete_sent_payload))
            complete_info = dict(self._complete_received_info) if isinstance(self._complete_received_info, dict) else None

        out.update({
            "late_cleartext_retransmit_count": late_cleartext_retransmit_count,
            "unexpected_cleartext_handshake_count": unexpected_cleartext_handshake_count,
            "adaptive_ooo_window_pkts": adaptive_ooo_window_pkts,
            "adaptive_last_gap_depth": adaptive_last_gap_depth,
            "adaptive_gap_depth_ewma": adaptive_gap_depth_ewma,
            "adaptive_gap_depth_max": adaptive_gap_depth_max,
            "adaptive_peer_desired_ooo": adaptive_peer_desired_ooo,
            "adaptive_peer_accepted_ooo": adaptive_peer_accepted_ooo,
            "replay_window_pkts": replay_window_pkts,
            "replay_auto_expand_margin_pkts": replay_auto_expand_margin_pkts,
            "fast_retx_gap_threshold_pkts": self._fast_retx_gap_threshold(),
            "fast_retx_missing_reports_required": self._fast_retx_missing_reports_required(),
            "complete_sent": complete_sent,
            "complete_received": complete_received,
            "complete_ack_received": complete_ack_received,
            "complete_info": complete_info,
        })
        return out

    def _estimate_bdp_packets(self) -> int:
        floor = max(1, int(getattr(self, "_adaptive_ooo_window_floor_pkts", 8) or 8))
        candidates = [floor]

        with self.lock:
            cap = int(getattr(self, "send_max_unacked_pkts", 0) or 0)
            if cap > 0:
                candidates.append(cap)
            outstanding = int(len(self.unacked))
            if outstanding > 0:
                candidates.append(outstanding)
            peer_acc = int(getattr(self, "_adaptive_peer_accepted_ooo", 0) or 0)
            if peer_acc > 0:
                candidates.append(peer_acc)
            cur_ooo = int(getattr(self, "_adaptive_ooo_window_pkts", 0) or 0)
            if cur_ooo > 0:
                candidates.append(cur_ooo)

        cwnd = None
        inflight = None
        try:
            with self._cc_lock:
                cc = self.cc
                if cc is not None:
                    cwnd = getattr(cc, "cwnd", None)
                    inflight = getattr(cc, "inflight_bytes", None)
        except Exception:
            cwnd = None
            inflight = None

        for value in (cwnd, inflight):
            try:
                if value is None:
                    continue
                pkts = int(math.ceil(float(value) / max(float(MSS), 1.0)))
                if pkts > 0:
                    candidates.append(pkts)
            except Exception:
                continue

        return max(candidates) if candidates else floor

    def _observe_gap_depth_locked(self, gap_depth: int) -> None:
        gap_depth = max(0, int(gap_depth or 0))
        self._adaptive_last_gap_depth = gap_depth
        if gap_depth <= 0:
            if float(getattr(self, "_adaptive_gap_depth_ewma", 0.0) or 0.0) > 0.0:
                self._adaptive_gap_depth_ewma = 0.98 * float(self._adaptive_gap_depth_ewma)
            return
        self._adaptive_gap_depth_max = max(int(getattr(self, "_adaptive_gap_depth_max", 0) or 0), gap_depth)
        ewma = float(getattr(self, "_adaptive_gap_depth_ewma", 0.0) or 0.0)
        if ewma <= 0.0:
            self._adaptive_gap_depth_ewma = float(gap_depth)
        else:
            self._adaptive_gap_depth_ewma = 0.875 * ewma + 0.125 * float(gap_depth)

    def _compute_adaptive_ooo_window_locked(self, desired_ooo=None) -> int:
        floor = max(1, int(getattr(self, "_adaptive_ooo_window_floor_pkts", 8) or 8))
        cap = max(floor, int(getattr(self, "_adaptive_ooo_window_cap_pkts", 65535) or 65535))
        bdp_gain = max(1.0, float(getattr(self, "_adaptive_ooo_bdp_gain", 1.25) or 1.25))
        gap_gain = max(1.0, float(getattr(self, "_adaptive_ooo_gap_gain", 1.5) or 1.5))

        desired = 0
        if desired_ooo is not None:
            try:
                desired = max(0, int(desired_ooo))
            except Exception:
                desired = 0
        if desired > 0:
            self._adaptive_peer_desired_ooo = desired
        else:
            try:
                desired = max(0, int(getattr(self, "_adaptive_peer_desired_ooo", 0) or 0))
            except Exception:
                desired = 0

        peer_acc = max(0, int(getattr(self, "_adaptive_peer_accepted_ooo", 0) or 0))
        gap_ref = max(
            int(getattr(self, "_adaptive_last_gap_depth", 0) or 0),
            int(math.ceil(float(getattr(self, "_adaptive_gap_depth_ewma", 0.0) or 0.0))),
        )
        bdp_pkts = max(1, int(self._estimate_bdp_packets()))
        bdp_term = int(math.ceil(bdp_gain * float(bdp_pkts)))
        gap_term = int(math.ceil(gap_gain * float(gap_ref))) if gap_ref > 0 else 0

        ooo = max(floor, bdp_term, gap_term, desired, peer_acc)
        return min(cap, int(ooo))

    def _sync_adaptive_reorder(self, desired_ooo=None, reason: str = ""):
        with self.lock:
            rp = getattr(self.crypto, "replay_protector", None)
            before_ooo = int(getattr(self, "_adaptive_ooo_window_pkts", 0) or 0)
            before_window = int(getattr(rp, "window_size", 0) or 0) if rp is not None else 0
            before_margin = int(getattr(rp, "auto_expand_margin", 0) or 0) if rp is not None else 0

            ooo = self._compute_adaptive_ooo_window_locked(desired_ooo=desired_ooo)
            self._adaptive_ooo_window_pkts = int(ooo)

            replay_window = int(ooo) + max(2, int(getattr(self, "_adaptive_replay_extra_pkts", 4) or 4))
            replay_margin = max(
                int(getattr(self, "_adaptive_replay_margin_floor_pkts", 8) or 8),
                int(math.ceil(float(getattr(self, "_adaptive_replay_margin_mult", 1.0) or 1.0) * float(max(1, ooo)))),
            )

            after_window = before_window
            after_margin = before_margin
            if rp is not None:
                target_window = max(before_window, replay_window)
                rp.set_window_size(target_window)
                after_window = int(getattr(rp, "window_size", target_window) or target_window)
                if hasattr(rp, "set_auto_expand_margin"):
                    target_margin = max(before_margin, replay_margin)
                    rp.set_auto_expand_margin(target_margin)
                    after_margin = int(getattr(rp, "auto_expand_margin", target_margin) or target_margin)

        changed = (int(before_ooo) != int(ooo)) or (int(before_window) != int(after_window)) or (int(before_margin) != int(after_margin))
        if changed and reason:
            try:
                self.logger.info(
                    f"Adaptive reorder tune({reason}): ooo_window={ooo}, replay_window={after_window}, replay_margin={after_margin}, "
                    f"gap_last={getattr(self, '_adaptive_last_gap_depth', 0)}, gap_ewma={float(getattr(self, '_adaptive_gap_depth_ewma', 0.0) or 0.0):.2f}, "
                    f"bdp_est_pkts={self._estimate_bdp_packets()}"
                )
            except Exception:
                pass
        return int(ooo), int(after_window), int(after_margin)

    def _fast_retx_gap_threshold(self) -> int:
        with self.lock:
            gap_ref = max(
                int(getattr(self, "_adaptive_last_gap_depth", 0) or 0),
                int(math.ceil(float(getattr(self, "_adaptive_gap_depth_ewma", 0.0) or 0.0))),
            )
            ooo = int(getattr(self, "_adaptive_ooo_window_pkts", 0) or 0)

        # 让阈值随着观测乱序与 BDP 轻度上升，但不会无限放大。
        bdp_component = int(math.ceil(max(0.0, min(float(ooo), 32.0)) * 0.25))
        threshold = max(3, gap_ref, bdp_component)
        return int(min(64, threshold))

    def _fast_retx_missing_reports_required(self) -> int:
        """Return how many consecutive ACK1 missing reports are required before fast retransmit.

        Base policy is 2 consecutive reports. Under heavier observed reordering / larger BDP
        the requirement rises conservatively so a single transient gap does not immediately
        trigger recovery traffic and squeeze fresh-data sending.
        """
        base = max(2, int(getattr(self, "_fr_missing_reports_required_base", 2) or 2))
        cap = max(base, int(getattr(self, "_fr_missing_reports_required_cap", base) or base))

        fr_gap_threshold = int(self._fast_retx_gap_threshold())
        with self.lock:
            ooo = int(getattr(self, "_adaptive_ooo_window_pkts", 0) or 0)

        required = base
        if fr_gap_threshold >= 6 or ooo >= 24:
            required += 1
        if fr_gap_threshold >= 12 or ooo >= 64:
            required += 1
        return int(min(cap, required))

    def _update_fast_retx_missing_report_streaks(self, reported_missing_seqs):
        """Track consecutive ACK1 reports for explicit missing candidates.

        Only sequences that continue to appear in successive ACK1 reports keep their streak.
        Once a sequence disappears from the current missing view, its streak is dropped so a
        future appearance must mature again from 1. This makes fast retransmit more resistant
        to transient late-packet reordering.
        """
        current = set()
        for seq in list(reported_missing_seqs or []):
            try:
                seq = int(seq)
            except Exception:
                continue
            if seq > 0:
                current.add(seq)

        with self.lock:
            prev = dict(getattr(self, "_fr_missing_report_streak", {}) or {})
            active_unacked = set(int(x) for x in self.unacked.keys())
            next_state = {}
            for seq in current:
                if seq not in active_unacked:
                    continue
                next_state[int(seq)] = int(prev.get(int(seq), 0)) + 1
            self._fr_missing_report_streak = next_state
            return dict(next_state)

    def _snapshot_true_inflight_bytes(self) -> int:
        with self.lock:
            total = 0
            for meta in self.unacked.values():
                try:
                    total += int(meta.get("wire_size", len(meta.get("enc_data", b""))))
                except Exception:
                    continue
            return int(total)

    def _sync_cc_inflight_bytes(self) -> int:
        inflight = self._snapshot_true_inflight_bytes()

        with self._cc_lock:
            cc = self.cc
            if cc is None:
                return int(inflight)

            syncer = getattr(cc, "sync_inflight_bytes", None)
            if callable(syncer):
                syncer(int(inflight))
            else:
                cc_lock = getattr(cc, "_lock", None)
                if cc_lock is not None:
                    with cc_lock:
                        cc.inflight_bytes = max(0, int(inflight))
                else:
                    cc.inflight_bytes = max(0, int(inflight))
        return int(inflight)

    def can_send(self, packet_size: int) -> bool:
        """Unified gating for the application send path.

        Applies:
        - hard outstanding cap (send_max_unacked_pkts) if configured
        - congestion control (cc) if enabled
        """
        with self.lock:
            cap = int(getattr(self, "send_max_unacked_pkts", 0) or 0)
            if cap > 0 and len(self.unacked) >= cap:
                return False
        self._sync_cc_inflight_bytes()
        return self.cc_can_send(int(packet_size))

    def _app_pacing_params(self):
        with self._cc_lock:
            cc = self.cc
            if cc is None:
                return None

            rate_getter = getattr(cc, "get_pacing_rate_bytes_per_s", None)
            if callable(rate_getter):
                try:
                    byte_rate = float(rate_getter(
                        gain=float(self._app_pacing_gain),
                        min_rtt=float(self._app_pacing_min_rtt),
                        fallback_rtt=float(self._app_pacing_fallback_rtt),
                        min_rate=float(self._app_pacing_min_bps),
                    ))
                except Exception:
                    byte_rate = None
            else:
                srtt = getattr(cc, "srtt", None)
                last_rtt = getattr(cc, "last_rtt_sample", None)
                min_rtt = getattr(cc, "min_rtt", None)
                cwnd = getattr(cc, "cwnd", None)
                try:
                    ref_rtt = float(srtt or last_rtt or min_rtt or self._app_pacing_fallback_rtt)
                    ref_rtt = max(float(self._app_pacing_min_rtt), ref_rtt)
                    cwnd = max(float(MSS), float(cwnd or 0.0))
                    byte_rate = max(float(self._app_pacing_min_bps), float(self._app_pacing_gain) * cwnd / ref_rtt)
                except Exception:
                    byte_rate = None

        if byte_rate is None or byte_rate <= 0.0:
            return None

        pkt_rate = max(float(self._app_pacing_min_pps), byte_rate / max(float(MSS), 1.0))
        byte_burst = max(float(self._app_pacing_burst_bytes), float(self._app_pacing_burst_pkts) * float(MSS))
        pkt_burst = max(1.0, float(self._app_pacing_burst_pkts))
        with self._pacing_stats_lock:
            self._app_last_pacing_bps = float(byte_rate)
        return float(byte_rate), byte_burst, pkt_rate, pkt_burst

    def wait_for_data_send(self, packet_size: int) -> None:
        packet_size = max(0, int(packet_size or 0))
        while self.running:
            if self.has_fatal_error():
                raise RuntimeError(self.get_fatal_error() or "fatal protocol error")

            while self.running and (not self.can_send(packet_size)):
                if self.has_fatal_error():
                    raise RuntimeError(self.get_fatal_error() or "fatal protocol error")
                time.sleep(0.001)

            if (not self.running):
                break

            if self.app_pacing_enabled:
                params = self._app_pacing_params()
                if params is not None:
                    byte_rate, byte_burst, pkt_rate, pkt_burst = params
                    self._app_send_pacer.wait(packet_size, byte_rate, byte_burst, pkt_rate, pkt_burst)
                    # While waiting for pacing tokens, retransmissions or loss events may have
                    # changed inflight/cwnd. Re-check the window gate before returning.
                    if not self.can_send(packet_size):
                        continue

            return

        raise RuntimeError("session stopped")

    def send_app_data(self, seq: int, payload: bytes):
        app_payload = bytes(payload or b"")
        expected_wire_size = int(self.data_packet_wire_size(len(app_payload)))
        self.wait_for_data_send(expected_wire_size)
        sent_wire_size = int(self.send_precise(int(seq), app_payload))
        self.cc_on_packet_sent(sent_wire_size)

    # ---------------- Congestion-control wrappers (thread-safe) ----------------
    def cc_can_send(self, packet_size: int) -> bool:
        self._sync_cc_inflight_bytes()
        with self._cc_lock:
            if self.cc is None:
                return True
            return bool(self.cc.can_send(int(packet_size)))

    def cc_on_packet_sent(self, size: int) -> None:
        with self._cc_lock:
            if self.cc is None:
                return
            self.cc.on_packet_sent(int(size))
        self._sync_cc_inflight_bytes()

    def cc_on_ack_received(self, rtt_sample=None, bytes_acked=None) -> None:
        with self._cc_lock:
            if self.cc is None:
                return
            self.cc.on_ack_received(rtt_sample=rtt_sample, bytes_acked=bytes_acked)
        self._sync_cc_inflight_bytes()

    def cc_on_packet_lost(self) -> None:
        with self._cc_lock:
            if self.cc is None:
                return
            self.cc.on_packet_lost()
        self._sync_cc_inflight_bytes()

    def has_fatal_error(self) -> bool:
        return self._fatal_error_event.is_set()

    def get_fatal_error(self):
        with self.lock:
            return self.fatal_error_reason

    def get_last_error(self):
        with self.lock:
            return self.last_error_reason

    def abort(self, reason: str):
        self._set_error(str(reason), fatal=True)

    def wait_for_complete(self, timeout=None) -> bool:
        return bool(self._wait_event_or_terminal(self._complete_received_event, timeout=timeout))

    def wait_for_complete_raw(self, timeout=None) -> bool:
        return bool(self._wait_event_or_terminal(self._complete_raw_received_event, timeout=timeout))

    def wait_for_complete_ack(self, timeout=None) -> bool:
        return bool(self._wait_event_or_terminal(self._complete_ack_received_event, timeout=timeout))

    def get_received_complete_info(self):
        with self.lock:
            info = self._complete_received_info
            if not isinstance(info, dict):
                return None
            return dict(info)

    def get_received_complete_raw_info(self):
        with self.lock:
            info = self._complete_raw_received_info
            if not isinstance(info, dict):
                return None
            return dict(info)

    def get_complete_validation_error(self):
        with self.lock:
            detail = self._complete_validation_error
            if isinstance(detail, dict):
                return dict(detail)
            return detail

    def set_complete_expectations(self, final_seq: int, total_bytes: int):
        with self.lock:
            self._complete_expected_final_seq = int(final_seq)
            self._complete_expected_total_bytes = int(total_bytes)

    def _set_complete_commit_state(self, status: str, detail=None):
        with self.lock:
            self._complete_commit_status = str(status)
            self._complete_commit_detail = detail

    def get_complete_commit_state(self):
        with self.lock:
            return {
                "status": str(self._complete_commit_status),
                "detail": self._complete_commit_detail,
            }

    def get_last_complete_commit_status(self):
        with self.lock:
            return str(self._complete_commit_status)

    def _set_error(self, reason: str, fatal: bool = True):
        """Record an error; if fatal, terminate this session locally and optionally notify peer via RST."""
        reason = str(reason)
        send_rst = False
        first_fatal = False
        with self.lock:
            self.last_error_reason = reason
            if fatal and (not self._fatal_error):
                self._fatal_error = True
                self.fatal_error_reason = reason
                self._fatal_error_event.set()
                send_rst = True
                first_fatal = True

        if fatal:
            with self._hs_lock:
                self._hs_state = "failed"
                self._hs_next_deadline = None
                self._hs_tail_deadline = None
            self._hs_event.set()

        # Best-effort peer notification before flipping the local session into terminated state.
        if send_rst and (not self._rst_sent):
            self._rst_sent = True
            try:
                payload = reason.encode("utf-8", errors="ignore")[:200]
            except Exception:
                payload = b"fatal"
            try:
                self._send_ctrl(FLAG_RST, payload)
            except Exception:
                pass

        if fatal:
            self.running = False
            self.close_app_stream()
            try:
                self._recovery_send_event.set()
            except Exception:
                pass
            try:
                with self._ordered_ready_cv:
                    self._ordered_ready_closed = True
                    self._ordered_ready_cv.notify_all()
            except Exception:
                pass
            try:
                with self._app_queue_cv:
                    self._app_queue_cv.notify_all()
            except Exception:
                pass

    # ---------------- 接收端 API（与 server 对齐） ----------------
    def recv(self, timeout=None):
        return self.get_app_item(timeout=timeout)

    # ---------------- receiver thread（client 侧使用） ----------------
    def _receiver_thread(self):
        # NOTE: Do not silently die on transient recvfrom() errors.
        # Only exit on expected close errors (e.g., socket closed while self.running is False).
        while self.running:
            try:
                data, addr = self._sock_recvfrom(65535)
                self.handle_packet(data, addr)
            except OSError:
                # Expected shutdown path: socket closed after stop().
                if not self.running:
                    break
                self.logger.exception("receiver_thread recvfrom() OSError")
                time.sleep(0.05)
                continue
            except Exception:
                self.logger.exception("receiver_thread unexpected exception")
                time.sleep(0.05)
                continue

    # ---------------- RANGE 宣告 ----------------
    def send_range_announce(self, start_seq: int, end_seq: int, ooo_window: int = None):
        """Announce the DATA seq range and an adaptive out-of-order budget.

        Payload format (backward compatible):
          - base: mtype(1) + start(8) + end(8)
          - optional: + ooo_window(4)  (sender-side adaptive reorder budget in packets)
        """

        with self.lock:
            self.range_start = int(start_seq)
            self.range_end = int(end_seq)

        if ooo_window is None:
            ooo_window, _rpw, _rpm = self._sync_adaptive_reorder(reason="range_announce")

        payload = bytearray()
        payload.append(META_TYPE_RANGE)
        payload.extend(int(start_seq).to_bytes(8, "big"))
        payload.extend(int(end_seq).to_bytes(8, "big"))
        if ooo_window is not None:
            try:
                ow = max(0, int(ooo_window))
            except Exception:
                ow = 0
            # uint32 is enough for typical bounded shuffle windows
            payload.extend(int(ow & 0xFFFFFFFF).to_bytes(4, "big"))

        # 关键：RANGE META 做成可靠控制消息，直到收到 META|ACK 才停止重传
        self._range_meta_acked.clear()
        self._range_meta_accepted_ooo = None
        meta_id = self._send_ctrl(FLAG_META, bytes(payload), track=True, mtype=META_TYPE_RANGE)

        with self.lock:
            self._range_meta_id = meta_id
        return meta_id

    def wait_range_announce_ack(self, timeout=None) -> bool:
        """可选：client 侧在 burst 乱序发送前等待 RANGE 已被对端采纳。"""
        return self._range_meta_acked.wait(timeout=timeout)

    def get_range_accepted_ooo(self):
        """If peer included an accepted out-of-order window in META|ACK, return it (int) else None."""
        return self._range_meta_accepted_ooo

    def _handle_meta(self, pkt: Packet, addr=None):
        if len(pkt.payload) < 1:
            return False
        mtype = pkt.payload[0]

        if self.is_client and mtype == META_TYPE_HANDSHAKE_CONFIRM:
            if len(pkt.payload) != 1 + KX_FINISHED_LEN:
                return False

            token = bytes(pkt.payload[1:])
            if (self._finished_token is None) or (token != bytes(self._finished_token)):
                self.logger.warning(
                    f"Ignoring HANDSHAKE_CONFIRM with invalid finished token for session {self.conn_id}"
                )
                return False

            if addr is not None:
                with self.lock:
                    self.peer_addr = addr
                    self.addr = addr

            self._mark_peer_confirmed_established(
                f"Peer confirmed established via HANDSHAKE_CONFIRM for session {self.conn_id}"
            )
            return True

        if mtype == META_TYPE_PATH_CHALLENGE and len(pkt.payload) >= 1 + PATH_CHALLENGE_LEN:
            token = bytes(pkt.payload[1:1 + PATH_CHALLENGE_LEN])
            with self.lock:
                self.path_challenge_recv_count += 1
            if addr is None:
                return False
            self._send_path_response(addr, token)
            try:
                self.logger.info(f"PATH_RESPONSE sent to {addr} for session {self.conn_id}")
            except Exception:
                pass
            return True

        if mtype == META_TYPE_PATH_RESPONSE and len(pkt.payload) >= 1 + PATH_CHALLENGE_LEN:
            with self.lock:
                self.path_response_recv_count += 1
            if addr is None:
                with self.lock:
                    self.path_response_invalid_count += 1
                return False
            token = bytes(pkt.payload[1:1 + PATH_CHALLENGE_LEN])
            addr_key = self._addr_key(addr)
            with self.lock:
                pending = self._path_validation.get(addr_key)
            if not pending:
                with self.lock:
                    self.path_response_invalid_count += 1
                return False
            expected = bytes(pending.get("token", b""))
            if expected != token:
                with self.lock:
                    self.path_response_invalid_count += 1
                self.logger.warning(f"Ignoring PATH_RESPONSE with mismatched token from {addr}")
                return False
            sent_ts = float(pending.get("sent_ts", 0.0) or 0.0)
            rtt_sample = None
            if sent_ts > 0.0:
                rtt_sample = max(0.0, time.time() - sent_ts)
            with self.lock:
                self.path_response_valid_count += 1
            self._promote_validated_path(addr, validation_rtt=rtt_sample)
            return True

        if mtype == META_TYPE_RANGE and len(pkt.payload) >= 1 + 8 + 8:
            self.range_start = int.from_bytes(pkt.payload[1:9], "big")
            self.range_end = int.from_bytes(pkt.payload[9:17], "big")

            total = (self.range_end - self.range_start + 1)

            # Optional bounded out-of-order window from sender.
            desired_ooo = None
            if len(pkt.payload) >= 1 + 8 + 8 + 4:
                desired_ooo = int.from_bytes(pkt.payload[17:21], "big")

            try:
                rp = getattr(self.crypto, "replay_protector", None)
                current = int(getattr(rp, "window_size", 0) or 0) if rp is not None else 0
                rp_max = getattr(rp, "max_window_size", "n/a") if rp is not None else "n/a"
            except Exception:
                current = 0
                rp_max = "n/a"

            accepted_ooo, rp_after, rp_margin = self._sync_adaptive_reorder(
                desired_ooo=desired_ooo,
                reason="range_meta",
            )

            self.logger.info(
                f"RANGE OOO negotiate: desired_ooo={desired_ooo}, total={total}, "
                f"rp.window(before)={current}, rp.max={rp_max}, accepted_ooo={accepted_ooo}, "
                f"rp.window(after)={rp_after}, rp.margin(after)={rp_margin}"
            )

            self.logger.info(f"Got RANGE: {self.range_start}..{self.range_end}")

            self._send_ctrl(FLAG_META | FLAG_ACK, self._build_range_meta_ack_payload(int(pkt.pkt_num)))

            try:
                self._send_ack1(force=True)
            except Exception:
                pass
            return True

        return False

    def _handle_meta_ack(self, pkt: Packet):
        """
        META|ACK payload:
          - RANGE: mtype(1) + acked_ctrl_pkt_num(8) + accepted_ooo(4)
        """
        if len(pkt.payload) < 9:
            self.logger.warning(f"Malformed META|ACK rejected: len={len(pkt.payload)}")
            return False

        mtype = pkt.payload[0]
        acked_id = int.from_bytes(pkt.payload[1:9], "big")
        accepted_ooo = None

        if mtype == META_TYPE_RANGE:
            if len(pkt.payload) != 13:
                self.logger.warning(f"Malformed RANGE META|ACK rejected: len={len(pkt.payload)}")
                return False
            accepted_ooo = int.from_bytes(pkt.payload[9:13], "big")
            with self.lock:
                self.range_meta_ack_recv_count += 1
        elif mtype == META_TYPE_PATH_CHALLENGE:
            if len(pkt.payload) != 9:
                self.logger.warning(f"Malformed TICKET META|ACK rejected: len={len(pkt.payload)}")
                return False
        else:
            self.logger.warning(f"Unsupported META|ACK mtype rejected: {mtype}")
            return False

        removed = False
        with self.lock:
            if acked_id in self.ctrl_unacked:
                self.ctrl_unacked.pop(acked_id, None)
                removed = True
            if removed and mtype == META_TYPE_RANGE and acked_id == self._range_meta_id:
                self._range_meta_accepted_ooo = int(accepted_ooo)
                self._adaptive_peer_accepted_ooo = int(accepted_ooo)
                self._range_meta_acked.set()

        if removed and mtype == META_TYPE_RANGE and accepted_ooo is not None:
            self._sync_adaptive_reorder(desired_ooo=accepted_ooo, reason="range_ack")

        if removed:
            self.logger.info(f"META ACKED: mtype={mtype}, id={acked_id}")
            return True
        return False

    # ---------------- Range 工具 ----------------
    @staticmethod
    def _merge_ranges(ranges):
        if not ranges:
            return []
        ranges = sorted(ranges)
        out = [ranges[0]]
        for s, e in ranges[1:]:
            ps, pe = out[-1]
            if s <= pe + 1:
                out[-1] = (ps, max(pe, e))
            else:
                out.append((s, e))
        return out

    @staticmethod
    def _ranges_subtract(a, b):
        """返回 a \\ b，a,b 都是已合并的闭区间列表"""
        if not a:
            return []
        if not b:
            return a[:]
        out = []
        j = 0
        for s, e in a:
            cur_s, cur_e = s, e
            while j < len(b) and b[j][1] < cur_s:
                j += 1
            k = j
            while k < len(b) and b[k][0] <= cur_e:
                bs, be = b[k]
                if bs > cur_s:
                    out.append((cur_s, min(cur_e, bs - 1)))
                cur_s = max(cur_s, be + 1)
                if cur_s > cur_e:
                    break
                k += 1
            if cur_s <= cur_e:
                out.append((cur_s, cur_e))
        return out

    def _complement_missing_from_start(self, max_ranges=32):
        if self.range_start is None or self.range_end is None:
            return []
        rs, re = self.range_start, self.range_end
        recv = self._merge_ranges(self.recv_ranges)

        missing = []
        cur = rs
        for s, e in recv:
            if e < rs:
                continue
            if s > re:
                break
            s = max(s, rs)
            e = min(e, re)
            if cur < s:
                missing.append((cur, s - 1))
                if len(missing) >= max_ranges:
                    return missing
            cur = max(cur, e + 1)
            if cur > re:
                break
        if cur <= re and len(missing) < max_ranges:
            missing.append((cur, re))
        return missing[:max_ranges]

    def _seq_in_ranges(self, seq: int, ranges) -> bool:
        for s, e in ranges:
            if seq < s:
                return False
            if s <= seq <= e:
                return True
        return False

    # ---------------- recv_ranges 维护 ----------------
    def _insert_range(self, seq: int):
        # 简单实现：append 后 merge（吞吐较大时可做增量插入）
        self.recv_ranges.append((seq, seq))
        self.recv_ranges = self._merge_ranges(self.recv_ranges)

    def _mono_now_us(self) -> int:
        try:
            return int(time.monotonic_ns() // 1000)
        except Exception:
            return int(time.monotonic() * 1_000_000.0)

    def _build_data_wire_payload(self, app_payload: bytes, tx_ts_us: int = None) -> bytes:
        payload = bytes(app_payload or b"")
        if tx_ts_us is None:
            tx_ts_us = self._mono_now_us()
        tx_ts_us = max(0, int(tx_ts_us))
        return DATA_FRAME_TAG + tx_ts_us.to_bytes(8, "big") + payload

    def _parse_data_wire_payload(self, payload: bytes):
        if not isinstance(payload, (bytes, bytearray)):
            return None, None
        payload = bytes(payload)
        if len(payload) < DATA_FRAME_HEADER_LEN:
            return None, None
        if payload[:2] != DATA_FRAME_TAG:
            return None, None
        tx_ts_us = int.from_bytes(payload[2:10], "big")
        return payload[10:], tx_ts_us

    def _extract_ack_payload_log_fields(self, payload: bytes):
        parsed = self._parse_ack_state_payload(payload)
        if parsed is None:
            return None, None, None
        return int(parsed["ack_base"]), int(parsed["seen_max"]), len(parsed.get("missing", []))

    def _ack1_timing_params(self):
        """Return effective ACK1 timing derived from RTT state when available.

        Policy:
        - ack1_min_interval tracks a fraction of SRTT so low-RTT paths are not over-throttled.
        - ack1_rto follows RTT variation, preferring the CC estimator when available.
        - ack1_grace_period scales with ACK1 RTO so tail convergence remains tolerant under jitter.

        Returned tuple:
            (ack1_min_interval_s, ack1_rto_s, ack1_grace_period_s, srtt_s, rttvar_s)
        """
        srtt = None
        rttvar = None
        cc_rto = None
        try:
            with self._cc_lock:
                cc = self.cc
                if cc is not None:
                    srtt = getattr(cc, "srtt", None)
                    rttvar = getattr(cc, "rttvar", None)
                    cc_rto = getattr(cc, "rto", None)
        except Exception:
            srtt = None
            rttvar = None
            cc_rto = None

        try:
            srtt = float(srtt) if srtt is not None else None
        except Exception:
            srtt = None
        try:
            rttvar = float(rttvar) if rttvar is not None else None
        except Exception:
            rttvar = None
        try:
            cc_rto = float(cc_rto) if cc_rto is not None else None
        except Exception:
            cc_rto = None

        if srtt is None or srtt <= 0.0:
            min_interval = max(0.0, float(getattr(self, "ack1_min_interval", 0.01) or 0.01))
            rto = max(0.0, float(getattr(self, "ack1_rto", 0.2) or 0.2))
            grace = max(0.0, float(getattr(self, "ack1_grace_period", 1.0) or 1.0))
            return float(min_interval), float(rto), float(grace), None, None

        min_interval = float(self._ack1_min_interval_gain) * float(srtt)
        min_interval = max(float(self._ack1_min_interval_floor), min_interval)
        min_interval = min(float(self._ack1_min_interval_cap), min_interval)

        if cc_rto is not None and cc_rto > 0.0:
            rto = cc_rto
        else:
            eff_rttvar = float(rttvar) if (rttvar is not None and rttvar >= 0.0) else (0.5 * float(srtt))
            rto = float(srtt) + max(0.010, 4.0 * eff_rttvar)
        rto = max(float(self._ack1_rto_floor), rto)
        rto = min(float(self._ack1_rto_cap), rto)

        grace = float(self._ack1_grace_period_mult) * float(rto)
        grace = max(float(self._ack1_grace_period_floor), grace)
        grace = min(float(self._ack1_grace_period_cap), grace)
        return float(min_interval), float(rto), float(grace), float(srtt), (None if rttvar is None else float(rttvar))

    def _ack1_resender_sleep_interval(self) -> float:
        min_interval, rto, _grace, _srtt, _rttvar = self._ack1_timing_params()
        ref = min(min_interval, rto, float(self._ack1_resender_sleep_cap))
        ref = max(float(self._ack1_resender_sleep_floor), 0.5 * float(ref))
        ref = min(float(self._ack1_resender_sleep_cap), ref)
        return float(ref)

    # ---------------- ACK1 构造/发送/重发 ----------------
    
    def _build_ack1_payload(self):
        """Build ACK state payload.

        ACK v2 format:
            ver(1=2) | ack_base(8) | seen_max(8) | rtt_ref_seq(8) | ts_echo_us(8) | ack_delay_us(4) |
            missing_count(1) | missing_ranges...

        where missing_ranges are inclusive [start,end] within [ack_base, seen_max].

        RTT fields semantics:
        - rtt_ref_seq: a packet seq that is acknowledged by this ACK state and chosen as the RTT reference
        - ts_echo_us: the sender-origin transmit timestamp carried in that DATA packet and echoed back verbatim
        - ack_delay_us: receiver-side delay from that packet's arrival to ACK generation

        Safety invariant:
            The (seen_max, missing_ranges) pair fully describes the receiver state within [ack_base, seen_max].
            The sender must NOT infer anything about seq > seen_max.
        """
        MAX_MISSING = 255  # uint8 on-wire; 256 会溢出，所以这里取 255
        ack_base = int(self.next_seq_expected)

        recv_merged = self._merge_ranges(self.recv_ranges)
        seen_max_full = 0
        for _s, e in recv_merged:
            try:
                e = int(e)
            except Exception:
                continue
            if e > seen_max_full:
                seen_max_full = e

        # No out-of-order info yet: only cumulative ACK.
        if seen_max_full < ack_base:
            seen_max = ack_base - 1
            missing = []
        else:
            missing_full = self._ranges_subtract([(ack_base, seen_max_full)], recv_merged)
            missing_full = self._merge_ranges(missing_full)

            # If too many gaps, shrink the report window so missing_ranges is complete (no truncation semantics).
            if len(missing_full) > MAX_MISSING:
                seen_max = int(missing_full[MAX_MISSING - 1][1])
            else:
                seen_max = int(seen_max_full)

            if seen_max < ack_base:
                seen_max = ack_base - 1
                missing = []
            else:
                missing = self._ranges_subtract([(ack_base, seen_max)], recv_merged)
                missing = self._merge_ranges(missing)

        ref_seq = int(getattr(self, "_ack1_rtt_ref_seq", 0) or 0)
        ts_echo_us = int(getattr(self, "_ack1_rtt_ref_tx_ts_us", 0) or 0)
        ref_recv_us = int(getattr(self, "_ack1_rtt_ref_recv_mono_us", 0) or 0)
        if ref_seq <= 0 or ts_echo_us <= 0 or ref_recv_us <= 0:
            ref_seq = 0
            ts_echo_us = 0
            ack_delay_us = 0
        else:
            ack_delay_us = max(0, self._mono_now_us() - ref_recv_us)
            ack_delay_us = min(int(ACK_DELAY_US_MAX), int(ack_delay_us))

        payload = bytearray()
        payload.append(ACK_STATE_V2)
        payload.extend(int(ack_base).to_bytes(8, "big"))
        payload.extend(int(seen_max).to_bytes(8, "big"))
        payload.extend(int(ref_seq).to_bytes(8, "big"))
        payload.extend(int(ts_echo_us).to_bytes(8, "big"))
        payload.extend(int(ack_delay_us).to_bytes(4, "big"))
        payload.append(len(missing))
        for s, e in missing:
            payload.extend(int(s).to_bytes(8, "big"))
            payload.extend(int(e).to_bytes(8, "big"))
        return bytes(payload)

    def _parse_ack_state_payload(self, payload: bytes):
        if not isinstance(payload, (bytes, bytearray)):
            return None
        payload = bytes(payload)
        if len(payload) < 18:
            return None

        ver = int(payload[0])
        if ver == ACK_STATE_V1:
            ack_base = int.from_bytes(payload[1:9], "big")
            seen_max = int.from_bytes(payload[9:17], "big")
            count = int(payload[17])
            offset = 18
            rtt_ref_seq = None
            ts_echo_us = None
            ack_delay_us = None
        elif ver == ACK_STATE_V2:
            if len(payload) < 38:
                return None
            ack_base = int.from_bytes(payload[1:9], "big")
            seen_max = int.from_bytes(payload[9:17], "big")
            rtt_ref_seq = int.from_bytes(payload[17:25], "big")
            ts_echo_us = int.from_bytes(payload[25:33], "big")
            ack_delay_us = int.from_bytes(payload[33:37], "big")
            count = int(payload[37])
            offset = 38
            if (rtt_ref_seq == 0) != (ts_echo_us == 0):
                return None
        else:
            return None

        if ack_base <= 0:
            return None
        if seen_max < (ack_base - 1):
            return None

        ranges, offset = self._parse_ranges(payload, offset, count)
        if len(ranges) != count or offset != len(payload):
            return None

        prev_end = None
        normalized = []
        for s, e in ranges:
            s = int(s)
            e = int(e)
            if s > e:
                return None
            if s < ack_base:
                return None
            if e > seen_max:
                return None
            if prev_end is not None and s <= (prev_end + 1):
                # ACKv1/v2 requires a canonical non-overlapping, non-adjacent encoding.
                return None
            normalized.append((s, e))
            prev_end = e

        if seen_max >= ack_base:
            if not normalized:
                return None
            if normalized[0][0] != ack_base:
                return None
        elif normalized:
            return None

        return {
            "version": ver,
            "ack_base": ack_base,
            "seen_max": seen_max,
            "missing": normalized,
            "rtt_ref_seq": rtt_ref_seq,
            "ts_echo_us": ts_echo_us,
            "ack_delay_us": ack_delay_us,
        }

    def _parse_ack2_state_payload(self, payload: bytes):
        parsed = self._parse_ack_state_payload(payload)
        if parsed is None:
            return None
        return parsed

    def _ranges_cover(self, outer, inner) -> bool:
        outer = self._merge_ranges(list(outer or []))
        inner = self._merge_ranges(list(inner or []))
        if not inner:
            return True
        if not outer:
            return False
        j = 0
        for s, e in inner:
            while j < len(outer) and outer[j][1] < s:
                j += 1
            if j >= len(outer):
                return False
            os, oe = outer[j]
            if os > s or oe < e:
                return False
        return True

    def _ack2_covers_ack1_payload(self, ack2_payload: bytes, ack1_payload: bytes) -> bool:
        ack2 = self._parse_ack2_state_payload(ack2_payload)
        ack1 = self._parse_ack_state_payload(ack1_payload)
        if ack2 is None or ack1 is None:
            return False

        if int(ack2["ack_base"]) < int(ack1["ack_base"]):
            return False
        if int(ack2["seen_max"]) < int(ack1["seen_max"]):
            return False

        ack2_missing = self._merge_ranges(list(ack2.get("missing", [])))
        ack1_missing = self._merge_ranges(list(ack1.get("missing", [])))

        # Only compare the portion that overlaps the current ACK1 state window.
        lo = int(ack1["ack_base"])
        hi = int(ack1["seen_max"])
        if hi < lo:
            return True

        clipped_ack2_missing = []
        for s, e in ack2_missing:
            s = max(int(s), lo)
            e = min(int(e), hi)
            if s <= e:
                clipped_ack2_missing.append((s, e))
        clipped_ack2_missing = self._merge_ranges(clipped_ack2_missing)

        return self._ranges_cover(clipped_ack2_missing, ack1_missing) and self._ranges_cover(ack1_missing, clipped_ack2_missing)

    
    def _ack1_pending(self) -> bool:
        """Whether ACK1 state indicates we should keep/resend.

        Key point: do NOT suppress the final cumulative ACK after RANGE completion.
        We still need at least one ACK1 that reflects ack_base == range_end+1, otherwise
        the sender may stall waiting for the tail.
        """
        ack_base = int(self.next_seq_expected)

        # Always ACK forward progress (cumulative ACK), even if there is no out-of-order data.
        try:
            if int(getattr(self, "ack1_last_ack_base", 0) or 0) != ack_base:
                return True
        except Exception:
            return True

        recv_merged = self._merge_ranges(self.recv_ranges)
        if not recv_merged:
            return False

        try:
            seen_max = max(int(e) for _s, e in recv_merged)
        except Exception:
            return False

        # Pending when we have anything at/after ack_base (out-of-order) or any gap.
        return bool(seen_max >= ack_base)

    
    def _send_ack1(self, force=False):
        """Build and (maybe) send ACK1.

        Fixes:
        - If we hit ack1_min_interval, we still update ack1_last_payload (cache) and mark ack1_dirty,
          so _ack1_resender() can send the newest cumulative state later.
        - Do not advance ack1_last_ack_base on a rate-limited (not actually sent) ACK1; otherwise
          _ack1_pending() may falsely become False and clear the cache.
        """
        payload_to_send = None
        log_line = None

        with self.lock:
            payload = self._build_ack1_payload()
            pending = self._ack1_pending()
            now = time.time()

            ack_base, seen_max, miss_cnt = self._extract_ack_payload_log_fields(payload)

            # Decide whether this ACK1 should exist at all.
            if not force and not pending:
                self.ack1_last_payload = b""
                self.ack1_dirty = False
                self.ack1_last_update_ts = 0.0
                return

            # Always cache the newest payload (even if rate-limited).
            self.ack1_last_payload = payload
            self.ack1_last_update_ts = now

            min_int, _ack1_rto, _ack1_grace, _ack1_srtt, _ack1_rttvar = self._ack1_timing_params()
            last_sent = float(self.ack1_last_sent_ts or 0.0)
            hit_min_interval = (not force) and (min_int > 0.0) and (last_sent > 0.0) and ((now - last_sent) < min_int)

            if hit_min_interval:
                # 有更新但没发出去：标记 dirty，交给 resender
                self.ack1_dirty = True

                # Only log "interesting" cases to avoid log spam.
                near_end = False
                try:
                    if self.range_end is not None and ack_base is not None:
                        near_end = (int(ack_base) >= int(self.range_end) - 4)
                except Exception:
                    near_end = False
                if near_end or (miss_cnt is not None and miss_cnt > 0):
                    log_line = (
                        f"ACK1 rate-limited: ack_base={ack_base}, seen_max={seen_max}, missing_cnt={miss_cnt}, "
                        f"min_interval={min_int}, dt={now - last_sent:.6f}, updated_cache=True"
                    )
                payload_to_send = None
            else:
                # Send now.
                self.ack1_dirty = False
                self.ack1_last_sent_ts = now
                # Track the last cumulative ack_base we've actually sent (used by _ack1_pending)
                if ack_base is not None:
                    self.ack1_last_ack_base = int(ack_base)

                near_end = False
                try:
                    if self.range_end is not None and ack_base is not None:
                        near_end = (int(ack_base) >= int(self.range_end) - 4)
                except Exception:
                    near_end = False
                if near_end or (miss_cnt is not None and miss_cnt > 0):
                    log_line = (
                        f"ACK1 send: ack_base={ack_base}, seen_max={seen_max}, missing_cnt={miss_cnt}, "
                        f"hit_min_interval=False, updated_cache=True"
                    )

                payload_to_send = payload

        if log_line:
            try:
                self.logger.info(log_line)
            except Exception:
                pass

        if payload_to_send is not None:
            with self.lock:
                self.ack1_sent_count += 1
            self._send_ctrl(FLAG_ACK, payload_to_send)

    
    def _ack1_resender(self):
        while self.running:
            time.sleep(self._ack1_resender_sleep_interval())

            payload_to_send = None
            reason = None
            ack_base = None
            seen_max = None
            miss_cnt = None

            with self.lock:
                if not self.ack1_last_payload:
                    continue

                now = time.time()
                payload = self.ack1_last_payload

                ack_base, seen_max, miss_cnt = self._extract_ack_payload_log_fields(payload)

                pending = self._ack1_pending()
                dirty = bool(getattr(self, "ack1_dirty", False))

                # Optional grace window: even if pending=False, keep the last ACK1 around briefly
                # so a lost final ACK1 still has a chance to be retransmitted.
                min_int, rto, grace, _ack1_srtt, _ack1_rttvar = self._ack1_timing_params()
                last_update = float(getattr(self, "ack1_last_update_ts", 0.0) or 0.0)

                if (not pending) and (not dirty) and grace > 0.0 and last_update > 0.0:
                    if (now - last_update) > grace:
                        self.ack1_last_payload = b""
                        continue

                last_sent = float(self.ack1_last_sent_ts or 0.0)

                # Dirty path: wait until min-interval is satisfied, then send the newest cached ACK1.
                if dirty:
                    if (last_sent <= 0.0) or (min_int <= 0.0) or ((now - last_sent) >= min_int):
                        payload_to_send = payload
                        reason = "dirty"
                else:
                    # Normal resend path: pending ACK1 state; resend on RTO.
                    if (last_sent <= 0.0) or ((now - last_sent) > rto):
                        # If not pending, only resend within grace window (if configured).
                        if pending or (grace <= 0.0) or (last_update <= 0.0) or ((now - last_update) <= grace):
                            payload_to_send = payload
                            reason = "rto"

                if payload_to_send is not None:
                    self.ack1_last_sent_ts = now
                    self.ack1_dirty = False
                    # Update last_ack_base to reflect what we actually sent.
                    if ack_base is not None:
                        self.ack1_last_ack_base = int(ack_base)

            if payload_to_send is not None:
                with self.lock:
                    self.ack1_resend_count += 1
                self._send_ctrl(FLAG_ACK, payload_to_send)

                # Log only interesting events (avoid log spam)
                try:
                    near_end = False
                    if self.range_end is not None and ack_base is not None:
                        near_end = (int(ack_base) >= int(self.range_end) - 4)
                    if near_end or (miss_cnt is not None and miss_cnt > 0) or reason == "dirty":
                        self.logger.info(
                            f"ACK1 resend({reason}): ack_base={ack_base}, seen_max={seen_max}, missing_cnt={miss_cnt}"
                        )
                except Exception:
                    pass

    # ---------------- ACK1/ACK2 解析/处理（发送端） ----------------
    def _parse_ranges(self, payload, offset, count):
        ranges = []
        for _ in range(count):
            if offset + 16 > len(payload):
                break
            s = int.from_bytes(payload[offset:offset + 8], "big")
            e = int.from_bytes(payload[offset + 8:offset + 16], "big")
            offset += 16
            ranges.append((s, e))
        return ranges, offset
    def _fast_retx_min_interval(self) -> float:
        """Rate-limit fast retransmit to avoid ACK-clocked spray.

        Uses congestion-control SRTT if available (half SRTT, clamped); otherwise uses a default.
        """
        srtt = None
        try:
            with self._cc_lock:
                cc = self.cc
                if cc is not None:
                    srtt = getattr(cc, "srtt", None)
        except Exception:
            srtt = None

        try:
            if srtt is not None:
                srtt = float(srtt)
        except Exception:
            srtt = None

        if srtt is None or srtt <= 0:
            return float(self._fr_min_interval_default)

        interval = 0.5 * srtt
        interval = max(float(self._fr_min_interval_floor), interval)
        interval = min(float(self._fr_min_interval_cap), interval)
        return float(interval)

    def _recovery_pacing_params(self):
        srtt = None
        cwnd = None
        try:
            with self._cc_lock:
                cc = self.cc
                if cc is not None:
                    srtt = getattr(cc, "srtt", None)
                    cwnd = getattr(cc, "cwnd", None)
        except Exception:
            srtt = None
            cwnd = None

        try:
            srtt = float(srtt) if srtt is not None else None
        except Exception:
            srtt = None
        try:
            cwnd = float(cwnd) if cwnd is not None else None
        except Exception:
            cwnd = None

        byte_rate = float(self._recovery_pacing_fallback_bps)
        if (srtt is not None) and (srtt > 0.0) and (cwnd is not None) and (cwnd > 0.0):
            ref_rtt = max(float(self._recovery_pacing_min_rtt), srtt)
            byte_rate = max(float(self._recovery_pacing_min_bps), float(self._recovery_pacing_gain) * cwnd / ref_rtt)

        pkt_rate = max(float(self._recovery_pacing_min_pps), byte_rate / max(float(MSS), 1.0))
        byte_burst = max(float(self._recovery_pacing_burst_bytes), float(self._recovery_pacing_burst_pkts) * float(MSS))
        pkt_burst = max(1.0, float(self._recovery_pacing_burst_pkts))
        return byte_rate, byte_burst, pkt_rate, pkt_burst

    def _queue_recovery_retransmit(self, seq: int, enc_data: bytes, packet_size: int, reason: str = "recovery") -> bool:
        seq = int(seq)
        item = (seq, bytes(enc_data), int(packet_size), str(reason))
        with self.lock:
            if seq not in self.unacked:
                return False
            if seq in self._recovery_send_queued:
                return False
            if str(reason) == "fast":
                self._recovery_send_queue.appendleft(item)
            else:
                self._recovery_send_queue.append(item)
            self._recovery_send_queued.add(seq)
        self._recovery_send_event.set()
        return True

    def _recovery_sender(self):
        while self.running:
            item = None
            with self.lock:
                if self._recovery_send_queue:
                    item = self._recovery_send_queue.popleft()
                else:
                    self._recovery_send_event.clear()

            if item is None:
                self._recovery_send_event.wait(timeout=0.05)
                continue

            seq, enc_data, packet_size, reason = item

            with self.lock:
                still_unacked = (int(seq) in self.unacked)
            if not still_unacked:
                with self.lock:
                    self._recovery_send_queued.discard(int(seq))
                continue

            if self.recovery_pacing_enabled:
                try:
                    byte_rate, byte_burst, pkt_rate, pkt_burst = self._recovery_pacing_params()
                    self._recovery_pacer.wait(packet_size, byte_rate, byte_burst, pkt_rate, pkt_burst)
                except Exception as e:
                    self.logger.error(f"Recovery pacing wait failed (seq={seq}, reason={reason}): {e}")

            with self.lock:
                still_unacked = (int(seq) in self.unacked)
            if not still_unacked:
                with self.lock:
                    self._recovery_send_queued.discard(int(seq))
                continue

            send_ts = time.time()
            try:
                self._sock_sendto(enc_data, self.addr)
                with self.lock:
                    wire_len = int(len(enc_data))
                    self._total_wire_bytes_sent += wire_len
                    self.data_packets_sent_total += 1
                    self.data_packets_retx_total += 1
                    self.data_wire_bytes_sent_retx += wire_len
                    self.data_wire_bytes_sent_total += wire_len
                    if str(reason) == "fast":
                        self.fast_retx_count += 1
                        self.data_packets_retx_fast += 1
                    elif str(reason) == "rto":
                        self.rto_retx_count += 1
                        self.data_packets_retx_rto += 1
                    self._recompute_wire_totals_locked()
            except Exception as e:
                self.logger.error(f"Recovery retransmit error ({reason}, seq={seq}): {e}")
            finally:
                with self.lock:
                    self._recovery_send_queued.discard(int(seq))
                    meta = self.unacked.get(int(seq))
                    if meta is not None:
                        meta["tx_ts"] = send_ts
                        if str(reason) in ("fast", "rto"):
                            # Unify recovery scheduling: after a fast retransmit actually goes out,
                            # the RTO path must measure from this recovery send instead of the old send epoch.
                            meta["ts"] = send_ts

    def _handle_ack1(self, pkt: Packet):
        """Process an ACK state payload.

        On-wire format:
        - ACK state v1: ver(1) | ack_base | seen_max | missing_ranges
        - ACK state v2: ver(2) | ack_base | seen_max | rtt_ref_seq | ts_echo_us | ack_delay_us | missing_ranges

        Any malformed payload is rejected so ACK parsing semantics stay single-source and exact.
        """
        if not pkt.payload:
            return False

        parsed = self._parse_ack_state_payload(pkt.payload)
        if parsed is None:
            try:
                ver = int(pkt.payload[0]) if pkt.payload else None
                if ver in (ACK_STATE_V1, ACK_STATE_V2):
                    self.logger.warning(f"Malformed ACK state rejected: ver={ver}, len={len(pkt.payload)}")
                else:
                    self.logger.warning("Unsupported ACK state version rejected")
            except Exception:
                pass
            return False

        ack_base = int(parsed["ack_base"])
        seen_max = int(parsed["seen_max"])
        missing_ranges = self._merge_ranges(list(parsed.get("missing", [])))
        rtt_ref_seq = parsed.get("rtt_ref_seq")
        ts_echo_us = parsed.get("ts_echo_us")
        ack_delay_us = parsed.get("ack_delay_us")

        ack_gap_depth = 0
        if seen_max >= ack_base:
            ack_gap_depth = max(0, int(seen_max - ack_base + 1))
            for s, _e in missing_ranges:
                try:
                    ack_gap_depth = max(ack_gap_depth, int(seen_max - int(s) + 1))
                except Exception:
                    continue
            if ack_gap_depth > 0:
                with self.lock:
                    self._observe_gap_depth_locked(ack_gap_depth)
                self._sync_adaptive_reorder(reason="ack1_gap")

        now = time.time()
        now_mono_us = self._mono_now_us()
        app_bytes_acked = 0
        wire_bytes_acked = 0
        rtt_samples = []
        rtt_ref_meta = None

        with self.lock:
            # dup-ACK tracking on ack_base (for optional fast retransmit on ack_base when no explicit missing info)
            if self._fr_last_ack_base == ack_base:
                self._fr_dup_acks += 1
            else:
                self._fr_last_ack_base = ack_base
                self._fr_dup_acks = 1

            to_delete = []
            for seq, meta in self.unacked.items():
                acked_now = False

                if seq < ack_base:
                    acked_now = True
                elif seq == ack_base:
                    acked_now = False   # 明确保护：ack_base 永远不能被 ACK state 直接确认
                elif seq <= seen_max:
                    # SNACK semantics: within [ack_base, seen_max], any seq NOT in missing_ranges is acked.
                    if not self._seq_in_ranges(int(seq), missing_ranges):
                        acked_now = True
                else:
                    continue

                if not acked_now:
                    continue

                to_delete.append(seq)
                app_bytes_acked += int(meta.get("app_size", meta.get("size", 0)))
                wire_bytes_acked += int(meta.get("wire_size", len(meta.get("enc_data", b""))))
                if (rtt_ref_seq is not None) and int(seq) == int(rtt_ref_seq):
                    rtt_ref_meta = meta
                if int(meta.get("retries", 0)) == 0 and int(meta.get("fast_cnt", 0)) == 0:
                    ts = meta.get("tx_ts", meta.get("ts", now))
                    try:
                        rtt_samples.append(max(0.0, now - float(ts)))
                    except Exception:
                        pass

            for seq in to_delete:
                self.unacked.pop(seq, None)

            self._total_bytes_acked += int(app_bytes_acked)
            self._total_wire_bytes_acked += int(wire_bytes_acked)

        # Congestion control bookkeeping (if enabled)
        if self.cc is not None and wire_bytes_acked > 0:
            rtt_sample = None

            if (parsed.get("version") == ACK_STATE_V2) and (rtt_ref_meta is not None):
                try:
                    if int(rtt_ref_meta.get("retries", 0)) == 0 and int(rtt_ref_meta.get("fast_cnt", 0)) == 0:
                        echoed_us = int(ts_echo_us or 0)
                        delay_us = int(ack_delay_us or 0)
                        sample_us = int(now_mono_us) - echoed_us - delay_us
                        if echoed_us > 0 and sample_us > 0:
                            rtt_sample = max(1e-6, float(sample_us) / 1_000_000.0)
                except Exception:
                    rtt_sample = None

            if rtt_sample is None and rtt_samples:
                ordered = sorted(float(x) for x in rtt_samples if x is not None)
                if ordered:
                    rtt_sample = ordered[len(ordered) // 2]

            self.cc_on_ack_received(rtt_sample=rtt_sample, bytes_acked=wire_bytes_acked)

        # ---------------- Fast retransmit (missing-driven) ----------------
        # Use missing range starts as candidates, but only once the gap has matured enough
        # relative to observed reordering. In addition, require the same missing start to be
        # reported by multiple consecutive ACK1 states before retransmitting it. This prevents
        # one-off fat-tail delay spikes from immediately converting into recovery traffic.
        fr_gap_threshold = int(self._fast_retx_gap_threshold())
        explicit_missing_candidates = []
        for s, _e in missing_ranges[:int(self._fr_nack_starts_max)]:
            s = int(s)
            if s <= 0:
                continue
            maturity = max(0, int(seen_max - s + 1))
            if maturity < fr_gap_threshold:
                continue
            explicit_missing_candidates.append(s)

        missing_streaks = self._update_fast_retx_missing_report_streaks(explicit_missing_candidates)
        missing_reports_required = int(self._fast_retx_missing_reports_required())
        candidates = []
        for seq in explicit_missing_candidates:
            if int(missing_streaks.get(int(seq), 0)) >= missing_reports_required:
                candidates.append(int(seq))

        with self.lock:
            dup_acks = int(self._fr_dup_acks)
            dup_thresh = int(self._fr_dup_thresh)

        ack_base_maturity = max(0, int(seen_max - ack_base + 1)) if seen_max >= ack_base else 0
        if (
            (ack_base not in candidates)
            and (not explicit_missing_candidates)
            and (ack_base_maturity >= fr_gap_threshold)
            and (dup_acks >= max(dup_thresh, fr_gap_threshold))
        ):
            candidates.insert(0, int(ack_base))

        uniq = []
        seen = set()
        for x in candidates:
            if x in seen:
                continue
            seen.add(x)
            uniq.append(x)
            if len(uniq) >= int(self._fr_max_per_ack):
                break

        resend_list = []
        min_interval = float(self._fast_retx_min_interval())
        with self.lock:
            for seq in uniq:
                meta = self.unacked.get(seq)
                if not meta:
                    continue

                last_tx = meta.get("tx_ts", meta.get("ts", 0.0))
                try:
                    last_tx = float(last_tx)
                except Exception:
                    last_tx = 0.0

                if now - last_tx < min_interval:
                    continue

                fast_cnt = int(meta.get("fast_cnt", 0))
                if fast_cnt >= int(self._fr_max_fast_cnt):
                    continue

                if seq in self._recovery_send_queued:
                    continue

                resend_list.append((seq, meta["enc_data"], len(meta["enc_data"])))
                meta["fast_cnt"] = fast_cnt + 1

        for _seq, enc_data, pkt_size in resend_list:
            self._queue_recovery_retransmit(_seq, enc_data, pkt_size, reason="fast")

        # ACK2 mirrors the exact ACK state the sender has processed so the receiver can
        # safely silence ACK1 resends without losing timing metadata fidelity.
        self._send_ctrl(FLAG_ACK2, bytes(pkt.payload))
        return True
    def _handle_ack2(self, pkt: Packet):
        # ACK2 echoes the ACK state that the sender has processed.
        # Because ctrl packets bypass anti-replay, old/late ACK2 can arrive after a newer ACK1
        # has already been generated. Only clear resend state when the ACK2 covers/equal the
        # currently cached latest ACK1 payload.
        with self.lock:
            self.ack2_recv_count += 1

        parsed = self._parse_ack2_state_payload(pkt.payload)
        if parsed is None:
            with self.lock:
                self.ack2_malformed_count += 1
            try:
                self.logger.warning("Unsupported or malformed ACK2 rejected")
            except Exception:
                pass
            return False

        with self.lock:
            current_ack1 = bytes(self.ack1_last_payload or b"")

        if current_ack1 and self._ack2_covers_ack1_payload(pkt.payload, current_ack1):
            with self.lock:
                self.ack1_last_payload = b""
                self.ack1_last_sent_ts = 0.0
                self.ack1_dirty = False
                self.ack1_last_update_ts = 0.0
                self.ack2_cover_count += 1
            return True

        # Stale or partial ACK2: ignore it and keep the current ACK1 resend state alive.
        with self.lock:
            self.ack2_stale_count += 1
        return True

        # ---------------- DATA 接收/重组/交付 ----------------
    def _handle_data(self, pkt: Packet):
            seq = int(pkt.pkt_num)
            data, peer_tx_ts_us = self._parse_data_wire_payload(pkt.payload)
            if data is None:
                try:
                    self.logger.warning(f"Malformed DATA frame rejected: seq={seq}, len={len(pkt.payload)}")
                except Exception:
                    pass
                return False
            rx_mono_us = self._mono_now_us()

            deliver_batch = []  # [(seq, data_or_len)] delivered outside self.lock

            dup = False
            observed_gap_depth = 0
            with self.lock:
                next_expected_before = int(self.next_seq_expected)
                if seq > next_expected_before:
                    observed_gap_depth = int(seq - next_expected_before)
                    self._observe_gap_depth_locked(observed_gap_depth)

                merged = self._merge_ranges(self.recv_ranges)
                if self._seq_in_ranges(seq, merged):
                    # 已收到：不重复交付；但要尽快回 ACK1（帮助对方停止尾部重传）
                    dup = True
                    self.data_packets_recv_duplicate += 1
                else:
                    self.data_packets_recv_new += 1
                    # Memory pressure fix for "stats-only" receivers:
                    # If len-only mode is enabled, do NOT retain large payload bytes in recv_buffer.
                    # Instead, keep only the length (int).
                    #
                    # Important: even when small_payload_threshold is tuned aggressively (e.g. payload_size-1),
                    # we still must keep STREAM header / EOF marker as bytes. If RANGE has been received,
                    # treat range_start/range_end as "must-keep-bytes".
                    force_keep_bytes = False
                    try:
                        if self.range_start is not None and seq == int(self.range_start):
                            force_keep_bytes = True
                        if self.range_end is not None and seq == int(self.range_end):
                            force_keep_bytes = True
                    except Exception:
                        force_keep_bytes = False

                    if self.app_len_only and (not force_keep_bytes) and len(data) > self._small_payload_threshold:
                        self.recv_buffer[seq] = int(len(data))
                    else:
                        self.recv_buffer[seq] = data

                    self._insert_range(seq)
                    self._ack1_rtt_ref_seq = int(seq)
                    self._ack1_rtt_ref_tx_ts_us = int(peer_tx_ts_us or 0)
                    self._ack1_rtt_ref_recv_mono_us = int(rx_mono_us)

                    # Pop deliverable in-order items under self.lock...
                    while self.next_seq_expected in self.recv_buffer:
                        data2 = self.recv_buffer.pop(self.next_seq_expected)
                        deliver_batch.append((self.next_seq_expected, data2))
                        self.data_packets_delivered += 1
                        if isinstance(data2, int):
                            self.app_bytes_delivered += max(0, int(data2))
                        else:
                            try:
                                self.app_bytes_delivered += len(data2)
                            except Exception:
                                pass
                        self.next_seq_expected += 1

            if observed_gap_depth > 0:
                self._sync_adaptive_reorder(reason="data_gap")

            # ...then stage the ordered batch outside self.lock. The dedicated delivery
            # worker will move it into the app queue without ever blocking _handle_data().
            if deliver_batch:
                self._enqueue_ordered_ready_batch(deliver_batch)

            # 事件驱动 ACK1：
            # - gap/out-of-order：尽快发（帮助发送端更快进入恢复），但受 ack1_min_interval 节流
            # - in-order：按 ack1_min_interval 节流
            is_gap = bool((not dup) and (observed_gap_depth > 0))

            force_now = bool(dup)
            if is_gap and (not force_now):
                now = time.time()
                min_int, _ack1_rto, _ack1_grace, _ack1_srtt, _ack1_rttvar = self._ack1_timing_params()
                with self.lock:
                    last = float(self.ack1_last_sent_ts or 0.0)
                if (last <= 0.0) or (min_int <= 0.0) or ((now - last) >= min_int):
                    force_now = True

            self._send_ack1(force=force_now)
            return True
        # ---------------- 重传线程（发送端） ----------------
    def _cc_data_rto_base(self) -> float:
            cc_rto = None
            try:
                with self._cc_lock:
                    cc = self.cc
                    if cc is not None:
                        cc_rto = getattr(cc, "rto", None)
            except Exception:
                cc_rto = None

            try:
                if cc_rto is not None:
                    cc_rto = float(cc_rto)
            except Exception:
                cc_rto = None

            if cc_rto is None or cc_rto <= 0.0:
                cc_rto = float(self.base_rto)

            cc_rto = max(float(self.min_data_rto), cc_rto)
            cc_rto = min(float(self.max_rto), cc_rto)
            return float(cc_rto)

    def _calc_rto(self, retries: int):
            base_rto = float(self._cc_data_rto_base())
            rto = min(float(self.max_rto), base_rto * (2 ** min(int(retries), 4)))
            return max(float(self.min_data_rto), float(rto))
        
    def _calc_ctrl_rto(self, retries: int):
            rto = min(self.ctrl_max_rto, self.ctrl_base_rto * (2 ** min(retries, 4)))
            return max(self.ctrl_base_rto, rto)

    def _retransmit_checker(self):
            while self.running:
                time.sleep(0.01)

                # If the session has already failed fatally, stop retransmitting to avoid noise.
                if self.has_fatal_error():
                    time.sleep(0.05)
                    continue

                now = time.time()
                to_resend = []
                trigger_cc_loss = False  # 本轮是否触发一次拥塞退让
                drop_now = []

                with self.lock:
                    for seq, meta in list(self.unacked.items()):
                        # Retry exhaustion: drop + fail-fast (avoid permanent hang/leak).
                        if meta.get("retries", 0) >= self.max_retries:
                            self.unacked.pop(seq, None)
                            drop_now.append(seq)
                            self.dropped_data_seqs.append(seq)
                            self.dropped_data_count += 1
                            self.data_packets_dropped_retry_exhausted += 1
                            continue

                        rto = self._calc_rto(meta.get("retries", 0))
                        if seq in self._recovery_send_queued:
                            continue

                        if now - meta.get("ts", now) > rto:
                            # 关键：首次 RTO 触发一次拥塞退让
                            if meta.get("retries", 0) == 0:
                                trigger_cc_loss = True

                            to_resend.append((seq, meta["enc_data"], len(meta["enc_data"])))
                            meta["ts"] = now
                            meta["retries"] = int(meta.get("retries", 0)) + 1

                # Fail-fast outside the session lock (may send RST).
                if drop_now:
                    self._sync_cc_inflight_bytes()
                    preview = drop_now[:8]
                    more = (len(drop_now) - len(preview))
                    suffix = (f" (+{more} more)" if more > 0 else "")
                    self._set_error(
                        f"DATA retries exhausted (max_retries={self.max_retries}): {preview}{suffix}",
                        fatal=True,
                    )

                # 在 session 锁外触发 cc 的 loss 回调
                if trigger_cc_loss and self.cc is not None:
                    try:
                        self.cc_on_packet_lost()
                    except Exception as e:
                        self.logger.error(f"cc.on_packet_lost failed: {e}")

                for seq, enc_data, pkt_size in to_resend:
                    self._queue_recovery_retransmit(seq, enc_data, pkt_size, reason="rto")

                # ---- 可靠控制包重传（不走拥塞控制）----
                ctrl_resend = []
                ctrl_drop_now = []
                range_meta_failed = False

                with self.lock:
                    for cid, meta in list(self.ctrl_unacked.items()):
                        if meta.get("retries", 0) >= self.ctrl_max_retries:
                            self.ctrl_unacked.pop(cid, None)
                            ctrl_drop_now.append(cid)
                            self.dropped_ctrl_ids.append(cid)
                            self.ctrl_packets_drop_total += 1
                            if meta.get("mtype") == META_TYPE_RANGE and cid == self._range_meta_id:
                                self.range_meta_failed_count += 1
                                range_meta_failed = True
                            continue

                        rto = self._calc_ctrl_rto(meta.get("retries", 0))
                        if now - meta.get("ts", now) > rto:
                            resend_addr = self._ctrl_retransmit_addr_locked(meta)
                            ctrl_resend.append((meta["enc_data"], resend_addr, meta.get("mtype")))
                            meta["ts"] = now
                            meta["tx_ts"] = now
                            meta["retries"] = int(meta.get("retries", 0)) + 1

                if range_meta_failed:
                    self._range_meta_failed.set()

                # 控制包重传耗尽通常不是致命错误（例如 RANGE 未 ACK：当前 in-order client 仍可继续发送）。
                if ctrl_drop_now:
                    preview = ctrl_drop_now[:8]
                    more = (len(ctrl_drop_now) - len(preview))
                    suffix = (f" (+{more} more)" if more > 0 else "")
                    self._set_error(
                        f"CTRL retries exhausted (ctrl_max_retries={self.ctrl_max_retries}): {preview}{suffix}",
                        fatal=False,
                    )

                for enc_data, target_addr, mtype in ctrl_resend:
                    try:
                        resend_addr = self.addr if target_addr is None else target_addr
                        self._sock_sendto(enc_data, resend_addr)
                        with self.lock:
                            self._record_ctrl_retx_success_locked(len(enc_data), mtype=mtype)
                            self._recompute_wire_totals_locked()
                    except Exception as e:
                        self.logger.error(f"Ctrl retransmit error: {e}")

    def _control_replay_seq(self, pkt_num: int) -> int:
        return int(int(pkt_num) & int(CTRL_SEQ_COUNTER_MASK)) + 1

    def _is_session_aead_control_packet(self, pkt: Packet, source: str) -> bool:
        if pkt is None:
            return False
        if str(source or "") != "session":
            return False
        if pkt.flags & FLAG_DATA:
            return False
        if pkt.flags & FLAG_SYN:
            return False
        return bool(int(pkt.pkt_num) & int(CTRL_SEQ_BIT))

    def _is_final_handshake_ack_packet(self, pkt: Packet) -> bool:
        if pkt is None:
            return False
        if not (pkt.flags & FLAG_ACK):
            return False
        if pkt.flags & (FLAG_SYN | FLAG_META | FLAG_ACK2 | FLAG_DATA | FLAG_RST):
            return False
        return self._parse_finished_payload(pkt.payload) is not None

    def _build_complete_payload(self, ack_base: int, seen_max: int, expected_total: int, body_bytes_recv: int) -> bytes:
        payload = bytearray()
        payload.extend(COMPLETE_PAYLOAD_TAG)
        payload.extend(int(ack_base).to_bytes(8, "big"))
        payload.extend(int(seen_max).to_bytes(8, "big"))
        payload.extend(int(expected_total).to_bytes(8, "big"))
        payload.extend(int(body_bytes_recv).to_bytes(8, "big"))
        return bytes(payload)

    def _parse_complete_payload(self, payload: bytes):
        if not isinstance(payload, (bytes, bytearray)):
            return None
        payload = bytes(payload)
        if len(payload) != COMPLETE_PAYLOAD_LEN:
            return None
        if not payload.startswith(COMPLETE_PAYLOAD_TAG):
            return None
        off = len(COMPLETE_PAYLOAD_TAG)
        ack_base = int.from_bytes(payload[off:off + 8], "big")
        off += 8
        seen_max = int.from_bytes(payload[off:off + 8], "big")
        off += 8
        expected_total = int.from_bytes(payload[off:off + 8], "big")
        off += 8
        body_bytes_recv = int.from_bytes(payload[off:off + 8], "big")
        if ack_base <= 0 or seen_max < (ack_base - 1):
            return None
        if expected_total < 0 or body_bytes_recv < 0:
            return None
        return {
            "ack_base": ack_base,
            "seen_max": seen_max,
            "expected_total": expected_total,
            "body_bytes_recv": body_bytes_recv,
        }

    def _validate_complete_payload_semantics(self, parsed: dict):
        try:
            ack_base = int(parsed["ack_base"])
            seen_max = int(parsed["seen_max"])
            expected_total = int(parsed["expected_total"])
            body_bytes_recv = int(parsed["body_bytes_recv"])
        except Exception:
            return False, {"reason": "complete_payload_parse_error"}

        with self.lock:
            final_seq = self._complete_expected_final_seq
            total_bytes = self._complete_expected_total_bytes

        if body_bytes_recv != expected_total:
            return False, {
                "reason": "body_bytes_recv_not_equal_expected_total",
                "expected_total": expected_total,
                "body_bytes_recv": body_bytes_recv,
            }

        if final_seq is not None:
            final_seq = int(final_seq)
            if ack_base != (final_seq + 1):
                return False, {
                    "reason": "ack_base_mismatch",
                    "ack_base": ack_base,
                    "expected_ack_base": final_seq + 1,
                }
            if seen_max != final_seq:
                return False, {
                    "reason": "seen_max_mismatch",
                    "seen_max": seen_max,
                    "expected_seen_max": final_seq,
                }

        if total_bytes is not None:
            total_bytes = int(total_bytes)
            if expected_total != total_bytes:
                return False, {
                    "reason": "expected_total_mismatch",
                    "expected_total": expected_total,
                    "local_total_bytes": total_bytes,
                }
            if body_bytes_recv != total_bytes:
                return False, {
                    "reason": "body_bytes_recv_mismatch",
                    "body_bytes_recv": body_bytes_recv,
                    "local_total_bytes": total_bytes,
                }

        return True, None

    def send_complete(self, ack_base: int, seen_max: int, expected_total: int, body_bytes_recv: int):
        payload = self._build_complete_payload(ack_base, seen_max, expected_total, body_bytes_recv)
        detail = {
            "ack_base": int(ack_base),
            "seen_max": int(seen_max),
            "expected_total": int(expected_total),
            "body_bytes_recv": int(body_bytes_recv),
        }
        pkt_num = self._send_ctrl(FLAG_FIN, payload, track=True, mtype="complete")
        if pkt_num is None:
            with self.lock:
                self._complete_sent_payload = b""
                self._complete_sent_pkt_num = None
            self._set_complete_commit_state("send_failed", detail)
            return {
                "ok": False,
                "status": "send_failed",
                "pkt_num": None,
                "detail": detail,
            }
        with self.lock:
            self._complete_ack_received_event.clear()
            self._complete_sent_payload = bytes(payload)
            self._complete_sent_pkt_num = int(pkt_num)
            self._complete_sent_count += 1
        detail = dict(detail)
        detail["pkt_num"] = int(pkt_num)
        self._set_complete_commit_state("sent", detail)
        return {
            "ok": True,
            "status": "sent",
            "pkt_num": int(pkt_num),
            "detail": detail,
        }

    def send_complete_commit(self, expected_total: int, body_bytes_recv: int):
        payload = self._build_ack1_payload()
        parsed = self._parse_ack_state_payload(payload)
        if parsed is None:
            detail = "ack_state_parse_failed"
            self._set_complete_commit_state("precheck_failed", detail)
            return {
                "ok": False,
                "status": "precheck_failed",
                "pkt_num": None,
                "detail": detail,
            }
        missing = list(parsed.get("missing", []))
        ack_base = int(parsed["ack_base"])
        seen_max = int(parsed["seen_max"])
        if missing:
            detail = {
                "reason": "ack_has_missing_ranges",
                "ack_base": ack_base,
                "seen_max": seen_max,
                "missing_count": len(missing),
            }
            self._set_complete_commit_state("precheck_failed", detail)
            return {
                "ok": False,
                "status": "precheck_failed",
                "pkt_num": None,
                "detail": detail,
            }
        if seen_max != (ack_base - 1):
            detail = {
                "reason": "seen_max_not_equal_ack_base_minus_1",
                "ack_base": ack_base,
                "seen_max": seen_max,
            }
            self._set_complete_commit_state("precheck_failed", detail)
            return {
                "ok": False,
                "status": "precheck_failed",
                "pkt_num": None,
                "detail": detail,
            }
        if (self.range_end is not None) and (ack_base < (int(self.range_end) + 1)):
            detail = {
                "reason": "range_not_fully_covered",
                "ack_base": ack_base,
                "range_end": int(self.range_end),
            }
            self._set_complete_commit_state("precheck_failed", detail)
            return {
                "ok": False,
                "status": "precheck_failed",
                "pkt_num": None,
                "detail": detail,
            }
        return self.send_complete(ack_base, seen_max, int(expected_total), int(body_bytes_recv))

    def _send_complete_ack(self, payload: bytes, addr=None):
        with self.lock:
            self._complete_ack_sent_count += 1
        self._send_ctrl_to(FLAG_FIN | FLAG_ACK, bytes(payload), addr=addr)

    def _handle_complete(self, pkt: Packet, addr=None):
        parsed = self._parse_complete_payload(pkt.payload)
        if parsed is None:
            try:
                self.logger.warning("Malformed COMPLETE rejected")
            except Exception:
                pass
            return False

        target_addr = self.addr if addr is None else addr
        payload = bytes(pkt.payload)
        with self.lock:
            current = bytes(self._complete_received_payload or b"")
            if current and current != payload:
                self.logger.warning("Conflicting COMPLETE ignored")
                return False
            self._complete_raw_received_info = dict(parsed)
            self._complete_raw_received_event.set()

        ok, detail = self._validate_complete_payload_semantics(parsed)
        if not ok:
            with self.lock:
                self._complete_validation_error = detail
            self.logger.warning(f"Invalid COMPLETE payload rejected: {detail}")
            self._set_error(f"invalid COMPLETE payload: {detail}", fatal=True)
            return False

        with self.lock:
            self._complete_received_payload = payload
            self._complete_received_info = dict(parsed)
            self._complete_validation_error = None
            self._complete_received_event.set()
            self.complete_recv_count += 1

        self._send_complete_ack(payload, addr=target_addr)
        return True

    def _accept_complete_ack_payload(self, payload: bytes) -> bool:
        parsed = self._parse_complete_payload(payload)
        if parsed is None:
            try:
                self.logger.warning("Malformed COMPLETE_ACK rejected")
            except Exception:
                pass
            return False

        with self.lock:
            expected = bytes(self._complete_sent_payload or b"")
            complete_pkt_num = self._complete_sent_pkt_num
            if expected and bytes(payload) != expected:
                return False
            if complete_pkt_num is not None:
                self.ctrl_unacked.pop(int(complete_pkt_num), None)
            if not self._complete_ack_received_event.is_set():
                self.complete_ack_recv_count += 1
            self._complete_ack_received_event.set()
        return True

    def _handle_complete_ack(self, pkt: Packet):
        return self._accept_complete_ack_payload(pkt.payload)

    def _build_range_meta_ack_payload(self, acked_ctrl_pkt_num: int) -> bytes:
        accepted_ooo = int(getattr(self, "_adaptive_peer_accepted_ooo", 0) or 0)
        if accepted_ooo <= 0:
            accepted_ooo = int(getattr(self, "_adaptive_ooo_window_pkts", 0) or 0)
        if accepted_ooo <= 0:
            accepted_ooo, _rpw, _rpm = self._sync_adaptive_reorder(reason="range_meta_ack")
        payload = bytearray()
        payload.append(META_TYPE_RANGE)
        payload.extend(int(acked_ctrl_pkt_num).to_bytes(8, "big"))
        payload.extend(int(accepted_ooo & 0xFFFFFFFF).to_bytes(4, "big"))
        return bytes(payload)

    def _accept_control_replay(self, pkt: Packet) -> int:
        if pkt is None:
            return ReplayProtector.DUP_OLD
        seq = self._control_replay_seq(int(pkt.pkt_num))
        with self.lock:
            rp = self.ctrl_replay_protector
            # The first session-AEAD control packet may legally start after cleartext SYN / SYN-ACK.
            # Seed base to first_seen_seq - 1 so the replay window starts in the encrypted
            # control namespace rather than at zero. With the high-water replay protector this
            # is no longer required for progress, but it keeps diagnostics stable.
            if int(getattr(rp, "base", 0) or 0) == 0 and int(getattr(rp, "bitmap", 0) or 0) == 0 and seq > 1:
                rp.base = int(seq) - 1
            verdict = rp.accept(int(seq))
            if verdict == ReplayProtector.DUP_OLD:
                self.ctrl_replay_duplicate_old_count += 1
            elif verdict == ReplayProtector.TOO_FAR_RIGHT:
                self.ctrl_replay_too_far_right_count += 1
                try:
                    self.logger.warning(
                        f"Control replay drop: seq={seq}, base={getattr(rp, 'base', None)}, "
                        f"window={getattr(rp, 'window_size', None)}, pkt_num={int(pkt.pkt_num)}"
                    )
                except Exception:
                    pass
            return verdict

    def _record_control_replay_observed(self, pkt: Packet):
        if pkt is None:
            return
        if pkt.flags & FLAG_DATA:
            return
        if not (int(pkt.pkt_num) & int(CTRL_SEQ_BIT)):
            return
        try:
            self._accept_control_replay(pkt)
        except Exception:
            pass

    def _handle_duplicate_control(self, pkt: Packet, addr=None):
        target_addr = self.addr if addr is None else addr

        if pkt.flags & FLAG_META:
            if pkt.flags & FLAG_ACK:
                return
            if len(pkt.payload) < 1:
                return
            mtype = pkt.payload[0]
            if mtype == META_TYPE_PATH_CHALLENGE and len(pkt.payload) >= 1 + PATH_CHALLENGE_LEN and addr is not None:
                token = bytes(pkt.payload[1:1 + PATH_CHALLENGE_LEN])
                self._send_path_response(addr, token)
                return
            if mtype == META_TYPE_RANGE and len(pkt.payload) >= 1 + 8 + 8:
                self._send_ctrl_to(
                    FLAG_META | FLAG_ACK,
                    self._build_range_meta_ack_payload(int(pkt.pkt_num)),
                    addr=target_addr,
                )
                return
            return

        if pkt.flags & FLAG_FIN:
            parsed = self._parse_complete_payload(pkt.payload)
            if parsed is None:
                return
            if pkt.flags & FLAG_ACK:
                self._accept_complete_ack_payload(pkt.payload)
                return
            ok, _detail = self._validate_complete_payload_semantics(parsed)
            if not ok:
                return
            with self.lock:
                current = bytes(self._complete_received_payload or b"")
                if current and current != bytes(pkt.payload):
                    return
            self._send_complete_ack(bytes(pkt.payload), addr=target_addr)
            return

        if pkt.flags & FLAG_ACK:
            if self._parse_finished_payload(pkt.payload) is not None:
                return
            if self._parse_ack_state_payload(pkt.payload) is None:
                return
            self._send_ctrl_to(FLAG_ACK2, bytes(pkt.payload), addr=target_addr)

    def handle_packet(self, raw_data, addr):
        pkt, source = self._decrypt_packet(raw_data)
        if not pkt:
            return

        if pkt.flags & FLAG_DATA:
            self._record_data_recv_wire(len(raw_data))
        else:
            self._record_ctrl_recv(len(raw_data), pkt=pkt)
        with self.lock:
            self._recompute_wire_totals_locked()

        if source == "late-cleartext-handshake":
            if self._is_consistent_late_cleartext_handshake(pkt):
                with self.lock:
                    self._late_cleartext_retransmit_count += 1
                return
            with self.lock:
                self._unexpected_cleartext_handshake_count += 1
            self.logger.warning("Unexpected late cleartext handshake packet ignored")
            return

        # Peer abort is globally terminal once it has been authenticated. Handle it before any
        # tuple/path quarantine logic so new-path or retired-path RST still stops the session.
        if pkt.flags & FLAG_RST:
            try:
                reason = pkt.payload.decode("utf-8", errors="ignore")
            except Exception:
                reason = repr(pkt.payload[:64])
            self._rst_sent = True
            self._set_error(f"peer reset: {reason}", fatal=True)
            self.stop()
            return

        handshake_final_ack = self._is_final_handshake_ack_packet(pkt)

        self._prune_path_state()

        meta_type = pkt.payload[0] if ((pkt.flags & FLAG_META) and len(pkt.payload) >= 1) else None
        is_path_challenge = (meta_type == META_TYPE_PATH_CHALLENGE)
        is_path_response = (meta_type == META_TYPE_PATH_RESPONSE)

        with self.lock:
            primary_addr = self.peer_addr
            known_pending = self._addr_key(addr) in self._path_validation
            recent_old = self._addr_key(addr) in self._retired_paths

        # Client handshake compatibility: a pre-handshake SYN-ACK may legitimately arrive from
        # a different tuple, but the tuple must remain provisional until pinned-key validation
        # and handshake signature verification both succeed. Otherwise a forged / corrupted
        # SYN-ACK can poison self.peer_addr / self.addr before authentication fails.
        pre_handshake_synack = bool(
            self.is_client and (not self.is_session_key_ready) and ((pkt.flags & FLAG_SYN) and (pkt.flags & FLAG_ACK))
        )
        candidate_handshake_addr = None

        if addr != primary_addr:
            if pre_handshake_synack:
                candidate_handshake_addr = addr
            elif handshake_final_ack:
                candidate_handshake_addr = addr
            elif recent_old:
                pass
            elif known_pending:
                # Pending-path quarantine: ordinary business packets are still isolated, but they now
                # retrigger PATH_CHALLENGE after the validation timeout expires.
                # Importantly, quarantined packets do NOT refresh last_activity; otherwise a session can
                # look alive forever even though no validated-path / ordered-progress work is happening.
                if not (is_path_challenge or is_path_response):
                    self._send_path_challenge(addr)
                    return
            else:
                # For post-handshake authenticated packets from a new tuple, validate the path first.
                # Also allow proactive migration when the peer probes from a new path with PATH_CHALLENGE.
                if is_path_response:
                    return
                allow_rebind = self._path_migration_allowed(pkt) or is_path_challenge
                if not allow_rebind:
                    return
                self._send_path_challenge(addr)
                if not is_path_challenge:
                    return

        # Final ACK is a handshake-tail special case. It is intentionally handled
        # outside the ordinary control freshness gate so it cannot be swallowed by
        # generic ACK-state replay logic. Repeated final ACKs are absorbed here and
        # also recorded into the control replay window so later session control
        # packets share one freshness domain.
        if handshake_final_ack:
            finished = self._parse_finished_payload(pkt.payload)
            if (self._finished_token is None) or (bytes(finished) != bytes(self._finished_token)):
                self.logger.warning(
                    f"Ignoring handshake ACK with invalid finished token for session {self.conn_id}"
                )
                return

            if candidate_handshake_addr is not None and not self.handshake_completed_local:
                self._commit_handshake_tail_addr(candidate_handshake_addr)

            self._record_control_replay_observed(pkt)
            self.last_activity = time.time()

            try:
                confirm_pkt_num = self._send_handshake_confirm(addr=addr)
            except Exception as e:
                self._set_error(f"failed to send HANDSHAKE_CONFIRM: {e}", fatal=True)
                return

            if confirm_pkt_num is None:
                self._set_error("failed to send HANDSHAKE_CONFIRM", fatal=True)
                return

            self._mark_handshake_completed_local(
                f"Local handshake completed via final ACK for session {self.conn_id}"
            )
            self._mark_peer_confirmed_established(
                f"Peer confirmed established via final ACK for session {self.conn_id}"
            )
            return

        # Control freshness is keyed to a lower-level fact boundary than
        # local handshake completion: once a ctrl-space packet has been authenticated by
        # the current session AEAD key, it belongs to the session control plane and
        # must pass the control replay window.
        if self._is_session_aead_control_packet(pkt, source):
            ctrl_verdict = self._accept_control_replay(pkt)
            if ctrl_verdict == ReplayProtector.TOO_FAR_RIGHT:
                return
            if ctrl_verdict == ReplayProtector.DUP_OLD:
                self._handle_duplicate_control(pkt, addr=addr)
                return

        self.addr = self.peer_addr
        accepted = False

        # META / META|ACK
        if pkt.flags & FLAG_META:
            if pkt.flags & FLAG_ACK:
                accepted = bool(self._handle_meta_ack(pkt))
            else:
                accepted = bool(self._handle_meta(pkt, addr=addr))
        # ACK2
        elif pkt.flags & FLAG_ACK2:
            accepted = bool(self._handle_ack2(pkt))
        # COMPLETE / COMPLETE_ACK
        elif pkt.flags & FLAG_FIN:
            if pkt.flags & FLAG_ACK:
                accepted = bool(self._handle_complete_ack(pkt))
            else:
                accepted = bool(self._handle_complete(pkt, addr=addr))
        # SYN-ACK（client 收到）
        elif (pkt.flags & FLAG_SYN) and (pkt.flags & FLAG_ACK):
            synack = self._parse_synack_payload(pkt.payload)
            if synack is None:
                self.logger.warning(f"Ignoring SYN-ACK with invalid KX payload for session {self.conn_id}")
                accepted = False
            else:
                self._server_hello_random = bytes(synack["server_random"])
                validator = self._server_identity_validator
                if validator is not None and (not validator(synack["server_identity_pub"])):
                    self.logger.error("SYN-ACK rejected by pinned server identity validator")
                    accepted = False
                elif not self._verify_server_handshake_signature(synack["server_identity_pub"], synack["signature"], server_pub_bytes=synack["server_pub"]):
                    self.logger.error("SYN-ACK signature verification failed")
                    accepted = False
                else:
                    self._server_identity_pub_bytes = bytes(synack["server_identity_pub"])
                    if candidate_handshake_addr is not None:
                        with self.lock:
                            self.peer_addr = candidate_handshake_addr
                            self.addr = candidate_handshake_addr
                    try:
                        self._derive_session_key_from_peer(synack["server_pub"])
                    except Exception as e:
                        self.logger.error(f"derive session key from SYN-ACK failed: {e}")
                        accepted = False
                    else:
                        self.logger.info("Received SYN-ACK, sending final ACK")
                        final_ack_pkt_num = self._send_final_handshake_ack()
                        if final_ack_pkt_num is None:
                            self._set_error("failed to send final ACK", fatal=True)
                            accepted = False
                        else:
                            self._mark_handshake_completed_local(
                                f"Local handshake completed on client after final ACK for session {self.conn_id}"
                            )
                            with self._hs_lock:
                                if not self.peer_confirmed_established:
                                    now = time.time()
                                    self._hs_state = "key_ready_unconfirmed"
                                    self._hs_rto = max(
                                        float(self._hs_initial_rto or 0.05),
                                        min(
                                            float(self._hs_rto or self._hs_initial_rto or 0.05),
                                            float(self._hs_final_ack_rto_cap or self._hs_initial_rto or 0.05),
                                        ),
                                    )
                                    self._hs_next_deadline = now + float(self._hs_rto)
                                    self._hs_tail_deadline = (
                                        None if self._hs_tail_timeout is None
                                        else now + float(self._hs_tail_timeout)
                                    )
                            self._hs_event.set()
                            self.logger.info(
                                f"Session key ready on client for session {self.conn_id}; awaiting peer confirmation"
                            )
                            accepted = True
        # Ordinary ACK state. Final ACK was already handled above as a dedicated
        # handshake-tail path and must not fall through into ACK-state parsing.
        elif pkt.flags & FLAG_ACK:
            accepted = bool(self._handle_ack1(pkt))
        # DATA
        elif pkt.flags & FLAG_DATA:
            accepted = bool(self._handle_data(pkt))
        # SYN（server 收到）
        elif pkt.flags & FLAG_SYN:
            self._syn_received = True
            syn_info = self._parse_syn_payload(pkt.payload)
            if syn_info is None:
                self.logger.warning(f"Ignoring SYN with invalid payload format for session {self.conn_id}")
                accepted = False
            else:
                # 先补齐握手随机数，再派生会话密钥
                self._client_hello_random = bytes(syn_info["client_random"])
                self._ensure_server_hello_random()

                try:
                    self._derive_session_key_from_peer(syn_info["client_pub"])
                except Exception as e:
                    self.logger.error(f"derive session key from SYN failed: {e}")
                    accepted = False
                else:
                    self._send_synack_cleartext()
                    accepted = True
        else:
            accepted = False

        if accepted:
            if pkt.flags & FLAG_DATA:
                self._peer_data_seen = True
            self.last_activity = time.time()
            self.addr = self.peer_addr
        return
