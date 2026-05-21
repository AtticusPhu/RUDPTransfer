import os
import struct
import time
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from utils import *
from utils import FLAG_ACK, FLAG_SYN, FLAG_DATA

CTRL_SEQ_BIT = 1 << 63
SESSION_KEY_LEN = 32
NONCE_SECRET_LEN = 32
FINISHED_TOKEN_LEN = 16


class ReplayProtector:
    """
    High-water anti-replay window.

    Earlier versions used a contiguous-base window: one lost sequence number could pin
    base forever, and after window_size later packets all new packets were classified
    as TOO_FAR_RIGHT. That is unsafe for this protocol because ACK1/ACK2 and DATA
    retransmissions are intentionally lossy/duplicated control flows. A missing
    untracked ACK must not make every later ACK look like a replay.

    This implementation uses the usual max-seen sliding-window rule:
      - base: largest authenticated sequence number observed so far;
      - bitmap bit 0 represents base, bit k represents base-k;
      - gaps do not block base advancement.

    Return values remain compatible with the old code:
      - OK: accepted as a new sequence within the replay window;
      - DUP_OLD: duplicate or too old for exact replay classification;
      - TOO_FAR_RIGHT: implausibly large forward jump, retained as a DoS guard.

    Important protocol rule: for DATA, DUP_OLD is still returned to the protocol
    layer by CryptoContext.decrypt(), because a reliable transport must be able to
    ACK authenticated duplicate/retransmitted DATA instead of dropping it in crypto.
    """
    OK = 0
    DUP_OLD = 1
    TOO_FAR_RIGHT = 2

    def __init__(self, window_size=1024, max_window_size=200000, auto_expand_margin=None):
        self.window_size = max(1, int(window_size))
        self.max_window_size = max(self.window_size, int(max_window_size))
        self.base = 0  # high-water mark / largest seq seen
        self.bitmap = 0
        if auto_expand_margin is None:
            auto_expand_margin = self.window_size
        self.auto_expand_margin = min(self.max_window_size, max(0, int(auto_expand_margin)))

    def set_window_size(self, new_size: int):
        try:
            new_size = int(new_size)
        except Exception:
            return
        if new_size <= 0:
            return
        self.window_size = min(new_size, self.max_window_size)
        self._trim_bitmap()

    def set_auto_expand_margin(self, new_margin: int):
        try:
            new_margin = int(new_margin)
        except Exception:
            return
        if new_margin < 0:
            return
        self.auto_expand_margin = min(new_margin, self.max_window_size)

    def _window_mask(self) -> int:
        return (1 << int(self.window_size)) - 1

    def _trim_bitmap(self) -> None:
        try:
            self.bitmap &= self._window_mask()
        except Exception:
            self.bitmap = 0

    def accept(self, seq: int) -> int:
        if seq is None:
            return self.DUP_OLD
        try:
            seq = int(seq)
        except Exception:
            return self.DUP_OLD
        if seq <= 0:
            return self.DUP_OLD

        # First authenticated sequence initializes the high-water mark.
        if self.base <= 0:
            self.base = seq
            self.bitmap = 1
            return self.OK

        if seq > self.base:
            diff = int(seq - self.base)

            # Keep the previous soft forward-jump guard. Sequential traffic with an
            # old gap advances one packet at a time and will not hit this guard;
            # only an implausibly large jump is rejected.
            if diff > self.window_size:
                soft_limit = min(self.max_window_size, int(self.window_size) + int(self.auto_expand_margin or 0))
                if diff > soft_limit:
                    return self.TOO_FAR_RIGHT
                self.set_window_size(diff)

            if diff >= int(self.window_size):
                # New seq is outside the retained history; older bits are irrelevant.
                self.bitmap = 1
            else:
                self.bitmap = ((int(self.bitmap) << diff) | 1) & self._window_mask()
            self.base = seq
            return self.OK

        # seq <= base: check whether it is still inside the retained window.
        offset = int(self.base - seq)
        if offset >= int(self.window_size):
            return self.DUP_OLD

        bit = 1 << offset
        if int(self.bitmap) & bit:
            return self.DUP_OLD

        self.bitmap = (int(self.bitmap) | bit) & self._window_mask()
        return self.OK

    def is_replay(self, seq: int) -> bool:
        # Compatibility with old callers.
        return self.accept(seq) != self.OK


class CryptoContext:

    """
    关键修复点：
    1) 控制包（pkt_num 高位=1<<63）完全跳过 anti-replay；
    2) DATA anti-replay 直接使用绝对数据序号 pkt_num，不再保留 session_start_seq 兼容支架；
    3) DATA 包若误入 ctrl_seq 空间，直接丢弃，避免污染重组逻辑。
    """
    def __init__(self, key=None, is_client: bool = False):
        bootstrap_key = key if key else AESGCM.generate_key(bit_length=256)
        # Direction binding for AES-GCM nonces:
        # - dir=1: packet sent by client
        # - dir=0: packet sent by server
        # This prevents nonce reuse when both directions share the same key and pkt_num space.
        self.is_client = bool(is_client)
        self.replay_protector = ReplayProtector()
        self.nonce_secret = b""
        self.update_key(bootstrap_key)

        # anti-replay / auth-fail 统计（用于定位“重复包被吞掉”等问题）
        self.logger = setup_logger("Crypto-C" if self.is_client else "Crypto-S")
        self._replay_stats = {
            "duplicate_old": 0,   # 认证成功，但被判定为 duplicate/old（现在会放行给协议层）
            "too_far_right": 0,   # 超出窗口右侧（丢弃）
            "auth_fail": 0,       # AEAD 认证失败（丢弃）
        }
        self._replay_last_log_ts = 0.0
        self._replay_last_logged = (0, 0, 0)  # (dup_old, too_far_right, auth_fail)
        self._replay_log_interval = 2.0

    def _maybe_log_replay_stats(self):
        now = time.time()
        if (now - float(self._replay_last_log_ts or 0.0)) < float(self._replay_log_interval or 2.0):
            return
        dup_old = int(self._replay_stats.get("duplicate_old", 0))
        too_far = int(self._replay_stats.get("too_far_right", 0))
        auth_fail = int(self._replay_stats.get("auth_fail", 0))
        last_dup, last_far, last_auth = self._replay_last_logged

        if (dup_old, too_far, auth_fail) != (last_dup, last_far, last_auth):
            self._replay_last_logged = (dup_old, too_far, auth_fail)
            self._replay_last_log_ts = now
            # 注意：dup_old 目前“计数但不丢弃”，用于触发协议层对重复包回 ACK
            try:
                self.logger.info(
                    f"anti-replay stats: dup_old={dup_old}, too_far_right_drop={too_far}, auth_fail={auth_fail}"
                )
            except Exception:
                pass
        else:
            self._replay_last_log_ts = now

    def update_key(self, key, nonce_secret: bytes = b""):
        key_bytes = bytes(key)
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AES-GCM key length must be 16/24/32 bytes")
        self.key = key_bytes
        self.aesgcm = AESGCM(self.key)
        self.nonce_secret = bytes(nonce_secret or b"")

    def derive_session_material(self, shared_secret: bytes, salt=None, info: bytes = b"rudp-kx-v1"):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_LEN + NONCE_SECRET_LEN + FINISHED_TOKEN_LEN,
            salt=bytes(salt) if salt is not None else bytes(self.key),
            info=bytes(info or b"rudp-kx-v1"),
        )
        okm = hkdf.derive(bytes(shared_secret))
        key = okm[:SESSION_KEY_LEN]
        nonce_secret = okm[SESSION_KEY_LEN:SESSION_KEY_LEN + NONCE_SECRET_LEN]
        finished = okm[SESSION_KEY_LEN + NONCE_SECRET_LEN:]
        return key, nonce_secret, finished

    def derive_and_update_key(self, shared_secret: bytes, salt=None, info: bytes = b"rudp-kx-v1"):
        key, nonce_secret, finished = self.derive_session_material(shared_secret, salt=salt, info=info)
        self.update_key(key, nonce_secret=nonce_secret)
        return finished

    def encrypt(self, packet_obj):
        header_bytes = packet_obj.pack_header()
        # outgoing direction
        dir_bit = 1 if self.is_client else 0
        nonce = self._generate_nonce(packet_obj.conn_id, packet_obj.pkt_num, dir_bit)
        ciphertext = self.aesgcm.encrypt(nonce, packet_obj.payload, header_bytes)
        return header_bytes + ciphertext

    def decrypt(self, raw_data, count_auth_fail: bool = True):
        if len(raw_data) < HEADER_SIZE:
            return None
        header_bytes = raw_data[:HEADER_SIZE]
        try:
            flags, conn_id, pkt_num = struct.unpack(HEADER_FORMAT, header_bytes)
        except Exception:
            return None

        ctrl_space = (pkt_num & CTRL_SEQ_BIT) != 0

        # 1) 解密
        # incoming direction (peer -> local)
        dir_bit = 0 if self.is_client else 1
        nonce = self._generate_nonce(conn_id, pkt_num, dir_bit)
        try:
            ciphertext = raw_data[HEADER_SIZE:]
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, header_bytes)
        except Exception:
            # AEAD 认证失败：丢弃并计数
            if count_auth_fail:
                try:
                    self._replay_stats["auth_fail"] += 1
                    self._maybe_log_replay_stats()
                except Exception:
                    pass
            return None

        # 2) 分类
        is_data_packet = (flags & FLAG_DATA) != 0

        # 边界规则：
        # - DATA 只能落在普通数据空间；
        # - 所有非 DATA 的 AEAD 控制包都必须落在 ctrl_seq 空间。
        # 这样 nonce 空间的分离假设才能与协议层保持一致。
        if is_data_packet:
            if ctrl_space:
                return None
            if pkt_num <= 0:
                # 保护：不接受 0 或负数
                return None

            verdict = self.replay_protector.accept(pkt_num)

            if verdict == ReplayProtector.TOO_FAR_RIGHT:
                # 超出窗口右侧：丢弃并计数（防 DoS / 防位图膨胀）
                try:
                    self._replay_stats["too_far_right"] += 1
                    self._maybe_log_replay_stats()
                except Exception:
                    pass
                return None

            if verdict == ReplayProtector.DUP_OLD:
                # 认证成功，但 duplicate/old：不在 crypto 层吞掉，
                # 交给协议层做 dedup，并触发“收到重复包 -> 回 ACK1”的补救路径。
                try:
                    self._replay_stats["duplicate_old"] += 1
                    self._maybe_log_replay_stats()
                except Exception:
                    pass

            return Packet(flags, conn_id, pkt_num, plaintext)

        if not ctrl_space:
            return None

        # 控制包空间：全部跳过 anti-replay（ACK/META/ACK2/SYN/RST/FIN 等都在这里）
        return Packet(flags, conn_id, pkt_num, plaintext)

    def _generate_nonce(self, conn_id, pkt_num, dir_bit: int):
        # Note: keep nonce derivation deterministic and collision-resistant.
        raw = struct.pack("!Q Q B", int(conn_id), int(pkt_num), int(dir_bit) & 0x01) + bytes(self.nonce_secret or b"")
        return hashlib.sha256(raw).digest()[:12]
