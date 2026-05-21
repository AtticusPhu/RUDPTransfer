import struct
import logging
import os

MSS = 1460  # Maximum Segment Size
MAX_PACKET_SIZE = 1470
HEADER_FORMAT = "!B Q Q"  # Flags(1), ConnID(8), PacketNum(8)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

FLAG_SYN = 0x01
FLAG_ACK = 0x02
FLAG_FIN = 0x04
FLAG_DATA = 0x08
FLAG_RST = 0x10
FLAG_META = 0x20
FLAG_ACK2 = 0x40

DEFAULT_DISABLE_CC_MAX_UNACKED_PKTS = 256


def resolve_send_max_unacked_config(explicit_max_unacked_pkts, disable_cc: bool = False, disable_cc_fallback: int = DEFAULT_DISABLE_CC_MAX_UNACKED_PKTS):
    """Resolve the sender outstanding DATA cap in one place.

    Resolution order:
    1) explicit positive cap always wins
    2) when congestion control is disabled, apply a fixed safety fallback
    3) otherwise leave the hard cap disabled and let the caller decide whether
       an additional auto-sizing policy such as BDP-based sizing should apply
    """
    try:
        explicit = int(explicit_max_unacked_pkts or 0)
    except Exception:
        explicit = 0

    if explicit > 0:
        return {
            'configured_max_unacked_pkts': int(explicit),
            'max_unacked_source': 'explicit',
        }

    if bool(disable_cc):
        fallback = max(1, int(disable_cc_fallback or DEFAULT_DISABLE_CC_MAX_UNACKED_PKTS))
        return {
            'configured_max_unacked_pkts': int(fallback),
            'max_unacked_source': 'auto_disable_cc_fallback',
        }

    return {
        'configured_max_unacked_pkts': 0,
        'max_unacked_source': 'disabled',
    }

class _ProtocolNoiseFilter(logging.Filter):
    """Suppress very frequent per-packet ACK logs in application mode.

    Set RUDP_VERBOSE_PROTOCOL=1 to restore full protocol logs.
    """
    NOISY_PREFIXES = (
        "ACK1 rate-limited",
        "ACK1 send",
        "ACK1 resend",
    )

    def filter(self, record):
        if os.environ.get("RUDP_VERBOSE_PROTOCOL", "").strip() in ("1", "true", "True", "yes"):
            return True
        if str(record.name).startswith("Session-"):
            msg = record.getMessage()
            if msg.startswith(self.NOISY_PREFIXES):
                return False
        return True


def setup_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.addFilter(_ProtocolNoiseFilter())
        formatter = logging.Formatter('[%(asctime)s] %(name)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

class Packet:
    def __init__(self, flags, conn_id, pkt_num, payload=b""):
        self.flags = flags
        self.conn_id = conn_id
        self.pkt_num = pkt_num
        self.payload = payload

    def pack_header(self):
        return struct.pack(HEADER_FORMAT, self.flags, self.conn_id, self.pkt_num)

    @staticmethod
    def unpack_header(data):
        if len(data) < HEADER_SIZE:
            return None, None
        header = data[:HEADER_SIZE]
        flags, conn_id, pkt_num = struct.unpack(HEADER_FORMAT, header)
        payload = data[HEADER_SIZE:]
        return Packet(flags, conn_id, pkt_num, payload), payload