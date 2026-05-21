import math
import threading
import time

from utils import MSS


class CubicCongestionControl:
    """CUBIC-like congestion control with standard initial window semantics.

    Design goals for this version:
    - No empirical initial_phase / warm-up bypass knobs.
    - Keep only a standard initial congestion window (default: RFC 6928 style 10*MSS).
    - Let slow start absorb early ramp-up by growing on bytes_acked.
    - Provide RTT/RTO diagnostics for logging.
    """

    _INF_SSTHRESH = 1 << 60

    def __init__(
        self,
        mss: int = MSS,
        initial_cwnd: int = None,
        min_cwnd: int = None,
        beta: float = 0.7,
        cubic_c: float = 0.4,
        min_rto: float = 0.2,
        max_rto: float = 4.0,
        initial_rtt: float = None,
        initial_rto: float = None,
    ):
        self._lock = threading.RLock()
        self.mss = max(1, int(mss or MSS))
        default_iw = min(10 * self.mss, max(2 * self.mss, 14600))
        self.initial_cwnd = max(self.mss, int(initial_cwnd or default_iw))
        self.min_cwnd = max(self.mss, int(min_cwnd or (2 * self.mss)))
        self.beta = min(0.95, max(0.1, float(beta)))
        self.cubic_c = max(1e-6, float(cubic_c))
        self.min_rto = max(0.05, float(min_rto))
        self.max_rto = max(self.min_rto, float(max_rto))

        self.cwnd = int(self.initial_cwnd)
        self.ssthresh = int(self._INF_SSTHRESH)
        self.inflight_bytes = 0

        self.srtt = None
        self.rttvar = None
        self.rto = float(self.min_rto)
        self.min_rtt = None
        self.last_rtt_sample = None
        self.tail_rtt = None
        self._tail_rtt_ts = None

        # High-RTT bootstrap:
        # If min_rto is lower than the real path RTT, the first DATA flight can
        # timeout before ACK1 returns. Once that happens, Karn-safe RTT sampling
        # is suppressed because those packets have retries > 0. Seeding srtt/rttvar
        # from the known Mininet delay prevents this false first RTO.
        seed_rtt = None
        try:
            if initial_rtt is not None and math.isfinite(float(initial_rtt)) and float(initial_rtt) > 0.0:
                seed_rtt = max(1e-6, float(initial_rtt))
        except Exception:
            seed_rtt = None

        if seed_rtt is not None:
            self.srtt = float(seed_rtt)
            self.rttvar = float(seed_rtt) / 2.0
            self.min_rtt = float(seed_rtt)
            self.last_rtt_sample = float(seed_rtt)
            self.tail_rtt = float(seed_rtt)
            self._tail_rtt_ts = time.time()
            est_rto = float(self.srtt) + max(0.010, 4.0 * float(self.rttvar))
            self.rto = min(self.max_rto, max(self.min_rto, est_rto))

        try:
            if initial_rto is not None and math.isfinite(float(initial_rto)) and float(initial_rto) > 0.0:
                self.rto = min(self.max_rto, max(self.min_rto, float(initial_rto)))
        except Exception:
            pass
        self.tail_guard_gain = 1.25
        self.tail_guard_trigger_gain = 1.25
        self.tail_guard_var_gain = 2.0
        self.tail_guard_decay_tau = 8.0

        self._epoch_start = None
        self._origin_point_cwnd = float(self.cwnd)
        self._last_max_cwnd = float(self.cwnd)
        self._tcp_cwnd = float(self.cwnd)
        self._k = 0.0

    def can_send(self, packet_size: int) -> bool:
        with self._lock:
            pkt = max(0, int(packet_size or 0))
            return (int(self.inflight_bytes) + pkt) <= int(self.cwnd)

    def on_packet_sent(self, size: int) -> None:
        with self._lock:
            self.inflight_bytes += max(0, int(size or 0))

    def on_ack_received(self, rtt_sample=None, bytes_acked=None) -> None:
        acked = max(0, int(bytes_acked or 0))
        with self._lock:
            if acked > 0:
                self.inflight_bytes = max(0, int(self.inflight_bytes) - acked)

            self._update_rtt_locked(rtt_sample)

            if acked <= 0:
                return

            # Standard slow start: grow by bytes_acked, with no extra warm-up bypass.
            if int(self.cwnd) < int(self.ssthresh):
                self.cwnd = int(max(self.min_cwnd, int(self.cwnd) + acked))
                return

            self._cubic_congestion_avoidance_locked(acked)

    def on_packet_lost(self) -> None:
        with self._lock:
            current_cwnd = max(self.min_cwnd, int(self.cwnd))
            self._last_max_cwnd = float(current_cwnd)
            new_cwnd = max(self.min_cwnd, int(current_cwnd * self.beta))
            self.ssthresh = int(max(self.min_cwnd, new_cwnd))
            self.cwnd = int(self.ssthresh)
            self._epoch_start = None
            self._origin_point_cwnd = float(self.cwnd)
            self._tcp_cwnd = float(self.cwnd)
            self._k = 0.0

    def sync_inflight_bytes(self, inflight_bytes: int) -> None:
        with self._lock:
            self.inflight_bytes = max(0, int(inflight_bytes or 0))

    def reset_after_migration(self, rtt_sample=None, initial_cwnd_pkts: int = 10) -> None:
        with self._lock:
            fresh_cwnd = max(1, int(initial_cwnd_pkts or 10)) * self.mss
            self.initial_cwnd = int(fresh_cwnd)
            self.cwnd = int(fresh_cwnd)
            self.ssthresh = int(self._INF_SSTHRESH)
            self.inflight_bytes = 0
            self._epoch_start = None
            self._origin_point_cwnd = float(self.cwnd)
            self._last_max_cwnd = float(self.cwnd)
            self._tcp_cwnd = float(self.cwnd)
            self._k = 0.0
            self._update_rtt_locked(rtt_sample)

    def get_debug_stats(self):
        with self._lock:
            return {
                "cwnd": int(self.cwnd),
                "bytes_in_flight": int(self.inflight_bytes),
                "ssthresh": int(self.ssthresh),
                "srtt": (None if self.srtt is None else float(self.srtt)),
                "rto": (None if self.rto is None else float(self.rto)),
                "tail_rtt": (None if self.tail_rtt is None else float(self.tail_rtt)),
            }

    def get_pacing_rate_bytes_per_s(
        self,
        gain: float = 1.0,
        min_rtt: float = 0.005,
        fallback_rtt: float = 0.1,
        min_rate: float = 0.0,
    ) -> float:
        with self._lock:
            cwnd = max(float(self.min_cwnd), float(self.cwnd))
            ref_rtt = self.srtt
            if ref_rtt is None or float(ref_rtt) <= 0.0:
                ref_rtt = self.last_rtt_sample
            if ref_rtt is None or float(ref_rtt) <= 0.0:
                ref_rtt = self.min_rtt
            if ref_rtt is None or float(ref_rtt) <= 0.0:
                ref_rtt = float(fallback_rtt)
            ref_rtt = max(float(min_rtt), float(ref_rtt))
            rate = float(gain) * cwnd / ref_rtt
            return max(float(min_rate), float(rate))

    def _decay_tail_rtt_locked(self, now: float, ref_rtt: float):
        tail = self.tail_rtt
        if tail is None:
            return None
        ref = max(1e-6, float(ref_rtt or tail))
        prev_ts = self._tail_rtt_ts
        if prev_ts is None:
            self._tail_rtt_ts = float(now)
            return max(ref, float(tail))
        dt = max(0.0, float(now) - float(prev_ts))
        tau = max(0.25, float(self.tail_guard_decay_tau or 8.0))
        decay = math.exp(-dt / tau)
        decayed = ref + (float(tail) - ref) * decay
        self._tail_rtt_ts = float(now)
        return max(ref, float(decayed))

    def _update_rtt_locked(self, rtt_sample) -> None:
        if rtt_sample is None:
            return
        try:
            sample = float(rtt_sample)
        except Exception:
            return
        if not math.isfinite(sample) or sample <= 0.0:
            return

        sample = max(1e-6, sample)
        now = time.time()
        prev_srtt = (None if self.srtt is None else float(self.srtt))
        prev_rttvar = (None if self.rttvar is None else float(self.rttvar))
        self.last_rtt_sample = sample
        if self.min_rtt is None or sample < float(self.min_rtt):
            self.min_rtt = sample

        ref_tail = prev_srtt if (prev_srtt is not None and prev_srtt > 0.0) else sample
        decayed_tail = self._decay_tail_rtt_locked(now, ref_tail)

        if prev_srtt is None or prev_rttvar is None:
            self.srtt = sample
            self.rttvar = sample / 2.0
            self.tail_rtt = sample
            self._tail_rtt_ts = float(now)
        else:
            tail_trigger = max(
                float(prev_srtt) * float(self.tail_guard_trigger_gain or 1.25),
                float(prev_srtt) + max(0.010, float(self.tail_guard_var_gain or 2.0) * float(prev_rttvar)),
            )
            if decayed_tail is None:
                decayed_tail = float(prev_srtt)
            if sample >= tail_trigger:
                self.tail_rtt = max(float(decayed_tail), float(sample))
                self._tail_rtt_ts = float(now)
            else:
                self.tail_rtt = max(float(prev_srtt), float(decayed_tail))
                self._tail_rtt_ts = float(now)

            err = abs(float(prev_srtt) - sample)
            self.rttvar = 0.75 * float(prev_rttvar) + 0.25 * err
            self.srtt = 0.875 * float(prev_srtt) + 0.125 * sample

        tail_rtt = self.tail_rtt if self.tail_rtt is not None else self.srtt
        est_rto_main = float(self.srtt) + max(0.010, 4.0 * float(self.rttvar))
        est_rto_tail = float(self.tail_guard_gain or 1.25) * float(tail_rtt)
        est_rto = max(est_rto_main, est_rto_tail)
        self.rto = min(self.max_rto, max(self.min_rto, est_rto))

    def _cubic_congestion_avoidance_locked(self, acked: int) -> None:
        now = time.time()
        current_cwnd = max(self.min_cwnd, int(self.cwnd))
        ref_rtt = max(0.001, float(self.srtt or self.last_rtt_sample or self.min_rtt or 0.1))

        if self._epoch_start is None:
            self._epoch_start = now
            if current_cwnd < int(self._last_max_cwnd):
                diff = float(self._last_max_cwnd) - float(current_cwnd)
                self._k = (diff / (self.cubic_c * float(self.mss))) ** (1.0 / 3.0)
                self._origin_point_cwnd = float(self._last_max_cwnd)
            else:
                self._k = 0.0
                self._origin_point_cwnd = float(current_cwnd)
                self._last_max_cwnd = float(current_cwnd)
            self._tcp_cwnd = max(float(self._tcp_cwnd), float(current_cwnd))

        t = max(0.0, (now - float(self._epoch_start)) + ref_rtt)
        target = self._origin_point_cwnd + self.cubic_c * ((t - self._k) ** 3) * float(self.mss)

        # Reno-friendly floor: about +1 MSS per RTT.
        reno_delta = (float(acked) * float(self.mss)) / max(float(current_cwnd), float(self.mss))
        self._tcp_cwnd += reno_delta
        target = max(target, self._tcp_cwnd)

        if target > float(current_cwnd):
            cubic_delta = ((target - float(current_cwnd)) * float(acked)) / max(float(current_cwnd), float(self.mss))
            delta = max(1.0, reno_delta, cubic_delta)
        else:
            delta = max(1.0, reno_delta)

        self.cwnd = int(max(self.min_cwnd, int(round(float(current_cwnd) + delta))))
