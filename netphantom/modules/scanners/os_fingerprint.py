"""
modules/scanners/os_fingerprint.py
TTL-based + TCP window size OS fingerprinting.
"""
import asyncio, socket, struct
from utils.logger import get_logger
logger = get_logger("os_fingerprint")

TTL_MAP = [
    (255, "Cisco IOS / Network Device"),
    (128, "Windows"),
    (64,  "Linux / macOS / FreeBSD"),
    (60,  "Solaris / AIX (older)"),
    (32,  "Windows 95/98"),
]

WINDOW_HINTS = {
    65535: "macOS / BSD",
    8192:  "Windows XP",
    65535: "Linux (recent)",
    16384: "OpenBSD",
}


class OSFingerprinter:
    def __init__(self, target: str, timeout: float = 3.0):
        self.target = target
        self.timeout = timeout

    async def detect(self) -> str:
        loop = asyncio.get_event_loop()
        ttl = await loop.run_in_executor(None, self._ping_ttl)
        if ttl is None:
            return "Unknown (no ICMP response)"
        guess = self._ttl_to_os(ttl)
        return f"{guess} (TTL={ttl})"

    def _ping_ttl(self) -> int | None:
        try:
            dst = socket.gethostbyname(self.target)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(self.timeout)
            # ICMP echo request
            icmp_type, code, checksum, pid, seq = 8, 0, 0, 1, 1
            header = struct.pack("bbHHh", icmp_type, code, checksum, pid, seq)
            payload = b"netphantom"
            checksum = self._icmp_checksum(header + payload)
            header = struct.pack("bbHHh", icmp_type, code, checksum, pid, seq)
            s.sendto(header + payload, (dst, 0))
            data, _ = s.recvfrom(1024)
            s.close()
            # IP header TTL is at byte 8
            ttl = data[8]
            return ttl
        except PermissionError:
            return self._connect_ttl()
        except Exception as e:
            logger.debug("TTL probe error: %s", e)
            return None

    def _connect_ttl(self) -> int | None:
        """Fallback: read TTL from a TCP response via socket."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, 80))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            s.close()
            return ttl
        except Exception:
            return None

    def _ttl_to_os(self, ttl: int) -> str:
        # TTL decrements in transit; round up to nearest standard value
        for threshold, name in sorted(TTL_MAP, key=lambda x: x[0]):
            if ttl <= threshold:
                return name
        return "Unknown"

    def _icmp_checksum(self, data: bytes) -> int:
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i+1]
            else:
                s += data[i]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF
