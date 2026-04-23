"""
modules/scanners/port_scanner.py

Raw async TCP port scanner supporting:
  - CONNECT scan  (asyncio streams, reliable, no root needed)
  - SYN scan      (raw socket, requires root)
  - FIN / XMAS / NULL scans (raw socket stealth techniques)

Port range parsing, concurrency limiting, and service name resolution included.
"""

import asyncio
import socket
import struct
import random
import time
from typing import List, Dict, Callable, Optional, Tuple

from utils.logger import get_logger
from utils.service_db import SERVICE_DB

logger = get_logger("port_scanner")

# Common TCP services map (supplemented by SERVICE_DB)
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def parse_port_range(port_str: str) -> List[int]:
    """Parse '22,80,443' or '1-1024' or '22,80,100-200' into sorted list."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def get_service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ─── CONNECT SCAN ────────────────────────────────────────────────────────────

async def _connect_probe(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> Dict:
    async with semaphore:
        state = "closed"
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            state = "open"
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        return {
            "port": port,
            "state": state,
            "service": get_service_name(port),
            "version": "",
            "banner": "",
        }


# ─── RAW SOCKET HELPERS ──────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    flags: int,
    src_port: Optional[int] = None,
) -> bytes:
    """
    Build a minimal TCP packet.
    flags: bitmask  FIN=0x01 SYN=0x02 RST=0x04 ACK=0x10 URG=0x20
    """
    src_port = src_port or random.randint(1024, 65535)
    seq = random.randint(0, 2**32 - 1)
    ack = 0
    offset_res = (5 << 4)  # data offset = 5 (20 bytes), reserved = 0
    window = socket.htons(5840)
    check = 0
    urg = 0

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack,
        offset_res, flags, window, check, urg,
    )

    # Pseudo-header for checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    pseudo = struct.pack("!4s4sBBH", src_addr, dst_addr, placeholder, protocol, tcp_length)
    check = _checksum(pseudo + tcp_header)

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack,
        offset_res, flags, window, check, urg,
    )
    return tcp_header


def _get_local_ip(dst: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


async def _raw_probe(
    host: str,
    port: int,
    flags: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> Dict:
    """
    Raw socket probe for SYN/FIN/XMAS/NULL.
    Requires root. Returns 'open|filtered' on no response (stealth scans).
    """
    async with semaphore:
        state = "closed"
        try:
            dst_ip = socket.gethostbyname(host)
            src_ip = _get_local_ip(dst_ip)
            packet = _build_tcp_packet(src_ip, dst_ip, port, flags)

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, _raw_send_recv, dst_ip, port, packet, timeout
            )
            state = result
        except PermissionError:
            logger.warning("Raw socket requires root. Falling back to CONNECT for port %d", port)
            # fallback
            probe = await _connect_probe(host, port, timeout, semaphore)
            return probe
        except Exception as e:
            logger.debug("Raw probe error on port %d: %s", port, e)

        return {
            "port": port,
            "state": state,
            "service": get_service_name(port),
            "version": "",
            "banner": "",
        }


def _raw_send_recv(dst_ip: str, port: int, packet: bytes, timeout: float) -> str:
    """Blocking raw socket send/recv (runs in executor)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(timeout)
        s.sendto(packet, (dst_ip, port))

        try:
            data, _ = s.recvfrom(1024)
            # Parse IP header (20 bytes) + TCP header
            ip_header_len = (data[0] & 0x0F) * 4
            tcp_data = data[ip_header_len:]
            if len(tcp_data) < 14:
                return "filtered"
            tcp_flags = tcp_data[13]
            # SYN+ACK = 0x12 → open; RST+ACK = 0x14 → closed
            if tcp_flags & 0x12 == 0x12:
                return "open"
            elif tcp_flags & 0x04:
                return "closed"
        except socket.timeout:
            return "open|filtered"
        finally:
            s.close()
    except Exception:
        return "filtered"
    return "filtered"


# ─── MAIN SCANNER CLASS ───────────────────────────────────────────────────────

class PortScanner:
    TECHNIQUE_FLAGS = {
        "syn":  0x02,       # SYN
        "fin":  0x01,       # FIN
        "xmas": 0x29,       # FIN + PSH + URG
        "null": 0x00,       # NULL (no flags)
    }

    def __init__(
        self,
        target: str,
        port_range: str = "1-1024",
        technique: str = "connect",
        timeout: float = 1.0,
        concurrency: int = 500,
    ):
        self.target = target
        self.ports = parse_port_range(port_range)
        self.technique = technique.lower()
        self.timeout = timeout
        self.concurrency = concurrency

    async def run(
        self,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> List[Dict]:
        semaphore = asyncio.Semaphore(self.concurrency)
        total = len(self.ports)
        completed = 0
        results = []

        async def probe_with_progress(port):
            nonlocal completed
            if self.technique == "connect":
                r = await _connect_probe(self.target, port, self.timeout, semaphore)
            else:
                flags = self.TECHNIQUE_FLAGS.get(self.technique, 0x02)
                r = await _raw_probe(self.target, port, flags, self.timeout, semaphore)
            completed += 1
            if progress_callback:
                progress_callback(int(completed / total * 100))
            return r

        tasks = [probe_with_progress(p) for p in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)
