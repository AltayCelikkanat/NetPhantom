"""
modules/scanners/banner_grabber.py

Grabs service banners from open TCP ports.
Sends protocol-specific probes for common services.
"""

import asyncio
import re
from typing import Optional, Dict
from utils.logger import get_logger

logger = get_logger("banner_grabber")

# Service probes: port → bytes to send to elicit a banner
SERVICE_PROBES: Dict[int, bytes] = {
    21:    b"",                           # FTP sends banner immediately
    22:    b"",                           # SSH sends banner immediately
    25:    b"EHLO netphantom\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   b"",                           # POP3 sends banner immediately
    143:   b"",                           # IMAP
    443:   b"HEAD / HTTP/1.0\r\n\r\n",
    3306:  b"",                           # MySQL sends greeting
    5432:  b"",
    6379:  b"*1\r\n$4\r\nINFO\r\n",      # Redis INFO
    8080:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # MongoDB OP_QUERY
            b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
            b"\x00\x00\x00\x00\xff\xff\xff\xff"
            b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
}

DEFAULT_PROBE = b"\r\n"


class BannerGrabber:
    def __init__(self, host: str, timeout: float = 3.0):
        self.host = host
        self.timeout = timeout

    async def grab(self, port: int) -> Optional[str]:
        probe = SERVICE_PROBES.get(port, DEFAULT_PROBE)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, port),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        banner = b""
        try:
            if probe:
                writer.write(probe)
                await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug("Banner grab error on port %d: %s", port, e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        if banner:
            return self._clean(banner)
        return None

    def _clean(self, raw: bytes) -> str:
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw)
        # Keep only printable + newlines
        text = re.sub(r"[^\x20-\x7e\n\r\t]", ".", text)
        return text.strip()[:256]

    async def grab_all(self, ports: list) -> Dict[int, str]:
        tasks = {port: self.grab(port) for port in ports}
        results = {}
        for port, coro in tasks.items():
            banner = await coro
            if banner:
                results[port] = banner
        return results
