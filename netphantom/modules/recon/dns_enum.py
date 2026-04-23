"""
modules/recon/dns_enum.py
Async DNS record enumeration: A, AAAA, MX, NS, TXT, CNAME, SOA
"""
import asyncio, socket
from typing import Dict, List
from utils.logger import get_logger
logger = get_logger("dns_enum")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSEnumerator:
    def __init__(self, target: str):
        self.target = target.lstrip("http://").lstrip("https://").split("/")[0]

    async def enumerate(self) -> Dict[str, List[str]]:
        loop = asyncio.get_event_loop()
        results = {}
        tasks = {rtype: loop.run_in_executor(None, self._query, rtype)
                 for rtype in RECORD_TYPES}
        for rtype, coro in tasks.items():
            try:
                records = await coro
                if records:
                    results[rtype] = records
            except Exception as e:
                logger.debug("DNS %s query failed: %s", rtype, e)
        return results

    def _query(self, rtype: str) -> List[str]:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.target, rtype, lifetime=5)
            return [str(r) for r in answers]
        except ImportError:
            return self._fallback_a() if rtype == "A" else []
        except Exception:
            return []

    def _fallback_a(self) -> List[str]:
        try:
            infos = socket.getaddrinfo(self.target, None)
            return list({i[4][0] for i in infos})
        except Exception:
            return []
