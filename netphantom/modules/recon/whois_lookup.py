"""
modules/recon/whois_lookup.py
WHOIS lookup via python-whois with socket fallback.
"""
import asyncio, socket, re
from typing import Dict
from utils.logger import get_logger
logger = get_logger("whois")

FIELDS = ["domain_name","registrar","creation_date","expiration_date",
          "name_servers","status","emails","org","country"]


class WhoisLookup:
    def __init__(self, target: str):
        self.target = target.lstrip("http://").lstrip("https://").split("/")[0]

    async def lookup(self) -> Dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._query)

    def _query(self) -> Dict:
        try:
            import whois
            w = whois.whois(self.target)
            result = {}
            for f in FIELDS:
                val = getattr(w, f, None)
                if val:
                    result[f] = str(val)[:120] if not isinstance(val, list) else ", ".join(str(v) for v in val)[:120]
            return result
        except ImportError:
            return self._raw_whois()
        except Exception as e:
            logger.debug("WHOIS error: %s", e)
            return {"error": str(e)}

    def _raw_whois(self) -> Dict:
        """Raw socket WHOIS against whois.iana.org"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.iana.org", 43))
            s.sendall((self.target + "\r\n").encode())
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            s.close()
            text = resp.decode("utf-8", errors="replace")
            result = {}
            for line in text.splitlines():
                if ":" in line and not line.startswith("%"):
                    k, _, v = line.partition(":")
                    result[k.strip().lower()] = v.strip()
            return dict(list(result.items())[:10])
        except Exception as e:
            return {"error": str(e)}
