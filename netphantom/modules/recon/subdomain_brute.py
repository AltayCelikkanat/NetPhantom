"""
modules/recon/subdomain_brute.py
Async subdomain brute-force with concurrency control.
"""
import asyncio, socket
from pathlib import Path
from typing import List, Dict
from utils.logger import get_logger
logger = get_logger("subdomain_brute")

DEFAULT_WORDLIST = Path(__file__).parent.parent.parent / "utils" / "wordlists" / "subdomains.txt"


class SubdomainBrute:
    def __init__(self, domain: str, wordlist: str = None, concurrency: int = 200):
        self.domain = domain.lstrip("http://").lstrip("https://").split("/")[0]
        self.wordlist = wordlist or str(DEFAULT_WORDLIST)
        self.concurrency = concurrency

    async def run(self) -> List[Dict]:
        words = self._load_words()
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._probe(word, semaphore) for word in words]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    def _load_words(self) -> List[str]:
        path = Path(self.wordlist)
        if path.exists():
            return [l.strip() for l in path.read_text().splitlines() if l.strip()]
        # Built-in mini list as fallback
        return ["www","mail","ftp","admin","vpn","dev","staging","api","blog",
                "shop","remote","test","ns1","ns2","smtp","pop","imap","portal",
                "cdn","static","assets","login","dashboard","secure","app","web"]

    async def _probe(self, word: str, sem: asyncio.Semaphore) -> Dict | None:
        subdomain = f"{word}.{self.domain}"
        async with sem:
            loop = asyncio.get_event_loop()
            try:
                ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
                return {"subdomain": subdomain, "ip": ip}
            except Exception:
                return None
