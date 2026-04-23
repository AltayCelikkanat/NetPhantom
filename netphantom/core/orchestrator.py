"""
core/orchestrator.py
Orchestrates the full recon → scan → vuln → report pipeline.
"""

import asyncio
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from utils.logger import get_logger

logger = get_logger("orchestrator")


@dataclass
class ScanResult:
    target: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    open_ports: List[Dict] = field(default_factory=list)
    recon_data: Dict = field(default_factory=dict)
    vulnerabilities: List[Dict] = field(default_factory=list)
    os_guess: str = "Unknown"
    summary: Dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class Orchestrator:
    def __init__(self, target: str):
        self.target = target
        self.result = ScanResult(target=target)

    async def run_full_pipeline(
        self,
        port_range: str = "1-1024",
        concurrency: int = 300,
    ) -> ScanResult:
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

        console = Console()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            # Stage 1: Recon
            t_recon = progress.add_task("[cyan]Reconnaissance...", total=3)
            recon_data = await self._run_recon(progress, t_recon)
            self.result.recon_data = recon_data

            # Stage 2: Port scan
            t_scan = progress.add_task("[cyan]Port scanning...", total=100)
            open_ports = await self._run_scan(port_range, concurrency, progress, t_scan)
            self.result.open_ports = open_ports

            # Stage 3: Banner grab + OS detect
            t_banner = progress.add_task("[cyan]Banner grabbing...", total=len(open_ports) or 1)
            await self._run_banners(open_ports, progress, t_banner)

            t_os = progress.add_task("[cyan]OS fingerprinting...", total=1)
            self.result.os_guess = await self._run_os_detect(progress, t_os)

            # Stage 4: Vuln check
            t_vuln = progress.add_task("[cyan]Vulnerability check...", total=len(open_ports) or 1)
            vulns = await self._run_vuln_check(open_ports, progress, t_vuln)
            self.result.vulnerabilities = vulns

        self.result.end_time = time.time()
        self.result.summary = self._build_summary()
        return self.result

    async def _run_recon(self, progress, task) -> Dict:
        from modules.recon.dns_enum import DNSEnumerator
        from modules.recon.whois_lookup import WhoisLookup

        data = {}

        wh = WhoisLookup(self.target)
        data["whois"] = await wh.lookup()
        progress.advance(task)

        dns = DNSEnumerator(self.target)
        data["dns"] = await dns.enumerate()
        progress.advance(task)

        progress.advance(task)
        return data

    async def _run_scan(self, port_range, concurrency, progress, task) -> List[Dict]:
        from modules.scanners.port_scanner import PortScanner

        scanner = PortScanner(
            target=self.target,
            port_range=port_range,
            technique="connect",
            concurrency=concurrency,
        )

        # Hook into scanner progress
        results = await scanner.run(progress_callback=lambda pct: progress.update(task, completed=pct))
        progress.update(task, completed=100)
        return [r for r in results if r["state"] == "open"]

    async def _run_banners(self, open_ports, progress, task):
        from modules.scanners.banner_grabber import BannerGrabber

        grabber = BannerGrabber(self.target)
        for port_info in open_ports:
            banner = await grabber.grab(port_info["port"])
            if banner:
                port_info["banner"] = banner
            progress.advance(task)

    async def _run_os_detect(self, progress, task) -> str:
        from modules.scanners.os_fingerprint import OSFingerprinter

        fp = OSFingerprinter(self.target)
        guess = await fp.detect()
        progress.advance(task)
        return guess

    async def _run_vuln_check(self, open_ports, progress, task) -> List[Dict]:
        from modules.scanners.vuln_checker import VulnChecker

        checker = VulnChecker()
        vulns = []
        for port_info in open_ports:
            found = checker.check(port_info)
            vulns.extend(found)
            progress.advance(task)
        return vulns

    def _build_summary(self) -> Dict:
        duration = self.result.end_time - self.result.start_time
        critical = sum(1 for v in self.result.vulnerabilities if v.get("severity") == "CRITICAL")
        high = sum(1 for v in self.result.vulnerabilities if v.get("severity") == "HIGH")
        return {
            "duration_seconds": round(duration, 2),
            "open_ports": len(self.result.open_ports),
            "vulnerabilities_total": len(self.result.vulnerabilities),
            "critical": critical,
            "high": high,
            "risk_score": min(100, critical * 25 + high * 10),
        }
